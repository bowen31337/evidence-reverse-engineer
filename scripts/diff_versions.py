#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Compare two versions of an artifact and emit comparison Evidence.

Usage:
  diff_versions.py <old> <new> [--record] [--workdir DIR] [--arch ARCH] [--timeout SEC]

Native (Mach-O/ELF/PE): symbols added/removed, linked libraries, strings added/removed,
  per-function changes (instruction shape hash with addresses masked; constants, calls and
  string references diffed for each changed function).
Archives (ZIP/APK/IPA/JAR/TAR): members added/removed/changed by sha256.
JavaScript (ASAR/dir): files changed + IPC channels / endpoints / security flags added/removed.

A changed function means its static code changed. Whether behaviour changed at
runtime is a separate question: record it as an inference or verify at runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import fail, identify, run_owned, which, workdir_path  # noqa: E402
from evidence import finish  # noqa: E402
import run_provider as rp  # noqa: E402
import js_bundle as jb  # noqa: E402

NATIVE = {"mach-o", "mach-o-universal", "elf", "pe"}
ARCHIVE = {"zip", "apk", "ipa", "jar", "msix", "wheel", "tar"}
JS = {"asar", "javascript-tree", "javascript", "macos-app-bundle"}
ADDR = re.compile(r"0x[0-9a-f]{5,}")


def immediates(insns):
    """Immediate operands that are values, not address arithmetic (adrp/add page offsets, ldr/str offsets)."""
    out, prev_adrp = set(), set()
    for i in insns:
        regs = set(re.findall(r"\b[xw]\d+\b", i["ops"]))
        if i["mnem"] == "adrp" or (i["mnem"] == "add" and (regs & prev_adrp or i["comment"])):
            prev_adrp = regs if i["mnem"] == "adrp" else set()
            continue
        if i["mnem"].startswith(("ld", "st")):
            continue
        out.update(re.findall(r"#0x[0-9a-f]+|\$0x[0-9a-f]+", i["ops"]))
    return out


def shape_hash(insns):
    h = hashlib.sha256()
    for i in insns:
        ops = ADDR.sub("ADDR", i["ops"])
        h.update(f'{i["mnem"]} {ops}\n'.encode())
    return h.hexdigest()[:16]


def nm_sets(path, arch):
    tool = "nm" if which("nm") else "llvm-nm"
    r = run_owned([tool, *(["-arch", arch] if arch else []), path], timeout=120)
    defined, imported = set(), set()
    for line in r["stdout"].splitlines():
        p = line.split()
        if len(p) == 3 and p[1] not in ("U",):
            defined.add(p[2])
        elif len(p) >= 2 and p[-2] == "U":
            imported.add(p[-1])
    return defined, imported


def native_diff(a, old, new, w):
    args = SimpleNamespace(arch=a.arch, timeout=a.timeout)
    d_old, d_new = rp.disassemble(args, old, w), rp.disassemble(args, new, w)
    fo, fn = d_old["functions"], d_new["functions"]
    added, removed = sorted(set(fn) - set(fo)), sorted(set(fo) - set(fn))
    changed = []
    for name in sorted(set(fo) & set(fn)):
        if shape_hash(fo[name]["insns"]) != shape_hash(fn[name]["insns"]):
            ao, an = rp.analyze_fn(name, fo[name], d_old["by_addr"]), rp.analyze_fn(name, fn[name], d_new["by_addr"])
            co = {c["insn"].split(" ", 1)[1] for c in ao["compared_constants"]}
            cn = {c["insn"].split(" ", 1)[1] for c in an["compared_constants"]}
            changed.append({
                "function": name,
                "instructions": [len(fo[name]["insns"]), len(fn[name]["insns"])],
                "calls_added": sorted({c["target"] for c in an["calls"]} - {c["target"] for c in ao["calls"]}),
                "calls_removed": sorted({c["target"] for c in ao["calls"]} - {c["target"] for c in an["calls"]}),
                "strings_added": sorted({s["text"] for s in an["string_refs"]} - {s["text"] for s in ao["string_refs"]}),
                "strings_removed": sorted({s["text"] for s in ao["string_refs"]} - {s["text"] for s in an["string_refs"]}),
                "comparisons_added": sorted(cn - co), "comparisons_removed": sorted(co - cn),
                "immediates_added": sorted(immediates(fn[name]["insns"]) - immediates(fo[name]["insns"]),
                                           key=lambda x: int(x.strip("#$"), 16))[:40],
                "immediates_removed": sorted(immediates(fo[name]["insns"]) - immediates(fn[name]["insns"]),
                                             key=lambda x: int(x.strip("#$"), 16))[:40],
            })
    new_fn_facts = {n: rp.analyze_fn(n, fn[n], d_new["by_addr"]) for n in added}
    sdo, sio = nm_sets(old["path"], a.arch)
    sdn, sin = nm_sets(new["path"], a.arch)
    so = {s for _, s in rp.extract_strings(Path(old["path"]).read_bytes(), 6)}
    sn = {s for _, s in rp.extract_strings(Path(new["path"]).read_bytes(), 6)}
    return {
        "kind": "native",
        "functions": {"old": len(fo), "new": len(fn), "added": added, "removed": removed,
                      "changed": changed, "unchanged": len(set(fo) & set(fn)) - len(changed)},
        "added_function_facts": {n: {"calls": sorted({c["target"] for c in f["calls"]}),
                                     "string_refs": [s["text"] for s in f["string_refs"]]} for n, f in new_fn_facts.items()},
        "imports": {"added": sorted(sin - sio), "removed": sorted(sio - sin)},
        "exports_or_defined": {"added": sorted(sdn - sdo), "removed": sorted(sdo - sdn)},
        "strings": {"added": sorted(sn - so)[:300], "removed": sorted(so - sn)[:300]},
    }, d_new["tool"]


def archive_diff(old, new):
    def members(ident):
        return {n: rp.sha256_bytes(d) for n, d, _ in rp._members(ident["path"], ident["format"])}
    mo, mn = members(old), members(new)
    return {"kind": "archive", "added": sorted(set(mn) - set(mo)), "removed": sorted(set(mo) - set(mn)),
            "changed": sorted(n for n in set(mo) & set(mn) if mo[n] != mn[n]),
            "unchanged": sum(1 for n in set(mo) & set(mn) if mo[n] == mn[n])}, "builtin"


def js_diff(old, new):
    fo, _, _ = jb.load(Path(old["path"]))
    fn, _, _ = jb.load(Path(new["path"]))
    ro, rn = jb.analyze(fo, []), jb.analyze(fn, [])
    ho = {k: rp.sha256_bytes(v) for k, v in fo.items()}
    hn = {k: rp.sha256_bytes(v) for k, v in fn.items()}

    def vals(r, key):
        return {x["value"] for x in r[key]}
    return {"kind": "javascript",
            "files": {"added": sorted(set(hn) - set(ho)), "removed": sorted(set(ho) - set(hn)),
                      "changed": sorted(n for n in set(ho) & set(hn) if ho[n] != hn[n])},
            "ipc_channels": {"added": sorted(set(rn["ipc_channels"]) - set(ro["ipc_channels"])),
                             "removed": sorted(set(ro["ipc_channels"]) - set(rn["ipc_channels"]))},
            "endpoints": {"added": sorted(vals(rn, "endpoints") - vals(ro, "endpoints")),
                          "removed": sorted(vals(ro, "endpoints") - vals(rn, "endpoints"))},
            "security_flags": {"added": sorted(set(rn["security_flags"]) - set(ro["security_flags"])),
                               "removed": sorted(set(ro["security_flags"]) - set(rn["security_flags"]))},
            "external_modules": {"added": sorted(set(rn["external_modules"]) - set(ro["external_modules"])),
                                 "removed": sorted(set(ro["external_modules"]) - set(rn["external_modules"]))},
            "package_version": [(ro["package"] or {}).get("version"), (rn["package"] or {}).get("version")]}, "builtin-js"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--workdir")
    ap.add_argument("--arch")
    ap.add_argument("--timeout", type=float, default=180)
    a = ap.parse_args()
    try:
        old, new = identify(a.old), identify(a.new)
    except FileNotFoundError as e:
        fail(f"target not found: {e}")
    w = workdir_path(a.workdir)
    fo, fnw = old["format"], new["format"]
    if fo in NATIVE and fnw in NATIVE:
        result, tool = native_diff(a, old, new, w)
    elif fo in ARCHIVE and fnw in ARCHIVE:
        result, tool = archive_diff(old, new)
    elif fo in JS and fnw in JS:
        result, tool = js_diff(old, new)
    else:
        fail(f"cannot compare {fo!r} with {fnw!r}; extract/route both to the same kind first")
    result["old"] = {k: old.get(k) for k in ("path", "sha256", "format", "arch")}
    result["identical"] = old["sha256"] == new["sha256"]
    lim = ["static comparison: a code change does not by itself prove a runtime behaviour change"]
    if result["kind"] == "native":
        lim.append("function matching is by symbol name; renamed or stripped functions appear as added+removed")
    payload = {"subject": {k: new.get(k) for k in ("path", "sha256", "digest_kind", "format", "arch", "size")},
               "provider": {"id": tool, "version": rp.tool_version(tool) if tool not in ("builtin", "builtin-js") else "1"},
               "operation": "compare:artifacts", "parameters": {"base_sha256": old["sha256"], "arch": a.arch},
               "normalized_result": result, "raw_result": None, "limitations": lim, "locations": [],
               "authority": "shipped-artifact", "confidence": "high"}
    summary = {k: v for k, v in result.items() if k not in ("strings",)}
    if "strings" in result:
        summary["strings"] = {"added": result["strings"]["added"][:40], "removed": result["strings"]["removed"][:40],
                              "added_count": len(result["strings"]["added"]), "removed_count": len(result["strings"]["removed"])}
    finish(payload, w, a.record, summary)


if __name__ == "__main__":
    main()
