#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Run one bounded analysis operation against a target and emit an Evidence payload.

Usage:
  run_provider.py <operation> <target> [options] [--record] [--workdir DIR] [--timeout SEC]

Baseline operations (need only Python + the OS toolchain: otool/objdump/nm):
  strings:extract      [--min 6] [--grep REGEX] [--limit 200]
  symbols:list         [--grep REGEX] [--limit 300]
  headers:info         sections, linked libraries, entry point, security-relevant flags
  disasm:function      --symbol NAME | --address 0xADDR  [--max-lines 400]
                       -> calls, string references, compared constants, instructions
  callgraph:build      [--root NAME] [--depth 3] [--direction callees|callers] [--max-nodes 200]
  xrefs:to             --symbol NAME | --string TEXT   (who calls / which functions reference a string)
  macho:objc           Objective-C classes/methods (otool -oV)
  codesign:info        signature, team id, entitlements (macOS)
  artifact:inventory   ZIP/APK/IPA/JAR/MSIX/TAR members with sha256 + content-identified kind  [--detail summary|complete]
  artifact:extract     --out NEW_DIR [--member NAME]...  (path-traversal safe)
Optional engines (used only when installed; see doctor.py):
  rizin:cmd | r2:cmd   --cmd "aaa;aflj"          raw JSON command through rizin/radare2
  ghidra:decompile     --symbol NAME             Ghidra headless pseudo-C
  jadx:decompile       --out NEW_DIR             APK/DEX/JAR -> Java
  apktool:decode       --out NEW_DIR             resources + AndroidManifest.xml
  dotnet:decompile     --out NEW_DIR             ilspycmd -> C#
  binwalk:scan                                   firmware regions (signature scan)
  binwalk:extract      --out NEW_DIR             recursive extraction; per-region success, unsquashfs fallback
  unblob:extract       --out NEW_DIR             recursive firmware extraction
  wasm:inspect                                   wasm-objdump -x (falls back to a built-in section parser)
Runtime (executes the target -- see references/runtime-observation.md for when that is allowed):
  run:process          [--arg A]... [--stdin TEXT] [--allow-network] [--timeout 20]
                       one sandboxed run (macOS sandbox-exec / Linux unshare): no network, writes only
                       to a temp dir, minimal env; records exit code + stdout as controlled-replay evidence

Output is summary-first: the summary is printed, the full output is stored under
<workdir>/raw/ and referenced from the Evidence payload. Disassembly of a target is
cached per (sha256, arch, tool) so repeated questions do not re-run the engine.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import sys
import tarfile
import time
import zipfile
from collections import deque
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (emit, fail, find_ghidra_headless, ghidra_java_home, identify, run_owned, sha256_bytes, store_raw, which,  # noqa: E402
                     workdir_path)
from evidence import finish  # noqa: E402

_VERSIONS: dict[str, str | None] = {}


def tool_version(tool: str) -> str | None:
    if tool not in _VERSIONS:
        path = which(tool)
        if not path:
            _VERSIONS[tool] = None
        else:
            r = run_owned([path, "--version"], timeout=10)
            line = (r["stdout"] or r["stderr"]).strip().splitlines()
            _VERSIONS[tool] = line[0][:100] if line else "unknown"
    return _VERSIONS[tool]


def need(tool: str, hint: str):
    if not which(tool):
        fail(f"provider '{tool}' is not installed", missing_provider=tool, install_hint=hint,
             next_step="record an Unknown naming what this provider would establish; continue with baseline operations")


def subject(ident: dict) -> dict:
    return {k: ident.get(k) for k in ("path", "sha256", "digest_kind", "format", "arch", "size")}


def payload(ident, provider, operation, params, normalized, raw=None, limitations=(), locations=(),
            authority="shipped-artifact", confidence="high"):
    return {"subject": subject(ident), "provider": {"id": provider, "version": tool_version(provider) if provider not in ("python", "builtin") else f"python-{sys.version_info.major}.{sys.version_info.minor}"},
            "operation": operation, "parameters": params, "normalized_result": normalized, "raw_result": raw,
            "limitations": list(limitations), "locations": list(locations), "authority": authority,
            "confidence": confidence}


# =========================================================================== strings

URL_RE = re.compile(r"(?:https?|wss?|ftp)://[^\s\"'<>]+")
PATH_RE = re.compile(r"^(?:/[\w.\-@]+){2,}|^[A-Za-z]:\\")
FMT_RE = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?[sdifuxXplc@]")
KEYISH_RE = re.compile(r"(?i)(api[_-]?key|secret|token|passw|bearer|private key|BEGIN [A-Z ]+KEY)")


def extract_strings(data: bytes, min_len: int):
    out = []
    for m in re.finditer(rb"[\x20-\x7e\t]{%d,}" % min_len, data):
        out.append((m.start(), m.group().decode("ascii")))
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data):
        out.append((m.start(), m.group().decode("utf-16le")))
    return sorted(out)


def op_strings(a, ident, w):
    data = Path(ident["path"]).read_bytes()
    strs = extract_strings(data, a.min)
    if a.grep:
        rx = re.compile(a.grep)
        strs = [s for s in strs if rx.search(s[1])]
    cats = {"urls": [], "paths": [], "format_strings": [], "secret_like": []}
    for off, s in strs:
        if URL_RE.search(s):
            cats["urls"].append(s)
        if PATH_RE.search(s):
            cats["paths"].append(s)
        if FMT_RE.search(s):
            cats["format_strings"].append(s)
        if KEYISH_RE.search(s):
            cats["secret_like"].append(s)
    raw = store_raw(w, "\n".join(f"{off:#x}\t{s}" for off, s in strs), f"strings-{ident['sha256'][:12]}")
    norm = {"count": len(strs), "min_len": a.min, "grep": a.grep,
            "categories": {k: sorted(set(v))[:a.limit] for k, v in cats.items()},
            "sample": [{"offset": hex(o), "text": s} for o, s in strs[:a.limit]],
            "truncated": len(strs) > a.limit}
    lim = ["file-offset strings only: presence of a string does not prove it is used at runtime"]
    if norm["truncated"]:
        lim.append(f"sample truncated to {a.limit}; full list in raw_result")
    p = payload(ident, "builtin", "strings:extract", {"min": a.min, "grep": a.grep}, norm, raw, lim)
    finish(p, a.workdir, a.record, {"count": norm["count"], **{k: len(v) for k, v in cats.items()},
                                     "urls": norm["categories"]["urls"][:20],
                                     "secret_like": norm["categories"]["secret_like"][:10],
                                     "matches": [s for _, s in strs[:30]] if a.grep else None})


# =========================================================================== symbols / headers

def op_symbols(a, ident, w):
    tool = "nm" if which("nm") else "llvm-nm"
    need(tool, "xcode-select --install / apt install binutils")
    args = [tool, "-C"] if ident["format"] != "mach-o" else [tool]
    if ident["format"] == "mach-o-universal" and a.arch:
        args += ["-arch", a.arch]
    r = run_owned(args + [ident["path"]], timeout=a.timeout)
    rows = []
    for line in r["stdout"].splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3:
            rows.append({"address": "0x" + parts[0].lstrip("0") if parts[0].strip("0") else "0x0", "type": parts[1], "name": parts[2]})
        elif len(parts) == 2:
            rows.append({"address": None, "type": parts[0], "name": parts[1]})
    if a.grep:
        rx = re.compile(a.grep)
        rows = [x for x in rows if rx.search(x["name"])]
    defined = [x for x in rows if x["type"] not in ("U", "u", "w", "v")]
    undefined = [x for x in rows if x["type"] in ("U",)]
    raw = store_raw(w, r["stdout"], f"nm-{ident['sha256'][:12]}")
    lim = []
    if not r["ok"]:
        lim.append(f"nm failed: {r['stderr'][:200]}")
    if not defined:
        lim.append("no defined symbols: binary may be stripped; function names will come from disassembly heuristics")
    norm = {"defined_count": len(defined), "imported_count": len(undefined),
            "defined": defined[:a.limit], "imported": [x["name"] for x in undefined][:a.limit],
            "truncated": len(defined) > a.limit or len(undefined) > a.limit}
    p = payload(ident, tool, "symbols:list", {"grep": a.grep, "arch": a.arch}, norm, raw, lim)
    finish(p, a.workdir, a.record, {"defined": len(defined), "imported": len(undefined),
                                     "defined_sample": [x["name"] for x in defined[:40]],
                                     "imported_sample": [x["name"] for x in undefined[:60]]})


def op_headers(a, ident, w):
    fmt = ident["format"]
    norm: dict = {"format": fmt, "arch": ident.get("arch")}
    lim = []
    texts = []
    if fmt.startswith("mach-o") and which("otool"):
        tool = "otool"
        arch = ["-arch", a.arch] if a.arch else []
        libs = run_owned(["otool", *arch, "-L", ident["path"]], timeout=a.timeout)
        lc = run_owned(["otool", *arch, "-l", ident["path"]], timeout=a.timeout)
        hv = run_owned(["otool", *arch, "-hv", ident["path"]], timeout=a.timeout)
        texts += [libs["stdout"], hv["stdout"], lc["stdout"]]
        norm["linked_libraries"] = [l.strip().split(" (")[0] for l in libs["stdout"].splitlines()[1:] if l.strip()]
        cmds = re.findall(r"cmd (LC_\w+)", lc["stdout"])
        norm["load_commands"] = {c: cmds.count(c) for c in sorted(set(cmds))}
        norm["sections"] = sorted(set(re.findall(r"sectname (\S+)\n\s+segname (\S+)", lc["stdout"])))
        norm["sections"] = [f"{s[1]},{s[0]}" for s in norm["sections"]]
        flags = hv["stdout"].split()
        norm["flags"] = [f for f in flags if f.isupper() and len(f) > 3 and f not in ("MH_MAGIC_64", "MH_MAGIC")]
        norm["pie"] = "PIE" in flags
        m = re.search(r"cmd LC_MAIN\s+cmdsize \d+\s+entryoff (\d+)", lc["stdout"])
        norm["entry_offset"] = int(m.group(1)) if m else None
        norm["encrypted"] = bool(re.search(r"cryptid 1", lc["stdout"]))
        if norm["encrypted"]:
            lim.append("FairPlay-encrypted (cryptid 1): code section is not analyzable statically")
    else:
        tool = "llvm-objdump" if which("llvm-objdump") else "objdump"
        need(tool, "xcode-select --install / apt install binutils")
        h = run_owned([tool, "-h", ident["path"]], timeout=a.timeout)
        pv = run_owned([tool, "-p", ident["path"]], timeout=a.timeout)
        texts += [h["stdout"], pv["stdout"]]
        norm["sections"] = re.findall(r"^\s*\d+\s+(\S+)\s+[0-9a-f]+\s+[0-9a-f]+", h["stdout"], re.M)
        needed = re.findall(r"NEEDED\s+(\S+)", pv["stdout"])
        dlls = re.findall(r"DLL Name:\s*(\S+)", pv["stdout"], re.I)
        norm["linked_libraries"] = needed or dlls
        m = re.search(r"(?:start address|AddressOfEntryPoint)\s*:?\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)", pv["stdout"] + h["stdout"])
        norm["entry"] = m.group(1) if m else None
        norm["stack_exec"] = bool(re.search(r"STACK.*flags rwx", pv["stdout"]))
        norm["relro"] = "RELRO" in pv["stdout"]
        if not h["ok"]:
            lim.append(f"{tool} -h failed: {h['stderr'][:200]}")
    raw = store_raw(w, "\n\n".join(texts), f"headers-{ident['sha256'][:12]}")
    p = payload(ident, tool, "headers:info", {"arch": a.arch}, norm, raw, lim)
    finish(p, a.workdir, a.record, norm)


# =========================================================================== disassembly model

CALL_MNEMONICS = {"bl", "blr", "call", "callq", "jal", "jalr", "bla", "blx", "calll"}
JUMP_MNEMONICS = {"b", "jmp", "jmpq", "j", "br"}
CMP_MNEMONICS = {"cmp", "cmpl", "cmpq", "cmpb", "cmpw", "cmn", "test", "testl", "tst", "subs", "ccmp"}


def _arch_args(a, ident):
    if ident["format"] == "mach-o-universal":
        arch = a.arch or "arm64"
        return ["-arch", arch]
    return []


def disassemble(a, ident, w) -> dict:
    """Return {tool, functions: {name: {addr, insns:[{addr, mnem, ops, comment}]}}, by_addr} (cached)."""
    fmt = ident["format"]
    use_otool = fmt.startswith("mach-o") and which("otool")
    tool = "otool" if use_otool else ("llvm-objdump" if which("llvm-objdump") else "objdump")
    need(tool, "xcode-select --install / apt install binutils")
    key = f"{ident['sha256'][:16]}-{a.arch or 'default'}-{tool}"
    cache = w / "cache" / f"disasm-{key}.json"
    if cache.exists():
        d = json.loads(cache.read_text())
        d["cached"] = True
        return d
    if use_otool:
        r = run_owned(["otool", *_arch_args(a, ident), "-tV", ident["path"]], timeout=a.timeout)
    else:
        r = run_owned([tool, "-d", "--no-show-raw-insn", "-C", ident["path"]], timeout=a.timeout)
    if r["timed_out"]:
        fail(f"disassembly timed out after {a.timeout}s", hint="raise --timeout or use rizin/ghidra")
    funcs: dict[str, dict] = {}
    cur = None
    strings_by_addr = data_strings(a, ident) if not use_otool else {}
    adrp: dict[str, int] = {}
    for line in r["stdout"].splitlines():
        if use_otool:
            if line and not line[0].isspace() and line.endswith(":") and "\t" not in line and not line.startswith("("):
                name = line[:-1]
                if name == ident["path"]:
                    continue
                cur = funcs.setdefault(name, {"addr": None, "insns": []})
                continue
            m = re.match(r"^([0-9a-f]{8,16})\t(\S+)\t?(.*)$", line)
            if not m:
                continue
            if cur is None:
                cur = funcs.setdefault("__unnamed_text", {"addr": None, "insns": []})
            addr, mnem, rest = int(m.group(1), 16), m.group(2), m.group(3)
            ops, _, comment = rest.partition(" ; ")
        else:
            mh = re.match(r"^([0-9a-f]+) <(.+)>:$", line)
            if mh:
                cur = funcs.setdefault(mh.group(2), {"addr": hex(int(mh.group(1), 16)), "insns": []})
                adrp.clear()
                continue
            m = re.match(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
            if not m or cur is None:
                continue
            addr, mnem, rest = int(m.group(1), 16), m.group(2), m.group(3)
            ops, _, comment = re.split(r"\s+[#;]\s*", rest, maxsplit=1)[0], None, (re.split(r"\s+[#;]\s*", rest, maxsplit=1) + [""])[1]
            # resolve string literals for ELF/PE: rip-relative comments and arm64 adrp+add pairs
            target = None
            mc = re.match(r"(0x)?([0-9a-f]+)", comment or "")
            if mc:
                target = int(mc.group(2), 16)
            if mnem == "adrp":
                mm = re.match(r"(\w+),\s*0x([0-9a-f]+)", ops)
                if mm:
                    adrp[mm.group(1)] = int(mm.group(2), 16)
            elif mnem == "add":
                mm = re.match(r"(\w+),\s*(\w+),\s*#0x([0-9a-f]+)", ops)
                if mm and mm.group(2) in adrp:
                    target = adrp[mm.group(2)] + int(mm.group(3), 16)
            if target is not None and target in strings_by_addr:
                comment = f'literal pool for: "{strings_by_addr[target]}"'
        if cur["addr"] is None:
            cur["addr"] = hex(addr)
        cur["insns"].append({"addr": hex(addr), "mnem": mnem, "ops": ops.strip(), "comment": (comment or "").strip()})
    by_addr = {f["addr"]: n for n, f in funcs.items() if f["addr"]}
    d = {"tool": tool, "functions": funcs, "by_addr": by_addr, "cached": False}
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(d))
    return d


def data_strings(a, ident) -> dict[int, str]:
    """Map virtual address -> C string from read-only data sections (ELF/PE path)."""
    tool = "llvm-objdump" if which("llvm-objdump") else "objdump"
    out: dict[int, str] = {}
    r = run_owned([tool, "-s", "-j", ".rodata", "-j", ".rdata", "-j", "__cstring", "-j", ".data", ident["path"]], timeout=a.timeout)
    buf, base = bytearray(), None
    for line in r["stdout"].splitlines():
        m = re.match(r"^\s([0-9a-f]+)\s((?:[0-9a-f]{2,8}\s?){1,4})\s", line)
        if not m:
            if line.startswith("Contents of section"):
                _flush_strings(buf, base, out)
                buf, base = bytearray(), None
            continue
        addr = int(m.group(1), 16)
        if base is None:
            base = addr
        buf += bytes.fromhex(m.group(2).replace(" ", ""))
    _flush_strings(buf, base, out)
    return out


def _flush_strings(buf, base, out):
    if base is None:
        return
    for m in re.finditer(rb"[\x20-\x7e\t\n]{2,}(?=\x00)", bytes(buf)):
        out[base + m.start()] = m.group().decode("ascii")


def call_target(insn, by_addr) -> str | None:
    c = insn["comment"]
    m = re.search(r"symbol stub for: (\S+)", c)
    if m:
        return m.group(1)
    m = re.search(r"<([^>+]+)(?:\+0x0)?>", insn["ops"])
    if m and "+" not in m.group(0):
        return m.group(1)
    if re.fullmatch(r"[A-Za-z_.$][\w.$@]*", insn["ops"]) and not re.fullmatch(r"[xwr]\d+|[re]?[a-d]x|lr", insn["ops"]):
        return insn["ops"]  # otool prints internal calls symbolically: "bl _decode"
    m = re.search(r"0x([0-9a-f]+)", insn["ops"])
    if m:
        return by_addr.get(hex(int(m.group(1), 16)))
    return None


def analyze_fn(name, fn, by_addr):
    calls, strings, consts, indirect = [], [], [], 0
    for i in fn["insns"]:
        mnem = i["mnem"].split(".")[0]
        if mnem in CALL_MNEMONICS:
            t = call_target(i, by_addr)
            if t:
                calls.append({"at": i["addr"], "target": t})
            else:
                indirect += 1
        elif mnem in JUMP_MNEMONICS:
            t = call_target(i, by_addr)
            if t and t != name:
                calls.append({"at": i["addr"], "target": t, "tail_call": True})
        m = re.search(r'literal pool for: "(.*)"', i["comment"]) or re.search(r'Objc cfstring ref: @"(.*)"', i["comment"])
        if m:
            strings.append({"at": i["addr"], "text": m.group(1)})
        if mnem in CMP_MNEMONICS:
            mc = re.search(r"#?(-?0x[0-9a-f]+|#-?\d+)$", i["ops"])
            if mc:
                v = mc.group(1).lstrip("#")
                val = int(v, 16) if "0x" in v else int(v)
                consts.append({"at": i["addr"], "insn": f'{i["mnem"]} {i["ops"]}', "value": val,
                               "as_char": chr(val) if 32 <= val < 127 else None})
    return {"calls": calls, "string_refs": strings, "compared_constants": consts, "indirect_calls": indirect}


def find_fn(d, a):
    funcs = d["functions"]
    if a.symbol:
        for cand in (a.symbol, "_" + a.symbol, a.symbol.lstrip("_")):
            if cand in funcs:
                return cand
        fail(f"function {a.symbol!r} not found", candidates=[n for n in funcs if a.symbol.lstrip("_") in n][:20],
             hint="symbols may be stripped; use --address from callgraph:build or xrefs:to")
    if a.address:
        target = int(a.address, 16)
        for n, f in funcs.items():
            addrs = [int(i["addr"], 16) for i in f["insns"]]
            if addrs and addrs[0] <= target <= addrs[-1]:
                return n
        fail(f"no function contains {a.address}")
    fail("need --symbol or --address")


def op_disasm(a, ident, w):
    d = disassemble(a, ident, w)
    name = find_fn(d, a)
    fn = d["functions"][name]
    facts = analyze_fn(name, fn, d["by_addr"])
    text = "\n".join(f'{i["addr"]}\t{i["mnem"]}\t{i["ops"]}' + (f'\t; {i["comment"]}' if i["comment"] else "") for i in fn["insns"])
    raw = store_raw(w, text, f"disasm-{ident['sha256'][:12]}-{name}")
    lim = ["static disassembly: describes code paths, not which path executes at runtime"]
    if facts["indirect_calls"]:
        lim.append(f"{facts['indirect_calls']} indirect call(s) not resolved statically")
    if len(fn["insns"]) > a.max_lines:
        lim.append(f"instruction listing truncated to {a.max_lines}; full listing in raw_result")
    norm = {"function": name, "address": fn["addr"], "instruction_count": len(fn["insns"]), **facts,
            "instructions": [f'{i["addr"]} {i["mnem"]} {i["ops"]}' + (f' ; {i["comment"]}' if i["comment"] else "") for i in fn["insns"][:a.max_lines]]}
    p = payload(ident, d["tool"], "disasm:function", {"function": name, "arch": a.arch}, norm, raw, lim,
                locations=[f"address:{fn['addr']}"])
    finish(p, a.workdir, a.record, {"function": name, "address": fn["addr"], "instructions": len(fn["insns"]),
                                     "calls": [c["target"] for c in facts["calls"]],
                                     "string_refs": [s["text"] for s in facts["string_refs"]],
                                     "compared_constants": [f'{c["insn"]}' + (f" ('{c['as_char']}')" if c["as_char"] else "") for c in facts["compared_constants"]],
                                     "listing": raw["path"], "disasm_cache": "hit" if d.get("cached") else "miss"})


def build_graph(d):
    g, rev = {}, {}
    for n, f in d["functions"].items():
        callees = sorted({c["target"] for c in analyze_fn(n, f, d["by_addr"])["calls"]})
        g[n] = callees
        for c in callees:
            rev.setdefault(c, []).append(n)
    return g, {k: sorted(v) for k, v in rev.items()}


def op_callgraph(a, ident, w):
    d = disassemble(a, ident, w)
    g, rev = build_graph(d)
    graph = rev if a.direction == "callers" else g
    lim = ["direct calls only; indirect calls (function pointers, vtables, objc_msgSend selectors) are not edges"]
    if a.root:
        class _A:  # reuse find_fn lookup rules
            symbol, address = a.root, None
        root = find_fn(d, _A) if a.root in d["functions"] or "_" + a.root in d["functions"] or a.root.lstrip("_") in d["functions"] else a.root
        seen, edges, q, truncated = {root: 0}, [], deque([root]), False
        while q:
            n = q.popleft()
            if seen[n] >= a.depth:
                continue
            for m in graph.get(n, []):
                edges.append([n, m] if a.direction == "callees" else [m, n])
                if m not in seen:
                    if len(seen) >= a.max_nodes:
                        truncated = True
                        continue
                    seen[m] = seen[n] + 1
                    q.append(m)
        nodes = sorted(seen)
        if truncated:
            lim.append(f"budget reached: max_nodes={a.max_nodes}")
        norm = {"root": root, "direction": a.direction, "depth": a.depth, "nodes": nodes,
                "edges": sorted(map(list, {tuple(e) for e in edges})), "truncated": truncated,
                "external": sorted(n for n in nodes if n not in d["functions"])}
    else:
        internal = sorted(d["functions"])
        roots = sorted(n for n in internal if n not in rev)
        norm = {"function_count": len(internal), "edge_count": sum(len(v) for v in g.values()),
                "roots_no_internal_callers": roots[:a.max_nodes],
                "most_called": sorted(((len(v), k) for k, v in rev.items()), reverse=True)[:30],
                "adjacency": {k: v for k, v in list(g.items())[:a.max_nodes]},
                "truncated": len(g) > a.max_nodes}
    raw = store_raw(w, json.dumps({"callees": g, "callers": rev}, indent=1), f"callgraph-{ident['sha256'][:12]}")
    p = payload(ident, d["tool"], "callgraph:build", {"root": a.root, "depth": a.depth, "direction": a.direction,
                                                     "max_nodes": a.max_nodes, "arch": a.arch}, norm, raw, lim)
    s = {k: v for k, v in norm.items() if k not in ("adjacency",)}
    finish(p, a.workdir, a.record, s)


def op_xrefs(a, ident, w):
    d = disassemble(a, ident, w)
    hits = []
    for n, f in d["functions"].items():
        facts = analyze_fn(n, f, d["by_addr"])
        if a.symbol:
            want = {a.symbol, "_" + a.symbol, a.symbol.lstrip("_")}
            hits += [{"function": n, "at": c["at"], "kind": "tail-call" if c.get("tail_call") else "call"} for c in facts["calls"] if c["target"] in want]
        if a.string:
            hits += [{"function": n, "at": s["at"], "kind": "string-ref", "text": s["text"]} for s in facts["string_refs"] if a.string in s["text"]]
    lim = ["direct references only; references through computed pointers or tables are not found"]
    if a.string and not d["tool"] == "otool":
        lim.append("ELF/PE string references resolved via rip-relative / adrp+add operands only")
    norm = {"query": {"symbol": a.symbol, "string": a.string}, "count": len(hits), "references": hits[:500]}
    if not hits:
        lim.append("no direct references found within the disassembled text sections (bounded negative)")
    p = payload(ident, d["tool"], "xrefs:to", {"symbol": a.symbol, "string": a.string, "arch": a.arch}, norm, None, lim,
                locations=sorted({f"address:{h['at']}" for h in hits})[:50])
    finish(p, a.workdir, a.record, norm)


# =========================================================================== mac specifics

def op_objc(a, ident, w):
    need("otool", "xcode-select --install")
    r = run_owned(["otool", *_arch_args(a, ident), "-oV", ident["path"]], timeout=a.timeout)
    classes = sorted(set(re.findall(r"^\s*name\s+0x[0-9a-f]+ (\S+)$", r["stdout"], re.M)))
    methods = sorted(set(re.findall(r"^\s+name\s+0x[0-9a-f]+ ([\w:]+:?)$", r["stdout"], re.M)))
    raw = store_raw(w, r["stdout"], f"objc-{ident['sha256'][:12]}")
    norm = {"names_count": len(classes), "names": classes[:a.limit], "selectors_sample": methods[:a.limit]}
    lim = ["names include classes, protocols, properties and selectors as printed by otool -oV; Swift-only types may be absent"]
    p = payload(ident, "otool", "macho:objc", {"arch": a.arch}, norm, raw, lim)
    finish(p, a.workdir, a.record, {"names_count": len(classes), "sample": classes[:60]})


def op_codesign(a, ident, w):
    need("codesign", "macOS only")
    r = run_owned(["codesign", "-dvvv", "--entitlements", ":-", ident["path"]], timeout=a.timeout)
    info = dict(re.findall(r"^(\w[\w ]*)=(.*)$", r["stderr"], re.M))
    ents = re.findall(r"<key>([^<]+)</key>", r["stdout"])
    norm = {"signed": "code object is not signed" not in r["stderr"], "identifier": info.get("Identifier"),
            "team_id": info.get("TeamIdentifier"), "authority": re.findall(r"Authority=(.*)", r["stderr"]),
            "flags": info.get("CodeDirectory v", "")[:120] or re.findall(r"flags=(\S+)", r["stderr"]),
            "hardened_runtime": "runtime" in r["stderr"], "entitlements": ents}
    raw = store_raw(w, r["stderr"] + "\n" + r["stdout"], f"codesign-{ident['sha256'][:12]}")
    p = payload(ident, "codesign", "codesign:info", {}, norm, raw, [])
    finish(p, a.workdir, a.record, norm)


# =========================================================================== artifacts

def _member_kind(head: bytes, name: str) -> str:
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "mach-o"
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"dex\n":
        return "dex"
    if head[:4] == b"PK\x03\x04":
        return "zip"
    if head[:4] == b"\0asm":
        return "wasm"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if len(head) >= 16 and struct.unpack_from("<I", head, 0)[0] == 4 and b'{"files"' in head[16:32]:
        return "asar"
    ext = os.path.splitext(name)[1].lower()
    return {".js": "javascript", ".mjs": "javascript", ".json": "json", ".plist": "plist", ".xml": "xml",
            ".so": "elf?", ".dylib": "mach-o?", ".dll": "pe?", ".py": "python", ".pyc": "python-bytecode",
            ".png": "image", ".jpg": "image", ".html": "html", ".css": "css", ".nib": "nib",
            ".car": "asset-catalog", ".arsc": "android-resources"}.get(ext, "other")


def _members(path, fmt):
    if fmt in ("zip", "apk", "ipa", "jar", "msix", "wheel"):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                data = z.read(info)
                yield info.filename, data, info.file_size
    elif fmt == "tar" or tarfile.is_tarfile(path):
        with tarfile.open(path) as t:
            for m in t.getmembers():
                if m.isfile():
                    f = t.extractfile(m)
                    data = f.read() if f else b""
                    yield m.name, data, m.size
    else:
        fail(f"artifact:inventory does not handle format {fmt!r}",
             hint="asar -> js_bundle.py; dmg -> hdiutil attach -readonly; firmware -> binwalk:scan / unblob:extract")


def op_inventory(a, ident, w):
    rows = []
    for name, data, size in _members(ident["path"], ident["format"]):
        rows.append({"name": name, "size": size, "sha256": sha256_bytes(data), "kind": _member_kind(data[:64], name)})
    rows.sort(key=lambda r: r["name"])
    kinds: dict[str, int] = {}
    for r in rows:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    exec_kinds = {"elf", "mach-o", "pe", "dex", "wasm"}
    executables = [r for r in rows if r["kind"] in exec_kinds]
    nested = [r for r in rows if r["kind"] in ("zip", "asar", "gzip")]
    raw = store_raw(w, json.dumps(rows, indent=1), f"inventory-{ident['sha256'][:12]}")
    norm = {"container": ident["format"], "member_count": len(rows), "total_uncompressed": sum(r["size"] for r in rows),
            "kinds": dict(sorted(kinds.items())), "executables": executables, "nested_containers": nested}
    if a.detail == "complete":
        norm["members"] = rows
    lim = ["member kinds are identified by magic bytes; '?' kinds are by extension only"]
    if ident["format"] == "ipa":
        lim.append("App Store IPAs are usually FairPlay-encrypted; check headers:info 'encrypted' on the extracted Mach-O")
    p = payload(ident, "builtin", "artifact:inventory", {"detail": a.detail}, norm, raw, lim)
    finish(p, a.workdir, a.record, {k: v for k, v in norm.items() if k != "members"})


def _safe_out(out: str) -> Path:
    p = Path(out).expanduser().resolve()
    if p.exists() and any(p.iterdir()):
        fail(f"output directory {p} is not empty; choose a new directory")
    p.mkdir(parents=True, exist_ok=True)
    return p


def op_extract(a, ident, w):
    if not a.out:
        fail("--out NEW_DIR is required")
    out = _safe_out(a.out)
    written = []
    for name, data, _ in _members(ident["path"], ident["format"]):
        if a.member and name not in a.member:
            continue
        dest = (out / name).resolve()
        if not str(dest).startswith(str(out) + os.sep):
            fail(f"refusing path-traversal member {name!r}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        written.append({"name": name, "path": str(dest), "sha256": sha256_bytes(data)})
    norm = {"out": str(out), "extracted": len(written), "members": written[:200]}
    p = payload(ident, "builtin", "artifact:extract", {"members": sorted(a.member or [])}, norm, None,
                ["extraction copies bytes; it does not execute anything"])
    finish(p, a.workdir, a.record, {"out": str(out), "extracted": len(written), "first": [x["name"] for x in written[:20]]})


# =========================================================================== optional engines

def op_rizin(a, ident, w, tool):
    need(tool, "brew install rizin" if tool == "rizin" else "brew install radare2")
    if not a.cmd:
        fail("--cmd is required, e.g. 'aaa;aflj' or 'aaa;pdfj @ main' or 'aaa;axtj @ sym.imp.strcmp'")
    r = run_owned([tool, "-q", "-e", "scr.color=0", "-c", a.cmd, ident["path"]], timeout=a.timeout)
    raw = store_raw(w, r["stdout"], f"{tool}-{ident['sha256'][:12]}")
    parsed = None
    for line in reversed(r["stdout"].strip().splitlines()):
        try:
            parsed = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    norm = {"cmd": a.cmd, "json": parsed if parsed is not None and len(json.dumps(parsed)) < 200_000 else None,
            "text_head": None if parsed is not None else r["stdout"][:4000]}
    lim = [] if r["ok"] else [f"{tool} exited {r['returncode']}: {r['stderr'][:200]}"]
    p = payload(ident, tool, f"{tool}:cmd", {"cmd": a.cmd}, norm, raw, lim)
    finish(p, a.workdir, a.record, {"cmd": a.cmd, "json_type": type(parsed).__name__,
                                     "items": len(parsed) if isinstance(parsed, list) else None, "raw": raw["path"]})


GHIDRA_SCRIPT = Path(__file__).parent / "ghidra" / "DecompileFunction.java"


def op_ghidra(a, ident, w):
    headless = find_ghidra_headless()
    if not headless:
        fail("Ghidra is not installed", missing_provider="ghidra",
             install_hint="brew install ghidra (macOS; pulls in its JDK), or unpack a release from github.com/NationalSecurityAgency/ghidra and export GHIDRA_INSTALL_DIR")
    jh = ghidra_java_home()
    if jh:
        os.environ["JAVA_HOME"] = jh   # inherited by analyzeHeadless; Homebrew's wrapper normally sets it
    proj = w / "ghidra-project"
    proj.mkdir(exist_ok=True)
    (w / "raw").mkdir(parents=True, exist_ok=True)
    out = w / "raw" / f"ghidra-{ident['sha256'][:12]}-{a.symbol or 'all'}.c"
    cmd = [headless, str(proj), f"p{ident['sha256'][:12]}", "-import", ident["path"], "-overwrite",
           "-scriptPath", str(GHIDRA_SCRIPT.parent), "-postScript", GHIDRA_SCRIPT.name, a.symbol or "main", str(out),
           "-deleteProject"]
    r = run_owned(cmd, timeout=max(a.timeout, 600))
    text = out.read_text() if out.exists() else ""
    lim = ["decompiler output is a reconstruction (analyst-grade inference from code), not original source"]
    if not text.strip():
        fail("Ghidra produced no decompilation", returncode=r["returncode"],
             stderr_tail=(r["stderr"] or r["stdout"] or "")[-600:],
             hint="check JAVA_HOME (JDK 21+), raise --timeout, or fall back to disasm:function")
    if text.lstrip().startswith("// function not found"):
        fail(f"Ghidra found no function named {a.symbol or 'main'!r}",
             hint="list names with symbols:list (Mach-O names may carry a leading _), or pass --symbol 0xADDRESS")
    norm = {"function": a.symbol or "main", "pseudo_c": text[:20000], "truncated": len(text) > 20000}
    raw = {"path": str(out), "sha256": sha256_bytes(text.encode()), "bytes": len(text)} if text else None
    p = payload(ident, "ghidra", "ghidra:decompile", {"function": a.symbol or "main"}, norm, raw, lim, confidence="medium")
    finish(p, a.workdir, a.record, {"function": norm["function"], "lines": text.count("\n"), "head": text[:1500]})


def op_tool_dir(a, ident, w, tool, args_fn, opname, hint):
    need(tool, hint)
    if not a.out:
        fail("--out NEW_DIR is required")
    out = _safe_out(a.out)
    r = run_owned(args_fn(out), timeout=max(a.timeout, 900))
    files = [p for p in out.rglob("*") if p.is_file()]
    exts: dict[str, int] = {}
    for f in files:
        exts[f.suffix or "(none)"] = exts.get(f.suffix or "(none)", 0) + 1
    norm = {"out": str(out), "files": len(files), "by_extension": dict(sorted(exts.items())),
            "sample": sorted(str(f.relative_to(out)) for f in files)[:100]}
    lim = [] if r["ok"] else [f"{tool} exited {r['returncode']}: {r['stderr'][-300:]}"]
    if opname.endswith("decompile"):
        lim.append("decompiled source is a reconstruction; names/structure may differ from the original")
    p = payload(ident, tool, opname, {}, norm, None, lim)
    finish(p, a.workdir, a.record, norm)


def _binwalk_log(w, ident, argv, timeout, cwd=None):
    """Run binwalk 3.x with a JSON log; returns (run result, list of analyses)."""
    (w / "raw").mkdir(parents=True, exist_ok=True)
    log = w / "raw" / f"binwalk-{ident['sha256'][:12]}-{int(time.time() * 1000)}.json"
    r = run_owned(["binwalk", "-q", "-l", str(log), *argv, ident["path"]], timeout=timeout, cwd=cwd)
    try:
        analyses = [x.get("Analysis", x) for x in _json_stream(log.read_text())]
    except OSError:
        analyses = None
    return r, (analyses or None), log


def _json_stream(text):
    """Objects from a JSON log that may be several concatenated documents.

    binwalk 3.1 with -M writes `[{...}],{...}]`, which json.loads rejects."""
    dec, i, objs = json.JSONDecoder(), 0, []
    while i < len(text):
        if text[i] in " \t\r\n,[]":
            i += 1
            continue
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError:
            break
        objs.extend(obj if isinstance(obj, list) else [obj])
    return objs


def op_binwalk(a, ident, w):
    need("binwalk", "brew install binwalk (3.x) / cargo install binwalk")
    r, analyses, log = _binwalk_log(w, ident, [], a.timeout)
    if analyses is None:   # binwalk 2.x has no JSON log: parse the text table
        r = run_owned(["binwalk", ident["path"]], timeout=a.timeout)
        regions = [{"offset": int(m.group(1)), "name": None, "description": m.group(3).strip()[:300]}
                   for m in (re.match(r"^\s*(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$", ln) for ln in r["stdout"].splitlines()) if m]
        raw = store_raw(w, r["stdout"], f"binwalk-{ident['sha256'][:12]}")
    else:
        regions = [{"offset": f["offset"], "size": f.get("size"), "name": f.get("name"),
                    "description": f.get("description", "")[:300]} for an in analyses for f in an.get("file_map", [])]
        raw = {"path": str(log), "sha256": sha256_bytes(log.read_bytes()), "bytes": log.stat().st_size}
    lim = ["signature scan: regions are candidates until extracted (binwalk:extract)"]
    covered = sum(x.get("size") or 0 for x in regions)
    if regions and covered and covered < ident["size"] * 0.5:
        lim.append(f"identified regions cover {covered} of {ident['size']} bytes; the rest is unidentified "
                   "(padding, encrypted or unknown formats)")
    p = payload(ident, "binwalk", "binwalk:scan", {}, {"regions": regions, "count": len(regions)}, raw, lim)
    finish(p, a.workdir, a.record, {"count": len(regions), "regions": regions[:40]})


def op_binwalk_extract(a, ident, w):
    """Extract every recognised region (recursively) into a NEW dir and report what really came out.

    binwalk 3.x exits 0 even when an extractor is missing, so per-region success comes from its
    JSON log. SquashFS falls back to unsquashfs -o OFFSET when sasquatch is not installed.
    """
    need("binwalk", "brew install binwalk (3.x) / cargo install binwalk")
    if not a.out:
        fail("--out NEW_DIR is required")
    out = _safe_out(a.out)
    r, analyses, log = _binwalk_log(w, ident, ["-e", "-M", "-C", str(out)], max(a.timeout, 900), cwd=str(out))
    if analyses is None:
        fail("binwalk produced no JSON log (binwalk 2.x?)", hint="use binwalk 3.x, or unblob:extract",
             stderr_tail=r["stderr"][-400:])
    regions, lim = [], []
    for an in analyses:
        src = an.get("file_path", "")
        exts = list(an.get("extractions", {}).values())
        for f in an.get("file_map", []):
            ex = an.get("extractions", {}).get(f.get("id"))
            if ex is None:   # ids can differ between file_map and extractions; match by output dir suffix
                ex = next((e for e in exts if (e.get("output_directory") or "").endswith(f"/{f['offset']:X}")
                           or (e.get("output_directory") or "").endswith(f"/{f['offset']}")), None)
            item = {"source": os.path.relpath(src, out) if src.startswith(str(out)) else os.path.basename(src),
                    "offset": f["offset"], "name": f.get("name"), "description": f.get("description", "")[:200],
                    "extracted": bool(ex and ex.get("success")), "extractor": (ex or {}).get("extractor") or None,
                    "output": os.path.relpath(ex["output_directory"], out) if ex and ex.get("output_directory") else None}
            if not item["extracted"] and f.get("name") == "squashfs" and which("unsquashfs") and ex:
                dest = Path(ex["output_directory"]) / "squashfs-root"
                if dest.exists():
                    shutil.rmtree(dest)
                dest.parent.mkdir(parents=True, exist_ok=True)   # binwalk removes the dir of a failed extraction
                u = run_owned(["unsquashfs", "-no-xattrs", "-n", "-d", str(dest), "-o", str(f["offset"]), src],
                              timeout=max(a.timeout, 600))
                if dest.exists() and any(dest.rglob("*")):
                    item.update(extracted=True, extractor="unsquashfs (fallback: sasquatch missing)",
                                output=os.path.relpath(dest, out))
                    if not u["ok"]:
                        lim.append(f"unsquashfs at {src}@{f['offset']} reported errors (device nodes need root): "
                                   f"{(u['stderr'] or u['stdout'])[-200:]}")
            if not item["extracted"]:
                lim.append(f"NOT extracted: {item['name']} at offset {item['offset']} in {item['source']} "
                           "(extractor missing or failed); its contents were not observed")
            regions.append(item)
    files = sorted(p for p in out.rglob("*") if p.is_file() and not p.is_symlink())
    roots = sorted({os.path.relpath(d.parent, out) for d in out.rglob("etc") if d.is_dir()})
    norm = {"out": str(out), "regions": regions, "extracted": sum(x["extracted"] for x in regions),
            "failed": sum(not x["extracted"] for x in regions), "files": len(files), "filesystem_roots": roots,
            "sample": [os.path.relpath(p, out) for p in files][:150]}
    lim.append("extraction recreates files only: ownership, device nodes and setuid bits may differ from the device")
    raw = {"path": str(log), "sha256": sha256_bytes(log.read_bytes()), "bytes": log.stat().st_size}
    p = payload(ident, "binwalk", "binwalk:extract", {"recursive": True}, norm, raw, lim)
    finish(p, a.workdir, a.record, {k: norm[k] for k in ("out", "extracted", "failed", "files", "filesystem_roots")}
           | {"regions": regions[:30], "sample": norm["sample"][:40]})


def _leb(data, i):
    result = shift = 0
    while True:
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return result, i


def op_wasm(a, ident, w):
    if which("wasm-objdump"):
        r = run_owned(["wasm-objdump", "-x", ident["path"]], timeout=a.timeout)
        raw = store_raw(w, r["stdout"], f"wasm-{ident['sha256'][:12]}")
        imports = re.findall(r"<- (\S+)", r["stdout"])
        exports = re.findall(r"-> \"([^\"]+)\"", r["stdout"])
        norm = {"imports": imports[:a.limit], "exports": exports[:a.limit]}
        p = payload(ident, "wasm-objdump", "wasm:inspect", {}, norm, raw, [])
        finish(p, a.workdir, a.record, norm)
    data = Path(ident["path"]).read_bytes()
    i, sections, imports, exports = 8, [], [], []
    names = {0: "custom", 1: "type", 2: "import", 3: "function", 5: "memory", 7: "export", 10: "code", 11: "data"}
    while i < len(data):
        sid = data[i]
        size, j = _leb(data, i + 1)
        body = data[j:j + size]
        sections.append({"id": sid, "name": names.get(sid, str(sid)), "size": size})
        try:
            if sid == 2:
                n, k = _leb(body, 0)
                for _ in range(n):
                    ml, k = _leb(body, k); mod = body[k:k + ml].decode(); k += ml
                    fl, k = _leb(body, k); fld = body[k:k + fl].decode(); k += fl
                    kind = body[k]; k += 1
                    if kind == 0: _, k = _leb(body, k)
                    elif kind == 1: k += 1; flags = body[k]; k += 1; _, k = _leb(body, k); k = _leb(body, k)[1] if flags & 1 else k
                    elif kind == 2: flags = body[k]; k += 1; _, k = _leb(body, k); k = _leb(body, k)[1] if flags & 1 else k
                    elif kind == 3: k += 2
                    imports.append(f"{mod}.{fld}")
            if sid == 7:
                n, k = _leb(body, 0)
                for _ in range(n):
                    nl, k = _leb(body, k); exports.append(body[k:k + nl].decode()); k += nl
                    k += 1; _, k = _leb(body, k)
        except (IndexError, UnicodeDecodeError):
            pass
        i = j + size
    norm = {"sections": sections, "imports": imports[:a.limit], "exports": exports[:a.limit]}
    p = payload(ident, "builtin", "wasm:inspect", {}, norm, None,
                ["built-in parser: imports/exports only, no disassembly (install wabt for wasm2wat)"])
    finish(p, a.workdir, a.record, norm)


# =========================================================================== runtime (controlled replay)

def op_run(a, ident, w):
    """Run the target once in a sandbox and record what it did (authority: controlled-replay)."""
    import platform
    import shutil
    import tempfile
    if not os.access(ident["path"], os.X_OK):
        fail("target is not executable", hint="use a copy with chmod +x if the user agreed to run it")
    tmp = Path(tempfile.mkdtemp(prefix="run-", dir=w))
    home = tmp / "home"
    home.mkdir()
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp), "LANG": "C", "USER": "re-sandbox"}
    argv = [ident["path"], *(a.arg or [])]
    lim, sandbox = [], "none"
    def _probe(cmd):
        try:
            return sp.run(cmd, capture_output=True, timeout=10).returncode == 0
        except (OSError, sp.SubprocessError):
            return False
    import subprocess as sp
    darwin_ok = platform.system() == "Darwin" and which("sandbox-exec") and \
        _probe(["sandbox-exec", "-p", "(version 1)(allow default)(deny network*)", "/usr/bin/true"])
    linux_ok = platform.system() == "Linux" and which("unshare") and _probe(["unshare", "-rn", "true"])
    if darwin_ok:
        rules = ["(version 1)", "(allow default)", "(deny file-write*)",
                 f'(allow file-write* (subpath "{tmp.resolve()}") (literal "/dev/null") (literal "/dev/tty") (subpath "/dev/fd"))']
        if not a.allow_network:
            rules.append("(deny network*)")
        argv = ["sandbox-exec", "-p", "".join(rules), *argv]
        sandbox = "macos-sandbox-exec: writes limited to temp dir" + ("" if a.allow_network else ", network denied")
    elif linux_ok and not a.allow_network:
        argv = ["unshare", "-rn", *argv]
        sandbox = "linux-unshare: network namespace without interfaces"
        lim.append("filesystem writes are not restricted on Linux; run from a disposable copy")
    elif not a.no_sandbox:
        fail("no working sandbox on this host (sandbox-exec / unshare probe failed)", missing_provider="sandbox",
             install_hint="run inside a disposable VM/container, or pass --no-sandbox only if the user explicitly "
                          "agreed to an unisolated run")
    else:
        lim.append("no sandbox available: network and filesystem were NOT isolated (--no-sandbox)")
    started_proc = None
    import subprocess as sp
    import signal as sg
    import time as tm
    t0 = tm.time()
    try:
        started_proc = sp.Popen(argv, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, cwd=str(tmp), env=env,
                                start_new_session=True)
        out, err = started_proc.communicate(input=(a.stdin or "").encode(), timeout=a.timeout)
        timed_out = False
    except sp.TimeoutExpired:
        os.killpg(started_proc.pid, sg.SIGKILL)
        out, err = started_proc.communicate()
        timed_out = True
    finally:
        if started_proc and started_proc.poll() is None:
            os.killpg(started_proc.pid, sg.SIGKILL)
    written = sorted(str(p.relative_to(tmp)) for p in tmp.rglob("*") if p.is_file())
    shutil.rmtree(tmp, ignore_errors=True)
    stdout, stderr = out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    norm = {"argv": a.arg or [], "stdin": a.stdin, "exit_code": started_proc.returncode if started_proc else None,
            "timed_out": timed_out, "stdout": stdout[:4000], "stderr": stderr[:2000], "files_written": written[:100],
            "sandbox": sandbox}
    if len(stdout) > 4000:
        lim.append("stdout truncated to 4000 chars")
    if "deny" in stderr.lower() and "sandbox" in stderr.lower():
        lim.append("sandbox denied an operation; behaviour may differ from an unsandboxed run")
    lim.append("one run with one input: shows what happened here, not every path the program can take")
    p = payload(ident, "shell", "run:process", {"argv": a.arg or [], "stdin": a.stdin, "allow_network": a.allow_network,
                                                "sandbox": sandbox.split(":")[0]}, norm, None, lim,
                authority="controlled-replay")
    p["environment"] = {"host": platform.system(), "isolation": sandbox, "env": sorted(env)}
    finish(p, a.workdir, a.record, {"exit_code": norm["exit_code"], "stdout": stdout[:600], "stderr": stderr[:300],
                                     "timed_out": timed_out, "sandbox": sandbox, "seconds": round(tm.time() - t0, 3),
                                     "files_written": written[:20]})


# =========================================================================== cli

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("operation")
    ap.add_argument("target")
    ap.add_argument("--workdir")
    ap.add_argument("--record", action="store_true", help="add the result to the evidence ledger")
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--arch", help="slice for universal Mach-O (arm64, x86_64)")
    ap.add_argument("--min", type=int, default=6)
    ap.add_argument("--grep")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--symbol")
    ap.add_argument("--address")
    ap.add_argument("--string")
    ap.add_argument("--max-lines", type=int, default=400)
    ap.add_argument("--root")
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--direction", choices=["callees", "callers"], default="callees")
    ap.add_argument("--max-nodes", type=int, default=200)
    ap.add_argument("--detail", choices=["summary", "complete"], default="summary")
    ap.add_argument("--out")
    ap.add_argument("--member", action="append")
    ap.add_argument("--cmd")
    ap.add_argument("--arg", action="append", help="run:process argument (repeatable, in order); use --arg=-x for values starting with -")
    ap.add_argument("--stdin", help="run:process standard input")
    ap.add_argument("--allow-network", action="store_true", help="run:process: do not block network")
    ap.add_argument("--no-sandbox", action="store_true",
                    help="run:process: run even when no sandbox works (only with the user's explicit consent)")
    a = ap.parse_args()
    if a.operation == "run:process" and a.timeout == 180:
        a.timeout = 20
    try:
        ident = identify(a.target)
    except FileNotFoundError as e:
        fail(f"target not found: {e}")
    w = workdir_path(a.workdir)
    a.workdir = str(w)
    p = ident["path"]
    ops = {
        "strings:extract": op_strings, "symbols:list": op_symbols, "headers:info": op_headers,
        "disasm:function": op_disasm, "callgraph:build": op_callgraph, "xrefs:to": op_xrefs,
        "macho:objc": op_objc, "codesign:info": op_codesign,
        "artifact:inventory": op_inventory, "artifact:extract": op_extract,
        "rizin:cmd": lambda a, i, w: op_rizin(a, i, w, "rizin"),
        "r2:cmd": lambda a, i, w: op_rizin(a, i, w, "r2"),
        "ghidra:decompile": op_ghidra,
        "jadx:decompile": lambda a, i, w: op_tool_dir(a, i, w, "jadx", lambda o: ["jadx", "-d", str(o), p], "jadx:decompile", "brew install jadx"),
        "apktool:decode": lambda a, i, w: op_tool_dir(a, i, w, "apktool", lambda o: ["apktool", "d", "-f", "-o", str(o), p], "apktool:decode", "brew install apktool"),
        "dotnet:decompile": lambda a, i, w: op_tool_dir(a, i, w, "ilspycmd", lambda o: ["ilspycmd", "-p", "-o", str(o), p], "dotnet:decompile", "dotnet tool install -g ilspycmd"),
        "unblob:extract": lambda a, i, w: op_tool_dir(a, i, w, "unblob", lambda o: ["unblob", "-e", str(o), p], "unblob:extract", "pipx install unblob"),
        "binwalk:scan": op_binwalk, "binwalk:extract": op_binwalk_extract, "wasm:inspect": op_wasm,
        "run:process": op_run,
    }
    fn = ops.get(a.operation)
    if not fn:
        fail(f"unknown operation {a.operation!r}", operations=sorted(ops))
    fn(a, ident, w)


if __name__ == "__main__":
    main()
