#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Static analysis of JavaScript / Electron applications. Never executes the code.

Usage:
  js_bundle.py <app.asar | app-dir | file.js> [--extract NEW_DIR] [--trace TERM]... [--record] [--workdir DIR]

Reads ASAR archives directly (no npx/asar needed). Reports, with file:line locations:
  - Electron IPC channels (ipcMain.handle/on, ipcRenderer.invoke/send, webContents.send)
    and contextBridge.exposeInMainWorld APIs
  - network endpoints (URL literals, fetch/axios/WebSocket/XMLHttpRequest targets, '/api/...' paths)
  - module graph edges (require / import / dynamic import)
  - Electron security posture (nodeIntegration, contextIsolation, sandbox, webSecurity, openExternal ...)
  - HTTP routes, source-map references, package.json identity, secret-like literals
--trace TERM lists every file:line mentioning TERM (lightweight feature tracing).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import fail, identify, sha256_bytes, store_raw, workdir_path  # noqa: E402
from evidence import finish  # noqa: E402

TEXT_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".html", ".htm"}
MAX_FILE = 8 << 20

Q = r"""['"`](?P<v>[^'"`\n]{1,300})['"`]"""
PATTERNS = {
    "ipc_main": re.compile(r"ipcMain\.(?P<m>handle|handleOnce|on|once)\(\s*" + Q),
    "ipc_renderer": re.compile(r"ipcRenderer\.(?P<m>invoke|send|sendSync|on|once|sendTo)\(\s*" + Q),
    "ipc_webcontents": re.compile(r"webContents\.send\(\s*" + Q),
    "exposed_api": re.compile(r"contextBridge\.exposeInMainWorld\(\s*" + Q),
    "fetch": re.compile(r"\bfetch\(\s*" + Q),
    "axios": re.compile(r"\baxios(?:\.(?P<m>get|post|put|patch|delete|request))?\(\s*" + Q),
    "websocket": re.compile(r"new\s+WebSocket\(\s*" + Q),
    "xhr": re.compile(r"\.open\(\s*['\"](?P<m>GET|POST|PUT|DELETE|PATCH)['\"]\s*,\s*" + Q),
    "url_literal": re.compile(r"""['"`](?P<v>(?:https?|wss?)://[^'"`\s]{3,300})['"`]"""),
    "api_path": re.compile(r"""['"`](?P<v>/(?:api|v\d+|graphql|auth|oauth|rpc)[/\w\-.:{}]*)['"`]"""),
    "require": re.compile(r"\brequire\(\s*" + Q + r"\s*\)"),
    "import": re.compile(r"""(?:\bimport\s[^;'"]*?from\s*|\bimport\s*\(?\s*)['"](?P<v>[^'"]+)['"]"""),
    "route": re.compile(r"\b(?:app|router|server)\.(?P<m>get|post|put|patch|delete|all|use)\(\s*" + Q),
    "sourcemap": re.compile(r"sourceMappingURL=(?P<v>\S+)"),
    "secret_like": re.compile(r"""(?i)['"`]?(?P<m>api[_-]?key|secret|access[_-]?token|client[_-]?secret|password)['"`]?\s*[:=]\s*['"`](?P<v>[^'"`\s]{8,})['"`]"""),
}
SECURITY = {
    "nodeIntegration: true": re.compile(r"nodeIntegration\s*:\s*true"),
    "contextIsolation: false": re.compile(r"contextIsolation\s*:\s*false"),
    "sandbox: false": re.compile(r"sandbox\s*:\s*false"),
    "webSecurity: false": re.compile(r"webSecurity\s*:\s*false"),
    "allowRunningInsecureContent: true": re.compile(r"allowRunningInsecureContent\s*:\s*true"),
    "enableRemoteModule: true": re.compile(r"enableRemoteModule\s*:\s*true"),
    "shell.openExternal": re.compile(r"shell\.openExternal\("),
    "child_process": re.compile(r"""require\(\s*['"](?:node:)?child_process['"]\s*\)|\bexecSync\(|\bspawn\("""),
    "eval/new Function": re.compile(r"\beval\(|new Function\("),
    "setAsDefaultProtocolClient": re.compile(r"setAsDefaultProtocolClient\("),
    "autoUpdater.setFeedURL": re.compile(r"autoUpdater\.setFeedURL"),
}


# --------------------------------------------------------------------------- sources

def read_asar(path: Path) -> tuple[dict[str, bytes], list[str]]:
    data = path.read_bytes()
    _size, header_size = struct.unpack_from("<II", data, 0)
    _payload, json_len = struct.unpack_from("<II", data, 8)
    header = json.loads(data[16:16 + json_len].decode("utf-8"))
    base = 8 + header_size
    files, unpacked = {}, []

    def walk(node, prefix):
        for name, entry in node.get("files", {}).items():
            rel = f"{prefix}{name}"
            if "files" in entry:
                walk(entry, rel + "/")
            elif entry.get("unpacked"):
                unpacked.append(rel)
            elif "offset" in entry:
                off = base + int(entry["offset"])
                files[rel] = data[off:off + int(entry["size"])]
    walk(header, "")
    return files, unpacked


def read_tree(path: Path) -> dict[str, bytes]:
    out = {}
    for p in sorted(path.rglob("*")):
        if p.is_file() and "node_modules" not in p.parts and ".git" not in p.parts:
            out[str(p.relative_to(path))] = p.read_bytes() if p.stat().st_size <= MAX_FILE else b""
    return out


def load(target: Path) -> tuple[dict[str, bytes], list[str], str]:
    ident = identify(target)
    if ident["format"] == "asar":
        files, unpacked = read_asar(target)
        return files, unpacked, "asar"
    if target.is_dir():
        asar = target / "Contents" / "Resources" / "app.asar"
        if asar.exists():
            files, unpacked = read_asar(asar)
            return files, unpacked, "asar-in-app-bundle"
        return read_tree(target), [], "directory"
    return {target.name: target.read_bytes()}, [], "file"


# --------------------------------------------------------------------------- analysis

def resolve_rel(src: str, spec: str, names: set[str]) -> str | None:
    if not spec.startswith("."):
        return None
    base = os.path.normpath(os.path.join(os.path.dirname(src), spec))
    for cand in (base, base + ".js", base + ".mjs", base + ".cjs", base + ".ts", base + "/index.js"):
        if cand in names:
            return cand
    return None


def analyze(files: dict[str, bytes], traces: list[str]) -> dict:
    names = set(files)
    found: dict[str, list] = {k: [] for k in PATTERNS}
    security: dict[str, list] = {k: [] for k in SECURITY}
    edges, externals, trace_hits = [], {}, {t: [] for t in traces}
    pkg = None
    scanned = 0
    for name in sorted(files):
        if os.path.splitext(name)[1].lower() not in TEXT_EXT:
            continue
        raw = files[name]
        if not raw or len(raw) > MAX_FILE:
            continue
        text = raw.decode("utf-8", "replace")
        scanned += 1
        if os.path.basename(name) == "package.json" and pkg is None:
            try:
                j = json.loads(text)
                pkg = {k: j.get(k) for k in ("name", "version", "main", "productName")}
                pkg["dependencies"] = sorted((j.get("dependencies") or {}).keys())
            except json.JSONDecodeError:
                pass
        line_starts = [0] + [m.end() for m in re.finditer("\n", text)]

        def line_of(pos):
            lo, hi = 0, len(line_starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if line_starts[mid] <= pos:
                    lo = mid
                else:
                    hi = mid - 1
            return lo + 1

        for kind, rx in PATTERNS.items():
            for m in rx.finditer(text):
                gd = m.groupdict()
                method, value = gd.get("m"), gd["v"]
                if kind == "secret_like":
                    value, method = f"{method}=<{len(value)} chars redacted>", None
                item = {"value": value, "where": f"{name}:{line_of(m.start())}"}
                if method:
                    item["method"] = method
                found[kind].append(item)
                if kind in ("require", "import"):
                    tgt = resolve_rel(name, value, names)
                    if tgt:
                        edges.append([name, tgt])
                    elif not value.startswith("."):
                        externals[value] = externals.get(value, 0) + 1
        for label, rx in SECURITY.items():
            for m in rx.finditer(text):
                security[label].append(f"{name}:{line_of(m.start())}")
        for t in traces:
            for m in re.finditer(re.escape(t), text):
                ln = line_of(m.start())
                snippet = text[line_starts[ln - 1]:line_starts[ln] if ln < len(line_starts) else len(text)].strip()[:200]
                trace_hits[t].append({"where": f"{name}:{ln}", "line": snippet})

    def uniq(items, key="value"):
        seen, out = {}, []
        for it in items:
            k = (it.get("method"), it[key])
            if k not in seen:
                seen[k] = dict(it, occurrences=[it["where"]])
                seen[k].pop("where")
                out.append(seen[k])
            else:
                seen[k]["occurrences"].append(it["where"])
        return out

    ipc = {"main_handlers": uniq(found["ipc_main"]), "renderer_calls": uniq(found["ipc_renderer"]),
           "main_to_renderer": uniq(found["ipc_webcontents"]), "exposed_apis": uniq(found["exposed_api"])}
    handled = {x["value"] for x in ipc["main_handlers"]}
    called = {x["value"] for x in ipc["renderer_calls"] if x.get("method") in ("invoke", "send", "sendSync")}
    endpoints = uniq(found["url_literal"]) + uniq(found["api_path"])
    net_calls = uniq(found["fetch"]) + uniq(found["axios"]) + uniq(found["websocket"]) + uniq(found["xhr"])
    return {
        "package": pkg,
        "files_total": len(files),
        "files_scanned": scanned,
        "ipc": ipc,
        "ipc_channels": sorted(handled | called | {x["value"] for x in ipc["main_to_renderer"]}),
        "ipc_unhandled_renderer_calls": sorted(called - handled),
        "endpoints": endpoints,
        "network_calls": net_calls,
        "routes": uniq(found["route"]),
        "security_flags": {k: v for k, v in security.items() if v},
        "module_edges": sorted(map(list, {tuple(e) for e in edges})),
        "external_modules": dict(sorted(externals.items())),
        "sourcemaps": uniq(found["sourcemap"]),
        "secret_like": uniq(found["secret_like"]),
        "traces": trace_hits,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--extract")
    ap.add_argument("--trace", action="append", default=[])
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--workdir")
    a = ap.parse_args()
    target = Path(a.target).expanduser().resolve()
    if not target.exists():
        fail(f"target not found: {target}")
    w = workdir_path(a.workdir)
    ident = identify(target)
    files, unpacked, source_kind = load(target)
    if a.extract:
        out = Path(a.extract).expanduser().resolve()
        if out.exists() and any(out.iterdir()):
            fail(f"{out} is not empty; choose a new directory")
        for rel, data in files.items():
            dest = (out / rel).resolve()
            if not str(dest).startswith(str(out) + os.sep):
                fail(f"refusing path-traversal entry {rel!r}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
    result = analyze(files, a.trace)
    result["source_kind"] = source_kind
    result["unpacked_entries"] = unpacked
    result["file_digests"] = {k: sha256_bytes(v) for k, v in sorted(files.items())}
    raw = store_raw(w, json.dumps(result, indent=1), f"js-{ident['sha256'][:12]}")
    norm = dict(result)
    norm["file_digests"] = f"{len(files)} files (see raw_result)"
    lim = ["static pattern analysis: computed channel names, string concatenation and minified indirection are not resolved",
           "presence in code is not proof the path executes; confirm at runtime if it matters"]
    if unpacked:
        lim.append(f"{len(unpacked)} entries are in app.asar.unpacked and were not read from the archive")
    if any(f.endswith(".map") for f in files) or result["sourcemaps"]:
        lim.append("source maps present: original sources may be recoverable")
    payload = {"subject": {k: ident.get(k) for k in ("path", "sha256", "digest_kind", "format", "arch", "size")},
               "provider": {"id": "builtin-js", "version": "1"}, "operation": "js:analyze-application",
               "parameters": {"trace": sorted(a.trace)}, "normalized_result": norm, "raw_result": raw,
               "limitations": lim, "locations": [], "authority": "shipped-artifact", "confidence": "high"}
    summary = {
        "package": result["package"], "files": result["files_total"], "source_kind": source_kind,
        "ipc_channels": result["ipc_channels"],
        "exposed_apis": [x["value"] for x in result["ipc"]["exposed_apis"]],
        "endpoints": [x["value"] for x in result["endpoints"]][:60],
        "network_calls": [f'{x.get("method") or ""} {x["value"]}'.strip() for x in result["network_calls"]][:60],
        "security_flags": {k: len(v) for k, v in result["security_flags"].items()},
        "external_modules": list(result["external_modules"])[:40],
        "traces": {k: v[:20] for k, v in result["traces"].items()},
        "extracted_to": a.extract,
    }
    finish(payload, w, a.record, summary)


if __name__ == "__main__":
    main()
