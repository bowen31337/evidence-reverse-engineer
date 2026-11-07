#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Detect which analysis providers exist on this machine. Read-only: installs nothing.

Usage:
  doctor.py [--workdir DIR] [--refresh]

Writes the result to <workdir>/doctor.json and reuses it on later calls unless
--refresh is given (run it once per investigation, not before every step).
Each provider reports: available, path, version, what it adds, install hint.
"""
import argparse
import json
import os
import platform
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import emit, find_ghidra_headless, run_owned, which, workdir_path  # noqa: E402

# name: (candidate executables, version args, capability, install hint)
PROVIDERS = {
    "otool": (["otool"], None, "Mach-O headers, load commands, symbolicated disassembly (stubs + string literals), ObjC metadata", "xcode-select --install"),
    "objdump": (["llvm-objdump", "objdump"], ["--version"], "disassembly + section/private headers for ELF/PE/Mach-O", "xcode-select --install / apt install binutils"),
    "nm": (["nm", "llvm-nm"], None, "symbol tables", "xcode-select --install / apt install binutils"),
    "readelf": (["readelf", "llvm-readelf"], ["--version"], "ELF headers, dynamic section, notes", "apt install binutils / brew install binutils"),
    "codesign": (["codesign"], None, "macOS code signature + entitlements", "ships with macOS"),
    "strings": (["strings"], None, "printable strings (strings:extract has a built-in fallback)", "built in fallback available"),
    "file": (["file"], ["--version"], "libmagic second opinion", "ships with most OSes"),
    "rizin": (["rizin"], ["-v"], "full static analysis: functions, xrefs, pseudo-C (pdg with rz-ghidra)", "brew install rizin"),
    "radare2": (["r2", "radare2"], ["-v"], "full static analysis: functions, xrefs, pseudo-C (pdc)", "brew install radare2"),
    "ghidra": (["analyzeHeadless"], None, "best decompiler (pseudo-C) for native code incl. NativeAOT", "brew install ghidra (macOS), or a GitHub release + GHIDRA_INSTALL_DIR"),
    "jadx": (["jadx"], ["--version"], "APK/DEX/JAR -> Java source", "brew install jadx"),
    "apktool": (["apktool"], ["--version"], "APK resources + decoded AndroidManifest.xml", "brew install apktool"),
    "ilspycmd": (["ilspycmd"], ["--version"], ".NET assembly -> C#", "dotnet tool install -g ilspycmd"),
    "binwalk": (["binwalk"], ["--version"], "firmware region scan + recursive extraction", "brew install binwalk"),
    "unsquashfs": (["sasquatch", "unsquashfs"], None, "SquashFS extraction (binwalk 3.x needs sasquatch; unsquashfs is the fallback)", "brew install squashfs"),
    "unblob": (["unblob"], ["--version"], "recursive firmware extraction", "pipx install unblob (Linux preferred)"),
    "wasm-objdump": (["wasm-objdump"], ["--version"], "WASM sections/imports/exports", "brew install wabt"),
    "wasm2wat": (["wasm2wat"], ["--version"], "WASM -> text format", "brew install wabt"),
    "node": (["node"], ["--version"], "run JS tooling (asar, source-map)", "brew install node"),
    "java": (["java"], ["-version"], "runtime for jadx/apktool/ghidra", "brew install openjdk@21"),
    "lldb": (["lldb"], ["--version"], "runtime: breakpoints / call tracing (needs user approval)", "xcode-select --install"),
    "gdb": (["gdb"], ["--version"], "runtime debugger (Linux)", "apt install gdb"),
    "frida": (["frida"], ["--version"], "runtime instrumentation (needs user approval)", "pipx install frida-tools"),
    "strace": (["strace"], ["-V"], "syscall trace (Linux)", "apt install strace"),
    "dtruss": (["dtruss"], None, "syscall trace (macOS, needs SIP/root)", "ships with macOS"),
    "upx": (["upx"], ["--version"], "unpack UPX-packed executables (on a copy)", "brew install upx"),
}


def probe(name, spec):
    exes, vargs, adds, hint = spec
    path = next((which(e) for e in exes if which(e)), None)
    if name == "ghidra":
        path = find_ghidra_headless()
    version = None
    if path and vargs:
        r = run_owned([path, *vargs], timeout=10)
        text = (r["stdout"] or r["stderr"]).strip().splitlines()
        version = text[0][:120] if text else None
    return {"available": bool(path), "path": path, "version": version, "adds": adds,
            "install_hint": None if path else hint}


def sandbox_probe():
    """Can run:process isolate a run here? sandbox-exec is deprecated on macOS, so test it rather than trust it."""
    if platform.system() == "Darwin" and which("sandbox-exec"):
        r = run_owned(["sandbox-exec", "-p", "(version 1)(allow default)(deny network*)", "/usr/bin/true"], timeout=10)
        return {"available": r["returncode"] == 0, "engine": "sandbox-exec", "detail": (r["stderr"] or "").strip()[:200] or None}
    if platform.system() == "Linux" and which("unshare"):
        r = run_owned(["unshare", "-rn", "true"], timeout=10)
        return {"available": r["returncode"] == 0, "engine": "unshare -rn",
                "detail": (r["stderr"] or "").strip()[:200] or "network isolated; filesystem writes are not restricted"}
    return {"available": False, "engine": None, "detail": "no sandbox: run:process refuses unless --no-sandbox"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workdir")
    ap.add_argument("--refresh", action="store_true")
    a = ap.parse_args()
    w = workdir_path(a.workdir)
    cache = w / "doctor.json"
    if cache.exists() and not a.refresh:
        data = json.loads(cache.read_text())
        data["cached"] = True
        emit(data)
    providers = {n: probe(n, s) for n, s in PROVIDERS.items()}
    avail = sorted(n for n, p in providers.items() if p["available"])
    decompiler = next((n for n in ("ghidra", "rizin", "radare2") if providers[n]["available"]), None)
    data = {
        "ok": True,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
        "available": avail,
        "missing": sorted(set(providers) - set(avail)),
        "capability_summary": {
            "native_disassembly": bool(providers["otool"]["available"] or providers["objdump"]["available"]),
            "native_decompiler": decompiler,
            "android": providers["jadx"]["available"],
            "dotnet": providers["ilspycmd"]["available"],
            "firmware": providers["binwalk"]["available"] or providers["unblob"]["available"],
            "wasm": providers["wasm-objdump"]["available"],
            "runtime": [n for n in ("lldb", "gdb", "frida", "strace", "dtruss") if providers[n]["available"]],
            "sandboxed_run": sandbox_probe(),
        },
        "providers": providers,
        "note": "Nothing was installed. Missing providers only limit what can be observed; record that as a limitation or Unknown.",
    }
    cache.write_text(json.dumps(data, indent=2))
    emit(data)


if __name__ == "__main__":
    main()
