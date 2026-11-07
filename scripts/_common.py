"""Shared helpers for the evidence-reverse-engineer scripts.

Standard library only. Every script inserts its own directory on sys.path so it
works under `python3 -I` (isolated mode drops the script dir from sys.path).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import NoReturn

SKILL_VERSION = "1"
DEFAULT_WORKDIR = "re-work"


# --------------------------------------------------------------------------- json / hashing

def canonical_json(obj) -> str:
    """Byte-stable JSON: sorted keys, no whitespace variance, UTF-8 safe."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_tree(root: str | os.PathLike) -> str:
    """Deterministic digest of a directory: relative path + file digest, sorted."""
    root = Path(root)
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            h.update(str(p.relative_to(root)).encode())
            h.update(b"\0")
            h.update(sha256_file(p).encode())
            h.update(b"\n")
    return h.hexdigest()


def atomic_write_text(path: str | os.PathLike, text: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def emit(obj, code: int = 0) -> NoReturn:
    """Print JSON result to stdout and exit."""
    sys.stdout.write(json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False) + "\n")
    sys.exit(code)


def fail(message: str, code: int = 2, **extra) -> NoReturn:
    emit({"ok": False, "error": message, **extra}, code)


# --------------------------------------------------------------------------- owned processes

def run_owned(cmd: list[str], timeout: float = 120, cwd: str | None = None,
              max_output: int = 64 << 20) -> dict:
    """Run a provider command in its own process group; kill the whole group on timeout.

    Mirrors REA's 'owned child process' rule: no engine survives the call.
    """
    started = time.time()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=cwd, start_new_session=True)
    except FileNotFoundError:
        return {"ok": False, "returncode": None, "stdout": "", "stderr": f"not found: {cmd[0]}",
                "timed_out": False, "seconds": 0.0, "cmd": cmd}
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    return {
        "ok": (not timed_out) and proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": out[:max_output].decode("utf-8", "replace"),
        "stderr": err[-8192:].decode("utf-8", "replace"),
        "timed_out": timed_out,
        "seconds": round(time.time() - started, 3),
        "cmd": cmd,
    }


def which(name: str) -> str | None:
    return shutil.which(name)


def find_ghidra_headless() -> str | None:
    """analyzeHeadless from $GHIDRA_INSTALL_DIR, PATH, or next to ghidraRun (Homebrew links only ghidraRun)."""
    cands = []
    if os.environ.get("GHIDRA_INSTALL_DIR"):
        cands.append(Path(os.environ["GHIDRA_INSTALL_DIR"]) / "support" / "analyzeHeadless")
    if which("analyzeHeadless"):
        cands.append(Path(which("analyzeHeadless")))
    run = which("ghidraRun")
    if run:
        real = Path(os.path.realpath(run))
        cands += [real.parent / "support" / "analyzeHeadless", real.parent.parent / "libexec" / "support" / "analyzeHeadless"]
    for prefix in ("/opt/homebrew/opt/ghidra", "/usr/local/opt/ghidra"):
        cands.append(Path(prefix) / "libexec" / "support" / "analyzeHeadless")
    return next((str(p) for p in cands if p.is_file() and os.access(p, os.X_OK)), None)


def ghidra_java_home() -> str | None:
    """JAVA_HOME for headless Ghidra: env, then the default baked into Homebrew's ghidraRun wrapper."""
    if os.environ.get("JAVA_HOME"):
        return os.environ["JAVA_HOME"]
    run = which("ghidraRun")
    if run:
        try:
            m = re.search(r'JAVA_HOME:-([^}"]+)', Path(run).read_text(errors="replace"))
        except OSError:
            m = None
        if m and Path(m.group(1)).is_dir():
            return m.group(1)
    return None


# --------------------------------------------------------------------------- target identification

ELF_MACHINES = {0x03: "x86", 0x08: "mips", 0x14: "ppc", 0x28: "arm", 0x3E: "x86_64",
                0xB7: "arm64", 0xF3: "riscv", 0x5E: "xtensa"}
MACHO_CPU = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64",
             0x0200000C: "arm64_32"}
PE_MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64", 0x1C0: "arm", 0x1C4: "armnt"}


def _read(path: Path, n: int, offset: int = 0) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(n)


def _tail(path: Path, n: int) -> bytes:
    size = path.stat().st_size
    with open(path, "rb") as f:
        f.seek(max(0, size - n))
        return f.read()


def _pe_info(path: Path, head: bytes) -> dict:
    info = {"format": "pe", "arch": None, "bitness": None, "managed": False}
    try:
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        hdr = _read(path, 512, e_lfanew)
        if hdr[:4] != b"PE\0\0":
            return {"format": "dos-mz"}
        machine = struct.unpack_from("<H", hdr, 4)[0]
        info["arch"] = PE_MACHINES.get(machine, hex(machine))
        opt = 24
        magic = struct.unpack_from("<H", hdr, opt)[0]
        info["bitness"] = 64 if magic == 0x20B else 32
        dd = opt + (112 if magic == 0x20B else 96)
        _clr_rva, clr_size = struct.unpack_from("<II", hdr, dd + 14 * 8)
        info["managed"] = clr_size > 0
        chars = struct.unpack_from("<H", hdr, 22)[0]
        info["dll"] = bool(chars & 0x2000)
    except (struct.error, IndexError):
        pass
    return info


def _zip_kind(path: Path) -> tuple[str, list[str]]:
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except zipfile.BadZipFile:
        return "zip-corrupt", []
    s = set(names)
    if "AndroidManifest.xml" in s and any(n.endswith(".dex") for n in names):
        return "apk", names
    if any(n.startswith("Payload/") and ".app/" in n for n in names):
        return "ipa", names
    if "AppxManifest.xml" in s:
        return "msix", names
    if "META-INF/MANIFEST.MF" in s:
        return "jar", names
    if any(n.endswith(".whl") or n.endswith(".dist-info/WHEEL") for n in names):
        return "wheel", names
    return "zip", names


def identify(path: str | os.PathLike) -> dict:
    """Identify a target by content (magic bytes), not by its name."""
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(str(p))
    if p.is_dir():
        kind = "directory"
        hints = []
        if (p / "package.json").exists():
            kind = "javascript-tree"
        if p.suffix == ".app" and (p / "Contents" / "Info.plist").exists():
            kind = "macos-app-bundle"
            asar = p / "Contents" / "Resources" / "app.asar"
            if asar.exists():
                hints.append(f"electron app: {asar}")
        return {"path": str(p), "kind": kind, "format": kind, "sha256": sha256_tree(p),
                "digest_kind": "tree", "size": sum(f.stat().st_size for f in p.rglob("*") if f.is_file()),
                "hints": hints}

    size = p.stat().st_size
    head = _read(p, 4096)
    info: dict = {"format": "unknown"}
    hints: list[str] = []

    if head[:4] == b"\x7fELF":
        bits = 64 if head[4] == 2 else 32
        endian = "<" if head[5] == 1 else ">"
        e_type, e_machine = struct.unpack_from(endian + "HH", head, 16)
        info = {"format": "elf", "bitness": bits, "arch": ELF_MACHINES.get(e_machine, hex(e_machine)),
                "endian": "little" if endian == "<" else "big",
                "elf_type": {1: "relocatable", 2: "executable", 3: "shared-object", 4: "core"}.get(e_type, e_type)}
    elif head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        le = head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
        cpu, _sub, ftype = struct.unpack_from(("<" if le else ">") + "iII", head, 4)
        info = {"format": "mach-o", "bitness": 64 if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32,
                "arch": MACHO_CPU.get(cpu, hex(cpu & 0xFFFFFFFF)),
                "macho_type": {1: "object", 2: "executable", 6: "dylib", 8: "bundle"}.get(ftype, ftype)}
    elif head[:4] == b"\xca\xfe\xba\xbe":
        nfat = struct.unpack_from(">I", head, 4)[0]
        if nfat < 40:
            archs = []
            for i in range(nfat):
                cpu = struct.unpack_from(">i", head, 8 + i * 20)[0]
                archs.append(MACHO_CPU.get(cpu, hex(cpu & 0xFFFFFFFF)))
            info = {"format": "mach-o-universal", "arch": ",".join(archs)}
        else:
            info = {"format": "java-class"}
    elif head[:2] == b"MZ":
        info = _pe_info(p, head)
        if info.get("managed"):
            info["format"] = "pe-dotnet"
    elif head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        kind, names = _zip_kind(p)
        info = {"format": kind, "members": len(names)}
    elif head[:4] == b"\0asm":
        info = {"format": "wasm", "wasm_version": struct.unpack_from("<I", head, 4)[0]}
    elif head[:4] == b"dex\n":
        info = {"format": "dex"}
    elif head[:4] == b"GGUF":
        info = {"format": "gguf"}
    elif len(head) >= 16 and struct.unpack_from("<I", head, 0)[0] == 4 and b'{"files"' in head[16:32]:
        info = {"format": "asar"}
    elif head[:2] == b"\x1f\x8b":
        info = {"format": "gzip"}
    elif head[:6] == b"\xfd7zXZ\0":
        info = {"format": "xz"}
    elif head[:6] == b"7z\xbc\xaf\x27\x1c":
        info = {"format": "7z"}
    elif head[:4] in (b"hsqs", b"sqsh"):
        info = {"format": "squashfs"}
    elif head[:4] == b"\x27\x05\x19\x56":
        info = {"format": "uimage"}
    elif head[:4] == b"\xd0\x0d\xfe\xed":
        info = {"format": "device-tree-blob"}
    elif len(head) > 262 and head[257:262] == b"ustar":
        info = {"format": "tar"}
    elif len(head) >= 4 and head[2:4] == b"\r\n" and p.suffix == ".pyc":
        info = {"format": "python-bytecode"}
    elif head[:1] == b"\xe9" and p.suffix == ".bin":
        info = {"format": "esp-image-candidate"}

    tail = _tail(p, 1 << 16)
    if tail[-512:-508] == b"koly":
        info = {"format": "dmg"}
    if b"MEI\x0c\x0b\x0a\x0b\x0e" in tail:
        hints.append("pyinstaller CArchive appended: the Python application layer is the archive, not the bootloader")
        info["packer"] = "pyinstaller"
    if b"---- Bun! ----" in tail:
        hints.append("bun --compile standalone: the embedded module graph is the application layer")
        info["packer"] = "bun"
    if info.get("format") in ("elf", "mach-o", "pe") and b"UPX!" in head:
        hints.append("UPX-packed: unpack (upx -d on a copy) before static analysis")
        info["packer"] = "upx"

    if info["format"] == "unknown":
        try:
            text = head.decode("utf-8")
            info = {"format": "javascript" if p.suffix in (".js", ".mjs", ".cjs") else "text"}
            if "sourceMappingURL" in text:
                hints.append("source map referenced")
        except UnicodeDecodeError:
            if size > 64 * 1024:
                info = {"format": "unknown-blob"}
                hints.append("large unidentified blob: try a firmware region scan (binwalk/unblob) or entropy check")

    return {"path": str(p), "kind": "file", **info, "sha256": sha256_file(p), "digest_kind": "file",
            "size": size, "hints": hints}


ROUTES = {
    "mach-o": ("native", ["symbols:list", "headers:info", "strings:extract", "disasm:function", "callgraph:build"]),
    "mach-o-universal": ("native", ["headers:info", "symbols:list", "disasm:function (use --arch)"]),
    "elf": ("native", ["symbols:list", "headers:info", "strings:extract", "disasm:function", "callgraph:build"]),
    "pe": ("native", ["headers:info", "symbols:list", "strings:extract", "disasm:function"]),
    "pe-dotnet": ("managed-dotnet", ["dotnet:decompile (ilspycmd)", "strings:extract"]),
    "apk": ("android", ["artifact:inventory", "jadx:decompile", "apktool:decode"]),
    "dex": ("android", ["jadx:decompile"]),
    "ipa": ("packaged-app", ["artifact:inventory", "artifact:extract then route the Mach-O"]),
    "zip": ("packaged-app", ["artifact:inventory"]),
    "jar": ("packaged-app", ["artifact:inventory", "jadx:decompile"]),
    "msix": ("packaged-app", ["artifact:inventory"]),
    "wheel": ("packaged-app", ["artifact:inventory"]),
    "tar": ("packaged-app", ["artifact:inventory"]),
    "dmg": ("packaged-app", ["hdiutil attach -readonly -nobrowse, then route contents"]),
    "asar": ("javascript-electron", ["js_bundle.py"]),
    "javascript-tree": ("javascript-electron", ["js_bundle.py"]),
    "javascript": ("javascript-electron", ["js_bundle.py"]),
    "macos-app-bundle": ("native", ["route Contents/MacOS/<exe>; if Electron route app.asar to js_bundle.py"]),
    "wasm": ("native", ["wasm:inspect"]),
    "uimage": ("firmware", ["binwalk:scan", "unblob:extract"]),
    "squashfs": ("firmware", ["unblob:extract"]),
    "device-tree-blob": ("firmware", ["binwalk:scan"]),
    "unknown-blob": ("firmware", ["binwalk:scan", "strings:extract"]),
    "esp-image-candidate": ("firmware", ["strings:extract", "binwalk:scan"]),
    "python-bytecode": ("packaged-app", ["strings:extract", "external pyc decompiler"]),
}


def route_for(ident: dict) -> dict:
    fmt = ident.get("format") or "unknown"
    domain, ops = ROUTES.get(fmt, ("unknown", ["strings:extract", "binwalk:scan"]))
    if ident.get("packer") == "pyinstaller":
        domain, ops = "packaged-app", ["pyinstxtractor-style extraction", "strings:extract"]
    if ident.get("packer") == "bun":
        domain, ops = "javascript-electron", ["strings:extract (embedded JS)", "js_bundle.py on extracted modules"]
    return {"domain": domain, "suggested_operations": ops,
            "reference": f"references/{DOMAIN_REFERENCE.get(domain, 'routing')}.md"}


DOMAIN_REFERENCE = {"native": "native", "managed-dotnet": "managed-dotnet", "android": "android",
                    "packaged-app": "packaged-apps", "javascript-electron": "javascript-electron",
                    "firmware": "firmware"}


def subject_for(path: str | os.PathLike) -> dict:
    ident = identify(path)
    return {k: ident.get(k) for k in ("path", "sha256", "digest_kind", "format", "arch", "size")}


def workdir_path(workdir: str | None) -> Path:
    w = Path(workdir or os.environ.get("RE_WORKDIR") or DEFAULT_WORKDIR).expanduser().resolve()
    (w / "raw").mkdir(parents=True, exist_ok=True)
    return w


def store_raw(workdir: Path, text: str, label: str) -> dict:
    data = text.encode("utf-8")
    digest = sha256_bytes(data)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in label)[:60]
    out = workdir / "raw" / f"{safe}-{digest[:12]}.txt"
    if not out.exists():
        out.write_bytes(data)
    return {"path": str(out), "sha256": digest, "bytes": len(data)}
