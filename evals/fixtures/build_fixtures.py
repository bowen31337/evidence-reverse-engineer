#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Build eval fixtures into OUT_DIR (needs a C compiler: cc/clang).

Usage: uv run evals/fixtures/build_fixtures.py OUT_DIR

Produces:
  crackme                 native license-check binary (XOR-obfuscated prefix + checksum)
  v1/tool, v2/tool        two versions of a CLI (v2 adds telemetry upload, removes a flag, raises a timeout)
  notekeeper/app.asar     Electron app packed as a real ASAR archive
  bundle.zip              archive with a native exe, a nested zip, JS and docs
  notekeeper-mobile.apk   APK-shaped zip (manifest + classes.dex) for the missing-engine case
  repo/                   plain source repository (negative case)
  fw_RT-AX1800_1.0.4.bin  router firmware: uImage kernel + SquashFS rootfs (needs mksquashfs;
                          skipped with a warning when absent)
"""
import json
import lzma
import os
import tempfile
import time
import zlib
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

SRC = Path(__file__).parent / "src"


def cc(src: Path, out: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cc", "-O1", "-o", str(out), str(src)], check=True)


def write_asar(src_dir: Path, out: Path):
    files_tree: dict = {"files": {}}
    blobs, offset = [], 0
    for p in sorted(src_dir.rglob("*")):
        if not p.is_file():
            continue
        node = files_tree
        parts = p.relative_to(src_dir).parts
        for d in parts[:-1]:
            node = node["files"].setdefault(d, {"files": {}})
        data = p.read_bytes()
        node["files"][parts[-1]] = {"size": len(data), "offset": str(offset)}
        blobs.append(data)
        offset += len(data)
    js = json.dumps(files_tree, separators=(",", ":")).encode()
    pad = (4 - len(js) % 4) % 4
    payload = struct.pack("<I", len(js)) + js + b"\0" * pad
    header_pickle = struct.pack("<I", len(payload)) + payload
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(struct.pack("<II", 4, len(header_pickle)) + header_pickle + b"".join(blobs))


FIRMWARE_FILES = {
    "etc/passwd": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\nnobody:x:65534:65534::/:/bin/false\n",
    "etc/shadow": "root:$1$GTN.gpri$DlSyKvZKMh0vAbxEJ1Kp51:18000:0:99999:7:::\nadmin:$1$Qx7.Ab12$y0Lr4kqZ1d2mHf9TcVn3E/:18000:0:99999:7:::\n",
    "etc/init.d/rcS": "#!/bin/sh\nmount -t proc proc /proc\n/usr/sbin/nvram_load /etc/nvram.default\n"
                      "/usr/sbin/telnetd -l /bin/sh -p 23 &\n/usr/sbin/httpd -h /www -p 80 &\n"
                      "/usr/sbin/dropbear -p 22 -r /etc/dropbear_rsa_host_key &\n",
    "etc/nvram.default": "http_username=admin\nhttp_passwd=admin\ntelnetd_enable=1\nssh_enable=1\n"
                         "wan_proto=dhcp\nfw_version=1.0.4\ncloud_server=mgmt.routerco-cloud.net\n",
    "etc/dropbear_rsa_host_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
                                 "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END RSA PRIVATE KEY-----\n",
    "www/index.html": "<html><body><form action=/cgi-bin/login.cgi method=post>user <input name=u> pass <input name=p type=password></form></body></html>\n",
    "www/cgi-bin/login.cgi": "#!/bin/sh\n# login handler\nread -r BODY\nU=$(echo \"$BODY\" | sed -n 's/.*u=\\([^&]*\\).*/\\1/p')\n"
                             "P=$(echo \"$BODY\" | sed -n 's/.*p=\\([^&]*\\).*/\\1/p')\n"
                             "if [ \"$U\" = \"support\" ] && [ \"$P\" = \"Rc0-Supp0rt!2019\" ]; then echo 'Set-Cookie: sess=root'; exit 0; fi\n"
                             "if [ \"$U\" = \"$(nvram get http_username)\" ] && [ \"$P\" = \"$(nvram get http_passwd)\" ]; then echo 'Set-Cookie: sess=user'; fi\n",
    "usr/sbin/telnetd": "#!/bin/sh\n# busybox applet placeholder\nexec busybox telnetd \"$@\"\n",
    "usr/sbin/httpd": "#!/bin/sh\nexec busybox httpd \"$@\"\n",
}


def build_firmware(out: Path):
    """uImage (LZMA kernel) + SquashFS rootfs, like a typical consumer-router image."""
    if not shutil.which("mksquashfs"):
        print("warning: mksquashfs missing (brew install squashfs); firmware fixture skipped", file=sys.stderr)
        return
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "rootfs"
        for rel, text in FIRMWARE_FILES.items():
            f = root / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text)
            if rel.startswith(("usr/sbin/", "etc/init.d/", "www/cgi-bin/")):
                f.chmod(0o755)
        for d in ("proc", "tmp", "dev", "home/admin"):
            (root / d).mkdir(parents=True, exist_ok=True)
        sq = Path(td) / "rootfs.sqsh"
        subprocess.run(["mksquashfs", str(root), str(sq), "-comp", "xz", "-all-root", "-noappend", "-quiet", "-no-xattrs",
                        "-mkfs-time", "1700000000", "-all-time", "1700000000"], check=True, stdout=subprocess.DEVNULL)
        kernel = lzma.compress(b"Linux version 3.10.14 (builder@routerco) (gcc 5.5) #1 SMP\n" + bytes(range(256)) * 64,
                               format=lzma.FORMAT_ALONE)
        hdr = struct.pack(">IIIIIIIBBBB32s", 0x27051956, 0, 1700000000, len(kernel), 0x80008000, 0x80008000,
                          zlib.crc32(kernel), 5, 2, 2, 3, b"Linux-3.10.14 RT-AX1800")
        hdr = hdr[:4] + struct.pack(">I", zlib.crc32(hdr)) + hdr[8:]
        body = hdr + kernel
        body += b"\xff" * (-len(body) % 0x10000)
        (out / "fw_RT-AX1800_1.0.4.bin").write_bytes(body + sq.read_bytes())


def main(out_dir: str):
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    cc(SRC / "crackme.c", out / "crackme")
    cc(SRC / "tool_v1.c", out / "v1" / "tool")
    cc(SRC / "tool_v2.c", out / "v2" / "tool")
    write_asar(SRC / "electron", out / "notekeeper" / "app.asar")

    inner = out / "_inner.zip"
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("plugins/readme.txt", "plugin pack v1\n")
        z.write(out / "v1" / "tool", "plugins/helper-tool")
    with zipfile.ZipFile(out / "bundle.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.write(out / "crackme", "bin/activate")
        z.write(inner, "extras/plugins.zip")
        z.write(SRC / "electron" / "src" / "license.js", "web/license.js")
        z.writestr("docs/README.md", "# Bundle\nInstaller payload.\n")
        z.writestr("lib/libfake.so", "this is not really a shared object\n")
    inner.unlink()

    # Not a loadable DEX (no d8 here): a DEX header followed by a MUTF-8 string pool, so the
    # file carries realistic string-level hints but no decodable code.
    pool = ["Lcom/notekeeper/mobile/license/LicenseManager;", "verifyLicense", "isTrialExpired",
            "Lcom/notekeeper/mobile/net/ApiClient;", "/license/verify", "X-Device-Id",
            "Landroid/provider/Settings$Secure;", "android_id", "license_cache", "LICENSE_GRACE_DAYS",
            "Lokhttp3/OkHttpClient;", "Lokhttp3/Request$Builder;"]
    dex = b"dex\n035\0" + b"\0" * 104 + b"".join(bytes([len(x)]) + x.encode() + b"\0" for x in pool)
    with zipfile.ZipFile(out / "notekeeper-mobile.apk", "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\0" * 60)
        z.writestr("classes.dex", dex)
        z.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\0" * 28)
        z.writestr("assets/config.json", json.dumps({"api": "https://api.notekeeper-app.io/mobile/v3"}))
        z.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF\x02\x01\x01" + b"\0" * 57)

    build_firmware(out)

    if (out / "repo").exists():
        shutil.rmtree(out / "repo")
    shutil.copytree(SRC / "repo", out / "repo")
    print(json.dumps({"ok": True, "out": str(out),
                      "files": sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())}, indent=1))


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if len(sys.argv) == 2 else 1)
    main(sys.argv[1])
