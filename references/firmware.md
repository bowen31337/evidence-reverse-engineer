# Firmware images

1. `identify_target.py` may report uimage/squashfs/device-tree-blob, or `unknown-blob` for raw dumps.
2. `run_provider.py binwalk:scan fw.bin --record` returns candidate regions (offset, size,
   description). These are signature matches, i.e. candidates, and the summary says how
   much of the file they cover.
3. `run_provider.py binwalk:extract fw.bin --out NEW_DIR --record` extracts recursively.
   Check the summary before trusting the tree:
   - `failed > 0`: binwalk 3.x exits 0 even when an extractor is missing, so the script
     reads per-region success from binwalk's log. Every unextracted region is a limitation
     ("contents were not observed"). Record an Unknown if it matters to the question.
   - SquashFS needs `sasquatch` in binwalk 3.x. When that's missing, the script falls back
     to `unsquashfs -o OFFSET` (brew `squashfs`) and names the fallback in `extractor`.
   - `filesystem_roots` lists the directories that contain `etc/`, which is where to start.
   `unblob:extract` is the alternative recursive extractor (best on Linux).
4. Without binwalk/unblob: `strings:extract` (banners, versions, URLs, default
   credentials) plus manual carving at known magic offsets (`dd if=fw.bin of=part.sqsh
   bs=1 skip=<offset>`) into the workdir. Record the carve parameters in the evidence
   (`--params`).

## Triage an extracted root filesystem

Extracted files are new artifacts, so cite them by path and sha256. Record a finding with
`evidence.py record --from <file>`, or run `strings:extract` / `headers:info` on it.
Typical questions and where they're answered:

| Question | Look at |
|---|---|
| Accounts and password hashes | `etc/passwd`, `etc/shadow` (hash type from the prefix: `$1$` md5crypt, `$5$`/`$6$` sha-crypt). Report hashes; don't crack them unless asked and authorised |
| Default / hardcoded web credentials | NVRAM defaults (`etc/nvram.default`, `*.cfg`, `default.conf`), CGI scripts and web-server binaries (`www/cgi-bin/*`, `httpd`), JS in `www/` |
| Backdoor-style logins | string comparisons against literals in CGI or auth binaries (a second user/password pair beside the configured one) |
| Which network services start | `etc/init.d/rcS`, `etc/inittab`, `etc/rc.d/*`, `etc/init.d/*`: telnetd/dropbear/sshd/httpd/upnpd lines and their ports/flags (`telnetd -l /bin/sh` = shell with no login) |
| Embedded keys and certs | `-----BEGIN ... PRIVATE KEY-----` files, `*.pem`, `*.key`; a shared host key across devices is a finding |
| Cloud / phone-home endpoints | URLs and hostnames from configs and `strings:extract` on service binaries |

Keep the boundary between what is configured and what runs. "rcS starts telnetd on boot"
is an observation of the image. "Telnet is reachable on the device" needs runtime
evidence or an inference that says so. Also check for gating flags such as
`telnetd_enable=1` in NVRAM that an init script might read.

Service binaries are usually MIPS or ARM ELF: `headers:info`, `strings:extract` and
`symbols:list` work cross-architecture (objdump). Use `disasm:function` on those only when
the installed objdump supports that target.

## ESP32 / microcontroller images
A first byte of `0xE9` in a `.bin` is a hint for an ESP app image. The segment headers
follow, and strings plus the partition table are the fastest wins. Without a dedicated tool,
state that code-level analysis needs Ghidra with the Xtensa/RISC-V processor module.

## Limits
- Encrypted or signed-and-compressed regions show high entropy. Record them as Unknowns and
  don't guess their content.
- Extraction never executes anything. Emulation (qemu) is runtime observation and
  needs user approval.
