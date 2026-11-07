# Routing table and engine recipes

Identify by content (`identify_target.py`), never by extension alone. When a container
holds other artifacts, inventory it, extract into a new directory, and route each
interesting member separately. Each member has its own sha256 and its own evidence.

## Signatures recognised by identify_target.py

| Magic / marker | format | Route |
|---|---|---|
| `7f 45 4c 46` | elf | native |
| `cf fa ed fe` / `ce fa ed fe` | mach-o | native |
| `ca fe ba be` (nfat < 40) | mach-o-universal | native (pass `--arch arm64` or `x86_64`) |
| `ca fe ba be` (else) | java-class | android/jar tools |
| `MZ` + `PE\0\0`, CLR dir present | pe-dotnet | managed-dotnet |
| `MZ` + `PE\0\0` | pe | native |
| `PK 03 04` + AndroidManifest.xml + *.dex | apk | android |
| `PK 03 04` + Payload/*.app/ | ipa | packaged-apps → native |
| `PK 03 04` + AppxManifest.xml / META-INF/MANIFEST.MF | msix / jar | packaged-apps |
| uint32 `4` + `{"files"` at 16 | asar | javascript-electron |
| `\0asm` | wasm | `wasm:inspect` |
| `dex\n` | dex | android |
| `koly` trailer | dmg | packaged-apps (hdiutil) |
| `MEI\x0c\x0b\x0a\x0b\x0e` near end | packer=pyinstaller | packaged-apps |
| `---- Bun! ----` near end | packer=bun | javascript-electron |
| `UPX!` | packer=upx | unpack a **copy** with `upx -d`, then native |
| `hsqs`/`sqsh`, uImage `27 05 19 56`, DTB `d0 0d fe ed` | firmware | firmware |
| large unidentified binary | unknown-blob | firmware scan + strings |

## Baseline operations (always available on macOS/Linux with a C toolchain)

| Operation | Engine | Notes |
|---|---|---|
| `strings:extract` | built-in | ASCII + UTF-16LE, categorised (urls, paths, format strings, secret-like) |
| `symbols:list` | nm | defined vs imported; empty defined set ⇒ stripped |
| `headers:info` | otool (Mach-O) / objdump | libraries, load commands/sections, PIE, entry, FairPlay `cryptid` |
| `disasm:function` | otool -tV (Mach-O) / objdump -d | calls, string refs, compared constants; cached |
| `callgraph:build` | same cache | direct edges only, `--max-nodes` budget |
| `xrefs:to` | same cache | `--symbol` callers or `--string` referencing functions |
| `macho:objc` | otool -oV | ObjC classes/selectors |
| `codesign:info` | codesign | signer, team id, hardened runtime, entitlements |
| `artifact:inventory` / `artifact:extract` | built-in | ZIP family + TAR; traversal-safe extraction into a NEW dir |
| `run:process` | sandbox-exec / unshare | one run, no network, writes only to a temp dir, minimal env; `controlled-replay` evidence. The sandbox is probed before each run, and the run is refused if none works (`--no-sandbox` overrides, only with consent). When it is allowed: `runtime-observation.md` |

Why otool for Mach-O: on arm64 a string load is an `adrp`+`add` pair. `otool -tV`
resolves it to `literal pool for: "text"` and resolves stub calls to `symbol stub
for: _puts`. Plain llvm-objdump mislabels stubs (`<_strlen+0x...>`). For ELF/PE the
script resolves strings itself from rip-relative comments and adrp+add pairs against
`.rodata`/`.rdata`.

## Optional engines

| Need | Operation | Install hint (do not run without asking) |
|---|---|---|
| Pseudo-C for native code | `ghidra:decompile --symbol NAME` | `brew install ghidra` (macOS), or a GitHub release + `GHIDRA_INSTALL_DIR` |
| Full analysis, xrefs through data, pseudo-C | `rizin:cmd --cmd "aaa;pdfj @ sym.main"`, `"aaa;axtj @ str.ok"`, `"aaa;aflj"` (`r2:cmd` same) | `brew install rizin` / `radare2` |
| APK/DEX → Java | `jadx:decompile --out NEW_DIR` | `brew install jadx` |
| APK resources/manifest | `apktool:decode --out NEW_DIR` | `brew install apktool` |
| .NET → C# | `dotnet:decompile --out NEW_DIR` | `dotnet tool install -g ilspycmd` |
| Firmware regions / extraction | `binwalk:scan`, `binwalk:extract --out NEW_DIR`, `unblob:extract --out NEW_DIR` | `brew install binwalk squashfs` (binwalk 3.x; squashfs gives the unsquashfs fallback), `pipx install unblob` |
| WASM | `wasm:inspect` (built-in parser fallback) | `brew install wabt` |

`ghidra/DecompileFunction.java` is the headless post-script (tested with Ghidra 12.2).
`ghidra:decompile` finds `analyzeHeadless` through `GHIDRA_INSTALL_DIR`, PATH, or next to
Homebrew's `ghidraRun`, and takes `JAVA_HOME` from the wrapper. A first run imports and
analyses the whole binary (seconds for small targets, minutes for large ones). Pass
`--symbol NAME` or `--symbol 0xADDRESS`; `*` decompiles everything. Pseudo-C is a
reconstruction: cite it as `confidence: medium` and confirm key details against
`disasm:function` (exact constants, operand widths). If it fails, record the failure as a
limitation and fall back to disassembly.

## When an engine is missing

1. The operation returns `ok:false` with `missing_provider` and `install_hint`.
2. Record an Unknown saying what that engine would establish ("Java source of
   com.example.LicenseCheck requires jadx").
3. Keep going with the baseline. Inventory, strings and manifest bytes often answer part
   of the question.
4. Tell the user the exact install command and what it would unlock. Don't run it yourself.
