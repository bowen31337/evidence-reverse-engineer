# Native binaries (ELF, Mach-O, PE)

## Contents
1. Standard pass
2. Answering "what does it check / when does it print X"
3. Call graphs and xrefs
4. Stripped, packed, encrypted
5. Swift / Objective-C
6. Version comparison
7. Budgets

## 1. Standard pass

```bash
R="uv run $S/run_provider.py"
$R headers:info  T --workdir W --record   # libraries, PIE, entry, encryption
$R symbols:list  T --workdir W --record   # defined functions + imported APIs
$R strings:extract T --workdir W --record # urls, paths, format strings
```
Imported APIs are a cheap capability map. `system`, `popen`, `connect`, `SecItemCopyMatching`,
`ptrace`, `dlopen`, `CreateRemoteThread`, `CryptEncrypt` each suggest a question to
follow up. Treat these as leads, not conclusions.

## 2. "What does it check before printing X?"

1. `xrefs:to T --string "X"` finds the function that references the message.
2. `disasm:function T --symbol <that function>` gives the calls, string refs and compared constants.
3. Follow the call that decides the branch (often `validate_*`, `check_*`, or the call just
   before the conditional branch that skips the message).
4. `disasm:function` on that checker. Read `compared_constants` (lengths, separator chars
   shown as `('-')`, checksums, moduli) and `calls` (`strncmp`, `memcmp`, `strlen`, decode
   helpers). For loops, read the instruction listing (`evidence.py show ID --field
   normalized_result.instructions --page N`).
5. When data is obfuscated (XOR tables, base64), find the table (`symbols:list --grep`
   or the `adrp` target), read its bytes (`xxd -s <file offset> -l N T`), and decode
   it yourself. Record the decode as an **inference** linked to the disassembly evidence.
   Arithmetic you did by hand isn't an observation.
6. Write each condition as a separate claim with its evidence ID. If a value is only
   derived (e.g. "sum % 7 == 3" from a multiply-shift sequence), label it an inference.
7. If `doctor.py` reports `native_decompiler: ghidra`, `ghidra:decompile T --symbol <checker>
   --record` gives pseudo-C that turns loops and multiply-shift modulo sequences back into
   readable conditions (`iVar2 % 7 == 3`). It cross-checks your reading of the
   disassembly. Cite both records. The disassembly is the exact observation and the
   pseudo-C is a medium-confidence reconstruction. When they disagree, trust the
   disassembly and record the disagreement.

## 3. Call graphs and xrefs

- `callgraph:build T --root main --depth 3` gives callees. `--direction callers` gives who reaches a function.
- Without `--root` you get roots (functions with no internal callers) and the most-called functions.
- Only direct edges are included. `blr x8`, `call *%rax`, vtables and `objc_msgSend`
  selectors appear as `indirect_calls`. Name these in limitations, and use rizin/Ghidra or
  runtime tracing if they matter.
- `xrefs:to --symbol strcmp` finds every comparison site.

## 4. Stripped, packed, encrypted

- **Stripped** (`defined_count` ≈ 0): otool/objdump still split at known starts. Work
  from string xrefs and imported-API call sites. rizin `aaa` recovers far more functions.
- **UPX** (`packer: upx`): copy the file and run `upx -d` on the copy (if the user agrees and upx exists).
- **FairPlay** (`encrypted: true`): code isn't analyzable statically. Record an Unknown.
  Don't attempt decryption.
- **Universal Mach-O**: pass `--arch arm64` or `--arch x86_64` consistently. Different
  slices are different evidence.

## 5. Swift / Objective-C

- `macho:objc T` lists classes and selectors. Selector names often describe the feature.
- Swift symbols are mangled (`$s...`). Demangle with `xcrun swift-demangle` if available.
- UI actions in NIB/storyboards connect to selectors. Grep the bundle's `.nib` files for
  the selector name to link UI to code.

## 6. Version comparison

`uv run $S/diff_versions.py old new --workdir W --record` reports:
- functions added/removed/changed. "Changed" means the instruction shape hash differs
  with addresses masked. Each changed function lists calls, string refs, comparisons
  and immediates added/removed (e.g. `#0xbb8 → #0x2328` = 3000 → 9000).
- facts about added functions (their calls and strings): usually the headline of a release diff.
- imports, defined symbols and strings added/removed.

A changed function means the static code changed. Whether *behaviour* changes is an
inference until runtime evidence shows it. Matching is by symbol name, so in stripped
binaries renames show up as an add plus a remove.

## 7. Budgets

Defaults: `--max-lines 400` per listing, `--max-nodes 200` per graph, `--timeout 180`.
Raise a budget deliberately, when the truncated part is what the question needs. Each
truncation is recorded in `limitations`.
