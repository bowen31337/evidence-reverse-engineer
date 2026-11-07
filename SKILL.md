---
name: evidence-reverse-engineer
description: "Reverse engineer compiled or packaged files and keep evidence you can audit. Use this skill whenever the answer has to come from inside a shipped artifact rather than readable source, even for a quick look you could do with file/strings/nm/otool/binwalk: router or IoT firmware images (.bin/.img/.trx dumps: unpack, hardcoded credentials, telnet/ssh/web services), Mach-O/ELF/PE binaries (sections such as __TEXT,__cstring, symbols, strings, which functions reference a string, xrefs, call graphs, disassembly, what it does or phones home to), .NET DLL/EXE decompilation, Android APKs, Electron/ASAR and minified JS bundles, ZIP/IPA/DMG/PyInstaller packages, WASM, CTF crackmes, static malware triage, and diffs between two builds. It records each result as citable evidence, tracks open questions, and separates observed facts from inferences. Not for source code you can read directly, for writing parsers or RE tooling, or for bypassing licensing or DRM."
---

# Evidence-first reverse engineering

This skill gives you the same discipline as REA (Reverse Engineer Anything): route the
target to the right engine, analyze summary-first within budgets, and turn every result
into evidence you can cite. The scripts do the mechanical work and the ledger keeps you
honest. Your job is to ask good questions of the artifact and to say clearly what is
known, what is inferred, and what is still open.

All scripts are standard-library Python with uv inline metadata. Run them with
`uv run <skill>/scripts/<name>.py`. Below, `$S` means this skill's `scripts/` directory.
Every script prints JSON and supports `--help`.

## 1. Decide whether this skill applies

Use it when a claim depends on a **shipped artifact**: compiled code, a packed bundle, an
archive, firmware, or the differences between two builds. If the user has the source and
asks about the source, read the source with normal tools. Running binary tooling on
`.js`/`.py` files from a repository wastes time and produces weaker answers. A minified
or packaged JS bundle *is* a shipped artifact, so it qualifies.

Analyze only targets the user owns or is authorized to examine: their own software, CTF
challenges, malware triage, interoperability and security research. Decline requests
whose goal is to bypass licensing, DRM, or anti-cheat in software they don't own, and
say why.

## 2. Set up the investigation

Pick a working directory for the investigation, by default `./re-work/<short-name>/`. Pass it
as `--workdir` to every script, or export `RE_WORKDIR`. The ledger (`evidence.json`), raw
outputs, caches and the final report all live there.

```bash
uv run $S/doctor.py --workdir W        # once per investigation; cached in W/doctor.json
uv run $S/identify_target.py <target>  # sha256, format, arch, packer hints, suggested route
```

`doctor.py` only detects tools. **Never install an engine the user didn't ask for.** If a
missing provider limits the answer, say what it would add, give its `install_hint`, and
record an Unknown. Then carry on with what is available. The baseline (otool / objdump /
nm plus the built-in parsers) answers most questions about native code.

## 3. Route the target first

Choose the first operation from what `identify_target.py` reports (by content, not file
name). Then read **only** the matching reference:

| Target | First step | Reference |
|---|---|---|
| ELF / Mach-O / PE executable or library | `symbols:list`, `headers:info`, then `disasm:function` / `callgraph:build` / `xrefs:to` | `references/native.md` |
| .NET assembly (`pe-dotnet`) | `dotnet:decompile` (ilspycmd), else strings + metadata | `references/managed-dotnet.md` |
| APK / DEX / JAR | `artifact:inventory`, then `jadx:decompile` / `apktool:decode` | `references/android.md` |
| ASAR, Electron `.app`, JS tree or bundle | `js_bundle.py` | `references/javascript-electron.md` |
| ZIP / IPA / MSIX / TAR / DMG / PyInstaller / Bun | `artifact:inventory`, extract, then route each member | `references/packaged-apps.md` |
| Firmware / unknown blob | `binwalk:scan`, then `binwalk:extract --out NEW_DIR` (or `unblob:extract`), `strings:extract` | `references/firmware.md` |
| Two versions of anything | `diff_versions.py old new` | `references/native.md` (diff section) |

`references/routing.md` has the full routing table, signatures and engine recipes.

## 4. Analyze summary-first, inside budgets

`run_provider.py <operation> <target> --workdir W --record` runs one bounded operation. It
prints a **summary**, stores the full output under `W/raw/`, and with `--record` adds an
Evidence record to the ledger and prints its `evidence_id`.

- Start with the smallest overview that can answer the question: symbols, headers,
  inventory. Drill in only when a specific question is still open.
- Disassembly is cached per (sha256, arch, tool), so follow-up questions about other
  functions are cheap. Don't repeat an identical call: read the stored evidence instead
  (`evidence.py show ID --field normalized_result.<key> --page N`).
- Each engine call runs in its own process group with a timeout and is killed on exit.
  If a call times out, change something (narrower scope, longer `--timeout`, a stronger
  engine) before you retry.
- For a crackme or license check, the useful facts are usually the **compared constants**
  (`cmp w8, #0x2d ('-')`), **calls** (`strncmp`, `strlen`) and **string references**
  (`literal pool for: "ok"`) in the checking function. `disasm:function` extracts all
  three. Follow helper calls (e.g. a decode routine) with another `disasm:function`.

## 5. Evidence discipline

This is the core of the skill. A reverse-engineering answer is only as good as the
reader's ability to check it.

- **Observations** come from a tool run on the artifact. Record them with `--record`.
  Their authority is `shipped-artifact` (or `controlled-replay` for runtime observation).
- **Inferences** are your reasoning over observations: "this loop sums bytes 5–11", "the
  XOR decodes to `REA?`". Record each one and link the evidence it rests on:
  `uv run $S/evidence.py --workdir W record --infer "<statement>" --link <ev-id> [--link ...]`
- **Unknowns** are questions you couldn't close: a missing engine, an indirect call,
  encrypted code, behaviour that needs runtime. Record them:
  `uv run $S/evidence.py --workdir W unknown add --question "..." --severity high --domain native --supporting <ev-id>`
  When evidence later closes one, update it with `--expected-revision N --status resolved --resolution "..."`.
- Static analysis never observes execution. Don't write "the program sends X" from
  disassembly alone. Write "the code contains a path that sends X".
- Confirm at runtime when it's cheap and authorized. If the user supplied the binary and
  their request implies running it (a CTF key, their own build), confirm your static
  answer with one sandboxed run, plus one run that should fail:
  `run_provider.py run:process T --arg <input> --record`. That runs with no network,
  writes only to a temp dir, and records `controlled-replay` evidence. Ask first for
  vendor or third-party binaries, suspected malware, network access, debuggers or root
  (`references/runtime-observation.md`). If the user said not to execute, don't.
- Keep each record's `limitations` (truncation, unresolved indirect calls, stripped
  symbols) and carry them into the report.

`references/evidence-model.md` describes every field, the authority levels and a worked example.

## 6. Broad investigations

When a request spans several features or several questions:

1. Write the request as a checklist of questions, each with the evidence that would
   answer it.
2. Reuse what's already in the ledger (`evidence.py list`) before running anything new.
3. Answer each question from its entry point to its result: overview, then function,
   then callee.
4. If subagents are available and the questions are independent, give each one a
   distinct scope and the same `--workdir`. The ledger is file-locked and idempotent, so
   shared recording is safe. Ask each subagent to return evidence IDs, conclusions and
   open gaps.
5. Before finishing, mark every checklist question **answered**, **partial**, or
   **unresolved**. A bounded search that found nothing is a bounded negative ("no
   direct references in the text section"), not proof of absence.

## 7. Check claims, then finish

1. Write the key claims to `W/claims.json` (format in `references/evidence-model.md`) and run
   `uv run $S/evidence.py --workdir W verify W/claims.json`. A claim fails if it's labelled
   an observation but only inference supports it, if it asserts runtime behaviour without
   runtime evidence, or if an `expect` check doesn't match the cited record. A claim is
   unknown if its evidence is contradicted by an open Unknown, or if it lists an open
   Unknown in `depends_on_unknowns`. Declare a dependency only when the claim's truth
   hinges on that question. Fix or relabel every failure before you report.
2. Write `W/report.md` using `references/report-template.md`: findings with evidence IDs,
   then an evidence table, unknowns, limitations, and the checklist status.
3. Export the bundle: `uv run $S/evidence.py --workdir W export W/evidence-bundle.json --overwrite`,
   and run `evidence.py validate`. The bundle is canonical and byte-stable, and
   `import` restores it in a later session.
4. In the chat reply, give the answer in plain language first, then point to the report
   and bundle paths. List the open unknowns with what would close each one.

## Script reference

| Script | Purpose |
|---|---|
| `doctor.py` | Detect providers (read-only, cached) |
| `identify_target.py` | Content-based identification, sha256, route |
| `run_provider.py` | One bounded operation → Evidence payload (`--record` to ledger); `run:process` = one sandboxed run (controlled-replay) |
| `js_bundle.py` | ASAR/JS static analysis: IPC, endpoints, module graph, Electron security flags, `--trace TERM` |
| `diff_versions.py` | Version comparison (native functions/strings/imports, archive members, JS features) |
| `evidence.py` | Ledger: `record`, `show`, `list`, `unknown add/update/list`, `verify`, `export`, `import`, `validate` |
