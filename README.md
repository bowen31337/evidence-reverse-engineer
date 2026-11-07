# evidence-reverse-engineer

An evidence-first reverse-engineering [skill](https://docs.claude.com/en/docs/claude-code/skills) for Claude Code. It routes a
compiled or packaged target to the right engine, analyzes summary-first within
budgets, and turns every result into **citable evidence** — so a reader can
audit how each claim was reached, and observed facts stay separated from
inferences.

## What it handles

- **Native binaries** — ELF / Mach-O / PE: symbols, strings, sections (e.g.
  `__TEXT,__cstring`), disassembly, call graphs, xrefs ("which functions
  reference this string"), and what a binary does or phones home to.
- **Firmware / IoT images** — `.bin` / `.img` / `.trx`: unpack, hardcoded
  credentials, telnet/ssh/web services.
- **.NET** assemblies, **Android** APKs, **Electron/ASAR** and minified JS
  bundles, **ZIP/IPA/DMG/PyInstaller** packages, **WASM**.
- **CTF crackmes**, **static malware triage**, and **diffs between two builds**.

It is **not** for source you can read directly, for writing parsers/RE tooling,
or for bypassing licensing or DRM.

## Install

Clone into your Claude Code skills directory:

```bash
git clone https://github.com/bowen31337/evidence-reverse-engineer.git \
  ~/.claude/skills/evidence-reverse-engineer
```

The skill triggers automatically when a request depends on a shipped artifact.

## How it works

`SKILL.md` is the entry point. Mechanical work is done by standard-library
Python scripts (run with [`uv`](https://docs.astral.sh/uv/)):

| Script | Purpose |
|---|---|
| `scripts/doctor.py` | Detect available providers (read-only, cached) |
| `scripts/identify_target.py` | Content-based identification, sha256, route |
| `scripts/run_provider.py` | One bounded operation → Evidence record |
| `scripts/js_bundle.py` | ASAR/JS static analysis (IPC, endpoints, module graph) |
| `scripts/diff_versions.py` | Version comparison |
| `scripts/evidence.py` | The ledger: record, verify, export, validate |

Per-domain recipes live in `references/`. The evidence model (content-addressed
records, authority levels, residual unknowns, byte-stable bundles) is described
in `references/evidence-model.md`.

### Baseline vs. optional engines

The baseline (otool / objdump / nm plus built-in parsers) answers most native
questions with no extra install. Optional engines unlock more and are never
installed without the user asking: Ghidra (pseudo-C), rizin/radare2, jadx,
apktool, ilspycmd (.NET), binwalk + squashfs (firmware). `doctor.py` reports
which are present and prints an install hint for the rest.

## Authorized use only

Analyze only targets you own or are authorized to examine — your own software,
CTF challenges, malware triage, interoperability and security research. Requests
whose goal is to bypass licensing, DRM, or anti-cheat in software you don't own
are declined.

## License

[MIT](LICENSE) © 2026 Bowen Li
