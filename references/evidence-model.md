# Evidence model

## Evidence record
| Field | Meaning |
|---|---|
| `evidence_id` | `ev-` + sha256 of canonical {subject.sha256, provider{id,version}, operation, parameters, normalized_result}. Same observation ⇒ same ID |
| `subject` | path, sha256 (file digest or deterministic tree digest), format, arch, size |
| `provider` | engine id + version (otool, objdump, nm, builtin, builtin-js, ghidra, jadx, analyst, shell…) |
| `operation`, `parameters` | what was asked, normalised (function, arch, grep, budgets…) |
| `normalized_result` | the structured answer, bounded (lists truncated, with a flag) |
| `raw_result` | `{path, sha256, bytes}` of the full engine output under `W/raw/` |
| `authority` | `shipped-artifact` (static on the real artifact), `controlled-replay` (runtime you ran), `historical-reference` (older build / prior bundle), `external-service` (online lookup), `analyst-inference` (your reasoning) |
| `confidence` | high / medium / low |
| `limitations` | what this record can't tell you (truncation, indirect calls, stripped, encrypted, static-only) |
| `locations` | `address:0x…`, `file:line` |
| `evidence_links` | the records this one depends on (required for inferences) |

Recording is idempotent. If the same content is recorded twice you get the same ID with
`status: existing`. If the same identity comes with different authority, limitations or
links, the record is rejected as a conflict. Records are never edited. Record a new one
that links the old.

## Residual Unknown
`unknown_id` (stable from question + subject), `question`, `severity`, `domain`,
`status` (open → investigating → resolved | wont-resolve), `revision` (optimistic
concurrency: updates must pass `--expected-revision`), `supporting_evidence_ids`,
`contradicting_evidence_ids`, `resolution`, `history`. Resolving requires resolution
text and at least one supporting evidence ID.

## Bundle
`W/evidence.json` is always canonical: records sorted by ID, unknowns by ID, plus
derived `subjects` and `providers` manifests, sorted-key JSON. `export` copies it
byte-for-byte. `import` validates every ID and reference first and merges all or nothing.
`validate` recomputes everything and checks canonical form.

## Claims file for `evidence.py verify`
```json
{"claims": [
  {"id": "c1", "statement": "validate_key requires length 12", "kind": "observation",
   "evidence_ids": ["ev-…"],
   "expect": [{"evidence_id": "ev-…", "path": "normalized_result.compared_constants", "contains": "#0xc"}]},
  {"id": "c2", "statement": "the hidden prefix is REA?", "kind": "inference", "evidence_ids": ["ev-<inference>"]},
  {"id": "c3", "statement": "v2 uploads the user name at runtime", "kind": "observation", "runtime": true,
   "evidence_ids": ["ev-<diff>"]},
  {"id": "c4", "statement": "contextBridge is ineffective in this build", "kind": "inference",
   "evidence_ids": ["ev-<js>"], "depends_on_unknowns": ["unk-<electron-version>"]}
]}
```
Rules: missing cited evidence → fail. No evidence → unknown. An `observation` supported
only by `analyst-inference` → fail. `runtime: true` without `controlled-replay` evidence →
fail. `requires_authority` not met → fail. Any `expect` (`equals` | `contains` | `min`)
false → fail. Every cited record's limitations are echoed back. Fix c3 above by restating
it as a static inference ("v2's sync_data contains a call to upload_metrics") or by
adding runtime evidence.

Open Unknowns affect a claim only when they actually bear on it:
- an open Unknown lists a cited record in `contradicting_evidence_ids` → **unknown**
  (the evidence is disputed);
- the claim names the Unknown in `depends_on_unknowns` and it is still open, or was
  closed as `wont-resolve` → **unknown**. A name that isn't in the ledger → fail;
- an open Unknown that only cites the same record as *supporting* context (a follow-up
  question that evidence raised) → status unchanged, plus a note suggesting
  `depends_on_unknowns` if the claim really relies on it.

So "the app has 6 IPC channels" stays **pass** even while "is the WebSocket ever
opened?" is open against the same js evidence. Declare a dependency only when the
claim's truth changes with the Unknown's answer (c4: whether contextBridge works
depends on the Electron version).

## Worked example (crackme)
1. `xrefs:to --string ok` → `ev-A`: `_main` references "ok".
2. `disasm:function --symbol validate_key` → `ev-B`: compares `#0xc`, `#0x2d ('-')`, calls `_decode`, `_strncmp`.
3. `disasm:function --symbol decode` → `ev-C`: loop of 8, XOR with `#0x4a`.
4. Read the `kEnc` bytes with `xxd` → record as `shell:xxd` evidence `ev-D`.
5. `record --infer "decode() yields 'REA?YSD!'; strncmp compares the first 4 chars, so the key must start with 'REA?'" --link ev-C --link ev-D` → `ev-E`.
6. Claims cite ev-B (observations) and ev-E (inference). Verify, then report.
