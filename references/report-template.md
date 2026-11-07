# Report template (W/report.md)

Use this structure. Keep findings short. The evidence table carries the detail.

```markdown
# <Target name> — <question in a few words>

**Target:** `<path>` · sha256 `<first 16>` · <format>/<arch> · analysed <date> with <providers>
**Answer:** <2–4 sentences in plain language that answer the user's question>

## Findings
1. **<finding>** — <one or two sentences>. *Observed* · [ev-…]
2. **<finding>** — <…>. *Inferred from* [ev-…, ev-…]
3. …

## Evidence
| ID | Operation | Provider | Authority | What it shows |
|---|---|---|---|---|
| ev-… | disasm:function `_validate_key` | otool | shipped-artifact | compares len 12, '-' at [4], calls strncmp |

## Unknowns
| ID | Question | Severity | Status | What would close it |
|---|---|---|---|---|
| unk-… | <question> | high | open | <engine / runtime step / data needed> |

## Limitations
- <carried from evidence records: static-only, truncation, stripped symbols, missing engines>

## Question checklist
| Question | Status | Evidence |
|---|---|---|
| <q1> | answered | ev-… |
| <q2> | partial | ev-…; unk-… |

Bundle: `W/evidence-bundle.json` (validate: `uv run <skill>/scripts/evidence.py validate <path>`)
```

Labels: *Observed* means a tool saw it in the artifact (or at runtime, if you say so).
*Inferred* means your reasoning over cited evidence. Never present an inference as an
observation, and never present static code paths as observed runtime behaviour.
