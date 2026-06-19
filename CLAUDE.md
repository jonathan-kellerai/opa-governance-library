@AGENTS.md

# CLAUDE.md — Claude Code instructions for opa-governance-library

@AGENTS.md

## Claude-specific notes

The content above is imported from `AGENTS.md` and applies in full. The notes
below are specific to Claude Code.

### Verification

This is a runnable policy library. The canonical verification command is:

```text
opa test circuit-breaker-policy/ audit-trail-policy/ plugin-governance/ fed-inventory/
```

The three original pillars must report `PASS: 38/38` (or higher).
The fed-inventory suite runs independently and all its tests must pass.
Run before and after any `.rego` edit.
After editing a `data.json` or `schema.json` file, also run the
`opa eval` deny-set check described in `AGENTS.md`.

### Pre-edit checklist

1. Read the target file before editing it.
2. When editing a `.rego` file, also read its paired `_test.rego` file and any
   `data.json` / `schema.json` keys it references.
3. Make the change, then re-run `opa test`.
4. If you touched any `*.md` file, run `bash scripts/check-sanitization.sh`.

### Skills

- `writing-clearly-and-concisely` — prose edits to `README.md` or `docs/`.
- `human-writing` — tone passes on human-facing prose.
- `5pass` — any structural rewrite of the README or the whitepaper.

### No issue tracker

This repository has no `bd` / `.beads/` tracker and no project-management
tooling. Traceability comes from Conventional Commits plus `AGENTS.md` and this
file. Do not run beads-style workflows here.

### Citations

Internal references use `file:line` (for example `circuit_breaker.rego:110`).
External and academic references use a full bibliographic citation. See
[`docs/agents/citation.md`](docs/agents/citation.md).

### Staging artifacts

`.claude/`, `.claude-tmp/`, `CRITIQUE-pass*.md`, `README-v2.md`,
`KICKOFF-PROMPT.md`, and `STAGING-NOTES.md` are gitignored and are not part of
the published repository. Never reference them from a publishable file.
