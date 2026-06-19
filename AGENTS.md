# AGENTS.md

This file is the entry point for AI agents and automated tooling working in
this repository. **Humans should read [README.md](README.md) instead.** Claude
Code users: start with [CLAUDE.md](CLAUDE.md), which imports this file.

## Purpose

`opa-governance-library` is a four-pillar [Open Policy Agent](https://www.openpolicyagent.org/)
Rego **governance pattern library**. Each pillar is a self-contained policy
package shipped with tests, an example input, and a configuration document.
The policies are **advisory only**: they emit structured `deny` decisions, and
the *caller* is responsible for enforcing them (an admission webhook, a CI
gate, a deployment script).

## What this repo IS and IS NOT

- IS: a pattern library of Rego policies, tests, JSON data, and documentation,
  meant to be read, adapted, and copied into adopter systems.
- IS NOT: a runtime enforcer, a turnkey product, or a managed service. It does
  not block operations, manage secrets, or authenticate actors.

Facts an agent can rely on: four pillars; 38 passing tests for the original three pillars;
OPA `>= 0.59.0`; Apache-2.0 licensed.

## File layout and reading order

| Path | What it is | Read it when |
| ---- | ---------- | ------------ |
| `circuit-breaker-policy/` | Pillar 1 — four-quadrant operational-report validator (package `circuit_breaker`). | Working on readiness scoring or quadrant checks. |
| `audit-trail-policy/` | Pillar 2 — financial-ledger structural and arithmetic validator (package `audit_trail`). | Working on reconciliation or ledger checks. |
| `plugin-governance/` | Pillar 3 — meta-validation of plugin, agent, and skill definitions (package `plugins.standard`, rules R1–R21). | Working on manifest or governance rules. |
| `fed-inventory/` | Pillar 4 — advisory conformance policy for the OMB 2025 Federal AI Use-Case Inventory disclosure schema (`fed-inventory@2025`, retrieved 2026-06-18); package `fed.inventory`; field-presence + enum-validity only. Sources: <https://github.com/ombegov/2025-Federal-Agency-AI-Use-Case-Inventory> (authoritative schema) and <https://www.federalreserve.gov/AI-use-case-inventory-2025.htm>. | Working on federal AI disclosure or inventory ingestion. |
| `docs/architecture.md` | Cross-cutting design patterns and the rationale behind them. | You need the "why" behind a pattern. |
| `docs/threat-model.md` | Threats each pillar mitigates and residual risk. | You touch a security-relevant rule. |
| `docs/whitepaper-opa-governance-patterns.md` | The full technical whitepaper. | You need deep background or future-direction context. |
| `docs/agents/` | Tier-2 agent references (see below). | You need conventions, vocabulary, or citation rules. |

Each pillar directory holds: `<name>.rego` (the rules), `<name>_test.rego`
(the tests), `data.json` or `schema.json` (thresholds and enumerations),
`input.example.json` (a sample input document), and a `README.md`.

## The runnable contract — agents MUST verify changes

This is a runnable policy library, not a documentation set. Before proposing a
commit:

- Any `.rego` change → run `opa test circuit-breaker-policy/ audit-trail-policy/ plugin-governance/ fed-inventory/`
  and confirm the suite still reports **38 or more** passing tests (the three original pillars)
  plus all fed-inventory tests passing.
- Any `data.json` or `schema.json` change → additionally run
  `opa eval --data <pillar>/ --input <pillar>/input.example.json 'data.<package>.deny'`
  and confirm the deny set still behaves sensibly.
- Any change to `README.md`, `docs/**`, or a pillar `README.md` → run
  `bash scripts/check-sanitization.sh` and confirm it exits `0`.

CI (`.github/workflows/ci.yml`) re-runs every gate; a pull request that fails
any of them will not merge.

## Conventions

- The default branch is `main`. **Never** use `master`.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/):
  `<type>(<scope>): <subject>`, subject ≤ 50 characters, imperative mood, no
  trailing period. `commitlint` enforces this in CI.
- Agent branches are named `<agent>/<scope>` (for example
  `claude/fix-readiness-docs`). Human branches use `feat/*`, `fix/*`, `docs/*`,
  or `chore/*`. Always branch from `main`.
- Editing a publishable file (`*/*.rego`, `*/*.json`, `*.md`, `docs/**`)
  requires a pull request. Editing a gitignored staging file may be direct.
- **Never delete a file without explicit human permission.**

Full detail — types, scopes, branch edge cases, PR format, citation format —
is in [`docs/agents/conventions.md`](docs/agents/conventions.md).

## Two corrected framings — do not regress them

The whitepaper corrected two earlier mis-descriptions. Do not write them back
into any file:

1. `circuit-breaker-policy` is a **four-quadrant validator**, not a
   circuit-breaker state machine. The policy stores no
   state field; it emits a `deny` set and a continuous `readiness` score
   (whitepaper §3.2).
2. The operator / reviewer / admin separation of duties is a **caller-applied,
   file-ownership operating model** — it is *not* enforced by policy code.

## Open architectural question

Real, policy-layer separation-of-duties role gating is an open future
direction (whitepaper §12.1), as is a conformance test suite for
adopter-supplied configuration (§12.2). When discussing the architecture,
surface these as *future work* — never describe them as implemented. See the
"Future directions" section of
[`docs/agents/glossary.md`](docs/agents/glossary.md).

## Tier-2 references

- [`docs/agents/conventions.md`](docs/agents/conventions.md) — full commit,
  branch, PR, and citation conventions, plus the CI gate contract.
- [`docs/agents/glossary.md`](docs/agents/glossary.md) — load-bearing
  vocabulary (four-quadrant validator, deny set, severity tiers, readiness
  score, meta-validation, fail-secure sentinel guards, advisory-only, more).
- [`docs/agents/citation.md`](docs/agents/citation.md) — how to cite this
  library and its whitepaper.
- [`docs/agents/enforcement.md`](docs/agents/enforcement.md) — how these
  conventions are enforced (CI, hooks, review checklist).
