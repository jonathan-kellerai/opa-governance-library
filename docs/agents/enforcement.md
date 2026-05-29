# Enforcement

How the conventions in [`../../AGENTS.md`](../../AGENTS.md) and
[`conventions.md`](conventions.md) are kept true over time. This is a process
document — terse and actionable.

## Automated gates

### Continuous integration — `.github/workflows/ci.yml`

Every push and pull request runs, on `ubuntu-latest`, with every action pinned
to a commit SHA:

- **`opa test`** — all three pillars. The baseline is **38 passing tests**;
  that count is the project's published contract. A pull request that lowers
  it is a publish-blocking failure.
- **`opa check`** — every pillar compiles.
- **JSON well-formedness** — `jq` parses every JSON file.
- **Markdown lint** — `markdownlint-cli2` against the lenient
  `.markdownlint-cli2.yaml`.
- **Sanitization gate** — `scripts/check-sanitization.sh` (see below).
- **Link check** — `lychee` over every Markdown file.

All six are hard gates: a red check blocks merge.

### Commit messages — `.github/workflows/commitlint.yml`

`commitlint` checks every pull-request commit against `commitlint.config.mjs`
(Conventional Commits, subject 50 characters or fewer). A non-conforming
message fails CI.

### Pre-commit hook — `lefthook.yml`

Running `lefthook install` once wires a pre-commit hook that runs `opa test`
and the sanitization script locally, so a commit that would fail CI is caught
before it is pushed.

## The sanitization gate

`scripts/check-sanitization.sh` decodes a base64-encoded denylist of internal
pre-publication terms and scans every tracked file. The denylist is encoded so
the terms are not themselves republished in cleartext. The script is a **hard
gate** in CI and in the pre-commit hook: any match fails the build.

## The framing regression canary

`circuit-breaker-policy` is a four-quadrant validator, and the operator /
reviewer / admin separation of duties is a file-ownership operating model —
see "Two corrected framings" in `AGENTS.md`. The `regression-canary` job in
`ci.yml` greps the primary docs for reintroduced circuit-breaker state-machine
framing. It is an **alert, not a block**: it raises a CI warning so a reviewer
notices, but never fails the build. Role-gating wording is deliberately not
canaried — operator / reviewer / admin is legitimate, documented vocabulary.

## Human review

- The pull-request template requires the contributor to paste `opa test`
  output and classify the change under semantic versioning.
- `.github/CODEOWNERS` routes changes to `.github/`, licensing, the agent
  contract, and every `.rego` file to the repository owner for review.

## Keeping the docs canonical

- `AGENTS.md` is the canonical statement of the conventions. When a convention
  changes, it changes there first, then propagates to `conventions.md`,
  `CONTRIBUTING.md`, and `README.md`.
- Any pull request that adds a pattern or a pillar must add or update the
  [`glossary.md`](glossary.md) terms it introduces. A new term with no glossary
  entry is grounds for a request for changes in review.

## Blast-radius pulse

The blast-radius pulse is an advisory cross-file change-impact gate decided in
`docs/adr/ADR-002-blast-radius-pulse.md`. It answers: *when file A changes,
which other files must also move?* The gate is surfaced in three places — the
lefthook pre-commit hook (live), `scripts/pulse.sh` (predictive), and
`.github/workflows/blast-radius-pulse.yml` (audited, writes one JSONL line per
run to `audit/blast-radius.jsonl`).

### How it works

The manifest `conformance/affects.json` declares 13 cross-file relationships
(BR-001 through BR-013). Each entry carries:

- `when_changed` — a path glob (or `path#json.pointer` sub-target) that
  triggers the entry when a matching file appears in the git diff.
- `affects` — a list of globs that should also be checked or updated.
- `required_actions` — ordered imperative steps the author must discharge.
- `severity` — `error` or `warning`.
- `verifiable` — boolean; see below.

The pure Rego function in `conformance/blast_radius.rego` (package
`conformance.blast_radius`) consumes the changed file set as `input` and the
manifest as `data.blast_radius.affects` (`blast_radius.rego:23`). It returns
exactly one `result` structure with `verdict`, `fired`, `errors`, and
`warnings` fields (`blast_radius.rego:231-245`).

**Discharging actions.** Each triggered `required_action` is assigned a
composite id (for example `BR-001-1`). The author marks an action done by
adding a `Pulse-Action: BR-001-1 DONE` line to the PR or commit message footer.
The engine reads `input.commit_footer_actions_done` and sets `action.done =
true` for every matching id (`blast_radius.rego:121-125`).

**Verdicts.** The policy emits one of three verdicts (`blast_radius.rego:206-215`):

| Verdict | Condition |
| ------- | --------- |
| `clear` | No entry fired with any owed action. |
| `owed` | At least one owed action exists, but none qualify as a hard block. |
| `blocked` | At least one `error`-severity, `verifiable: true` entry has owed actions. |

Only entries with both `severity: error` AND `verifiable: true` can produce a
`blocked` verdict and fail CI. Entries with `severity: error` but `verifiable:
false` downgrade to advisory warnings (`blast_radius.rego:174-194`). This
keeps the gate honest: a block means a machine-checkable invariant is owed.

### Manifest entries (BR-001 – BR-013)

Every entry is tested by a positive and a cleared case in
`conformance/blast_radius_test.rego`. Changes to the manifest itself (BR-011)
require adding both test cases there and updating this document.

| Entry ID | Trigger (`when_changed`) | Severity | What it guards |
| -------- | ------------------------ | -------- | -------------- |
| BR-001-conformance-rego | `conformance/conformance.rego` | error (verifiable) | Policy-integrity digest refreeze + enforcement doc update |
| BR-002-artifact-types-triplicate | `conformance/data.json#schema.artifact_types` | error (advisory) | Triplicated artifact-type set across data.json, bootstrap.sh, and conformance.yml (G-05) |
| BR-003-required-files | `conformance/data.json#schema.required_files` | error (advisory) | Required-file additions need a template copy and a MAJOR CHANGELOG entry |
| BR-004-agents-md | `AGENTS.md` | warning (verifiable) | AGENTS.md line-count cap enforced by conformance/data.json:content_assertions |
| BR-005-claude-md | `CLAUDE.md` | error (verifiable) | CLAUDE.md line-count cap and required first-content-line (`@AGENTS.md`) |
| BR-006-new-rego-policy | `conformance/*.rego` | error (advisory) | Every new Rego policy must have a sibling `*_test.rego` |
| BR-007-trust-dial-manifest | `conformance/trust_dial.rego` | error (advisory) | Trust-dial policy, data, tests, and templatized mirrors must move as a unit |
| BR-008-templatized-required-file | `template/_files/**` | warning (advisory) | Templatized required files must still satisfy content_assertions after token substitution |
| BR-009-conformance-workflow | `.github/workflows/conformance.yml` | warning (advisory) | Conformance workflow contract changes require enforcement-doc update |
| BR-010-scripts-coverage | `scripts/**` | warning (verifiable) | Script changes may shift the operational contract documented here |
| BR-011-affects-manifest | `conformance/affects.json` | error (verifiable) | Manifest edits require paired test cases in blast_radius_test.rego and this doc update |
| BR-012-docs-agents-coverage | `docs/agents/**` | warning (advisory) | Tier-2 agent prose must stay consistent with conventions.md |
| BR-013-template-coverage | `template/**` | warning (advisory) | Template files are stamped by bootstrap.sh; required-file paths need a dry-run self-check |

Severity column: **error (verifiable)** = can block CI; **error (advisory)** =
owed actions downgrade to a warning despite `error` severity because
`verifiable: false`; **warning** = always advisory.

The completeness of this manifest is itself enforced by the
`affects_manifest_complete` deny family in `conformance/conformance.rego`:
every tracked file under `conformance/`, `template/`, `scripts/`, and
`docs/agents/` must be reachable from at least one manifest entry or the
policy emits a deny.

Source files: `conformance/affects.json`, `conformance/blast_radius.rego`.
