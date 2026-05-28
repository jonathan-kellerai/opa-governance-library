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
