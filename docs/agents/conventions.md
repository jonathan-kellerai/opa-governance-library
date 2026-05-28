# Conventions

A Tier-2 reference for agents and contributors. The summary lives in
[`../../AGENTS.md`](../../AGENTS.md); this file is the detail.

## Commit messages

Commits follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>(<scope>): <subject>
```

- **type** (required): one of `feat`, `fix`, `docs`, `chore`, `refactor`,
  `test`, `ci`, `build`, `perf`, `revert`.
- **scope** (optional but encouraged): one of `circuit-breaker`,
  `audit-trail`, `plugin-gov`, `docs`, `ci`. Kebab-case.
- **subject** (required): imperative mood ("add", not "added" or "adds"),
  50 characters or fewer, with no trailing period.
- **body** (optional): separated from the subject by a blank line, wrapped at
  72 columns, explaining *why* rather than *what*.

`commitlint` enforces the type and subject rules in CI; a non-conforming
message fails the build.

### Examples

```text
feat(plugin-gov): add rule for skill version pinning
fix(circuit-breaker): guard readiness divisor against empty reports
docs(audit-trail): clarify the reconciliation tolerance
ci: pin lychee-action to a commit SHA
```

## Branch naming

- Agent work: `<agent>/<scope>` — for example `claude/fix-readiness-docs` or
  `codex/tighten-sentinel-guard`.
- Human work: `feat/*`, `fix/*`, `docs/*`, `chore/*`.
- The default branch is `main`; `master` is forbidden.

## Edge cases that trip up agents

- **Committing to `main` or a detached HEAD** — never commit directly to
  `main`; branch first. On a detached HEAD, create a branch before editing.
- **Always branch from `main`** — a new branch's base is `main`, not another
  feature branch, unless you are explicitly continuing that branch.
- **Multi-scope change** — if a change genuinely spans two pillars, omit the
  scope (`fix: ...`) rather than inventing a compound scope; better still,
  split it into two commits.
- **Scope spelling** — scopes are kebab-case and drawn from the fixed set
  above. Do not invent new scopes casually.
- **Revert and hotfix** — use the `revert` type for a revert; a hotfix is an
  ordinary `fix` on a `fix/*` branch cut from `main`.
- **Continuing another agent's branch** — keep the existing branch name; do
  not rename it to your own `<agent>/` prefix.
- **Worktrees** — one branch per worktree; never check the same branch out in
  two worktrees at once.
- **Commit type for non-code edits** — `CHANGELOG.md` edits are `docs`;
  workflow and tooling-config edits are `ci`; edits to `AGENTS.md`,
  `CLAUDE.md`, or `docs/agents/*` are `docs`.
- **Fork vs same-repo PR** — external contributors open a pull request from a
  branch on their fork, never from the fork's `main`.

## Pull requests

Fill in every section of the pull-request template: summary, artifacts
touched, validation output (paste the `opa test` result), semver
classification, and the contributor checkbox. A pull request must come from a
non-`main` branch.

## Citation format

- **Internal references** use `file:line` — for example `circuit_breaker.rego:110`
  or `plugin-governance/schema.json:12`.
- **External and academic references** use a full bibliographic citation:
  author, title, venue or publisher, year, and URL.

## CI gate contract

Every pull request must keep all of these green:

- `opa test` across all three pillars — the baseline is **38** passing tests;
  never merge a drop.
- `opa check` — every pillar compiles.
- `jq` — every JSON file is well-formed.
- `markdownlint-cli2` — every Markdown file passes the lenient ruleset.
- `scripts/check-sanitization.sh` — zero forbidden-term matches.
- `lychee` — no broken links.

See [`enforcement.md`](enforcement.md) for how these gates are wired.
