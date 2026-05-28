# Contributing

Thank you for your interest in `jonathan-kellerai/opa-governance-library`. This is a
small, focused policy library, and contributions of all sizes are welcome.

## Ways to contribute

- **File an issue** — report a bug, ask for clarification, propose a new
  pattern, or ask an integration question. Pick the issue template that fits:
  bug, clarification, amendment proposal, or integration question.
- **Open a pull request** — fix a bug, improve documentation, or add a rule or
  a pillar.

## Filing a good issue

A well-formed issue is far easier to act on. Please include:

1. **Reproduction steps** — the exact policy, input, and command sequence
   needed to observe the behavior.
2. **`opa` version** — the output of `opa version`, so we can confirm whether
   the behavior is version-specific.
3. **Expected vs actual** — what you expected the policy to evaluate to, and
   what it actually returned.

The smaller and more self-contained the reproduction, the faster we can
respond.

## Opening a pull request

The full conventions live in [`AGENTS.md`](AGENTS.md) and
[`docs/agents/conventions.md`](docs/agents/conventions.md). In short:

1. **Branch from `main`.** Name the branch `feat/*`, `fix/*`, `docs/*`, or
   `chore/*`. Automated agents use `<agent>/<scope>`. The default branch is
   `main`; `master` is not used.
2. **Make the change.** Keep policy logic in `.rego` and tunable thresholds in
   `data.json` / `schema.json` — see the rules-as-Rego pattern in
   [`docs/architecture.md`](docs/architecture.md).
3. **Verify locally.** Run `opa test circuit-breaker-policy/ audit-trail-policy/ plugin-governance/`;
   the suite must still report 38 or more passing tests. If you changed any
   Markdown, also run `bash scripts/check-sanitization.sh`.
4. **Write a Conventional Commit.** `<type>(<scope>): <subject>`, with the
   subject 50 characters or fewer in imperative mood. `commitlint` enforces
   this.
5. **Open the pull request** and fill in every section of the pull-request
   template, including the `opa test` output and a semver classification.

Installing the git hooks with `lefthook install` runs the test and
sanitization gates automatically before each commit.

## Continuous integration

Every pull request runs `opa test`, `opa check`, JSON well-formedness checks,
Markdown lint, the sanitization gate, and a link check. A pull request must
keep all of them green to be merged.

## Code of conduct

Please be respectful and constructive in all issues and pull requests. Reports
and suggestions are read carefully, even when they cannot be acted on
immediately.
