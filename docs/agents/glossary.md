# Glossary

Load-bearing vocabulary for `opa-governance-library`. Definitions are drawn from the
technical whitepaper and the policy source. Agents should use these terms
precisely and not invent alternatives.

## Pillars

**circuit-breaker-policy** — Pillar 1, Rego package `circuit_breaker`.
Validates a four-quadrant operational status report and emits a `deny` set
plus a continuous `readiness` score. Despite the name, it is a *validator*,
not a runtime circuit breaker (see *four-quadrant validator*).

**audit-trail-policy** — Pillar 2, Rego package `audit_trail`. Validates
financial-style ledger records for structural completeness and arithmetic
reconciliation within a configurable tolerance.

**plugin-governance** — Pillar 3, Rego package `plugins.standard`. Applies
*meta-validation* to plugin manifests and agent/skill definitions through the
named rules `R1`–`R21`.

## Core concepts

**Four-quadrant validator** — the structural model of circuit-breaker-policy.
The input report is organized into four quadrants — `working_well`, `needed`,
`at_risk`, and `next` — whose names are read from `data.schema.quadrants` and
are not hardcoded. The policy validates the items within each quadrant. It is
*not* a circuit-breaker state machine and stores no state field.

**Deny set** — the partial set of structured findings a pillar emits. Each
finding is an object carrying `msg`, `severity`, `field`, and (where
applicable) `rule`. An empty deny set is the only signal of approval.

**Severity tiers** — the `severity` value on a deny finding: `error`,
`warning`, `critical`, or `info`. Only `error` reduces the readiness score;
`critical`, `warning`, and `info` appear in the deny set but do not change it.
(circuit-breaker-policy uses `error`/`warning`/`critical`; audit-trail-policy
and plugin-governance use `error`/`warning`/`info`.)

**Readiness score** — circuit-breaker-policy only. A continuous value in
`[0.0, 1.0]` computed as `1.0 − (error-severity findings ÷ total item count)`,
or `0.0` when the report has no items.

**Meta-validation** — a policy whose subject of evaluation is itself another
definition (a plugin manifest, an agent or skill definition).
plugin-governance also meta-validates its *own* configuration document before
validating any manifest, so a missing schema or threshold becomes a loud
denial rather than a silent pass.

**Fail-secure sentinel guards** — rules that deny by default when required
input is absent. plugin-governance defines a unique `_sentinel` object and a
`_field_present` helper that distinguishes a genuinely absent field from one
that is present but falsy (`0`, `false`, `null`, `""`, `[]`, `{}`).
circuit-breaker-policy and audit-trail-policy use `default valid := false` for
the same purpose.

**Rules-as-Rego, thresholds-as-JSON** — the shared authoring discipline.
Decision logic lives only in `.rego` source; tunable numeric limits and
enumerations live only in the JSON configuration document (`data.json` or
`schema.json`). An operator retunes a gate by editing one JSON value and never
touches, re-reviews, or re-tests the policy code.

**Advisory-only** — the library emits structured `deny` decisions but does not
enforce them. A caller — an admission webhook, a CI gate, a deployment script
— is responsible for translating the deny set into an enforcement action.

**R1–R21** — the named rules of plugin-governance, grouped by concern:
meta-validation, plugin-manifest validation, agent compliance, skill
compliance, and governance compliance.

## Separation of duties — an operating model, not code

**operator / reviewer / admin** — a three-role separation-of-duties model the
library is *designed to be operated under*: the operator authors input, the
reviewer inspects the deny set and accepts or rejects it, and the admin owns
the JSON configuration. It is enforced today only through *file ownership* of
the configuration documents — there is no policy-layer role-gating code.
Making role separation explicit at the policy layer is future work
(whitepaper §12.1).

## Future directions

The whitepaper §12 records open questions: policy-layer role gating (§12.1), a
conformance test suite for adopter-supplied configuration (§12.2),
bundle-server integration patterns (§12.3), and semantic validation beyond
structural conformance (§12.4). Agents discussing the architecture should
present these as future work, never as implemented features.
