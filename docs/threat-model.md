# Threat Model — OPA Rego Governance Patterns

- **Title:** Threat Model for `jonathan-kellerai/opa-governance-library`
- **Audience:** Policy authors, platform engineers, and security reviewers evaluating the library for adoption
- **Scope:** The three policy pillars in this repository — plugin governance, circuit-breaker review, and audit-trail validation — and the security properties their Rego rules are designed to provide
- **Last updated:** 2026-05-20

---

## 1. Overview

This document describes the threats that the policy patterns in this repository are
designed to address, the controls each pillar implements, and the residual risk that
adopters must manage themselves. The repository contains three independent Open Policy
Agent (OPA) Rego policy bundles:

- **`plugin-governance`** — validates that plugin and agent/skill manifests are
  structurally complete and conform to a declared schema before they are trusted
  (`plugin-governance/plugin.rego`).
- **`circuit-breaker-policy`** — validates the structure, cross-references, and risk
  scoring of a periodic operational review (`circuit-breaker-policy/circuit_breaker.rego`).
- **`audit-trail-policy`** — validates the internal consistency and reconciliation of a
  financial audit trail (`audit-trail-policy/audit_trail.rego`).

The patterns share a common design philosophy: **deny by default, validate
structurally, and surface every violation as a structured, severity-tagged record.**
The sections below treat that philosophy as a set of named security controls.

## 2. Trust Model and Assumptions

The policies operate on a single trust boundary: an untrusted `input` document is
evaluated against a trusted `data` document (schema and thresholds). The policy engine
itself, and the `data` bundle it loads, are assumed to be trustworthy and to originate
from a controlled source. The `input` document is assumed to be attacker-influenced or,
at minimum, error-prone.

Each pillar produces a `deny` set. An empty `deny` set is the only signal of approval;
`audit-trail-policy` makes this explicit with `default valid := false`
(`audit-trail-policy/audit_trail.rego:108`) so that a non-evaluating or partially
evaluating policy can never report a passing result.

## 3. Control: Meta-Validation as a Security Control

A policy bundle is only as trustworthy as the schema and thresholds it is evaluated
against. If the `data` document that defines "what correct looks like" is itself missing,
empty, or under-specified, a naive policy would evaluate every rule that depends on that
data as vacuously true — and an attacker-supplied manifest would pass review without ever
being checked. This is the threat of **malformed or under-specified policy definitions
silently passing.**

`plugin-governance` addresses this with a dedicated meta-validation section
(`plugin-governance/plugin.rego:71-134`) that validates the *validator's own
configuration* before any manifest rule runs:

- **`data_sentinel`** (`plugin.rego:86-92`) emits an `error`-severity denial when
  `data.schema` or `data.thresholds` is missing or empty. Without this rule, an empty
  schema would cause every downstream `some f in schema.required_plugin_fields` iteration
  to produce zero results — a silent, total bypass of field validation.
- **`threshold_bounds`** (`plugin.rego:104-113`) denies when any of the six required
  threshold keys (`min_description_length`, `max_agent_turns`, `min_agent_turns`,
  `min_keyword_count`, `max_deny_entries`, `min_skill_tool_count`) is absent. A missing
  threshold key would otherwise cause the rule that consumes it to fail to evaluate,
  again producing a silent gap.
- **`schema_list_nonempty`** (`plugin.rego:125-134`) denies when any required schema
  list — including `allowed_models`, `required_plugin_fields`, and `allowed_cost_tiers` —
  is empty. An empty allowlist is functionally a wildcard: `not m in _allowed_models`
  would be true for every model if `allowed_models` were `[]`.

Meta-validation converts a class of silent failures into loud, `error`-severity
denials. It is the structural equivalent of verifying that the lock exists before
trusting the door.

## 4. Control: Fail-Secure Sentinel Guards

The policies are designed so that the *absence* of required input is itself a denial,
rather than a condition that skips a check. This is the fail-secure principle: when a
rule cannot obtain the data it needs to make a decision, it denies.

The `_field_present` helper (`plugin-governance/plugin.rego:44-53`) is the foundation of
this control. It uses an explicit `_sentinel` object (`plugin.rego:42`) as the default
return of `object.get`, then rejects every OPA falsy edge case — `null`, `""`, `0`,
`false`, `[]`, `{}`. This distinguishes "the field is genuinely absent" from "the field
is present but holds a falsy value," so a manifest cannot satisfy a presence check by
supplying an empty string or an empty object.

Concrete sentinel/guard rules built on this principle include:

- **`plugin_present`** (`plugin.rego:146-148`) — denies with `error` severity when
  `input.plugin` is missing or empty. The plugin manifest is mandatory; its absence is a
  failure, not a skipped section.
- **`plugin_required_fields`** (`plugin.rego:150-160`) — for each field in
  `schema.required_plugin_fields`, denies when `_field_present` is false. Note the guard
  conjunction `_plugin_present` and `_schema_present`: the rule only runs when both the
  input and the schema are available, and the meta-validation rules above ensure their
  absence is independently caught.
- **`agent_metadata_complete`** (`plugin.rego:300-310`) — denies when any required
  metadata key (`oracle.task_type`, `koth.domain`, `cost_tier`, `effort_level`) is absent
  from an agent's `metadata` object, again via `_field_present`.
- **`skill_invocable_explicit`** (`plugin.rego:361-370`) — denies when a skill omits the
  `user_invocable` field entirely. Because `user_invocable: false` is a legitimate value,
  this rule deliberately uses the `_sentinel` comparison rather than a truthiness check:
  it requires the author to make an explicit declaration rather than allowing a dangerous
  default to be assumed.
- **`governance_sica_required`** (`plugin.rego:377-384`) and
  **`governance_output_validation`** (`plugin.rego:387-394`) — both use
  `not object.get(governance, "<flag>", false) == true`, so a missing governance object,
  a missing flag, or an explicit `false` all produce a denial. The secure state is the
  default.

The same pattern appears in the other pillars. `circuit-breaker-policy` denies on any
missing required metadata field (`circuit_breaker.rego:17-20`) and any missing base or
quadrant-specific field (`circuit_breaker.rego:23-36`). `audit-trail-policy` denies on
any missing required top-level field (`audit_trail.rego:23-26`) and any missing
line-item field (`audit_trail.rego:43-48`). In every case, missing input produces a
denial rather than a pass.

## 5. Control: Tool-Allowlist Enforcement

An agent or skill that can invoke an unconstrained set of tools is a standing risk: an
over-broad tool grant means a compromised, misconfigured, or simply over-eager agent can
reach capabilities it was never intended to use. The threat is **privilege creep through
unscoped tool grants.**

`plugin-governance` constrains tool grants in two ways:

- **Mandatory declaration.** `allowed_tools` is a required field for both agents and
  skills (`plugin-governance/schema.json:6-7`). The `agent_required_fields`
  (`plugin.rego:228-238`) and `skill_required_fields` (`plugin.rego:335-345`) rules deny
  any manifest that omits it. An agent therefore cannot exist in a valid manifest without
  an explicit, enumerated tool list — there is no implicit "all tools" grant.
- **Scope floor.** `skill_tool_count` (`plugin.rego:348-358`) flags a skill whose
  `allowed_tools` list falls below `thresholds.min_skill_tool_count`, prompting review of
  skills that appear to have a degenerate or accidental scope.

Because `allowed_tools` is an enumerated list rather than a pattern or wildcard, the
allowlist is auditable: a reviewer can read exactly which tools each agent may invoke.
Adopters who need to additionally *constrain the contents* of that list (for example, to
forbid a specific high-risk tool) can extend the schema with an `allowed_tools` membership
check modeled on the existing `agent_model_allowed` rule (`plugin.rego:241-253`), which
already demonstrates allowlist-membership enforcement for the `model` field.

## 6. Control: Separation of Duties

Single-actor compromise — one credential, one role, or one mistaken individual able to
both author and approve a change — is a recurring root cause in governance failures.
Separation of duties mitigates this by requiring distinct roles for distinct stages of a
change.

The patterns in this repository are designed to be operated under a three-role model:

- **operator** — authors and submits the `input` document (a plugin manifest, a
  circuit-breaker review, or an audit trail).
- **reviewer** — evaluates the policy result and confirms that the `deny` set is empty or
  that every remaining warning is justified.
- **admin** — owns the trusted `data` bundle (schema and thresholds) and approves changes
  to the policy rules themselves.

This split is enforceable using the policies as written. Because the schema and
thresholds live in a separate `data` document from the `input`, the **admin** who defines
"what correct looks like" is structurally distinct from the **operator** who must conform
to it. The `audit-trail-policy` reinforces the principle for the audit domain: its
`owner` field and the `owner_overload` check in the sibling circuit-breaker policy
(`circuit-breaker-policy/circuit_breaker.rego:103-106`) discourage concentration of
ownership in a single actor. No single role can simultaneously relax the schema, submit a
non-conforming manifest, and sign off on the result.

## 7. Threat Summary Table

| Threat | Mitigating pillar / rule | Residual risk |
|--------|--------------------------|---------------|
| Empty or missing schema/thresholds causes all checks to pass vacuously | `plugin-governance` — `data_sentinel` (`plugin.rego:86-92`), `schema_list_nonempty` (`plugin.rego:125-134`) | A *wrong but well-formed* `data` bundle still passes meta-validation; correctness of schema content is the admin's responsibility |
| Manifest omits a required field and is silently trusted | `plugin-governance` — `plugin_required_fields` (`plugin.rego:150-160`), `agent_required_fields` (`plugin.rego:228-238`), `skill_required_fields` (`plugin.rego:335-345`) | Required-field *list* must itself be complete; a field not named in the schema is not checked |
| Falsy value (`""`, `{}`, `0`) used to fake field presence | `plugin-governance` — `_field_present` helper (`plugin.rego:44-53`) | Semantic validity of a non-falsy value is not verified — only its presence |
| Dangerous default assumed when `user_invocable` is omitted | `plugin-governance` — `skill_invocable_explicit` (`plugin.rego:361-370`) | Author may still declare `user_invocable: true` inappropriately; this is a review decision |
| Governance controls (SICA, output validation) silently disabled | `plugin-governance` — `governance_sica_required` (`plugin.rego:377-384`), `governance_output_validation` (`plugin.rego:387-394`) | Flags can be set `true` without the corresponding control actually running outside the policy's view |
| Over-broad / unscoped tool grant | `plugin-governance` — mandatory `allowed_tools` field, `skill_tool_count` (`plugin.rego:348-358`) | Library checks that a list exists and is non-degenerate, not that its *contents* are individually justified |
| Disallowed model used by an agent | `plugin-governance` — `agent_model_allowed` (`plugin.rego:241-253`) | Allowlist must be kept current as models change |
| Unbounded agent turn budget (runaway cost / loop) | `plugin-governance` — `agent_turns_bounds` (`plugin.rego:255-281`) | Bounds are advisory `warning` severity; enforcement of the budget at runtime is out of scope |
| Duplicate or colliding identifiers in a review | `circuit-breaker-policy` — `unique_id` (`circuit_breaker.rego:55-62`) | Detects collisions within one `input`, not across separate submissions |
| Unresolved or dangling dependency reference | `circuit-breaker-policy` — `dependency` (`circuit_breaker.rego:65-69`) | Resolves IDs structurally; does not verify the referenced item is itself correct |
| Stale review data treated as current | `circuit-breaker-policy` — `staleness` (`circuit_breaker.rego:87-93`) | Relies on a self-reported `last_updated` field that the operator controls |
| Single owner overloaded — concentration risk | `circuit-breaker-policy` — `owner_overload` (`circuit_breaker.rego:103-106`) | `warning` severity only; does not enforce reassignment |
| Financial figures that do not reconcile | `audit-trail-policy` — `net_movement` and `reconciliation` checks (`audit_trail.rego:64-73`) | Detects arithmetic inconsistency, not fraud in individually consistent figures |
| Large unexplained period-over-period variance | `audit-trail-policy` — variance check (`audit_trail.rego:86-91`) | An attacker-supplied `variance_explanations` entry suppresses the warning; explanation quality is a review judgement |
| Non-evaluating policy reports a false pass | `audit-trail-policy` — `default valid := false` (`audit_trail.rego:108`) | Mitigates the audit pillar; adopters should add an equivalent default to any custom entrypoint |
| Single-actor authoring and approving a change | Schema/`input` separation plus the operator / reviewer / admin role split (Section 6) | The library provides the *structure* for separation of duties; the actual role assignment and credential isolation are the adopter's responsibility |

## 8. Non-Goals and Out of Scope

This repository is a **pattern library**, not a turnkey security product. The following
are explicitly out of scope:

- **Runtime enforcement.** The policies validate the *structure and consistency* of a
  document at evaluation time. They do not intercept, gate, or block any live operation,
  and they do not guarantee that a manifest's declared controls are actually active in a
  running system.
- **Secret management.** Nothing in this repository stores, rotates, encrypts, or detects
  credentials, keys, or tokens. The `input` documents are assumed to be free of secrets.
- **Network policy.** The patterns make no statement about network segmentation, ingress
  or egress control, transport security, or service-to-service authentication.
- **Identity, authentication, and authorization of actors.** The operator / reviewer /
  admin model in Section 6 describes how the patterns are *intended to be operated*; the
  repository does not implement the authentication or access control that would bind a
  real principal to one of those roles.
- **Threat detection and monitoring.** The policies emit structured `deny` records; they
  do not aggregate, alert on, or persist them.

## 9. Adopter Responsibility

The patterns in this repository are **illustrative governance patterns.** They encode a
deny-by-default, fail-secure, structurally-validating design that is reusable across
domains, but they are calibrated to example schemas and example thresholds. Adopters must
not treat them as a finished security boundary.

Before relying on any pattern here, an adopter must validate it against their own threat
environment: confirm that the schema lists and thresholds reflect their real
requirements, extend the rule sets to cover threats specific to their domain, integrate
the policy evaluation into a workflow that genuinely separates the operator, reviewer,
and admin roles, and pair these document-time checks with the runtime, secret, and
network controls that this repository explicitly does not provide.
