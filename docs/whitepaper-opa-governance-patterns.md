# OPA Rego Governance Patterns: A Three-Pillar Policy Library for Multi-Agent and AI Toolchains

**A reference library of composable Open Policy Agent patterns for structural governance of operational reports, financial-style ledgers, and AI agent/plugin manifests.**

---

- **Version:** 0.1.0
- **Date:** May 2026
- **Author:** Jonathan A. Bowe
- **Repository:** `jonathan-kellerai/opa-governance-library`
- **Classification:** Technical White Paper

---

## Abstract

Multi-agent systems and AI toolchains have proliferated faster than the governance primitives required to admit, audit, and constrain them.
Plugin manifests, agent definitions, and tool surfaces frequently enter production without structural validation, leaving downstream enforcement layers to discover under-specified or malformed declarations at runtime.
This paper presents a reference library of three composable Open Policy Agent (OPA) Rego policy packages that address this gap through structural, advisory-only validation at definition time.
The first pillar, `circuit-breaker-policy`, validates a four-quadrant operational status report and emits severity-tiered findings together with a continuous readiness score.
The second pillar, `audit-trail-policy`, validates financial-style ledger records, including arithmetic reconciliation within a configurable tolerance.
The third pillar, `plugin-governance`, applies meta-validation to plugin manifests and agent/skill definitions, including sentinel guards on the policy's own configuration document.
A shared authoring discipline separates rules (Rego source) from thresholds (JSON configuration), enabling operator-side tuning without code changes.
The library is evidence-grounded: thirty-eight unit tests across the three pillars pass on a public repository.
The library is advisory only — it emits structured deny decisions but does not enforce them; callers must wire the output into an enforcement layer such as an admission webhook, a CI gate, or an OPA decision-log consumer.

## Contributions

This paper makes the following contributions.

1. A three-pillar OPA Rego pattern library that demonstrates a uniform authoring discipline (rules-as-Rego, thresholds-as-JSON) across three distinct validation domains.
2. A meta-validation pattern applied to AI plugin and agent manifests, including sentinel guards (`_field_present` and `_sentinel`) that close fail-open edge cases native to Rego's truth semantics.
3. A four-quadrant structural validator for operational status reports that produces a continuous readiness score rather than a binary pass/fail, while still surfacing critical findings to reviewers.
4. A reconciliation-aware audit-trail validator that enforces opening/closing balance identity within a configurable tolerance and signals a going-concern condition over a sliding window of historical periods.
5. A demonstration that policy configuration itself is a security surface: empty allowlists and missing threshold keys are treated as `error`-severity denials rather than as benign defaults.
6. A reproducible test corpus (thirty-eight passing tests) and a public repository layout that other adopters can clone, retune, and integrate into bundle-server and CI/CD pipelines.

## 1. Background

### 1.1 Open Policy Agent and Rego

Open Policy Agent is a general-purpose, open-source policy engine that decouples policy decisions from the services that consume them.
A service forwards a structured JSON document to OPA, which evaluates a Rego policy against the document and returns a decision.
Rego is a Datalog-inspired declarative language designed for fast in-process evaluation and human-readable policy authoring.
OPA is widely deployed for Kubernetes admission control, microservice authorization, CI/CD policy gates, and API-gateway decision points.

### 1.2 Policy-as-Code and the Configuration Boundary

A long-running tension in policy-as-code work is the boundary between rules and parameters.
Embedding numeric thresholds, allowlists, and field requirements directly into policy source produces a tightly coupled artifact that requires code review for every operational retune.
Externalizing these knobs to a JSON document enables operators to retune policy behavior without modifying — or even understanding — Rego source, at the cost of requiring the policy to defend itself against missing or empty configuration.
This library adopts the externalized pattern and addresses the resulting attack surface through explicit sentinel guards in the third pillar.

### 1.3 The Gap in Multi-Agent Governance

The Model Context Protocol (MCP), introduced in late 2024, gave language models a standardized way to discover and invoke external tools.
The proliferation of MCP servers and agent plugins has outpaced the maturation of governance primitives for those artifacts.
A plugin manifest may declare an agent without a model identifier, an `allowed_tools` list, or a turn bound; such an agent enters production under-specified, and downstream enforcement cannot characterize what it is permitted to do.
Existing policy-engine literature focuses on validating the data that flows through agentic systems (admission control, request authorization) rather than the structural completeness of the agent definitions themselves.
This library addresses that gap at the definition layer.

## 2. Architecture

### 2.1 The Three Pillars

The library comprises three independent Rego packages.
Each pillar addresses a distinct validation domain; none imports the others; all share an authoring discipline that separates rules from thresholds.

| Pillar | Package | Subject of validation | Configuration file |
| --- | --- | --- | --- |
| `circuit-breaker-policy` | `circuit_breaker` | Four-quadrant operational status report | `data.json` |
| `audit-trail-policy` | `audit_trail` | Financial-style ledger record | `data.json` |
| `plugin-governance` | `plugins.standard` | Plugin manifest and agent/skill definitions | `schema.json` |

The third pillar's subject is itself a governance artifact.
Where the first two pillars validate operational and financial documents, the third validates the structural correctness of plugin and agent definitions before they are loaded into a multi-agent system.
This recursion — using OPA to validate the inputs to other OPA-governed systems — is the library's novel security contribution and is referred to throughout this paper as the meta-validation pattern.

### 2.2 Authoring Discipline: Rules in Rego, Thresholds in JSON

All three pillars share a uniform authoring discipline.
Rule logic, severity assignments, and structural invariants live in `.rego` source.
Tunable parameters — numeric thresholds, allowlists, required-field lists, and enumerations — live in a JSON configuration document loaded into OPA's `data` namespace.

This separation gives platform operators a tuning surface that does not require Rego literacy.
It also gives reviewers a stable artifact (the `.rego` file) that changes only when behavior changes, distinct from the JSON document that changes when limits move.

### 2.3 Why `plugin-governance` Uses `schema.json`

OPA's `--data` flag merges any JSON file into the `data` namespace, keyed by the file's directory path.
The plugin-governance policy reads its configuration at `data.schema` and `data.thresholds` (`plugin.rego:59-61`).
Using the filename `schema.json` rather than `data.json` prevents a naming collision with the convention adopted by the first two pillars and signals to adopters that the file is the governing reference schema, not an operational data store.
The `data_sentinel` rule (`plugin.rego:86-91`) enforces the expectation explicitly: if `data.schema` or `data.thresholds` is missing or empty, evaluation immediately produces an `error`-severity denial.

### 2.4 Component Diagram

The data flow across the library is consistent across all three pillars.

```text
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Input      │───▶│   Rego       │───▶│   Decision   │
│   Document   │    │   Policy     │    │   Object     │
│   (JSON)     │    │   Package    │    │   (deny set, │
│              │    │              │    │    readiness)│
└──────────────┘    └──────▲───────┘    └──────────────┘
                           │
                    ┌──────┴───────┐
                    │   Config     │
                    │   Document   │
                    │   (JSON)     │
                    └──────────────┘
```

The input document and the configuration document are loaded into OPA's namespace; the policy package consumes both and emits a structured decision object.
The decision is advisory: a downstream component (admission webhook, CI gate, deployment script) is responsible for translating the deny set into an enforcement action.

## 3. Pillar 1 — circuit-breaker-policy

### 3.1 Subject and Entrypoints

The `circuit_breaker` package validates a four-quadrant operational status report.
The input document carries top-level metadata (`unit`, `reporting_period`, `classification`, `author`) and four quadrant arrays (`working_well`, `needed`, `at_risk`, `next`).
Each quadrant array contains item records with fields including `id`, `owner`, `last_updated`, and quadrant-specific attributes such as `likelihood` for at-risk items.

The package exposes five public entrypoints (`circuit_breaker.rego:8-12`): `deny` (the set of violation objects), `readiness` (a float between zero and one), `ready` (a boolean derived from `readiness`), `valid` (a boolean over the deny set), and `report` (an aggregate object suitable for downstream rendering).

### 3.2 Four-Quadrant Validation, Not a State Machine

The policy is structurally a four-quadrant validator, not a circuit-breaker state machine.
The names of the four quadrants are read from `data.schema.quadrants` (`data.json:3`); they are not hardcoded and an adopter may rename or extend them by editing the configuration document.
The policy iterates across all items from all four quadrants into a single set (`all_items` at `circuit_breaker.rego:13`) and runs a suite of structural and semantic checks.
The output is a graded readiness score plus a structured deny set.
The policy does not implement open/half-open/closed state transitions; the circuit-breaker name is retained as a governance metaphor for the gating role the policy plays in a release pipeline.

### 3.3 Cross-Quadrant Item Collection

The cross-quadrant iteration pattern uses a single set comprehension to collect every item regardless of its quadrant.

```rego
quadrants := data.schema.quadrants
all_items := {item | some quad in quadrants; some item in input[quad]}
all_ids := {item.id | some item in all_items}
```

This pattern enables cross-quadrant rules — unique-ID enforcement, conflict detection between `working_well` and `at_risk` — without quadrant-specific branching.

### 3.4 Rule Catalog

The deny set is populated by ten distinct rule classes with three severity levels.

| Rule | Lines | Severity | Condition |
| --- | --- | --- | --- |
| `metadata` | 17–20 | `error` | Required top-level field absent |
| `base_field` | 23–28 | `error` | Required base field absent from any item |
| `quadrant_field` | 31–36 | `error` | Quadrant-specific required field absent |
| `enum` | 39–52 | `error` | Enumeration value outside the allowed set |
| `unique_id` | 55–62 | `error` | Duplicate item ID across quadrants |
| `dependency` | 65–69 | `error` | `next` item references an ID not in `all_ids` |
| `conflict` | 72–78 | `warning` | Item ID appears in both `working_well` and `at_risk` |
| `risk_critical` | 81–84 | `critical` | `at_risk` item likelihood at or above the critical threshold |
| `staleness` | 87–93 | `warning` | Item `last_updated` older than `staleness_days` |
| `owner_overload` | 103–106 | `warning` | Owner has more items than `max_owner_items` |

### 3.5 The Readiness Formula

Only `error`-severity entries reduce the readiness score.
The aggregate computation at `circuit_breaker.rego:109-112` is:

$$
\mathrm{readiness} =
\begin{cases}
1 - \dfrac{|\{d \in \mathrm{deny} : d.\mathrm{severity} = \text{error}\}|}{|\mathrm{all\_items}|} & \text{if } |\mathrm{all\_items}| > 0 \\
0 & \text{otherwise}
\end{cases}
$$

The boolean `ready` evaluates true when `readiness >= readiness_threshold`.
The floor of zero on an empty report prevents an empty document from vacuously receiving a positive score.
Critical and warning findings appear in the deny set but do not numerically reduce readiness.
This is intentional: a critical at-risk likelihood is surfaced for human review, not treated as a structural defect that should block release on its own.

### 3.6 Staleness Detection

Staleness is computed by converting `last_updated` (an ISO-8601 date string) to nanoseconds and comparing against `time.now_ns()`.

```rego
ns_updated := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [item.last_updated]))
ns_now := time.now_ns()
ns_now - ns_updated > (((data.thresholds.staleness_days * 24) * 60) * 60) * 1000000000
```

The conversion to nanoseconds matches OPA's native time builtin return type.
The default `staleness_days` of fourteen produces a two-week staleness window; operators retune by editing `data.json`.

## 4. Pillar 2 — audit-trail-policy

### 4.1 Subject and Entrypoints

The `audit_trail` package validates financial-style ledger records.
The input document carries top-level ledger fields (`report_date`, `entity_name`, `currency`, `accounting_basis`, `net_movement`, `fund_balances`) and line-item arrays (`incoming_resources`, `resources_expended`).
Optional sections include `reconciliation`, `prior_period`, `historical_net_movements`, and `variance_explanations`.

The package exposes `deny`, `valid`, `errors`, and `warnings` entrypoints.
It is marked `entrypoint: true` (`audit_trail.rego:9`).

### 4.2 Density-Oriented Authoring Style

The audit-trail policy follows a deliberate density discipline noted in its metadata comment: maximum rules in minimum lines, no helper rules, a single deny set.
Five short data aliases (`_s`, `_t`, `_items`, `_all_items`, `_cats`, `_ftypes`) at lines 14–19 compress repeated path references without introducing named helper rules.
The result is a 113-line file that encodes structural validation, materiality floors, reconciliation arithmetic, variance detection, and a going-concern signal.

### 4.3 Reconciliation Arithmetic

Two independent reconciliation checks fire within a configurable tolerance.

```rego
computed := sum(incoming amounts) - sum(expended amounts)
abs(input.net_movement - computed) > _t.reconciliation_tolerance
```

```rego
abs((r.opening_total + r.net_movement) - r.closing_total) > _t.reconciliation_tolerance
```

The first compares a computed net movement (incoming minus expended) against the declared `net_movement`.
The second enforces the opening-plus-net-equals-closing balance identity.
The default `reconciliation_tolerance` of 0.01 absorbs floating-point rounding artifacts without admitting material errors.

### 4.4 Variance Detection with Explanation Suppression

The variance rule (lines 86–91) compares each current-period balance against its prior-period counterpart and fires only when the proportional change exceeds `variance_limit` and no explanation is supplied.

```rego
abs(input[k] - input.prior_period[k]) / abs(input.prior_period[k]) > _t.variance_limit
not input.variance_explanations[k]
```

A divide-by-zero guard on the prior-period balance prevents the rule from misfiring on a zero baseline.
An entry in `variance_explanations[k]` suppresses the warning.
This pattern — flag the anomaly, suppress on explanation — is a recurring shape across the library.

### 4.5 Going-Concern Signal

A trailing window over `historical_net_movements` flags persistent negative movement.

```rego
h := object.get(input, "historical_net_movements", [])
n := _t.going_concern_periods
count(h) >= n
every p in array.slice(h, count(h) - n, count(h)) { p < 0 }
```

The default of two consecutive negative periods reflects a conservative trigger appropriate for early warning rather than a definitive finding.

### 4.6 Severity Partitioning

The errors and warnings sets are partitioned by severity (lines 112–113).

```rego
errors   := {d | some d in deny; d.severity == "error"}
warnings := {d | some d in deny; d.severity in {"warning", "info"}}
```

The `warnings` set deliberately includes both `warning` and `info` severities.
Because `valid` evaluates against the full deny set, an `info`-level finding also makes `valid` false.
Callers wanting to tolerate non-error findings should gate on `count(data.audit_trail.errors) == 0` rather than on `valid` directly.

## 5. Pillar 3 — plugin-governance

### 5.1 Subject and Entrypoints

The `plugins.standard` package validates plugin manifests and the agent and skill definitions they contain.
The input document carries four top-level sections: `plugin` (the manifest object), `agents` (an array), `skills` (an array), and `governance` (a flags object).
All four are aliased with `object.get` defaults at `plugin.rego:63-69` so that absent sections produce structured denials rather than evaluation errors.

The package exposes `deny` (the structured violation set) and `rule_titles` (a human-readable rule name map).
It is marked `entrypoint: true` (`plugin.rego:16`).

### 5.2 The Twenty-One Rule Catalog

The policy organizes twenty-one named rules (R1–R21) into six concern sections.
The first section, meta-validation, validates the policy's own configuration document before any manifest rule runs.

#### 5.2.1 Meta-Validation (R1, R3, R4)

| Rule | Lines | Severity | Guards |
| --- | --- | --- | --- |
| `data_sentinel` | 86–91 | `error` | `data.schema` or `data.thresholds` missing or empty |
| `threshold_bounds` | 104–113 | `error` | Required threshold keys absent |
| `schema_list_nonempty` | 125–134 | `error` | Required schema lists empty |

The security significance is concrete.
An empty `allowed_models` list would make `not m in _allowed_models` true for every model — a wildcard bypass.
An empty `required_plugin_fields` list would cause the field-presence iteration to produce zero denials even for a wholly empty manifest.
The `schema_list_nonempty` guard turns each bypass condition into an explicit `error`-severity denial.

#### 5.2.2 Plugin Manifest Validation (R5–R9)

| Rule | Lines | Severity | Checks |
| --- | --- | --- | --- |
| `plugin_present` | 146–148 | `error` | `input.plugin` missing or empty |
| `plugin_required_fields` | 150–160 | `error` | Each required field present via `_field_present` |
| `plugin_name_format` | 163–176 | `error` | Name matches kebab-case regex |
| `plugin_version_format` | 179–192 | `error` | Version matches semver regex |
| `plugin_description_length` | 195–206 | `warning` | Description meets minimum length |
| `plugin_keywords_count` | 209–219 | `warning` | Keywords array meets minimum count |

#### 5.2.3 Agent Compliance (R10–R15)

| Rule | Lines | Severity | Checks |
| --- | --- | --- | --- |
| `agent_required_fields` | 228–238 | `error` | Each required field present (key-presence) |
| `agent_model_allowed` | 241–253 | `error` | Agent model in allowlist |
| `agent_turns_bounds` (min) | 255–267 | `warning` | `maxTurns` at or above minimum |
| `agent_turns_bounds` (max) | 269–281 | `warning` | `maxTurns` at or below maximum |
| `agent_description_length` | 283–295 | `warning` | Description meets minimum length |
| `agent_metadata_complete` | 298–310 | `warning` | Required metadata keys present |
| `agent_cost_tier_valid` | 312–328 | `warning` | Cost tier in allowlist |

The `agent_required_fields` rule uses a key-presence check rather than `_field_present` so that legitimate `false` values — for example, `user_invocable: false` — pass the presence requirement.

#### 5.2.4 Skill Compliance (R16–R18)

| Rule | Lines | Severity | Checks |
| --- | --- | --- | --- |
| `skill_required_fields` | 335–345 | `error` | Each required field present (key-presence) |
| `skill_tool_count` | 348–358 | `info` | `allowed_tools` meets minimum count |
| `skill_invocable_explicit` | 361–370 | `warning` | `user_invocable` explicitly declared |

The `skill_invocable_explicit` rule deserves emphasis.
Absence of a `user_invocable` declaration is a governance ambiguity: the adopter's runtime cannot determine whether the skill should appear in a user-facing command palette.
The rule forces an explicit `true` or `false` rather than a silent default.

#### 5.2.5 Governance Compliance (R19–R21)

| Rule | Lines | Severity | Checks |
| --- | --- | --- | --- |
| `governance_sica_required` | 377–384 | `error` | `governance.sica_enabled == true` |
| `governance_output_validation` | 387–394 | `error` | `governance.output_validation == true` |
| `governance_rego_version` | 397–405 | `error` | `governance.rego_version` matches semver |

### 5.3 The Fail-Secure Sentinel Pattern

The `_field_present` helper at `plugin.rego:42-53` is the cornerstone of the fail-secure design.

```rego
_sentinel := {"__sentinel__": true}

_field_present(obj, field) if {
    val := object.get(obj, field, _sentinel)
    val != _sentinel
    not val == null
    not val == ""
    not val == 0
    not val == false
    not val == []
    not val == {}
}
```

The sentinel object `{"__sentinel__": true}` is used as the `object.get` default; it cannot collide with any legitimate field value an adopter might supply.
The helper then explicitly rejects each of Rego's falsy edge cases.
The result is that a manifest cannot satisfy a presence check by supplying an empty string, a zero, or an empty container.
A field is present only when it is supplied with a non-empty, non-zero, non-null value.

### 5.4 The `rule_titles` Map

A lookup object at `plugin.rego:411-433` maps each of the twenty-one rule identifiers to a human-readable title.
This enables downstream reporting layers to render findings without hardcoding string literals against rule identifiers.
The map is exposed as a public entrypoint alongside `deny`.

## 6. Algorithm Details

Three rules deserve focused treatment because they illustrate the library's recurring design patterns.

### 6.1 The Four-Quadrant Deny Comprehension

The cross-quadrant collection at `circuit_breaker.rego:12-14` (reproduced below) is the engine that powers every cross-quadrant check in pillar one.

```rego
quadrants := data.schema.quadrants
all_items := {item | some quad in quadrants; some item in input[quad]}
all_ids := {item.id | some item in all_items}
```

Reading from `data.schema.quadrants` rather than hardcoding the four names is the data-driven discipline applied to schema structure itself: an adopter can rename, reorder, or extend the quadrants without modifying the rule logic.

### 6.2 The Readiness Formula

The aggregate at `circuit_breaker.rego:109-112` computes the readiness score and the boolean ready flag.

```rego
errors := count({d | some d in deny; d.severity == "error"})
readiness := 1.0 - (errors / count(all_items)) if count(all_items) > 0
readiness := 0.0 if count(all_items) == 0
ready := readiness >= data.thresholds.readiness_threshold
```

The formula yields a continuous score on $[0, 1]$ that compresses to one when no errors are present and degrades linearly with each error finding.
This is the only aggregate metric the library exposes; the other two pillars emit only severity-partitioned deny sets.

### 6.3 The Fail-Secure Presence Helper

The `_field_present` helper from §5.3 is reproduced here to emphasize its role as a security primitive: it is the answer Rego authors should reach for when they need a true presence check that defeats every native falsy edge case.

```rego
_sentinel := {"__sentinel__": true}

_field_present(obj, field) if {
    val := object.get(obj, field, _sentinel)
    val != _sentinel
    not val == null
    not val == ""
    not val == 0
    not val == false
    not val == []
    not val == {}
}
```

The helper is six lines of conditions; each line closes a Rego idiom where a naïve presence check would silently pass.

## 7. Use Cases

### 7.1 AI and Multi-Agent Toolchain Governance

The primary use case is governance of AI agent plugins before they are loaded into a multi-agent system.
A plugin developer submits a manifest in the shape of `input.example.json`; the `plugin-governance` policy evaluates it against `schema.json`; the resulting deny set either blocks release on `error`-severity findings or surfaces review notes on `warning` and `info` findings.

The security-relevant innovation is the meta-validation pattern.
By validating the structural completeness of agent definitions — required fields, model allowlist, `allowed_tools` declarations, governance flags — the policy prevents under-specified or malformed plugin and agent definitions from silently entering production.
An agent without an `allowed_tools` declaration cannot be characterized for audit and cannot be scoped for least-privilege enforcement; the `agent_required_fields` rule turns the omission into a hard `error` rather than an ambiguous silence.

The `agent_model_allowed` rule provides a structural control against model substitution: only models in the platform-approved allowlist may be declared.
The `agent_turns_bounds` rule flags agents whose `maxTurns` falls outside a configured range, surfacing runaway-cost and agentic-loop risks before release.
The `skill_invocable_explicit` rule eliminates a class of governance ambiguity by requiring every skill to declare its user-invocability explicitly.

### 7.2 Plugin and Extension Marketplace Validation

The plugin-governance pillar generalizes to any marketplace where contributors submit plugin or extension definitions that must conform to a platform schema before publication.
The data-driven threshold pattern means the platform operator retunes minimum description lengths, keyword counts, and model allowlists in `schema.json` without touching policy code.
The `rule_titles` map supports automated report generation for contributor feedback: a submission that fails `R12` can be returned with the human-readable title rather than the bare identifier.

### 7.3 Audit-Grade Decision Logs for Compliance Review

The audit-trail pillar validates financial-style ledger records.
Arithmetic reconciliation checks (net movement and balance identity within tolerance) and the going-concern signal over historical periods provide a compact policy-encoded audit step suitable for embedding in a financial reporting pipeline.
Because the deny output is structured JSON with `severity`, `field`, and `msg` fields, it is directly consumable by SIEM and compliance tooling without additional transformation.

The same shape generalizes beyond charity finance to any domain with a reconcilable numeric record: resource allocation, budget tracking, or incident cost accounting.

## 8. Contributions to AI and the Open-Source Community

The library makes four contributions that are specifically relevant to the AI and open-source ecosystems.

First, the meta-validation pattern is a security primitive for AI toolchains.
Validating the structural completeness of agent definitions at admission time is structurally analogous to validating Kubernetes resources at admission time; the difference is that the resource being validated is an agent or plugin manifest rather than a Pod or Deployment.
The pattern is reusable: an adopter can replace `schema.json` with a schema appropriate to their plugin format and reuse the rule shape.

Second, the fail-secure default reduces a class of common Rego authoring mistakes.
Naïve presence checks in Rego silently pass on falsy values; the `_field_present` helper closes that gap with a sentinel-based defense.
Adopting this pattern as a community convention would eliminate a category of fail-open errors in policy libraries beyond this one.

Third, the tool-allowlist enforcement at the manifest layer aligns with the MCP threat model.
Security research on MCP and agentic systems identifies tool misuse, privilege escalation through inherited permissions, and compound action chaining as primary threat classes.
Requiring an explicit, enumerated `allowed_tools` declaration per agent or skill at definition time reduces the attack surface available to an under-specified agent at runtime.
Runtime enforcement remains the adopter's responsibility, but the definition-time control closes the most common omission.

Fourth, data-driven thresholds as a deployability primitive lower the integration cost.
A platform operator can adopt the library, edit `data.json` or `schema.json` to reflect their environment, and run the existing test suite as a configuration validator.
No Rego literacy is required for routine retuning; Rego literacy is required only when a new rule class is added.

## 9. Performance and Operational Properties

### 9.1 Stateless Single-Snapshot Evaluation

All three pillars are stateless over the input snapshot.
There is no accumulation across evaluations, no persistent state, no I/O, and no network calls within policy evaluation.
Each `opa eval` invocation reads one input document and one configuration document, evaluates the rules, and returns a result.
The time dimension is limited: staleness detection compares a `last_updated` date string against `time.now_ns()`, which is injected by the OPA runtime rather than by the policy itself.

### 9.2 OPA Version Requirement

The library requires OPA at version 0.59.0 or higher.
All three pillars use `import rego.v1`, introduced in OPA 0.59.0 (October 2023).
The `rego.v1` import enforces forthcoming OPA 1.0 semantics in policies written against earlier OPA releases: the `in` keyword is required for membership tests, the `every` keyword is available, and certain deprecated builtins are removed.
Adopters can verify their installation with `opa version`.

### 9.3 Test Suite

Thirty-eight unit tests cover the three pillars: ten in `circuit_breaker_test.rego`, eight in `audit_trail_test.rego`, and twenty in `plugin_test.rego`.
All thirty-eight pass against the bundled configuration documents.
A single command runs the full suite.

```sh
opa test circuit-breaker-policy/ audit-trail-policy/ plugin-governance/ -v
```

No formal benchmark is bundled.
Policy evaluation is single-document and in-memory; latency is sub-millisecond for typical document sizes.

### 9.4 Bundle Server and Decision Log Integration

The three pillar directories are directly suitable for packaging as OPA bundles (tar archives containing `.rego` sources and the JSON configuration document).
OPA bundle servers support periodic polling with ETag caching; a threshold change in `data.json` propagates to all evaluating OPA instances on the next poll without restart or redeployment.

OPA can emit a structured JSON record for every decision (query, input, result, timestamp, metadata).
Pairing the deny output from these policies with OPA decision logs produces a durable, machine-readable compliance record.

### 9.5 CI/CD Integration

Each pillar's test suite exits non-zero on test failure.
A CI step of `opa test <pillar>/ -v` is a complete policy-correctness gate.
Threshold changes in the JSON configuration are validated by the existing test suite at no additional cost, because tests inject fixture schemas and thresholds via `with data.schema as ...` and `with data.thresholds as ...` overrides.

## 10. Threat Model and Known Limitations

The library is advisory only.
Policies emit decisions; callers are responsible for enforcing them.
This is the library's most important framing constraint and the source of most of its known limitations.

The threat model documents five residual risks.

First, there is no input provenance chain.
A caller that controls the input document can fabricate passing values.
Mitigation requires an upstream identity or attestation layer outside the library's scope.

Second, there is no trusted clock.
Staleness detection relies on the self-reported `last_updated` field; an adversary who controls the field can suppress staleness findings.
Mitigation requires an external timestamping authority.

Third, there is no role gating in policy code.
The threat model describes a three-role intent (operator, reviewer, admin) achieved structurally through file ownership: the admin owns the configuration document, the operator owns the input document, and neither needs write access to the other.
The policy code does not currently make any claims about caller identity.
Real role-gated rules are listed as future work in §11.1.

Fourth, evaluation is single-snapshot.
The policies do not maintain history across evaluations.
Trend detection (the going-concern signal) is achieved through fields supplied in the input document, not through accumulation in OPA.

Fifth, type coercion is not performed.
A `likelihood` field supplied as a string `"4"` rather than an integer `4` will silently fail the risk-critical comparison due to OPA's mixed-type comparison semantics.
The deny output is therefore sensitive to input-document type fidelity.

The library makes no claims about formal certification or aviation-grade assurance; it is a reference pattern library suitable for integration into adopter-controlled enforcement layers.

## 11. Related Work

### 11.1 Open Policy Agent and Rego

OPA is a general-purpose policy engine that decouples policy decisions from the services that consume them.
Rego, a Datalog-inspired declarative language, is the policy language used throughout this library.
The library uses standard OPA features only: input and data namespaces, the `import rego.v1` compatibility import, structured `deny` sets as the conventional decision shape, and JSON configuration loaded via the `--data` flag.

### 11.2 Regal — The Rego Linter

Regal, maintained by Styra, is a linter for Rego policy code.
It catches style, correctness, and idiomatic issues — including rule naming, deprecated patterns, missing metadata annotations, and import ordering.
The library does not currently include a Regal lint step, but its dense, idiomatic style and metadata annotations are consistent with Regal's recommendations.
Adopters integrating the library into CI pipelines should evaluate adding Regal alongside `opa test`.

### 11.3 Kubernetes Validating Admission Policies

Kubernetes v1.26 introduced Validating Admission Policies expressed in the Common Expression Language (CEL) as an alternative to dynamic webhook-based admission control.
Like this library, CEL-based admission policies validate the structure of incoming resource definitions at submission time.
The structural parallel is instructive: both systems validate at submission time rather than at runtime, and both are advisory at the policy layer; the admission controller is the enforcement boundary.
The plugin-governance pillar can be understood as a Rego equivalent of a Validating Admission Policy applied to plugin manifests rather than to Kubernetes resources.

### 11.4 Policy-as-Code in AI Agent Security

The Model Context Protocol defines an open standard for how language models interact with external tools and data sources.
Security research on MCP and agentic systems identifies tool misuse, privilege escalation through inherited permissions, and compound action chaining as primary threat classes.
This library addresses the pre-deployment layer of that threat surface: by enforcing structural completeness of agent definitions before admission, the meta-validation pillar reduces the attack surface available to an under-specified agent at runtime.
Runtime behavioral enforcement remains the adopter's responsibility.

### 11.5 The Meta-Validation Gap

A focused literature search for "policies that validate policies" returned no direct precedents in the OPA and Rego ecosystem.
Kubernetes Validating Admission Policies validate Kubernetes resources rather than the policies themselves.
CEL schema validation validates data shapes rather than governance artifact structures.
The plugin-governance pillar's self-referential validation — R1 through R4 validating the validator's own configuration document — appears to be an original pattern in the OPA ecosystem.
Formal treatment of meta-policy validation, deny-by-default configuration guards, and the conditions under which a policy's configuration can be trusted is identified as an open research direction.

## 12. Open Questions and Future Directions

### 12.1 Real Separation-of-Duties Role Gating

The threat model describes a three-role intent (operator, reviewer, admin) achieved structurally through file ownership.
A future pillar could make role separation explicit at the policy layer: a policy that validates that a change submission carries a recognized reviewer attestation, or that a threshold change carries an admin approval token.
This would require pairing the policy with an identity and authentication layer — an explicit non-goal of the current library.

### 12.2 Conformance Test Suite for Adopters

The bundled tests are authored against the bundled configuration documents.
An adopter who substitutes their own configuration — as they must, to reflect real requirements — runs the existing tests against their configuration, but those tests were calibrated to the bundled defaults.
A future contribution would be a conformance test suite that validates structural properties of any adopter-supplied configuration: the `allowed_models` list is non-empty, the minimum is strictly less than the maximum for paired bounds, and each enumeration list contains at least one value.
The `schema_list_nonempty` and `threshold_bounds` rules in plugin-governance are a seed for this pattern.

### 12.3 Bundle-Server Integration Patterns

The library does not currently include a `.manifest` file or bundle build scripts.
A practical follow-on would document how to package each pillar as an OPA bundle, how to version the bundle alongside its configuration document, and how to integrate bundle polling into a continuous-validation pipeline.

### 12.4 Semantic Validation Beyond Structural Conformance

The library validates structural completeness and format conformance.
It does not validate semantic correctness of declared values: an `allowed_tools` list of the correct length but pointing to tools the agent has no business accessing will pass; a `variance_explanations` entry that reads "see attached" suppresses a variance warning regardless of quality.
Future work could explore semantic validation that cross-references tool names against a known-safe registry, or reviewer-attestation patterns requiring human sign-off on explanations above a materiality threshold.

## 13. Repository Layout

```text
opa-governance-library/
├── circuit-breaker-policy/
│   ├── circuit_breaker.rego
│   ├── circuit_breaker_test.rego
│   ├── data.json
│   ├── input.example.json
│   └── README.md
├── audit-trail-policy/
│   ├── audit_trail.rego
│   ├── audit_trail_test.rego
│   ├── data.json
│   ├── input.example.json
│   └── README.md
├── plugin-governance/
│   ├── plugin.rego
│   ├── plugin_test.rego
│   ├── schema.json
│   ├── input.example.json
│   └── README.md
├── docs/
│   ├── architecture.md
│   └── threat-model.md
├── README.md
└── LICENSE
```

## 14. Reproducing the Results

The full test suite runs in a single command after cloning the repository.

```sh
opa test circuit-breaker-policy/ audit-trail-policy/ plugin-governance/ -v
```

Expected output: thirty-eight tests, all passing.

Each pillar can also be evaluated against its bundled example input.

```sh
opa eval \
  --data circuit-breaker-policy/circuit_breaker.rego \
  --data circuit-breaker-policy/data.json \
  --input circuit-breaker-policy/input.example.json \
  'data.circuit_breaker.report'

opa eval \
  --data audit-trail-policy/audit_trail.rego \
  --data audit-trail-policy/data.json \
  --input audit-trail-policy/input.example.json \
  'data.audit_trail.deny'

opa eval \
  --data plugin-governance/plugin.rego \
  --data plugin-governance/schema.json \
  --input plugin-governance/input.example.json \
  'data.plugins.standard.deny'
```

The expected output is a JSON document containing the structured deny set (and, for circuit-breaker, the aggregate report including the readiness score).

## 15. Conclusion

The three pillars presented here demonstrate that a uniform OPA Rego authoring discipline — rules in Rego source, thresholds in JSON configuration, sentinel guards on the configuration itself — generalizes across operational status reporting, financial-style audit ledgers, and AI plugin manifest governance.
The meta-validation pattern is the library's most novel contribution: applying the same policy-as-code discipline to the validator's own configuration document closes a class of fail-open conditions endemic to externally configured policy engines.
Combined with the fail-secure presence helper and the tool-allowlist enforcement pattern, the library provides a reusable structural-validation layer suitable for integration into the admission and CI/CD pipelines of multi-agent and AI toolchain platforms.

Future work directs attention to explicit role-gated rules, an adopter-facing conformance test suite, bundle-server integration tooling, and semantic validation beyond structural conformance.
The library is offered as a pattern reference; productionizing it for any specific environment requires the adopter to wire its advisory decisions into an enforcement layer of their choosing.

## References

1. Open Policy Agent. *Policy Language Reference.* https://openpolicyagent.org/docs/policy-language
2. Open Policy Agent. *Management — Bundles.* https://openpolicyagent.org/docs/latest/management-bundles/
3. Styra. *OPA 1.0 is coming. Here's what you need to know.* https://blog.openpolicyagent.org
4. Permit.io. *What's new on OPA v1.* https://www.permit.io/blog/whats-new-on-opa-v1
5. StyraInc. *Regal — The Rego Linter.* https://github.com/StyraInc/regal
6. Styra. *Guarding the Guardrails — Introducing Regal the Rego Linter.* https://www.styra.com/blog
7. Eknert, A. *awesome-opa.* https://github.com/anderseknert/awesome-opa
8. Anthropic. *Model Context Protocol Specification (2025-06-18).* https://modelcontextprotocol.io/specification/2025-06-18
9. Zenity. *Securing the Model Context Protocol (MCP).* https://zenity.io/blog/security/securing-the-model-context-protocol-mcp
10. Zenity. *AI Agent Governance — Logging Alone Is Not Governance.* https://zenity.io/blog/security/ai-agent-governance
11. Protect AI. *MCP Security 101.* https://protectai.com/blog/mcp-security-101
12. Nirmata. *What Is a Kubernetes Validating Admission Policy?* https://nirmata.com/2023/09/08/what-is-kubernetes-validating-admission-policy

## Appendix A — Severity Conventions

The library uses four severity levels consistently across pillars.

| Severity | Meaning | Effect on readiness (pillar one) | Effect on `valid` (pillar two) |
| --- | --- | --- | --- |
| `error` | Structural defect or hard policy violation | Reduces score | Sets to false |
| `critical` | Material risk surfaced for review | Does not reduce score | Sets to false |
| `warning` | Soft policy violation | Does not reduce score | Sets to false |
| `info` | Advisory finding | Does not reduce score | Sets to false (pillar two) |

Pillar three (`plugin-governance`) does not expose a `valid` aggregate; callers gate on `count(error-severity deny entries) == 0`.

## Appendix B — Configuration File Reference

Each pillar's configuration document has the same two-section shape: a `schema` block (allowlists, required-field lists, enumerations, regex patterns) and a `thresholds` block (numeric tunables).
Editing either block does not require modifying the corresponding `.rego` source.
Operators retune thresholds by editing the configuration document; reviewers retune structural expectations (required fields, allowed values) the same way.
Threshold defaults and required-field lists are documented in each pillar's `README.md` and in `docs/architecture.md`.
