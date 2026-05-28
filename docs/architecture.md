# Architecture: opa-governance-library

- **Title:** Architecture of the opa-governance-library Governance Policy Library
- **Audience:** Technical architects and policy practitioners adopting Open Policy Agent (OPA) for declarative governance
- **Scope:** The three policy pillars in `jonathan-kellerai/opa-governance-library` — `circuit-breaker-policy`, `audit-trail-policy`, and `plugin-governance` — their entrypoints, inputs, configuration, evaluation flow, and shared design patterns
- **Last updated:** 2026-05-20

---

## 1. Overview

This repository is a reference library of production-grade Open Policy Agent (OPA) Rego policies. It exists to demonstrate how reusable governance logic can be expressed declaratively, kept readable, and operated safely by teams who are not the original policy authors. Each pillar is a self-contained policy package with its own entrypoint rules, example input, and configuration document.

The library is organised around three pillars, each addressing a distinct class of validation problem:

```text
┌───────────────────────┐   ┌───────────────────────┐   ┌───────────────────────┐
│  circuit-breaker-      │   │  audit-trail-policy    │   │  plugin-governance     │
│  policy                │   │                        │   │                        │
│                        │   │                        │   │                        │
│  Four-quadrant report  │   │  Financial-style       │   │  Meta-validation:      │
│  validation +          │   │  ledger integrity and  │   │  policies that        │
│  readiness scoring     │   │  reconciliation        │   │  validate other       │
│                        │   │                        │   │  policy/plugin defs    │
└───────────┬───────────┘   └───────────┬───────────┘   └───────────┬───────────┘
            │                           │                           │
            ▼                           ▼                           ▼
   package circuit_breaker      package audit_trail         package plugins.standard
```

Architects evaluating the library should read it as three independent case studies that happen to share a common authoring discipline. Practitioners integrating a single pillar can adopt that pillar without pulling in the others — there are no cross-package imports. Section 2 describes each pillar in turn; Section 3 documents the cross-cutting patterns that recur across all three; Section 4 describes the end-to-end evaluation flow.

Every pillar follows the same physical layout: a `.rego` policy module, an `input.example.json` request document, and a configuration document (`data.json` for the first two pillars, `schema.json` for `plugin-governance`).

## 2. The Three Pillars

### 2.1 circuit-breaker-policy

**Purpose.** This pillar validates the structural integrity of a quadrant-organised operational status report and computes a continuous numeric readiness score and a `ready` boolean gate. It answers two questions for an architect: *is this status report internally consistent?* and *is the system it describes ready to proceed?*

**Public entrypoint rules.** The policy is declared in `package circuit_breaker` (`circuit-breaker-policy/circuit_breaker.rego:8`). Its public surface consists of:

- `deny` — a set of structured violation objects, each carrying `msg`, `severity`, `field`, and `rule` keys (first defined at `circuit-breaker-policy/circuit_breaker.rego:17`).
- `readiness` — a floating-point score in the range `[0.0, 1.0]`, computed as `1.0 - (errors / item_count)` (`circuit-breaker-policy/circuit_breaker.rego:110-111`).
- `ready` — a boolean that is true when `readiness` meets the configured threshold (`circuit-breaker-policy/circuit_breaker.rego:112`).
- `valid` — true when the `deny` set is empty (`circuit-breaker-policy/circuit_breaker.rego:115`).
- `report` — a single aggregate object bundling `valid`, `deny`, `readiness`, `ready`, and `item_count` (`circuit-breaker-policy/circuit_breaker.rego:116`).

**Inputs.** The request document is `circuit-breaker-policy/input.example.json`. It must carry the four metadata fields declared in configuration (`unit`, `reporting_period`, `classification`, `author`) and four quadrant arrays (`working_well`, `needed`, `at_risk`, `next`). Each quadrant item carries the shared base fields plus quadrant-specific fields — for example, `at_risk` items additionally require `impact`, `likelihood`, and `mitigation`.

**Configuration.** Tunable values live in `circuit-breaker-policy/data.json`. The `schema` block defines the quadrant names, required metadata fields, base fields, per-quadrant required fields, and enumerations (`circuit-breaker-policy/data.json:2-18`). The `thresholds` block holds the four numeric knobs an operator retunes: `staleness_days` (14), `readiness_threshold` (0.7), `max_owner_items` (5), and `risk_critical_threshold` (4) (`circuit-breaker-policy/data.json:19-24`).

**Validation surface.** The policy enforces required metadata, per-item base and quadrant-specific fields, enum membership for `classification`/`priority`/`urgency`/`likelihood`, globally unique item IDs, dependency resolution for `next` items, a working-well/at-risk conflict check, critical-likelihood risk flagging, item staleness, and owner overload. Severities span `critical`, `error`, and `warning`; only `error`-severity entries reduce the readiness score (`circuit-breaker-policy/circuit_breaker.rego:109`).

**Evaluation.** Validate the request and read the aggregate report:

```bash
opa eval --format pretty \
  --data circuit-breaker-policy/circuit_breaker.rego \
  --data circuit-breaker-policy/data.json \
  --input circuit-breaker-policy/input.example.json \
  'data.circuit_breaker.report'
```

### 2.2 audit-trail-policy

**Purpose.** This pillar validates a financial-style audit ledger for structural correctness and arithmetic consistency. It checks that a period report reconciles, that line items reference known categories and fund types, and that period-over-period variance is explained. It is the library's example of integrity validation over a numeric, reconcilable document.

**Public entrypoint rules.** The policy is declared in `package audit_trail` and is marked `entrypoint: true` in its metadata header (`audit-trail-policy/audit_trail.rego:8-9`). Its public surface consists of:

- `deny` — a single structured violation set with `msg`, `severity`, and `field` keys (first defined at `audit-trail-policy/audit_trail.rego:23`).
- `valid` — defaults to `false` and becomes true only when `deny` is empty (`audit-trail-policy/audit_trail.rego:108-110`).
- `errors` and `warnings` — severity-partitioned subsets of `deny` for triage (`audit-trail-policy/audit_trail.rego:112-113`).

**Inputs.** The request document is `audit-trail-policy/input.example.json`. It must carry the seven required top-level fields (`report_date`, `entity_name`, `currency`, `incoming_resources`, `resources_expended`, `net_movement`, `fund_balances`), plus optional `reconciliation`, `prior_period`, `variance_explanations`, and `historical_net_movements` structures. Each line item under `incoming_resources` or `resources_expended` carries `description`, `amount`, `fund_type`, and `category`.

**Configuration.** Tunable values live in `audit-trail-policy/data.json`. The `schema` block defines required fields, the `date_pattern` and `currency_pattern` regular expressions, the valid `fund_types`, the income and expense category lists, line-item required fields, and accepted accounting bases (`audit-trail-policy/data.json:2-11`). The `thresholds` block holds the operator-tunable numerics: `materiality_floor` (100), `variance_limit` (0.20), `min_unrestricted_balance` (0), `reconciliation_tolerance` (0.01), and `going_concern_periods` (2) (`audit-trail-policy/data.json:12-18`).

**Validation surface.** The policy checks required-field presence, `report_date` and `currency` format, `accounting_basis` membership, per-line missing fields, category and fund-type membership, computed `net_movement` against declared `net_movement` within tolerance, the `reconciliation` identity `opening + net == closing`, fund-type coverage in `fund_balances`, a minimum unrestricted closing balance, unexplained period-over-period variance, a going-concern check over consecutive negative periods, and a sub-materiality `info` flag. The arithmetic checks all compare against `reconciliation_tolerance` so floating-point noise does not produce false denials (`audit-trail-policy/audit_trail.rego:64-73`).

**Evaluation.** Validate the ledger and inspect partitioned results:

```bash
opa eval --format pretty \
  --data audit-trail-policy/audit_trail.rego \
  --data audit-trail-policy/data.json \
  --input audit-trail-policy/input.example.json \
  'data.audit_trail'
```

### 2.3 plugin-governance

**Purpose.** This pillar is the library's meta-validation case study: it is a policy whose subject is *other policy and plugin definitions*. It validates the structural correctness of a tool-plugin manifest — the plugin descriptor, its agent definitions, its skill definitions, and its governance flags. The architectural point it demonstrates is that the same Rego discipline used to validate operational and financial documents also validates governance artefacts themselves.

**Public entrypoint rules.** The policy is declared in `package plugins.standard` and is marked `entrypoint: true` (`plugin-governance/plugin.rego:15-16`). Its public surface consists of:

- `deny` — a single structured violation set; each entry carries `msg`, `severity`, `field`, and a stable machine-readable `rule` identifier (first defined at `plugin-governance/plugin.rego:86`).
- `rule_titles` — a lookup object mapping each `rule` identifier to a human-readable title, so a downstream report can render violations without hard-coding strings (`plugin-governance/plugin.rego:411-433`).

**Inputs.** The request document is `plugin-governance/input.example.json`. It supplies a `plugin` manifest object, an `agents` array, a `skills` array, and a `governance` object. Each is read defensively through `object.get` with an empty-collection default, so a missing top-level section produces structured denials rather than an evaluation error (`plugin-governance/plugin.rego:63-69`).

**Configuration.** Unlike the other two pillars, configuration lives in `plugin-governance/schema.json`. It still exposes the same two-block shape under `data` — a `schema` block (allowed models, required field lists for plugin/agent/skill, allowed cost tiers and effort levels, name and semver patterns) and a `thresholds` block (`min_description_length` 40, `min_agent_turns` 5, `max_agent_turns` 50, `min_keyword_count` 3, `min_skill_tool_count` 1, `max_deny_entries` 100) (`plugin-governance/schema.json:3-21`).

**Validation surface.** The policy is organised into numbered rule groups. Rules R1–R4 are meta-validation guards over the configuration document itself — they fire when `data.schema` or `data.thresholds` is missing, when a required threshold key is absent, or when a required schema list is empty (`plugin-governance/plugin.rego:75-134`). Rules R5–R9 validate the plugin manifest (presence, required fields, kebab-case name, semver version, description length, keyword count). Rules R10–R15 validate agent definitions (required fields, model allowlist, `maxTurns` bounds, description length, metadata completeness, cost-tier validity). Rules R16–R18 validate skills. Rules R19–R21 validate the governance block.

**Evaluation.** Validate a plugin manifest:

```bash
opa eval --format pretty \
  --data plugin-governance/plugin.rego \
  --data plugin-governance/schema.json \
  --input plugin-governance/input.example.json \
  'data.plugins.standard.deny'
```

## 3. Cross-Cutting Design Patterns

The three pillars are deliberately heterogeneous in subject matter but homogeneous in technique. The following patterns recur across all of them and are the reusable lessons of the library.

### 3.1 Rules-as-Rego, Thresholds-as-JSON

Every pillar separates *policy logic* from *policy parameters*. The decision rules — what to check, in what order, with what severity — live exclusively in the `.rego` module. The tunable numeric limits and enumerations live exclusively in the JSON configuration document, addressed through `data.thresholds` and `data.schema`.

The circuit-breaker readiness gate is the clearest illustration. The rule expresses only the relationship:

```rego
ready if readiness >= data.thresholds.readiness_threshold
```

The number `0.7` appears nowhere in the policy — it lives in `circuit-breaker-policy/data.json:21`. An operator who wants a stricter gate edits one JSON value and never touches, re-reviews, or re-tests the policy logic. The same separation governs `staleness_days`, `max_owner_items`, `risk_critical_threshold`, the audit pillar's `variance_limit` and `reconciliation_tolerance`, and every plugin-governance threshold. This is the single most important adoption property of the library: retuning is a configuration change, not a code change.

### 3.2 Continuous Readiness Scoring

The `circuit-breaker-policy` pillar grades an operational report on a continuous scale rather than as a binary pass/fail. The `readiness` rule produces a score in `[0.0, 1.0]` by dividing error-severity denials by total item count (`circuit-breaker-policy/circuit_breaker.rego:109-111`): a report with no error-severity denials scores `1.0`, and the score degrades as errors accumulate. The companion `ready` rule is a boolean gate that is true when `readiness` clears the configured `readiness_threshold`.

Despite the pillar's name, the policy is structurally a four-quadrant validator, not a circuit-breaker state machine. It stores no state field and models no circuit-breaker state transitions. It emits a `deny` set, a `readiness` score, and a `ready` boolean gate, and leaves the decision of how to act on them to the caller.

Staleness detection adds to the same `deny` set. The staleness rule parses each item's `last_updated` date and denies any item older than `staleness_days` (`circuit-breaker-policy/circuit_breaker.rego:87-93`), so a report that stops being maintained gradually accumulates findings even if its content never changes.

### 3.3 Separation-of-Duties Role Gating

The library uses a deliberately generic three-role schema — `operator`, `reviewer`, and `admin` — to model separation of duties. The intent is that the *role authorised to submit or operate* a document is distinct from the *role authorised to review and accept* it, and distinct again from the *role authorised to change policy configuration*.

In practice this maps onto the pillars as follows: an **operator** authors the input documents (a status report, an audit ledger, a plugin manifest) and runs evaluation; a **reviewer** inspects the resulting `deny` set and `report` object and accepts or rejects; an **admin** owns the JSON configuration documents and is the only role permitted to retune thresholds or amend enumerations. Because Section 3.1 keeps thresholds out of the `.rego` code, this gate is enforceable purely through file ownership of the JSON configuration documents — the admin role controls `data.json` / `schema.json`, the operator role controls `input.example.json`, and neither needs write access to the other.

### 3.4 Meta-Validation — Policies That Validate Policies

`plugin-governance` is the library's demonstration that governance artefacts are themselves valid subjects of governance. Its input is not operational data; it is the descriptor of a tool plugin, including the manifests of the agents and skills that plugin defines. The policy validates that those definitions are structurally well-formed before they are trusted.

The meta-validation extends to the policy's own configuration. Rules R1, R3, and R4 validate the *configuration document itself* — `_schema_present` and `_thresholds_present` confirm `data.schema` and `data.thresholds` are non-empty objects (`plugin-governance/plugin.rego:76-92`), R3 confirms every required threshold key is present (`plugin-governance/plugin.rego:95-113`), and R4 confirms every required schema list is non-empty (`plugin-governance/plugin.rego:116-134`). A policy that cannot trust its own configuration says so explicitly rather than silently producing wrong answers.

### 3.5 Fail-Secure Sentinel Guards

All three pillars deny by default when required data is absent rather than passing by omission. Two complementary techniques implement this.

First, **explicit secure defaults.** The audit pillar declares `default valid := false` (`audit-trail-policy/audit_trail.rego:108`); validity is an earned state that only the absence of denials can produce. The circuit-breaker pillar likewise pins `readiness := 0.0` when there are no items to score (`circuit-breaker-policy/circuit_breaker.rego:111`), so an empty report scores as not-ready rather than vacuously ready.

Second, the **sentinel guard.** `plugin-governance` defines a unique sentinel object and a `_field_present` helper that distinguishes a genuinely absent field from a field that is present but falsy — `0`, `false`, `""`, `[]`, or `{}` (`plugin-governance/plugin.rego:42-53`). This matters because OPA treats those values as falsy, and a naive presence check would wrongly clear a field whose legitimate value happens to be `0` or `false`. The sentinel is also used to enforce that `skill.user_invocable` is *explicitly declared* — rule R18 fires when the key is absent entirely, forcing the author to make an intentional `true`/`false` choice rather than defaulting silently (`plugin-governance/plugin.rego:361-370`).

Together these guards ensure that missing or malformed input produces a structured denial, never an accidental pass.

## 4. Evaluation Flow

All three pillars share one evaluation contract. An evaluation consumes two documents and produces one result:

```text
┌──────────────────┐     ┌──────────────────┐
│ input.example.   │     │ data.json /      │
│ json             │     │ schema.json      │
│ (the request)    │     │ (the config)     │
└────────┬─────────┘     └────────┬─────────┘
         │                        │
         │   --input              │   --data
         ▼                        ▼
   ┌──────────────────────────────────────┐
   │   opa eval  /  opa test               │
   │   .rego module loaded via --data      │
   └──────────────────┬───────────────────┘
                       │
                       ▼
   ┌──────────────────────────────────────┐
   │  deny set  +  report / valid object   │
   └──────────────────────────────────────┘
```

The request document is supplied on `--input`; the policy module and its JSON configuration are both supplied on `--data`. OPA merges every `--data` document into the global `data` namespace, which is why a policy reads its configuration as `data.schema` and `data.thresholds` regardless of which file those blocks came from.

Two evaluation modes are supported. **Ad-hoc evaluation** uses `opa eval` with an explicit query — for example `data.circuit_breaker.report` or `data.plugins.standard.deny` — to compute a result against a single input. **Test evaluation** uses `opa test` to run the package's `_test.rego` suite, asserting that known-good inputs produce an empty `deny` set and known-bad inputs produce the expected denials:

```bash
opa test circuit-breaker-policy/ audit-trail-policy/ plugin-governance/ -v
```

The result of any evaluation is a structured object, never a bare boolean. The `deny` set is a list of violation records, each self-describing through its `severity`, `field`, and (where present) `rule` keys. Downstream tooling consumes this directly: it can partition by `severity` for triage, group by `field` to annotate a source document, or join `rule` against `plugin-governance`'s `rule_titles` map to render human-readable findings. The `report` and `valid` rules layer an at-a-glance summary on top of the same `deny` set without discarding the detail beneath it.

## 5. Adoption Notes

A team adopting one pillar copies its three-file directory, replaces `input.example.json` with its own request document, and retunes the JSON configuration to its own limits. No build step, package manager, or runtime beyond the `opa` binary is required. Because the pillars share no imports, adopting one imposes no dependency on the others, and the patterns of Section 3 — externalised thresholds, graded readiness, role-separated file ownership, meta-validation, and fail-secure defaults — transfer to any new policy written in the same style.
