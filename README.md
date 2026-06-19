# opa-governance-library

**OPA Rego policy patterns for governance audits of AI and multi-agent toolchains.**

> This is a pattern library, not a runtime enforcement system.
> The policies emit decisions; callers are responsible for enforcing them.

---

- **Repository:** `jonathan-kellerai/opa-governance-library`
- **Language:** Rego (OPA policy language), `import rego.v1`
- **License:** Apache-2.0
- **Version:** v0.1.0 — initial public release
- **Status:** Rule names, entrypoint paths, and deny-entry field names may change before v1.0.0.

---

## Overview

This repository collects four reusable OPA Rego policy patterns for governing
automated systems.
Each pattern is self-contained, data-driven, and designed to be evaluated in a
continuous-validation pipeline.

> "Patterns extracted from a working governance bundle used to validate a multi-agent toolchain."

The patterns share a common design philosophy: **policy logic lives in `.rego`
files, and tunable limits live in `data.json` or `schema.json`.**
Rules are written once and verified by tests; thresholds are adjusted without
touching policy code.
Every policy emits a structured `deny` set with severity-tagged violations.
The deny-entry shape (`msg`, `severity`, `field`, `rule`) is consistent across
pillars; the query interface differs per pillar — see Quick Start for the correct
entrypoints.

---

## Requirements

- **OPA >= 0.59.0** — all three pillars use `import rego.v1`, which was introduced
  in OPA v0.59.0 (released 2023-10-02).
  Verify with `opa version`.
  Install from [open-policy-agent/opa](https://github.com/open-policy-agent/opa).

---

## The Four Pillars

### 1. circuit-breaker-policy

A four-quadrant health validator for governance registers.

The policy validates items across four operational quadrants — `working_well`,
`needed`, `at_risk`, and `next` (defined at `data.json:3`) — and emits structured
`deny` findings.
The "circuit-breaker" name is retained as the directory and package name;
the policy does not implement a circuit-breaker state machine.

The policy validates:

- **Quadrant metadata** — required top-level fields (`unit`, `reporting_period`,
  `classification`, `author`) are checked against the schema in `data.json`.
  (`circuit_breaker.rego:17–20`)
- **Base and quadrant-specific fields** — every item must carry `id`, `title`,
  `description`, `owner`, `priority`, `last_updated`; quadrant-specific required
  fields (e.g., `evidence` for `working_well`, `impact`/`likelihood`/`mitigation`
  for `at_risk`) are enforced per-quadrant.
  (`circuit_breaker.rego:23–36`)
- **Enum integrity** — `classification`, `priority`, `urgency`, and `likelihood`
  values are validated against allowed sets in `data.json:12–17`.
  Note: `likelihood` values are integers `[1, 2, 3, 4, 5]`, not strings.
  (`circuit_breaker.rego:39–52`)
- **Unique ID enforcement** — duplicate IDs across any quadrant combination raise
  an error.
  (`circuit_breaker.rego:55–62`)
- **Dependency resolution** — `next` items that reference IDs not present in any
  quadrant raise an error.
  (`circuit_breaker.rego:64–68`)
- **Conflict detection** — an item appearing in both `working_well` and `at_risk`
  raises a warning.
  (`circuit_breaker.rego:72–78`)
- **Risk scoring** — `at_risk` items whose `likelihood` meets or exceeds
  `risk_critical_threshold` raise a `critical`-severity violation.
  (`circuit_breaker.rego:81–84`)
- **Staleness detection** — items whose `last_updated` date exceeds
  `staleness_days` raise warnings.
  (`circuit_breaker.rego:87–93`)
- **Owner-overload alarms** — any owner assigned more than `max_owner_items` items
  raises a warning.
  (`circuit_breaker.rego:103–106`)
- **Readiness scoring** — `readiness` is computed as `1.0 - (errors / item_count)`
  and compared to `readiness_threshold` to yield a boolean `ready` signal.
  (`circuit_breaker.rego:109–112`)
- **Data-driven thresholds** — `staleness_days` (14), `readiness_threshold` (0.70),
  `max_owner_items` (5), and `risk_critical_threshold` (4) are all read from
  `data.json:19–24`.

The `report` rule at `circuit_breaker.rego:116` returns `valid`, `deny`,
`readiness`, `ready`, and `item_count` in a single object.
Note: `valid` is undefined (not `false`) when the `deny` set is non-empty, because
no `default valid := false` is present.
For reliable output, query `deny` and `readiness` directly — see Quick Start.

### 2. audit-trail-policy

A minimal, dense audit-trail validator built on the same data-driven principles.

Every line of the policy earns its place: a single `deny` set, no helper
sprawl, and all limits sourced from `data.json`.
The policy validates:

- **Required fields and formats** — report date (`YYYY-MM-DD` pattern), currency
  (3-letter ISO code), and accounting basis (`accrual` or `cash`).
  (`audit_trail.rego:23–41`)
- **Line-item integrity** — categories and fund types for every incoming and
  expended resource line are checked against the schema lists.
  (`audit_trail.rego:43–62`)
- **Reconciliation** — `net_movement` is recomputed from line items and
  cross-checked; the opening/net/closing balance identity is verified within
  `reconciliation_tolerance` (0.01 by default).
  (`audit_trail.rego:64–73`)
- **Fund balance completeness** — every fund type present in line items must have
  a corresponding entry in `fund_balances`.
  (`audit_trail.rego:75–79`)
- **Variance and going-concern checks** — period-over-period variance beyond
  `variance_limit` (0.20 by default) must carry an explanation; consecutive
  negative net movements raise a going-concern warning.
  (`audit_trail.rego:86–98`)
- **Materiality floor** — line items below `materiality_floor` (100 by default)
  raise `info`-severity violations.
  (`audit_trail.rego:100–105`)
- **Readiness computation** — `valid` is `false` by default (`audit_trail.rego:108`)
  and `true` only when the `deny` set is empty.
  Violations are partitioned: `errors` contains severity `"error"` entries;
  `warnings` contains severity `"warning"` and `"info"` entries.
  (`audit_trail.rego:112–113`)

### 3. plugin-governance

Meta-validation: **policies that validate policies.**

This pillar inspects the structure of plugin manifests, agent definitions, and
skill definitions — and validates the governance configuration itself.
It demonstrates how to apply policy-as-code to the policy layer.

Plugin-governance differs structurally from the other two pillars: its schema
lists and thresholds live in `schema.json` (not `data.json`), which OPA loads
as `data.schema` and `data.thresholds`.
The `data_sentinel` rule at `plugin.rego:86–91` enforces this: evaluation fails
with an explicit error if `data.schema` or `data.thresholds` is missing or empty.

The policy validates:

- **Fail-secure sentinel guards** — a `_sentinel` object at `plugin.rego:42–53`
  distinguishes an absent field from a legitimately falsy value (`0`, `false`,
  `""`, `[]`, `{}`), so presence checks never silently misfire on OPA falsy
  edge cases.
- **Data-document sentinels** — `data.schema` and `data.thresholds` must be
  present and non-empty; every required threshold key and schema list is verified.
  (`plugin.rego:76–134`)
- **Plugin manifest compliance** — required fields, kebab-case name, semver
  version, minimum description length, minimum keyword count.
  (`plugin.rego:140–219`)
- **Agent compliance** — required fields, model against an allowed set, `maxTurns`
  bounds, description length, metadata completeness, cost tier validity.
  (`plugin.rego:224–328`)
- **Skill compliance** — required fields, minimum tool count, explicit
  `user_invocable` declaration.
  (`plugin.rego:333–370`)
- **Governance flags** — output validation and Rego version checks.
  (`plugin.rego:375–405`)
- **Rule titles** — `rule_titles` at `plugin.rego:411–433` provides a
  human-readable name for every rule identifier.

### 4. fed-inventory

An advisory conformance policy for the **OMB 2025 Federal AI Use-Case Inventory** disclosure schema.

This pillar encodes the government-wide OMB schema (`fed-inventory@2025`, retrieved 2026-06-18)
as a field-presence and enum-validity checker.
It does **not** assess substantive compliance or adequacy — callers are responsible for
enforcement decisions.

> The policies are advisory only: they emit structured `deny` decisions, and
> the *caller* is responsible for enforcing them.

Source attribution:

- OMB 2025 Federal Agency AI Use-Case Inventory: <https://github.com/ombegov/2025-Federal-Agency-AI-Use-Case-Inventory>
  (`Validation/data_dictionary.md` and `Validation/data_dictionary.json`)
- Federal Reserve AI Use-Case Inventory (2025): <https://www.federalreserve.gov/AI-use-case-inventory-2025.htm>
  (the Federal Reserve discloses approximately 39 use cases independently; it is **not** part of
  the OMB 56-agency dataset)

The policy validates:

- **Always-required fields (9)** — `agency`, `agency_name`, `id`, `use_case_name`, `agency_bureau`,
  `contact_email`, `is_withheld`, `development_stage`, `is_high_impact` must be present on
  every record. (`fed_inventory.rego:28`)
- **Conditional tier A (5 fields)** — required when `is_withheld` is not `"Yes…"` and
  `development_stage` is `Pre-deployment`, `Pilot`, or `Deployed`. (`fed_inventory.rego:34`)
- **Conditional tier B (7 fields)** — required when `is_withheld` is not `"Yes…"` and
  `development_stage` is `Pilot` or `Deployed`. (`fed_inventory.rego:43`)
- **Conditional `vendor_name`** — required when stage is `Pilot`/`Deployed` and
  `contracting_usage` indicates vendor involvement. (`fed_inventory.rego:52`)
- **Conditional `system_name_ato`** — required when stage is `Pilot`/`Deployed` and
  `have_ato` is `"Yes"`. (`fed_inventory.rego:61`)
- **Conditional `HI_justification`** — required when `is_high_impact` is
  `"Presumed High-Impact, but Not High-impact"`. (`fed_inventory.rego:70`)
- **Conditional tier C — 9 `hi_*` fields** — required when `is_high_impact` is `"High-impact"`
  and `development_stage` is `"Deployed"`. Presence-only check. (`fed_inventory.rego:77`)
- **Enum validity** — nine enumerated fields are validated against their allowed sets;
  out-of-vocabulary values produce `warning`-severity findings. (`fed_inventory.rego:87–129`)
- **Basic format checks** — `contact_email` must contain `@`; `id` must be non-empty.
  (`fed_inventory.rego:135–143`)

Note: `demographic_features` and all `hi_*` fields carry complex or multi-select values.
The policy checks presence only for these fields and does not enumerate sub-values, to avoid
false positives. This is documented at `fed_inventory.rego:133`.

Severity convention: `error` for missing required/conditional fields; `warning` for enum
violations and format failures.

---

## Output Format

Every pillar emits deny entries in this shape:

```json
{"msg": "string", "severity": "error|warning|critical|info", "field": "string", "rule": "string"}
```

Example entries:

```json
{"msg": "at_risk item AR-001 has critical likelihood: 4", "severity": "critical", "field": "at_risk.AR-001.likelihood", "rule": "risk_critical"}
{"msg": "working_well item WW-002 is stale (last updated: 2026-03-12)", "severity": "warning", "field": "working_well.WW-002.last_updated", "rule": "staleness"}
{"msg": "plugin.name \"My Plugin\" must be kebab-case", "severity": "error", "field": "input.plugin.name", "rule": "plugin_name_format"}
```

The severity levels used across pillars are: `error`, `warning`, `critical`, `info`.

Note: the circuit-breaker pillar uses all four severity levels.
The audit-trail pillar uses `error`, `warning`, and `info`.
The plugin-governance pillar uses `error`, `warning`, and `info`.
The fed-inventory pillar uses `error` and `warning` only.

---

## The Data-Driven Threshold Pattern

The circuit-breaker and audit-trail pillars follow a strict separation:

| Concern | Lives in | Changes by |
| ------- | -------- | ---------- |
| Policy logic (rules) | `*.rego` | Code review + tests |
| Tunable limits (thresholds) | `data.json` | Configuration edit |
| Schema enums / field lists | `data.json` (`data.schema`) | Configuration edit |

This means a threshold change — tightening a staleness window, raising a
readiness gate — is a data edit, not a code change.
The policy logic stays stable and test-covered; only the numbers move.

Plugin-governance uses a different data structure: its schema lists and thresholds
live in `schema.json`, which is loaded by OPA as `data.schema` and
`data.thresholds`.
The pattern is the same (policy logic separate from configuration); only the
configuration filename differs.

### Default threshold values

**circuit-breaker-policy** (`data.json:19–24`):

| Key | Default | Meaning |
|-----|---------|---------|
| `staleness_days` | 14 | Days since `last_updated` before a staleness warning fires |
| `readiness_threshold` | 0.70 | Minimum readiness score for `ready` to be `true` |
| `max_owner_items` | 5 | Maximum items per owner before an overload warning fires |
| `risk_critical_threshold` | 4 | Minimum `likelihood` integer for a `critical` risk violation |

**audit-trail-policy** (`data.json`):

| Key | Default | Meaning |
|-----|---------|---------|
| `materiality_floor` | 100 | Line-item amounts below this raise `info` violations |
| `variance_limit` | 0.20 | Period-over-period variance fraction requiring explanation |
| `reconciliation_tolerance` | 0.01 | Tolerance for balance identity checks |
| `going_concern_periods` | 2 | Consecutive negative-net-movement periods for going-concern warning |
| `min_unrestricted_balance` | 0 | Unrestricted closing balance minimum |

**plugin-governance** (`schema.json`):

| Key | Default | Meaning |
|-----|---------|---------|
| `min_description_length` | 40 | Minimum character count for plugin/agent descriptions |
| `min_agent_turns` | 5 | Minimum `maxTurns` for agents |
| `max_agent_turns` | 50 | Maximum `maxTurns` for agents |
| `min_keyword_count` | 3 | Minimum keywords in plugin manifest |
| `min_skill_tool_count` | 1 | Minimum tools declared by a skill |
| `max_deny_entries` | 100 | Not enforced by policy; advisory ceiling for deny-set size |

---

## Repository Layout

```text
opa-governance-library/
├── circuit-breaker-policy/
│   ├── circuit_breaker.rego        # four-quadrant health validator policy
│   ├── circuit_breaker_test.rego   # policy tests (10 tests)
│   ├── data.json                   # schema enums + thresholds
│   └── input.example.json          # sample input document
├── audit-trail-policy/
│   ├── audit_trail.rego            # dense audit-trail validator
│   ├── audit_trail_test.rego       # policy tests (8 tests)
│   ├── data.json                   # schema + thresholds
│   └── input.example.json          # sample input document
├── plugin-governance/
│   ├── plugin.rego                 # meta-validation policy (21 rules)
│   ├── plugin_test.rego            # policy tests (20 tests)
│   ├── schema.json                 # schema lists + thresholds (loaded as data.schema / data.thresholds)
│   └── input.example.json          # sample plugin manifest input
├── fed-inventory/
│   ├── fed_inventory.rego          # OMB 2025 inventory field-presence + enum-validity policy
│   ├── data.json                   # 35-field schema, enum sets, conditionality stage lists
│   └── docs/
│       └── ingestion-field-map.md  # CSV→JSON conversion guide and full field table
├── LICENSE
└── README.md
```

Note: plugin-governance uses `schema.json` rather than `data.json`.
OPA loads it at `data.schema` and `data.thresholds` when you point `--data` at the
directory.
The `data_sentinel` guard (`plugin.rego:86–91`) will emit a clear error if this
file is missing.

---

## Quick Start

Each pillar is evaluated by pointing `opa eval` at the policy directory,
an input document, and the desired entrypoint rule.
The commands below always produce defined output against the bundled example inputs.

**Circuit breaker — deny set, readiness score, and tests:**

```sh
# Violations (always defined; empty set when all rules pass)
opa eval --data circuit-breaker-policy/ --input circuit-breaker-policy/input.example.json \
  'data.circuit_breaker.deny'

# Readiness score (float 0.0–1.0)
opa eval --data circuit-breaker-policy/ --input circuit-breaker-policy/input.example.json \
  'data.circuit_breaker.readiness'

# Run tests
opa test circuit-breaker-policy/ -v
```

**Audit trail — violations, partitioned results, and tests:**

```sh
# Full deny set
opa eval --data audit-trail-policy/ --input audit-trail-policy/input.example.json \
  'data.audit_trail.deny'

# Errors only
opa eval --data audit-trail-policy/ --input audit-trail-policy/input.example.json \
  'data.audit_trail.errors'

# Warnings (includes info-severity entries)
opa eval --data audit-trail-policy/ --input audit-trail-policy/input.example.json \
  'data.audit_trail.warnings'

# Run tests
opa test audit-trail-policy/ -v
```

**Plugin governance — violation set, rule title map, and tests:**

```sh
# Structured violation set
opa eval --data plugin-governance/ --input plugin-governance/input.example.json \
  'data.plugins.standard.deny'

# Human-readable rule titles
opa eval --data plugin-governance/ --input plugin-governance/input.example.json \
  'data.plugins.standard.rule_titles'

# Run tests
opa test plugin-governance/ -v
```

**Federal AI inventory — summary, violations, and tests:**

```sh
# Full summary (valid flag, deny set, error/warning counts)
opa eval -d fed-inventory/ -i <record>.json 'data.fed.inventory.summary'

# Errors only (missing required fields)
opa eval -d fed-inventory/ -i <record>.json 'data.fed.inventory.errors'

# Run tests
opa test fed-inventory/ -v
```

For CSV-sourced records, convert first — see
[`fed-inventory/docs/ingestion-field-map.md`](fed-inventory/docs/ingestion-field-map.md).

**Run all test suites together:**

```sh
opa test circuit-breaker-policy/ audit-trail-policy/ plugin-governance/ fed-inventory/ -v
```

All 38 tests (circuit-breaker, audit-trail, plugin-governance) pass against the bundled example
inputs and data documents.
The fed-inventory suite passes independently via `opa test fed-inventory/ -v`.

---

## Known Limitations

1. **Advisory output only.** These are validators, not interceptors.
   They do not sit in a request path and cannot block an action at execution time.
   The caller must explicitly gate on the deny set for enforcement.

2. **No input provenance chain.** The policies trust the input document completely.
   There is no signature or chain-of-custody check on the input.
   A caller that can write the input document can trivially pass any policy check.

3. **No trusted clock.** Staleness detection is computed against `last_updated`
   date strings in the input, not against a trusted clock.
   A caller that fabricates `last_updated: <today>` will always pass staleness checks.

4. **Single-document, single-snapshot evaluation.** Each evaluation is stateless
   over the input snapshot provided.
   There is no cross-document or cross-period accumulation.

5. **`likelihood` is an integer type.** The `likelihood` enum in
   `circuit-breaker-policy/data.json:16` is `[1, 2, 3, 4, 5]` — JSON integers,
   not strings.
   Passing `"likelihood": "4"` (a string) will cause the risk-critical alarm at
   `circuit_breaker.rego:83` to not fire, because OPA comparison operators return
   undefined for mixed-type operands.

---

## For agents

Agents and automated tooling should start at [`AGENTS.md`](AGENTS.md), not this
README. Claude Code users: see [`CLAUDE.md`](CLAUDE.md), which imports
`AGENTS.md`. The agent docs cover the conventions, vocabulary, and verification
discipline — the `opa test` gate and the sanitization check — that agents are
expected to follow.

---

## References

- [open-policy-agent/opa](https://github.com/open-policy-agent/opa) — the Open
  Policy Agent project and `opa` CLI.
- [StyraInc/regal](https://github.com/StyraInc/regal) — a linter for Rego policy
  code.
- [anderseknert/awesome-opa](https://github.com/anderseknert/awesome-opa) — a
  curated list of OPA resources.

---

## License

Released under the Apache License 2.0.
See the [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) files for details.

---

> Built by Jonathan A. Bowe — Director of Safety / Staff System Safety Engineer / TPM background.
> These patterns express audit-grade governance patterns for AI / multi-agent toolchains in regulated environments.
