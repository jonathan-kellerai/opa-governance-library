# Phase 3 Feature Specification: SoFA and SoFREP Policy Hardening

- **Prepared by:** Spec-Orchestrator (Phase 3, Damascus Steel Process)
- **Date:** 2026-03-25
- **Scope:** `sofa/standard/sofa.rego`, `sofa/standard/schema.json`, `sofrep/standard/sofrep.rego`, `sofrep/standard/schema.json`
- **Inputs:** Tournament outputs A–F, cross-pollination matches R1-M1 through R3-M2
- **Status:** SINGLE SOURCE OF TRUTH for Phase 4 implementation

---

## Document Conventions

Every recommendation in this spec is assigned a stable identifier `Rn` that maps
one-to-one with a Rego rule name, a test case group, and a data document entry (where
applicable). Rule names in this spec appear as `snake_case` strings — they are the
exact values that will appear in `deny[_].rule` output.

Priority bands:

- **P0** — Structural safety: sentinel rules, default valid, type guards. Must land first.
  Prerequisites for all other work. Blocking if absent.
- **P1** — Silent-bypass closure: undefined-path fixes, falsy-value handling, DoS guards.
  Can cause false negatives on real input today.
- **P2** — New validation rules: compliance, cross-field, plausibility, SORP/CC17/ISO/SORTS.
  Extends coverage. Safe to add after P0/P1 are stable.
- **P3** — Testing infrastructure: differential harness, mutation testing, MC/DC analysis.
  No Rego changes. Tooling and test artifacts.
- **P4** — Style and metadata improvements: annotations, enum extraction, test isolation.
  Non-functional; improves maintainability.

---

## 1. Numbered Recommendations (R1–R33)

---

### P0 — Structural Safety Floor

---

#### R1: `data_sentinel`

- **Applies to:** BOTH
- **Layer:** meta-validation
- **Severity:** error
- **Rule name:** `data_sentinel`
- **Data dependencies:** `data.schema` (presence check only), `data.thresholds` (presence check only)
- **Source:** F-A1, C-Rec6, R1-M3-CP1, R2-M1-XP1, R2-M3-XP1
- **Implementation notes:** Fires when `data.schema` or `data.thresholds` is missing, empty,
  or lacks sentinel keys; produces an error-severity deny entry that blocks `valid`, ensuring
  no input can silently pass when the data document is absent or stripped.

The rule must guard:
- `count(object.get(data, "schema", {})) == 0` → deny
- `count(object.get(data, "thresholds", {})) == 0` → deny
- `count(object.get(data.schema, "required_fields", [])) == 0` (SoFA) → deny
- `count(object.get(data.schema, "required_metadata", [])) == 0` (SoFREP) → deny
- `count(object.get(data.schema, "quadrants", [])) == 0` (SoFREP) → deny

**Test cases:**
1. Valid: full `data.schema` + `data.thresholds` present → `data_sentinel` does not appear in deny
2. Invalid: evaluate policy with no data document bound → `data_sentinel` in deny; `valid == false`
3. Invalid: `data.schema = {}` → `data_sentinel` in deny
4. Edge: `data.schema.required_fields = []` → `data_sentinel` in deny (sentinel on list length)
5. Edge (SoFREP): `data.schema.quadrants = []` → `data_sentinel` in deny

---

#### R2: `sofrep_default_valid`

- **Applies to:** SoFREP only
- **Layer:** meta-validation
- **Severity:** (structural change, not a deny rule)
- **Rule name:** N/A — this is the `default valid := false` declaration
- **Data dependencies:** none
- **Source:** F-E2, C-Rec3, E-R-E04, R1-M3-E2, R2-M1-C1, R2-M3-F2, R3-M2-F2
- **Implementation notes:** Add `default valid := false` to `sofrep/standard/sofrep.rego` above the
  existing `valid := count(errors) == 0` rule. Replace the existing rule with `valid if count(errors) == 0`.
  This closes the third-state gap where absent `data.schema` leaves `valid` undefined rather than false.

**Test cases:**
1. Valid: well-formed input + data documents → `valid == true`
2. Invalid: evaluate with no `data.schema` bound → `valid == false` (not undefined, not true)
3. Edge: `deny` set empty but `data.schema` absent → `valid == false` due to `data_sentinel` error
4. Edge: confirm SoFA's existing `default valid := false` is unchanged and still effective

---

#### R3: `threshold_bounds`

- **Applies to:** BOTH
- **Layer:** meta-validation
- **Severity:** error
- **Rule name:** `threshold_bounds`
- **Data dependencies:** `data.thresholds.*` (all numeric threshold keys)
- **Source:** F-C (kill-switch table), C-Rec6, R1-M3-CP2, R2-M1-XP1, R2-M3-XP1
- **Implementation notes:** Validates every numeric threshold in `data.thresholds` against a
  hard-coded range guard. An out-of-range threshold disables rules without touching Rego code.
  The range bounds are embedded in the policy (not in data.thresholds itself, which would be
  circular) and represent plausible operational values.

SoFA bounds (hard-coded in Rego):

| Threshold key | Min | Max | Rationale |
|---|---|---|---|
| `reconciliation_tolerance` | 0 | 1000 | Penny-level to reasonable rounding |
| `materiality_floor` | 0 | 1000000 | Zero allowed; cap prevents disabling |
| `variance_limit` | 0.01 | 1.0 | At least 1% sensitivity |
| `going_concern_periods` | 1 | 24 | 1 period to 2 years |
| `min_unrestricted_balance` | -10000000 | 0 | Deficit allowance |

SoFREP bounds (hard-coded in Rego):

| Threshold key | Min | Max | Rationale |
|---|---|---|---|
| `staleness_days` | 1 | 365 | Daily to annual |
| `min_readiness_pct` | 0 | 100 | Percentage |
| `escalation_readiness_pct` | 0 | 100 | Percentage; must be ≤ min_readiness_pct |
| `max_owner_items` | 1 | 100 | Prevents owner-overload from never firing |
| `risk_critical` | 1 | 25 | 5x5 matrix max is 25 |
| `risk_high` | 1 | 25 | Must be < risk_critical |
| `risk_medium` | 1 | 25 | Must be < risk_high |

**Test cases:**
1. Valid: all thresholds within bounds → `threshold_bounds` absent from deny
2. Invalid (SoFA): `reconciliation_tolerance = 999999` → `threshold_bounds` in deny
3. Invalid (SoFREP): `staleness_days = 99999` → `threshold_bounds` in deny
4. Edge: `materiality_floor = 0` → valid (zero is allowed; disabling the floor is intentional)
5. Edge: `risk_critical = 26` → `threshold_bounds` in deny (exceeds 5x5 matrix maximum)

---

#### R4: `schema_list_nonempty`

- **Applies to:** BOTH
- **Layer:** meta-validation
- **Severity:** error
- **Rule name:** `schema_list_nonempty`
- **Data dependencies:** `data.schema.required_fields`, `data.schema.line_required`, `data.schema.fund_types`,
  `data.schema.income_categories`, `data.schema.expense_categories` (SoFA);
  `data.schema.quadrants`, `data.schema.required_metadata`, `data.schema.base_fields` (SoFREP)
- **Source:** F-C (DoS inversion vector), R1-M3-F2, R3-M2-F1
- **Implementation notes:** Guards that schema list keys contain at least the minimum number
  of entries required for meaningful validation. Distinct from R1: R1 guards against
  a missing/empty data document; R4 guards against a document where lists have been
  emptied out. For fund_types and income_categories, an empty list is a DoS vector
  (not a bypass), because `not item.fund_type in {}` always fires an error for every item.
  The guard prevents this inversion.

Minimum lengths:

| Policy | Key | Min length |
|---|---|---|
| SoFA | `required_fields` | 1 |
| SoFA | `line_required` | 1 |
| SoFA | `fund_types` | 1 |
| SoFA | `income_categories` | 1 |
| SoFA | `expense_categories` | 1 |
| SoFREP | `quadrants` | 4 |
| SoFREP | `required_metadata` | 1 |
| SoFREP | `base_fields` | 1 |

**Test cases:**
1. Valid: all lists meet minimum length → `schema_list_nonempty` absent
2. Invalid (SoFA): `fund_types = []` → `schema_list_nonempty` in deny (not a bypass; policy fires)
3. Invalid (SoFREP): `quadrants = ["working_well"]` (fewer than 4) → `schema_list_nonempty` in deny
4. Edge: `required_fields = ["report_date"]` (length 1) → valid (minimum met)

---

#### R5: `required_field_key_check`

- **Applies to:** SoFA only
- **Layer:** structural
- **Severity:** error
- **Rule name:** `required_field` (replaces existing rule of same name)
- **Data dependencies:** `data.schema.required_fields`
- **Source:** F-D2, R1-M3-F3, R2-M3-F3, R3-M2-F3
- **Implementation notes:** Replaces `not input[f]` with `not f in input` (explicit key-presence
  check). The current `not input[f]` evaluates to true for any falsy value (`0`, `false`, `""`,
  `[]`, `{}`), causing a false positive when `net_movement` is legitimately `0`. The fix
  uses `not f in input` (or equivalently `object.get(input, f, "__MISSING__") == "__MISSING__"`)
  which checks for key presence, not truthiness.

Current code (`sofa.rego:44-46`):
```rego
deny contains {...} if {
    some f in schema.required_fields
    not input[f]
}
```

Replacement:
```rego
deny contains {...} if {
    some f in schema.required_fields
    not f in input
}
```

**Test cases:**
1. Valid: `net_movement: 0` with `net_movement` in `required_fields` → no `required_field` deny
2. Valid: `fund_balances: {}` (empty object, but key present) → no `required_field` deny
3. Invalid: `net_movement` key absent entirely → `required_field` in deny
4. Edge: `net_movement: null` → `required_field` fires (null means the key is present but unset;
   decision: null is treated as missing. Document this decision in a comment)
5. Edge: `incoming_resources: false` → `required_field` fires (boolean is wrong type for array field)

---

#### R6: `field_presence_helper`

- **Applies to:** BOTH
- **Layer:** structural (helper function)
- **Severity:** N/A — helper only
- **Rule name:** `_field_present` (internal helper, leading underscore)
- **Data dependencies:** none
- **Source:** R1-M3-CP3, F-D1, F-D2, E-R-E06, E-R-E10
- **Implementation notes:** Adds a shared `_field_present(obj, field)` helper that returns true
  when a field is present and semantically non-empty. Handles all OPA falsy-value edge cases:
  `0`, `false`, `null`, `""`, `[]`, `{}`. Uses sentinel comparison to distinguish true
  key-absence from falsy-value presence. Both policies need this for different reasons:
  SoFREP's double-negation treats `null`/`0`/`false` as "present" (false negative);
  SoFA's `not input[f]` treats `0`/`false` as "missing" (false positive).

```rego
_sentinel := "__MISSING__"

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

**Test cases:**
1. `_field_present({"k": "v"}, "k")` → true
2. `_field_present({"k": 0}, "k")` → false (zero is not semantically present for string/text fields)
3. `_field_present({"k": null}, "k")` → false
4. `_field_present({}, "k")` → false
5. `_field_present({"k": []}, "k")` → false
6. Note: callers that need zero-valid (e.g., numeric amount fields) must use `f in obj` directly, not `_field_present`

---

#### R7: `sofrep_metadata_presence`

- **Applies to:** SoFREP only
- **Layer:** structural
- **Severity:** error
- **Rule name:** `required_metadata` (replaces existing double-negation pattern)
- **Data dependencies:** `data.schema.required_metadata`
- **Source:** E-R-E20, F-D1, R1-M3-CP3
- **Implementation notes:** Replaces the double-negation anti-pattern
  `not object.get(input, f, "") != ""` with a call to `_field_present(input, f)`.
  This closes the falsy-value blindness: a metadata field set to `0`, `false`, or `null`
  currently passes as "present and valid" when it is semantically empty.

Current (`sofrep.rego:26`):
```rego
not object.get(input, f, "") != ""
```

Replacement:
```rego
not _field_present(input, f)
```

The same replacement applies to the `reporting_period` sub-checks (lines 33-34, 39-40)
using `_field_present(rp, "start_date")` and `_field_present(rp, "end_date")`.

**Test cases:**
1. Valid: all metadata fields present with string values → no `required_metadata` deny
2. Invalid: `unit` field set to `null` → `required_metadata` fires for `unit`
3. Invalid: `author` field set to `0` → `required_metadata` fires
4. Invalid: `classification` field absent → `required_metadata` fires
5. Edge: `unit: ""` → `required_metadata` fires (empty string treated as absent)

---

#### R8: `impact_range`

- **Applies to:** SoFREP only
- **Layer:** type
- **Severity:** error
- **Rule name:** `impact_range`
- **Data dependencies:** none (range 1-5 is structural, not configurable)
- **Source:** F-D3, C-Rec5, R2-M3-XP3
- **Implementation notes:** Adds range validation for the `impact` field on `at_risk` items,
  mirroring the existing `likelihood_range` rule. Currently `impact` defaults to `0` via
  `object.get(item, "impact", 0)` in the risk matrix with no validation, causing silent
  `risk_score = 0` for items where `impact` is absent. The fix mirrors the `likelihood_range`
  rule pattern exactly.

```rego
deny contains {"msg": sprintf("at_risk item '%s' impact must be 1-5, got: %v", [id, v]),
    "severity": "error", "field": "impact", "rule": "impact_range"} if {
    some item in items_in("at_risk")
    id := object.get(item, "id", "<no-id>")
    v := object.get(item, "impact", 0)
    not _in_range(v, 1, 5)
}
```

Also add `is_number` guard to the existing `_in_range` helper (C-Rec5, type confusion fix):
```rego
_in_range(v, lo, hi) if {
    is_number(v)
    v >= lo
    v <= hi
}
```

**Test cases:**
1. Valid: `impact: 3`, `likelihood: 4` → no `impact_range` deny; `risk_score = 12`
2. Invalid: `impact` field absent → `impact_range` fires (defaults to 0, out of range)
3. Invalid: `impact: 0` → `impact_range` fires
4. Invalid: `impact: 6` → `impact_range` fires
5. Invalid: `impact: "high"` (string) → `impact_range` fires (is_number guard rejects it)
6. Edge: `impact: 5`, `likelihood: 5` → valid; `risk_score = 25` (maximum)

---

#### R9: `in_range_type_guard`

- **Applies to:** SoFREP only
- **Layer:** type
- **Severity:** error
- **Rule name:** `likelihood_range` (modifying existing rule's helper)
- **Data dependencies:** none
- **Source:** C-Rec5, R1-M2-XP3
- **Implementation notes:** The existing `_in_range(v, lo, hi)` helper at `sofrep.rego:111-114`
  lacks an `is_number(v)` guard. In Rego, `"5" >= 1` evaluates to `true` because strings
  sort after numbers in Rego's type ordering. A string `"5"` in the `likelihood` field
  passes the range check without this guard. Adding `is_number(v)` as the first condition
  closes this type confusion vulnerability for all callers of `_in_range`.

This is bundled with R8 as a single atomic change to `_in_range`.

**Test cases:**
1. Valid: `likelihood: 3` (integer) → no deny
2. Invalid: `likelihood: "3"` (string) → `likelihood_range` fires (is_number rejects string)
3. Invalid: `likelihood: 3.5` (float) → behavior depends on `is_number` for floats;
   document: `is_number` returns true for floats in OPA — if integer-only is required,
   add `v == round(v)` check. Defer this to a follow-on spec item.
4. Edge: `impact: true` (boolean) → `impact_range` fires (is_number(true) is false in OPA)

---

#### R10: `sofrep_fund_type_guard`

- **Applies to:** SoFREP only
- **Layer:** type
- **Severity:** error
- **Rule name:** `numeric_type_guard`
- **Data dependencies:** `data.thresholds.risk_critical`, `data.thresholds.risk_high`, `data.thresholds.risk_medium`
- **Source:** R1-M2-XP3, C-Rec5
- **Implementation notes:** The risk matrix computation at `sofrep.rego:181` uses
  `rs := imp * lik` without type-guarding `imp`. With R8's `impact_range` fix,
  `imp` will always be a validated number before reaching the risk matrix. However,
  the risk-level helper functions `_risk_level(s)` use `>=` comparisons against
  `data.thresholds.*` values. Add `is_number(s)` to `_risk_level` to prevent
  type confusion if a threshold value is loaded as a string from a JSON parser.

**Test cases:**
1. Valid: normal numeric risk score → correct risk level returned
2. Edge: `risk_critical` accidentally loaded as string `"20"` → `threshold_bounds` (R3) catches it first

---

### P1 — Silent-Bypass Closure

---

#### R11: `item_field_missing`

- **Applies to:** SoFREP only
- **Layer:** structural
- **Severity:** error
- **Rule name:** `base_fields` (replacing existing double-negation in current rule)
- **Data dependencies:** `data.schema.base_fields`
- **Source:** F-D1, R1-M3-CP3
- **Implementation notes:** The existing `base_fields` rule at `sofrep.rego:61` uses
  `not object.get(item, f, "") != ""` (same double-negation as `required_metadata`).
  Replace with `not _field_present(item, f)`. Fields like `title` or `description`
  set to `0` or `false` would currently pass; after this fix they correctly fire.

**Test cases:**
1. Valid: item with string values for all base fields → no `base_fields` deny
2. Invalid: `title: null` on any item → `base_fields` fires
3. Invalid: `owner: 0` → `base_fields` fires
4. Edge: `description: ""` → `base_fields` fires (empty string = missing)

---

#### R12: `sofa_fund_balance_type`

- **Applies to:** SoFA only
- **Layer:** type
- **Severity:** error
- **Rule name:** `fund_balance_type`
- **Data dependencies:** none
- **Source:** F-B10-B11, F-D (type confusion)
- **Implementation notes:** Currently `fund_reconciliation` and `aggregate_reconciliation`
  use `is_number(object.get(fb, "opening", null))` as a guard — if the value is a
  non-numeric string like `"TBD"`, the guard silently skips validation rather than
  flagging the type error. Add a companion error rule that explicitly fires when
  these fields are present but non-numeric, so the type error is surfaced rather
  than silently swallowed.

```rego
deny contains {"msg": sprintf("fund '%s': field '%s' must be numeric, got: %v", [ft, f, val]),
    "severity": "error", "field": "fund_balances", "rule": "fund_balance_type"} if {
    some ft, fb in object.get(input, "fund_balances", {})
    some f in ["opening", "net_movement", "closing"]
    f in fb
    val := fb[f]
    not is_number(val)
}
```

**Test cases:**
1. Valid: `{"opening": 100, "net_movement": 50, "closing": 150}` → no deny
2. Invalid: `{"opening": "TBD", "net_movement": 50}` → `fund_balance_type` fires for `opening`
3. Invalid: `{"closing": null}` with `closing` key present → `fund_balance_type` fires
4. Edge: `{"opening": 0}` → valid (zero is a number)

---

#### R13: `sofa_category_required`

- **Applies to:** SoFA only
- **Layer:** structural
- **Severity:** error
- **Rule name:** `category_required`
- **Data dependencies:** `data.schema.line_required`
- **Source:** F-B6-B7, F-B10
- **Implementation notes:** The existing `income_category` rule (`sofa.rego:74-78`) guards
  with `item.category` — if `category` is absent from the item, the rule silently skips,
  and the item passes with no category at all. The `line_required` rule should catch this
  (since `category` is in `schema.line_required`), but only if the item field check uses
  the corrected `_field_present` helper (R6). Ensure `line_required` rule at `sofa.rego:67-72`
  is updated to use `not _field_present(item, r)` instead of `not item[r]`.

Current (`sofa.rego:70`):
```rego
missing := {r | some r in schema.line_required; not item[r]}
```

Replacement:
```rego
missing := {r | some r in schema.line_required; not _field_present(item, r)}
```

**Note:** `amount` is a numeric field and `_field_present` rejects `0`. Items with
`amount: 0` are valid financial line items. For the `amount` field specifically, use
`not "amount" in item` instead of `_field_present`. Document this carve-out explicitly.

**Test cases:**
1. Valid: line item with all four `line_required` fields present → no deny
2. Invalid: line item with `category` absent → `line_required` fires listing `category` in missing
3. Invalid: line item with `category: null` → `line_required` fires
4. Valid: line item with `amount: 0` → no deny (zero is a valid amount)
5. Edge: line item with `amount: ""` → `line_required` fires (string is wrong type)

---

#### R14: `sofa_item_id_guard`

- **Applies to:** SoFREP only
- **Layer:** structural
- **Severity:** error
- **Rule name:** `item_id_required`
- **Data dependencies:** `data.schema.quadrants`
- **Source:** F-B21, F-B12
- **Implementation notes:** Items without an `id` field bypass `unique_ids` duplicate
  detection, `dependency_resolution`, and `conflict_detection`. The existing `base_fields`
  rule (`id` is in `data.schema.base_fields`) should catch this if the double-negation
  fix in R11 is applied. Verify that `id` remains in `base_fields` and that the fix
  from R11 correctly fires for `id: null` or absent `id`. No new rule needed if R11
  is correctly implemented; this entry tracks the dependency.

**Verification test cases:**
1. Invalid: item with no `id` key → `base_fields` fires listing `id`
2. Invalid: item with `id: null` → `base_fields` fires after R11 fix
3. Invalid: item with `id: ""` → `base_fields` fires after R11 fix

---

#### R15: `sofa_minimum_substance`

- **Applies to:** SoFA only
- **Layer:** structural
- **Severity:** warning
- **Rule name:** `minimum_substance`
- **Data dependencies:** `data.thresholds.min_substance_items` (new key, default: 0)
- **Source:** F-G (minimum viable valid input skeleton), R1-M3-F3
- **Implementation notes:** A SoFA report with empty `incoming_resources`, empty
  `resources_expended`, empty `fund_balances`, and empty `reconciliation` currently
  passes all validation. This is a skeleton document that games the validator.
  Add a warning rule that fires when `incoming_resources + resources_expended`
  total item count is below a configurable threshold. Default 0 (disabled by default)
  allows existing tests to pass; deployments can set `min_substance_items: 1` to enforce.

```rego
deny contains {"msg": "report has no line items: minimum substance requirement not met",
    "severity": "warning", "field": "incoming_resources", "rule": "minimum_substance"} if {
    total_line_items := count(items("incoming_resources")) + count(items("resources_expended"))
    total_line_items < thresholds.min_substance_items
    thresholds.min_substance_items > 0
}
```

**Test cases:**
1. Valid (default): empty arrays with `min_substance_items: 0` → no `minimum_substance` deny
2. Invalid: empty arrays with `min_substance_items: 1` → `minimum_substance` fires
3. Valid: 1 line item each with `min_substance_items: 1` → no deny
4. Edge: `min_substance_items` absent → rule does not fire (key not present; rule skips gracefully)

---

#### R16: `sofa_fund_balance_key_check`

- **Applies to:** SoFA only
- **Layer:** cross-entity
- **Severity:** error
- **Rule name:** `fund_balance_declared`
- **Data dependencies:** `data.schema.fund_types`
- **Source:** C-Rec8
- **Implementation notes:** `fund_balances` entries can reference fund types not declared
  in `data.schema.fund_types`. There is no Enron-analog rule ensuring that fund balance
  keys are drawn from the declared set. Add a rule that fires when a `fund_balances` key
  names a fund type not in the schema.

```rego
deny contains {"msg": sprintf("fund_balances key '%s' not in declared fund_types", [ft]),
    "severity": "error", "field": "fund_balances", "rule": "fund_balance_declared"} if {
    some ft, _ in object.get(input, "fund_balances", {})
    not ft in fund_types
}
```

**Test cases:**
1. Valid: `fund_balances.unrestricted` (in `fund_types`) → no deny
2. Invalid: `fund_balances.shadow_fund` (not in `fund_types`) → `fund_balance_declared` fires
3. Edge: `fund_types = []` → caught by R4 before this rule evaluates

---

#### R17: `sofa_regex_anchoring`

- **Applies to:** SoFA only (and SoFREP where date patterns are used)
- **Layer:** type
- **Severity:** (code quality, not a deny rule — affects `date_pattern` and `currency_pattern`)
- **Rule name:** N/A — data document fix
- **Data dependencies:** `data.schema.date_pattern`, `data.schema.currency_pattern`
- **Source:** C-Rec4, R1-M2 (Gatekeeper trailing-slash bypass)
- **Implementation notes:** Both `date_pattern` and `currency_pattern` in `sofa/standard/schema.json`
  must use anchored patterns (`^...$`) to prevent partial-match bypasses. Current values are:
  - `date_pattern: "^\\d{4}-\\d{2}-\\d{2}$"` — already anchored. No change needed.
  - `currency_pattern: "^[A-Z]{3}$"` — already anchored. No change needed.
  - `sofrep/standard/schema.json` `date_pattern: "^\\d{4}-\\d{2}-\\d{2}$"` — already anchored.

  Audit result: both patterns are already correctly anchored. No schema change required.
  Add a meta-validation rule that asserts patterns start with `^` and end with `$`:

```rego
deny contains {"msg": sprintf("schema.%s is not anchored (must start with ^ and end with $)", [k]),
    "severity": "error", "field": k, "rule": "pattern_anchoring"} if {
    some k in ["date_pattern", "currency_pattern"]
    pat := object.get(data.schema, k, "")
    pat != ""
    not startswith(pat, "^")
}
```

**Test cases:**
1. Valid: patterns with `^...$` → no `pattern_anchoring` deny
2. Invalid: `date_pattern: "\\d{4}-\\d{2}-\\d{2}"` (unanchored) → `pattern_anchoring` fires
3. Edge: `date_pattern: ""` → no fire (empty string; caught by R4-style guard)

---

#### R18: `sofrep_staleness_guard`

- **Applies to:** SoFREP only
- **Layer:** operational
- **Severity:** warning (guard change — existing staleness rule behavior fix)
- **Rule name:** `stale_item` / `stale_at_risk` (existing rules, guarded)
- **Data dependencies:** `reporting_period.end_date`
- **Source:** F-B22
- **Implementation notes:** The existing staleness rules guard with `_end_date != ""` — if
  `reporting_period.end_date` is absent, `_end_date` is `""` and all staleness checks are
  silently disabled. The `required_metadata` and temporal_validity rules should ensure
  `reporting_period` is present (and R7 fixes the double-negation). However, if `reporting_period`
  is present but `end_date` is missing, staleness is silently disabled without any error.
  Add an explicit error when `reporting_period` is present but `end_date` is absent:

```rego
deny contains {"msg": "reporting_period.end_date is required for staleness validation",
    "severity": "error", "field": "reporting_period", "rule": "end_date_required"} if {
    rp := object.get(input, "reporting_period", {})
    "reporting_period" in input
    not _field_present(rp, "end_date")
}
```

**Test cases:**
1. Valid: `reporting_period.end_date: "2025-12-31"` → no `end_date_required` deny
2. Invalid: `reporting_period: {"start_date": "2025-01-01"}` (no `end_date`) → `end_date_required` fires; staleness rules cannot fire
3. Invalid: `reporting_period: {}` → `end_date_required` fires
4. Edge: `reporting_period` absent entirely → `required_metadata` fires (R7); `end_date_required` does not fire (guarded by `"reporting_period" in input`)

---

#### R19: `sofrep_escalation_differentiation`

- **Applies to:** SoFREP only
- **Layer:** operational
- **Severity:** warning
- **Rule name:** `escalation_required` (modifying existing four rules)
- **Data dependencies:** none
- **Source:** E-R-E12, R1-M3-E1
- **Implementation notes:** The four escalation trigger rules at `sofrep.rego:299-313` all
  produce an identical deny object. Because `deny` is a set, all four collapse to one entry.
  A report with all four triggers active is indistinguishable from one with a single trigger.
  Differentiate the `msg` field per trigger to restore the full trigger count to consumers.

Replace the four identical deny objects with:
```rego
deny contains {"msg": "escalation required: critical risk item present", "severity": "warning",
    "field": "escalation", "rule": "escalation_required"} if { _has_critical_risk }

deny contains {"msg": "escalation required: readiness below escalation threshold",
    "severity": "warning", "field": "escalation", "rule": "escalation_required"} if {
    readiness_pct < data.thresholds.escalation_readiness_pct
}

deny contains {"msg": "escalation required: at_risk items exceed 50% of total",
    "severity": "warning", "field": "escalation", "rule": "escalation_required"} if { _high_at_risk_pct }

deny contains {"msg": "escalation required: P0 needed item is stale",
    "severity": "warning", "field": "escalation", "rule": "escalation_required"} if { _p0_stale }
```

**Test cases:**
1. Valid: no triggers active → no `escalation_required` in deny
2. Single trigger: only critical risk → one `escalation_required` entry with `"critical risk item"` msg
3. All four triggers: all escalation conditions met → four distinct deny entries (set deduplication no longer collapses them)
4. Edge: two triggers active → exactly two distinct `escalation_required` entries

---

### P2 — New Validation Rules

---

#### R20: `sofrep_severity_gated_mitigation`

- **Applies to:** SoFREP only
- **Layer:** cross-entity
- **Severity:** error
- **Rule name:** `high_priority_mitigation_required`
- **Data dependencies:** `data.thresholds.high_priority_mitigation_priorities` (new key, default: `["P0", "P1"]`)
- **Source:** A-Rec4 (PIREP severity-gating), R1-M1-A1, R2-M1-A1
- **Implementation notes:** A P0 or P1 `at_risk` item with no `mitigation` field currently passes
  validation. Aviation (UUA PIREP) rejects reports missing hazard detail when urgency is elevated.
  Add a deny rule that fires when an `at_risk` item has a qualifying priority and an absent/empty
  mitigation field. The qualifying priorities are configurable in `data.thresholds`.

```rego
deny contains {"msg": sprintf("at_risk item '%s' has priority %s: mitigation plan is required", [id, p]),
    "severity": "error", "field": "mitigation", "rule": "high_priority_mitigation_required"} if {
    some item in items_in("at_risk")
    id := object.get(item, "id", "<no-id>")
    p := object.get(item, "priority", "")
    p in {x | some x in data.thresholds.high_priority_mitigation_priorities}
    not _field_present(item, "mitigation")
}
```

**Test cases:**
1. Valid: P0 at_risk item with `mitigation: "Deploy redundancy by Q2"` → no deny
2. Invalid: P0 at_risk item with `mitigation` absent → `high_priority_mitigation_required` fires
3. Invalid: P1 at_risk item with `mitigation: ""` → `high_priority_mitigation_required` fires
4. Valid: P2 at_risk item with `mitigation` absent → no deny (P2 below threshold)
5. Edge: `high_priority_mitigation_priorities = []` → rule never fires (no qualifying priorities)

---

#### R21: `sofrep_contradictory_signals`

- **Applies to:** SoFREP only
- **Layer:** cross-entity
- **Severity:** warning
- **Rule name:** `contradictory_severity_signals`
- **Data dependencies:** none
- **Source:** A-Rec5 (AHRQ harm-severity coupling), C-Rec10, R1-M1-A3
- **Implementation notes:** Catches semantic contradictions between `urgency` and `priority`
  fields on the same item. A "needed" item with `urgency: "low"` and `priority: "P0"` sends
  contradictory signals (extremely urgent but lowest urgency declaration). An `at_risk` item
  with `priority: "P0"` and `impact: 1` (lowest possible impact, confirmed by R8) is
  similarly contradictory.

```rego
deny contains {"msg": sprintf("contradictory signals: item '%s' has priority P0/P1 but urgency low/medium", [id]),
    "severity": "warning", "field": "urgency", "rule": "contradictory_severity_signals"} if {
    some item in items_in("needed")
    id := object.get(item, "id", "<no-id>")
    p := object.get(item, "priority", "")
    u := object.get(item, "urgency", "")
    p in {"P0", "P1"}
    u in {"low", "medium"}
}
```

**Test cases:**
1. Valid: P0 needed item with `urgency: "critical"` → no deny
2. Invalid: P0 needed item with `urgency: "low"` → `contradictory_severity_signals` fires
3. Invalid: P1 needed item with `urgency: "medium"` → fires
4. Valid: P2 needed item with any urgency → no deny (P2 is not in the contradictory set)
5. Edge: `urgency` field absent → no fire (urgency is separately checked for presence by quadrant_fields)

---

#### R22: `sofa_going_concern_disclosure`

- **Applies to:** SoFA only
- **Layer:** operational
- **Severity:** error (escalated from existing warning)
- **Rule name:** `going_concern_disclosure`
- **Data dependencies:** `data.thresholds.going_concern_periods`
- **Source:** D-Rec9 (IAS 1), R1-M2-XP2
- **Implementation notes:** When the existing `going_concern` warning fires, IAS 1 requires
  a `going_concern_disclosure` narrative field. Currently the warning fires but no disclosure
  is required. Add a rule that fires with error severity when the going-concern condition
  is met AND `going_concern_disclosure` is absent or empty. Uses `_field_present` (R6)
  to avoid the `not input[f]` false positive on empty string.

```rego
deny contains {"msg": "going concern warning triggered: going_concern_disclosure narrative required",
    "severity": "error", "field": "going_concern_disclosure", "rule": "going_concern_disclosure"} if {
    hist := object.get(input, "historical_net_movements", [])
    n := thresholds.going_concern_periods
    count(hist) >= n
    every p in array.slice(hist, count(hist) - n, count(hist)) { p < 0 }
    not _field_present(input, "going_concern_disclosure")
}
```

**Test cases:**
1. Valid: two consecutive negative periods + non-empty `going_concern_disclosure` → no `going_concern_disclosure` deny
2. Invalid: two consecutive negative periods + no `going_concern_disclosure` field → fires
3. Invalid: two consecutive negative periods + `going_concern_disclosure: ""` → fires
4. Valid: only one negative period (< `going_concern_periods`) → does not fire
5. Edge: `going_concern_disclosure: 0` → fires (`_field_present` rejects `0`)

---

#### R23: `sofa_audit_status`

- **Applies to:** SoFA only
- **Layer:** compliance
- **Severity:** warning
- **Rule name:** `audit_status_check`
- **Data dependencies:** `data.thresholds.audit_threshold_major` (new, default: 1000000),
  `data.thresholds.audit_threshold_minor` (new, default: 250000),
  `data.thresholds.audit_asset_threshold` (new, default: 3260000),
  `data.thresholds.exam_threshold` (new, default: 25000)
- **Source:** D-Rec6 (CC17), R1-M2-D2
- **Implementation notes:** Validates that `audit_status` (if present) is consistent with
  computed income totals and CC17 thresholds. A charity declaring `audit_status: "none"`
  when `computed_income > audit_threshold_major` should receive a warning. Thresholds are
  stored in `data.thresholds` so the Oct 2026 changes (£1M→£1.5M, £3.26M→£5M) require
  only a data document update, not a Rego change.

```rego
deny contains {"msg": sprintf("audit_status '%s' inconsistent with income %v: statutory audit required above %v",
    [s, computed_income, thresholds.audit_threshold_major]),
    "severity": "warning", "field": "audit_status", "rule": "audit_status_check"} if {
    s := object.get(input, "audit_status", "")
    s != ""
    s != "audit"
    computed_income > thresholds.audit_threshold_major
}
```

**Test cases:**
1. Valid: income £800K with `audit_status: "independent_examination"` (below £1M) → no deny
2. Invalid: income £1.2M with `audit_status: "none"` → `audit_status_check` fires
3. Invalid: income £1.2M with `audit_status: "independent_examination"` → fires
4. Valid: income £1.2M with `audit_status: "audit"` → no deny
5. Edge: `audit_status` field absent → no fire (rule is advisory; presence not required)
6. Valid: no `audit_status` field → rule does not fire (field absent check)

---

#### R24: `sofa_sorp_categories`

- **Applies to:** SoFA only
- **Layer:** compliance
- **Severity:** warning
- **Rule name:** `sorp_category_alignment`
- **Data dependencies:** `data.schema.income_categories` (update required — see Section 2),
  `data.schema.sorp_version` (new, default: `"2026"`)
- **Source:** D-Rec2 (SORP 2026), R2-M3-D1
- **Implementation notes:** The current `income_categories` list uses pre-2026 SORP terminology.
  The SORP 2026 second edition (live now) renames categories. Update `data.schema.income_categories`
  to include SORP 2026 names and add backward-compatibility aliases. A `sorp_version` field
  in `data.schema` selects which category set is valid. Validation of category values is
  already covered by the existing `income_category` rule; this recommendation is primarily
  a data document update (see Section 2) with a version-selector guard.

**Test cases:**
1. Valid: `sorp_version: "2026"`, income category `"donations_and_legacies"` → no deny
2. Invalid (post-update): `sorp_version: "2026"`, income category `"voluntary_income"` (old name) → `income_category` fires
3. Valid: `sorp_version: "2019"`, income category `"voluntary_income"` (old name) → no deny
4. Edge: `sorp_version` absent → defaults to `"2026"` behavior (newest)

---

#### R25: `sofa_variance_ratio`

- **Applies to:** SoFA only
- **Layer:** cross-entity
- **Severity:** warning
- **Rule name:** `income_growth_plausibility`
- **Data dependencies:** `data.thresholds.max_income_growth_ratio` (new, default: 5.0),
  `data.thresholds.max_expense_growth_ratio` (new, default: 5.0)
- **Source:** C-Rec7 (Wirecard cross-field ratio), R2-M1-XP2
- **Implementation notes:** The existing `variance_analysis` rule checks year-over-year
  changes against a percentage threshold but does not catch implausible growth ratios.
  A charity reporting income 10x higher than prior year is structurally valid but
  potentially fraudulent (Wirecard pattern). Add a plausibility check that fires a
  warning when income grows beyond a configurable ratio multiplier.

```rego
deny contains {"msg": sprintf("income growth ratio %.1f exceeds plausibility threshold %.1f",
    [ratio, thresholds.max_income_growth_ratio]),
    "severity": "warning", "field": "incoming_resources_total", "rule": "income_growth_plausibility"} if {
    prior := object.get(input, "prior_period", {})
    prior_income := object.get(prior, "incoming_resources_total", 0)
    prior_income > 0
    current_income := object.get(input, "incoming_resources_total", computed_income)
    ratio := current_income / prior_income
    ratio > thresholds.max_income_growth_ratio
}
```

**Test cases:**
1. Valid: 50% income growth (ratio 1.5) with threshold 5.0 → no deny
2. Invalid: 10x income growth (ratio 10.0) with threshold 5.0 → `income_growth_plausibility` fires
3. Valid: prior income 0 → rule does not fire (guards `prior_income > 0`)
4. Edge: no `prior_period` field → rule does not fire
5. Edge: `max_income_growth_ratio = 0` → caught by R3 `threshold_bounds` (min bound)

---

#### R26: `sofrep_treatment_plan`

- **Applies to:** SoFREP only
- **Layer:** compliance
- **Severity:** warning
- **Rule name:** `treatment_plan_required`
- **Data dependencies:** `data.thresholds.risk_critical`, `data.thresholds.risk_high`
- **Source:** D-Rec23 (ISO 31000), R1-M2-D3
- **Implementation notes:** ISO 31000 clause 6.4 requires documented treatment plans for risks
  above risk appetite. SoFREP's current `mitigation` field is free text. Add a warning rule
  that fires when a critical or high risk score item lacks a structured `treatment_plan`
  object. The `treatment_plan` object should have sub-fields: `strategy`, `responsible_owner`,
  `target_date`, `status`. Warning (not error) because this is a compliance improvement,
  not a structural requirement.

```rego
deny contains {"msg": sprintf("at_risk item '%s' has %s risk (score=%d): structured treatment_plan required",
    [id, rl, rs]),
    "severity": "warning", "field": "treatment_plan", "rule": "treatment_plan_required"} if {
    some r in risk_matrix
    r.risk_level in {"critical", "high"}
    id := r.id
    rs := r.risk_score
    rl := r.risk_level
    item := [i | some i in items_in("at_risk"); i.id == id][0]
    not _field_present(item, "treatment_plan")
}
```

**Test cases:**
1. Valid: critical risk item with `treatment_plan: {"strategy": "mitigate", ...}` → no deny
2. Invalid: critical risk item with no `treatment_plan` field → `treatment_plan_required` fires
3. Invalid: high risk item with `treatment_plan: null` → fires
4. Valid: medium risk item with no treatment plan → no deny (threshold is critical/high only)
5. Edge: `treatment_plan: {}` → fires (`_field_present` rejects empty object)

---

#### R27: `sofrep_c_level`

- **Applies to:** SoFREP only
- **Layer:** operational
- **Severity:** warning
- **Rule name:** `c_level_readiness`
- **Data dependencies:** `data.thresholds.c1_threshold` (new, default: 90),
  `data.thresholds.c2_threshold` (new, default: 70),
  `data.thresholds.c3_threshold` (new, default: 50),
  `data.thresholds.c4_threshold` (new, default: 25)
- **Source:** D-Rec27 (SORTS/DRRS), R1-M2-D1
- **Implementation notes:** Computes a C1-C5 readiness level from `readiness_pct` using
  SORTS/DRRS threshold definitions. This replaces the current binary pass/fail threshold
  with a graduated five-level output. The `c_level` is an output value in `summary`, not
  a deny rule. However, C4 and C5 trigger a warning.

```rego
c_level := "C1" if readiness_pct >= data.thresholds.c1_threshold
c_level := "C2" if {
    readiness_pct < data.thresholds.c1_threshold
    readiness_pct >= data.thresholds.c2_threshold
}
# ... C3, C4, C5 following same pattern

deny contains {"msg": sprintf("readiness %d%% is C4/C5 — unit not mission capable", [readiness_pct]),
    "severity": "warning", "field": "readiness", "rule": "c_level_readiness"} if {
    c_level in {"C4", "C5"}
}
```

**Test cases:**
1. `readiness_pct: 95` → `c_level = "C1"`, no deny
2. `readiness_pct: 75` → `c_level = "C2"`, no deny
3. `readiness_pct: 20` → `c_level = "C4"`, `c_level_readiness` warning fires
4. `readiness_pct: 0` → `c_level = "C5"`, warning fires
5. Edge: C1/C2 threshold equal to `min_readiness_pct` → threshold_bounds (R3) protects against invalid threshold values

---

#### R28: `sofa_filing_deadline`

- **Applies to:** SoFA only
- **Layer:** compliance
- **Severity:** warning
- **Rule name:** `filing_deadline_check`
- **Data dependencies:** `data.thresholds.filing_deadline_days` (new, default: 304 — 10 months),
  `data.schema.jurisdiction` (new enum key)
- **Source:** D-Rec7 (CC17 filing deadline), D-Rec11 (OSCR 9-month deadline)
- **Implementation notes:** When `filing_date` is present, compute whether
  `filing_date - report_date` exceeds the jurisdiction-appropriate deadline.
  England/Wales = 304 days (10 months); Scotland = 273 days (9 months). Default to England/Wales.

```rego
deny contains {"msg": sprintf("filing_date %s may exceed %d-day deadline for %s jurisdiction",
    [fd, deadline, jur]),
    "severity": "warning", "field": "filing_date", "rule": "filing_deadline_check"} if {
    fd := object.get(input, "filing_date", "")
    fd != ""
    rd := object.get(input, "report_date", "")
    rd != ""
    jur := object.get(input, "jurisdiction", "england_wales")
    deadline := _filing_deadline_days(jur)
    _days_between_dates(rd, fd) > deadline
}
```

**Test cases:**
1. Valid: filing within 10 months for England/Wales → no deny
2. Invalid: filing 11 months after report date for England/Wales → fires
3. Invalid: filing 10 months after report date for Scotland (9-month deadline) → fires
4. Valid: `filing_date` absent → rule does not fire (field is optional)
5. Edge: `jurisdiction: "scotland"` with 9.5 months → fires (exceeds 9-month limit)

---

### P3 — Testing Infrastructure

---

#### R29: `diff_test_harness`

- **Applies to:** BOTH (tooling)
- **Layer:** N/A (testing infrastructure)
- **Severity:** N/A
- **Rule name:** N/A
- **Data dependencies:** N/A
- **Source:** B-Rec6, R1-M1-B2, R3-M2-B3
- **Implementation notes:** Create `tests/diff_test.sh` that evaluates two policy versions
  against a shared corpus directory and reports decision deltas. Must include a
  "no data document" corpus entry that asserts `valid == false` when data is absent,
  closing the regression gap identified in R3-M2-XP3. This artifact must exist before
  any P2 rule lands.

Deliverables:
- `tests/diff_test.sh` — `opa eval -d <version-a>/ -i corpus/` vs `opa eval -d <version-b>/ -i corpus/`
- `tests/corpus/` — shared test fixtures including `no_data_doc.json`
- `tests/corpus/no_data_doc.json` — minimal input evaluated without data bindings
- One explicit assertion: `valid == false` when no `data.*` is bound

---

#### R30: `invalidity_matrix`

- **Applies to:** BOTH (documentation artifact)
- **Layer:** N/A (test coverage documentation)
- **Severity:** N/A
- **Rule name:** N/A
- **Data dependencies:** N/A
- **Source:** B-Rec4, R3-M2-XP2, R1-M1-XP2
- **Implementation notes:** Create `tests/invalidity_matrix.md` enumerating every known
  category of invalid input with traceability to the deny rule and test case that covers it.
  Rows from F's Section B (22 silent non-firing vectors) and Section C (12 kill-switch
  configurations), structured into B's five taxonomy categories plus a sixth: data-document
  manipulation. Each row must include: category, rule name, test case file reference.

Deliverables:
- `tests/invalidity_matrix.md` with columns: Category | Invalid Input Type | Rule Name | Test Case | Status

---

#### R31: `mcdc_coverage`

- **Applies to:** BOTH (tooling)
- **Layer:** N/A (testing infrastructure)
- **Severity:** N/A
- **Rule name:** N/A
- **Data dependencies:** N/A
- **Source:** B-Rec3, R1-M1-B1, R3-M2-B1
- **Implementation notes:** Create `tests/test_coverage_mcdc.sh` that analyzes
  `opa test --coverage` JSON output and cross-references with rule conjunct counts
  to flag under-tested rules. For each deny rule with N conditions in its body,
  the script should report whether at least N+1 test cases exist that exercise that rule.
  This is a measurement script, not a gating test.

Deliverables:
- `tests/test_coverage_mcdc.sh` — parses `opa test --coverage --format=json` output

---

#### R32: `sofrep_inline_test_data`

- **Applies to:** SoFREP only (test file fix)
- **Layer:** N/A (test quality)
- **Severity:** N/A
- **Rule name:** N/A
- **Data dependencies:** N/A
- **Source:** E-R-E14, R1-M3-E3
- **Implementation notes:** `sofrep/standard/sofrep_test.rego` relies on external
  `data.schema` and `data.thresholds` files rather than injecting them inline. This
  makes tests non-portable and fragile to schema renames. Port SoFA's pattern
  (inline `with data.schema as _schema with data.thresholds as _thresholds`) to all
  SoFREP tests. Also fix backtick raw strings for regex patterns (R-E08).

Deliverables: modified `sofrep/standard/sofrep_test.rego` with complete inline `_schema`
and `_thresholds` definitions at the top of the test file.

---

### P4 — Style and Metadata Improvements

---

#### R33: `sofrep_package_metadata`

- **Applies to:** SoFREP only
- **Layer:** N/A (metadata)
- **Severity:** N/A
- **Rule name:** N/A
- **Data dependencies:** N/A
- **Source:** E-R-E01, E-R-E02, E-R-E03, E-R-E11, E-R-E15
- **Implementation notes:** Batched style improvements for SoFREP:
  1. Add package-level `# METADATA` block (matching SoFA's existing block)
  2. Extract repeated inline enum set constructions into named private rules:
     `_classification_values`, `_priority_values`, `_urgency_values`
  3. Create `.regal/config.yaml` in `sofrep/` (and `sofa/` if absent) per E's recommended config
  4. Add `default valid := false` — already captured in R2; do not duplicate

Deliverables: modified `sofrep/standard/sofrep.rego` top section; new `sofrep/.regal/config.yaml`; new `sofa/.regal/config.yaml`

---

## 2. Data Document Changes

### SoFA — `sofa/standard/schema.json`

#### New keys in `schema` object

| Key | Type | Default value | Rationale |
|---|---|---|---|
| `sorp_version` | string | `"2026"` | Selects SORP category name set (R24) |
| `jurisdiction` | string | `"england_wales"` | Controls filing deadline and audit thresholds (R28) |

#### Updated keys in `schema` object

| Key | Change | Rationale |
|---|---|---|
| `income_categories` | Update values to SORP 2026 terminology | D-Rec2: `"voluntary_income"` → `"donations_and_legacies"`, `"activities_for_generating_funds"` → `"other_trading_activities"`, retain `"investment_income"`, `"charitable_activities"`, `"other_incoming"`. Add `sorp_2019_aliases` sub-key for backward compatibility. |

#### New keys in `thresholds` object

| Key | Type | Default value | Rationale |
|---|---|---|---|
| `audit_threshold_major` | number | `1000000` | CC17: statutory audit above £1M (R23) |
| `audit_threshold_minor` | number | `250000` | CC17: audit when assets > £3.26M (R23) |
| `audit_asset_threshold` | number | `3260000` | CC17: asset threshold for audit (R23) |
| `exam_threshold` | number | `25000` | CC17: independent examination threshold (R23) |
| `filing_deadline_days` | number | `304` | England/Wales 10-month deadline (R28) |
| `min_substance_items` | number | `0` | Minimum line items (R15); 0 = disabled |
| `max_income_growth_ratio` | number | `5.0` | Wirecard plausibility cap (R25) |
| `max_expense_growth_ratio` | number | `5.0` | Expense plausibility cap (R25) |

#### Keys requiring range guards (R3, R4)

| Key | Min | Max | Guard type |
|---|---|---|---|
| `reconciliation_tolerance` | 0 | 1000 | threshold_bounds (R3) |
| `materiality_floor` | 0 | 1000000 | threshold_bounds (R3) |
| `variance_limit` | 0.01 | 1.0 | threshold_bounds (R3) |
| `going_concern_periods` | 1 | 24 | threshold_bounds (R3) |
| `min_unrestricted_balance` | -10000000 | 0 | threshold_bounds (R3) |
| `audit_threshold_major` | 500000 | 5000000 | threshold_bounds (R3) |
| All numeric keys | positive | reasonable upper | threshold_bounds (R3) |

---

### SoFREP — `sofrep/standard/schema.json`

#### New keys in `thresholds` object

| Key | Type | Default value | Rationale |
|---|---|---|---|
| `c1_threshold` | number | `90` | SORTS C1 readiness level (R27) |
| `c2_threshold` | number | `70` | SORTS C2 readiness level (R27) |
| `c3_threshold` | number | `50` | SORTS C3 readiness level (R27) |
| `c4_threshold` | number | `25` | SORTS C4 readiness level (R27) |
| `high_priority_mitigation_priorities` | array | `["P0", "P1"]` | Severity-gated mitigation (R20) |

#### Keys requiring range guards (R3, R4)

| Key | Min | Max | Guard type |
|---|---|---|---|
| `staleness_days` | 1 | 365 | threshold_bounds (R3) |
| `min_readiness_pct` | 0 | 100 | threshold_bounds (R3) |
| `escalation_readiness_pct` | 0 | 100 | threshold_bounds (R3) |
| `max_owner_items` | 1 | 100 | threshold_bounds (R3) |
| `risk_critical` | 1 | 25 | threshold_bounds (R3) |
| `risk_high` | 1 | 25 | threshold_bounds (R3) |
| `risk_medium` | 1 | 25 | threshold_bounds (R3) |
| `c1_threshold` through `c4_threshold` | 0 | 100 | threshold_bounds (R3) |

---

## 3. Error Code Registry

Every rule name below is the exact string that appears in `deny[_].rule` output.
Error codes follow the pattern `{Policy}-{Layer}{Seq}` where layers are:
`00` = meta-validation, `01` = structural, `02` = type/enum, `03` = cross-entity, `04` = operational, `05` = compliance.

| Rule Name | Error Code | Severity | Layer | Applies To |
|---|---|---|---|---|
| `data_sentinel` | `BOTH-0001` | error | meta-validation | BOTH |
| `threshold_bounds` | `BOTH-0002` | error | meta-validation | BOTH |
| `schema_list_nonempty` | `BOTH-0003` | error | meta-validation | BOTH |
| `pattern_anchoring` | `BOTH-0004` | error | meta-validation | BOTH |
| `required_field` | `SOFA-0101` | error | structural | SoFA |
| `date_format` | `SOFA-0102` | error | structural | SoFA |
| `currency_format` | `SOFA-0103` | error | structural | SoFA |
| `accounting_basis` | `SOFA-0104` | error | structural | SoFA |
| `line_required` | `SOFA-0105` | error | structural | SoFA |
| `category_required` | `SOFA-0106` | error | structural | SoFA |
| `income_category` | `SOFA-0201` | error | type | SoFA |
| `expense_category` | `SOFA-0202` | error | type | SoFA |
| `fund_type` | `SOFA-0203` | error | type | SoFA |
| `fund_balance_type` | `SOFA-0204` | error | type | SoFA |
| `net_movement_check` | `SOFA-0301` | error | cross-entity | SoFA |
| `fund_reconciliation` | `SOFA-0302` | error | cross-entity | SoFA |
| `aggregate_reconciliation` | `SOFA-0303` | error | cross-entity | SoFA |
| `transfer_netting` | `SOFA-0304` | error | cross-entity | SoFA |
| `restricted_purpose` | `SOFA-0305` | error | cross-entity | SoFA |
| `endowment_principal` | `SOFA-0306` | error | cross-entity | SoFA |
| `basis_consistency` | `SOFA-0307` | error | cross-entity | SoFA |
| `fund_balance_declared` | `SOFA-0308` | error | cross-entity | SoFA |
| `income_growth_plausibility` | `SOFA-0309` | warning | cross-entity | SoFA |
| `audit_reference` | `SOFA-0401` | warning | operational | SoFA |
| `variance_analysis` | `SOFA-0402` | warning | operational | SoFA |
| `unrestricted_balance` | `SOFA-0403` | warning | operational | SoFA |
| `liquidity_ratio` | `SOFA-0404` | warning | operational | SoFA |
| `going_concern` | `SOFA-0405` | warning | operational | SoFA |
| `minimum_substance` | `SOFA-0406` | warning | operational | SoFA |
| `materiality` | `SOFA-0407` | info | operational | SoFA |
| `audit_status_check` | `SOFA-0501` | warning | compliance | SoFA |
| `sorp_category_alignment` | `SOFA-0502` | warning | compliance | SoFA |
| `going_concern_disclosure` | `SOFA-0503` | error | compliance | SoFA |
| `filing_deadline_check` | `SOFA-0504` | warning | compliance | SoFA |
| `required_metadata` | `SOFREP-0101` | error | structural | SoFREP |
| `end_date_required` | `SOFREP-0102` | error | structural | SoFREP |
| `quadrant_presence` | `SOFREP-0103` | error | structural | SoFREP |
| `quadrant_non_empty` | `SOFREP-0104` | error | structural | SoFREP |
| `base_fields` | `SOFREP-0105` | error | structural | SoFREP |
| `quadrant_fields` | `SOFREP-0106` | error | structural | SoFREP |
| `classification_enum` | `SOFREP-0201` | error | type | SoFREP |
| `priority_enum` | `SOFREP-0202` | error | type | SoFREP |
| `urgency_enum` | `SOFREP-0203` | error | type | SoFREP |
| `likelihood_range` | `SOFREP-0204` | error | type | SoFREP |
| `impact_range` | `SOFREP-0205` | error | type | SoFREP |
| `date_format` | `SOFREP-0206` | error | type | SoFREP |
| `temporal_validity` | `SOFREP-0207` | error | type | SoFREP |
| `unique_ids` | `SOFREP-0301` | error | cross-entity | SoFREP |
| `dependency_resolution` | `SOFREP-0302` | error | cross-entity | SoFREP |
| `conflict_detection` | `SOFREP-0303` | error | cross-entity | SoFREP |
| `high_priority_mitigation_required` | `SOFREP-0304` | error | cross-entity | SoFREP |
| `contradictory_severity_signals` | `SOFREP-0305` | warning | cross-entity | SoFREP |
| `critical_risk` | `SOFREP-0401` | warning | operational | SoFREP |
| `low_readiness` | `SOFREP-0402` | warning | operational | SoFREP |
| `c_level_readiness` | `SOFREP-0403` | warning | operational | SoFREP |
| `defensive_posture` | `SOFREP-0404` | warning | operational | SoFREP |
| `dependency_on_risk` | `SOFREP-0405` | warning | operational | SoFREP |
| `owner_overload` | `SOFREP-0406` | warning | operational | SoFREP |
| `stale_item` | `SOFREP-0407` | warning | operational | SoFREP |
| `stale_at_risk` | `SOFREP-0408` | warning | operational | SoFREP |
| `priority_inversion` | `SOFREP-0409` | warning | operational | SoFREP |
| `escalation_required` | `SOFREP-0410` | warning | operational | SoFREP |
| `treatment_plan_required` | `SOFREP-0501` | warning | compliance | SoFREP |

**Note on the `layer` field:** Phase 4 implementation must add a `"layer"` field to every deny
object using the layer column above, and an `"error_code"` field using the error code column.
This satisfies A-Rec6 (EDI X12 hierarchical error taxonomy) and R1-M1-A2.
The deny object shape after Phase 4 will be:
```json
{
  "msg": "human-readable message",
  "severity": "error|warning|info",
  "field": "field_name",
  "rule": "rule_name",
  "layer": "meta-validation|structural|type|cross-entity|operational|compliance",
  "error_code": "SOFA-0101"
}
```

---

## 4. Attack Surface Notes

For each new rule, the following documents what input shape causes silent non-firing,
what data.schema value disables it, and the mitigation.

| Rule | Silent non-firing input | Data doc kill switch | Sentinel/Guard |
|---|---|---|---|
| `data_sentinel` | Cannot be silenced — it fires when data is absent | N/A — rule checks data itself | Hard-coded guard; no data dependency |
| `threshold_bounds` | Cannot be silenced — bounds are hard-coded in policy | N/A | Hard-coded bounds |
| `schema_list_nonempty` | Cannot be silenced — checks are hard-coded | N/A | Hard-coded minimum lengths |
| `required_field` (R5 fix) | Remove `f` from `required_fields` list | `required_fields = []` → R4 fires | R1 + R4 guard upstream |
| `_field_present` helper | Caller passes object without the field | N/A | Sentinel `"__MISSING__"` value |
| `sofrep_metadata_presence` | Remove `f` from `required_metadata` list | `required_metadata = []` → R4 fires | R1 + R4 guard upstream |
| `impact_range` | Omit `impact` key → defaults to `0` → rule fires correctly | `at_risk` quadrant removed from `quadrants` → R4 fires | `is_number` guard in `_in_range` |
| `fund_balance_type` | Omit `fund_balances` entirely → iteration yields nothing | N/A | Separate `fund_balance_declared` (R16) catches undeclared funds |
| `category_required` | Remove `category` from `line_required` | `line_required = []` → R4 fires | R1 + R4 guard upstream |
| `item_id_required` | Remove `id` from `base_fields` | `base_fields = []` → R4 fires | R1 + R4 guard upstream |
| `minimum_substance` | Set `min_substance_items: 0` | Kill switch is intentional; `0` = disabled | Documented; deploy with value > 0 |
| `fund_balance_declared` | Set `fund_types = []` → R4 fires first | `fund_types = []` → R4 fires | R4 guards list length |
| `pattern_anchoring` | Remove pattern from `data.schema` | `data.schema = {}` → R1 fires | R1 guards schema presence |
| `end_date_required` | Remove `reporting_period` entirely → `required_metadata` fires | `required_metadata = []` → R4 fires | Layered guards |
| `escalation_required` (differentiated) | No change — differentiation only affects msg, not firing condition | Same as before | Same as existing escalation guards |
| `high_priority_mitigation_required` | Omit `priority` → `priority_enum` fires (priority required) | `high_priority_mitigation_priorities = []` → rule never fires | Document that empty list disables severity-gating |
| `contradictory_severity_signals` | Omit both `priority` and `urgency` | N/A | Separate enum rules catch absent values |
| `going_concern_disclosure` | Omit `historical_net_movements` → going concern never triggers | `going_concern_periods = 999` → R3 fires (max 24) | R3 threshold bounds guard |
| `audit_status_check` | Omit `audit_status` field | N/A — field is optional; rule explicitly guards `s != ""` | Rule designed for optional advisory use |
| `income_growth_plausibility` | Omit `prior_period` → rule guards `prior_income > 0` | `max_income_growth_ratio = 999` → R3 fires (min bound enforced) | R3 threshold bounds guard |
| `treatment_plan_required` | Impact + likelihood values below high-risk threshold | `risk_critical = 999` → R3 fires | R3 threshold bounds guard |
| `c_level_readiness` | Set thresholds to 0/100 to prevent C4/C5 | `c4_threshold = 0` → C4 never fires | R3 threshold bounds guard on 0–100 range |
| `filing_deadline_check` | Omit `filing_date` field | N/A — field is optional; rule guards `fd != ""` | Rule designed for optional use |
| `audit_status_check` | N/A | `audit_threshold_major = 99999999` → R3 fires | R3 bounds: max 5000000 |

---

## 5. Implementation Order

### Wave 1 — Safety Floor (must land first, blocking prerequisites)

These changes are prerequisites for every other recommendation. They must all land in the same
commit or closely coupled commits. They introduce zero false positives on existing valid input
and do not change the schema.

1. **R2** — Add `default valid := false` to SoFREP (`sofrep.rego:322`, one line)
2. **R5** — Fix `not input[f]` → `not f in input` in SoFA (`sofa.rego:45`)
3. **R6** — Add `_field_present` helper to both policies
4. **R7** — Fix double-negation in SoFREP metadata check (`sofrep.rego:26,33,39`)
5. **R8** + **R9** — Add `impact_range` rule + `is_number` guard to `_in_range` in SoFREP
6. **R1** — Add `data_sentinel` meta-validation deny rules to both policies
7. **R3** — Add `threshold_bounds` meta-validation deny rules to both policies
8. **R4** — Add `schema_list_nonempty` meta-validation deny rules to both policies

**Wave 1 acceptance criteria:**
- All existing passing tests continue to pass
- A new test running either policy with no data document returns `valid == false` with `data_sentinel` in errors
- `net_movement: 0` on a valid SoFA report no longer produces a `required_field` error
- SoFREP item with `title: null` produces `base_fields` error

---

### Wave 2 — Core Validation Improvements

After Wave 1 is stable. These rules add net-new deny logic on previously-passing inputs.
Run the differential test harness (R29) before and after each rule to confirm only intended
behavioral changes.

9. **R11** — Fix SoFREP `base_fields` double-negation (after `_field_present` helper from Wave 1)
10. **R12** — Add SoFA `fund_balance_type` error rule
11. **R13** — Fix SoFA `line_required` category guard
12. **R14** — Verify item_id_required coverage via R11 (no new rule if R11 covers it)
13. **R15** — Add `minimum_substance` warning to SoFA (with `min_substance_items: 0` default — disabled)
14. **R16** — Add `fund_balance_declared` cross-entity rule to SoFA
15. **R17** — Add `pattern_anchoring` meta-validation rule; audit existing patterns (both already anchored)
16. **R18** — Add `end_date_required` structural rule to SoFREP
17. **R19** — Differentiate escalation trigger messages in SoFREP (R19)

**Wave 2 acceptance criteria:**
- Differential test shows no regressions on existing valid corpus
- Each new rule has a test case that fires it and a test case that does not fire it
- `invalidity_matrix.md` (R30) updated to reflect new coverage

---

### Wave 3 — Compliance and Domain Extensions

After Wave 2 is stable and the differential harness is in place.
These rules require schema additions (new threshold and schema keys).

18. **R20** — `high_priority_mitigation_required` (SoFREP severity-gating)
19. **R21** — `contradictory_severity_signals` (SoFREP semantic contradiction check)
20. **R22** — `going_concern_disclosure` (SoFA IAS 1)
21. **R23** — `audit_status_check` + new threshold keys (SoFA CC17)
22. **R24** — SORP 2026 category update + `sorp_version` schema key
23. **R25** — `income_growth_plausibility` (SoFA Wirecard plausibility check)
24. **R26** — `treatment_plan_required` (SoFREP ISO 31000)
25. **R27** — `c_level_readiness` + new threshold keys (SoFREP SORTS/DRRS)
26. **R28** — `filing_deadline_check` + jurisdiction schema key (SoFA CC17/OSCR)
27. Add `layer` and `error_code` fields to all deny objects (A-Rec6 / EDI X12 taxonomy)

**Wave 3 acceptance criteria:**
- Schema changes documented in `schema.json` for both policies with rationale comments
- All new threshold keys include range guards enforced by R3
- All new rules use `_field_present` helper (R6) for field-presence checks
- SORP 2026 category update includes backward-compatibility aliases with `sorp_version` guard

---

### Wave 4 — Testing Infrastructure

Tooling and documentation. Can begin in parallel with Wave 2 once Wave 1 is stable.

28. **R29** — `diff_test.sh` + `tests/corpus/` directory with `no_data_doc.json`
29. **R30** — `tests/invalidity_matrix.md` populated from F's findings
30. **R31** — `tests/test_coverage_mcdc.sh`
31. **R32** — SoFREP test inline data injection
32. **R33** — SoFREP package metadata + enum extraction + `.regal/config.yaml`

**Wave 4 acceptance criteria:**
- `diff_test.sh` runs without errors against Wave 1+2 policy versions
- `invalidity_matrix.md` has rows for all 22 silent non-firing vectors from F
- MC/DC analysis script produces output for both policies
- SoFREP tests pass without external data file dependency

---

## Appendix A: Cross-Pollination Synthesis Map

The following identifies synthesized insights that no single research output produced alone,
and which implementation recommendations they informed:

| Synthesis | Source Outputs | Captured in |
|---|---|---|
| Fail-closed hardening trio (sentinel + default valid + error codes) | F-A1 + E-R-E04 + R1-M3-CP1 | R1, R2, R3 |
| `_field_present` helper (dual false-positive/false-negative fix) | F-D1 + F-D2 + E-R-E06 | R6 |
| Invariant-driven mutation targets | A-Rec1 + B-Rec2 + R1-M1-XP1 | R30 (invalidity_matrix) |
| Error taxonomy as invalidity matrix | A-Rec6 + B-Rec4 + R1-M1-XP2 | Section 3 (error_code field) |
| Differential testing as regression guard for new rules | A-Rec1 + B-Rec6 + R1-M1-XP3 | R29 |
| Data poisoning attacks the thresholds D defines | C-Rec6 + D thresholds + R1-M2-XP1 | R3 + Wave 3 bounds |
| `undefined`-pass threatens every new warning rule | C-Rec3 + D rules + R1-M2-XP2 | Wave 1 sequencing requirement |
| Type confusion threatens every numeric rule D introduces | C-Rec5 + D numeric fields + R1-M2-XP3 | R8, R9, `_in_range` fix |
| Jurisdiction-adjusted plausibility bounds | D-Rec11 + C-Rec7 + R1-M2-XP4 | R25, R28 |
| Fix `not input[f]` before D's disclosure rules | F-D2 + D-Rec9 + R2-M3-XP2 | Wave 1 before Wave 3 ordering |
| Anti-fixture test pattern (TDD for minimum-substance) | F-G + E-R-E14 + R1-M3-CP4 | R15 + R32 |
| Meta-validation layer on error taxonomy | A-Rec6 + C-Rec6 + R2-M1-XP3 | Section 3 `layer: meta-validation` |
| Mutation testing targets F's 22 silent-non-firing vectors | B-Rec2 + F-B tables + R3-M2-XP1 | R30 + R31 |
| No-data-doc corpus entry for differential testing | F-E2 + B-Rec6 + R3-M2-XP3 | R29 `corpus/no_data_doc.json` |

---

## Appendix B: Recommendation Summary Table

| ID | Rule Name | Priority | Policy | Layer | Severity | Wave |
|---|---|---|---|---|---|---|
| R1 | `data_sentinel` | P0 | BOTH | meta-validation | error | 1 |
| R2 | `sofrep_default_valid` | P0 | SoFREP | meta-validation | structural | 1 |
| R3 | `threshold_bounds` | P0 | BOTH | meta-validation | error | 1 |
| R4 | `schema_list_nonempty` | P0 | BOTH | meta-validation | error | 1 |
| R5 | `required_field` (fix) | P0 | SoFA | structural | error | 1 |
| R6 | `_field_present` (helper) | P0 | BOTH | structural | helper | 1 |
| R7 | `required_metadata` (fix) | P0 | SoFREP | structural | error | 1 |
| R8 | `impact_range` | P0 | SoFREP | type | error | 1 |
| R9 | `in_range_type_guard` | P0 | SoFREP | type | error | 1 |
| R10 | `numeric_type_guard` | P0 | SoFREP | type | helper | 1 |
| R11 | `base_fields` (fix) | P1 | SoFREP | structural | error | 2 |
| R12 | `fund_balance_type` | P1 | SoFA | type | error | 2 |
| R13 | `category_required` | P1 | SoFA | structural | error | 2 |
| R14 | `item_id_required` (verify) | P1 | SoFREP | structural | error | 2 |
| R15 | `minimum_substance` | P1 | SoFA | operational | warning | 2 |
| R16 | `fund_balance_declared` | P1 | SoFA | cross-entity | error | 2 |
| R17 | `pattern_anchoring` | P1 | BOTH | meta-validation | error | 2 |
| R18 | `end_date_required` | P1 | SoFREP | structural | error | 2 |
| R19 | `escalation_required` (fix) | P1 | SoFREP | operational | warning | 2 |
| R20 | `high_priority_mitigation_required` | P2 | SoFREP | cross-entity | error | 3 |
| R21 | `contradictory_severity_signals` | P2 | SoFREP | cross-entity | warning | 3 |
| R22 | `going_concern_disclosure` | P2 | SoFA | compliance | error | 3 |
| R23 | `audit_status_check` | P2 | SoFA | compliance | warning | 3 |
| R24 | `sorp_category_alignment` | P2 | SoFA | compliance | warning | 3 |
| R25 | `income_growth_plausibility` | P2 | SoFA | cross-entity | warning | 3 |
| R26 | `treatment_plan_required` | P2 | SoFREP | compliance | warning | 3 |
| R27 | `c_level_readiness` | P2 | SoFREP | operational | warning | 3 |
| R28 | `filing_deadline_check` | P2 | SoFA | compliance | warning | 3 |
| R29 | `diff_test_harness` | P3 | BOTH | testing | N/A | 4 |
| R30 | `invalidity_matrix` | P3 | BOTH | testing | N/A | 4 |
| R31 | `mcdc_coverage` | P3 | BOTH | testing | N/A | 4 |
| R32 | `sofrep_inline_test_data` | P3 | SoFREP | testing | N/A | 4 |
| R33 | `sofrep_package_metadata` | P4 | SoFREP | style | N/A | 4 |
