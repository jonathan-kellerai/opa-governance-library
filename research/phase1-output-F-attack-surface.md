# Research Output F: Attack Surface Analysis

- **Agent:** DS-3 (Attack Surface Mapper)
- **Date:** 2026-03-25
- **Scope:** SoFA (`sofa/standard/sofa.rego`) and SoFREP (`sofrep/standard/sofrep.rego`) standard policies
- **Method:** Rule-by-rule bypass analysis across three axes: silent non-firing via undefined references, data-document kill switches, and edge-case mishandling

---

## A. Sentinel Rules: Missing `data.schema` / `data.thresholds` (CRITICAL)

**Finding A-1: Neither policy guards against absent data documents.**

| Policy | File:Line | Confidence |
|--------|-----------|------------|
| SoFA | `sofa.rego:21-37` | **High** |
| SoFREP | `sofrep.rego:7-18` | **High** |

Both policies bind `schema := data.schema` and `thresholds := data.thresholds` as bare aliases. If an OPA evaluator loads the policy without the companion `schema.json`, every rule that references `schema.*` or `thresholds.*` evaluates to **undefined** -- not false. The `deny` set is empty, `errors` is empty, and `valid` is `true`. An attacker (or misconfigured deployment) can pass any input through both validators by simply omitting the data document.

**So what:** The policies need a sentinel deny rule that fires when `data.schema` or `data.thresholds` is missing or empty, producing an error-severity finding that blocks `valid`.

---

## B. Per-Rule Silent Non-Firing Analysis (Q1)

### SoFA Policy

| # | Rule Name | File:Line | Missing Field That Silences | Confidence |
|---|-----------|-----------|---------------------------|------------|
| 1 | `required_field` | `sofa.rego:43-46` | Remove `data.schema.required_fields` -- iteration over undefined produces zero bindings, no deny entries | High |
| 2 | `date_format` | `sofa.rego:48-51` | Omit `input.report_date` entirely -- guard `input.report_date` is undefined, rule body never enters | High |
| 3 | `currency_format` | `sofa.rego:53-56` | Omit `input.currency` -- same guard pattern | High |
| 4 | `accounting_basis` | `sofa.rego:58-61` | Omit `input.accounting_basis` -- same guard pattern | High |
| 5 | `line_required` | `sofa.rego:67-72` | Set `input.incoming_resources` to a non-array (e.g., `"yes"`) -- `items()` returns `[]` via `object.get` default, iteration produces nothing | Medium |
| 6 | `income_category` | `sofa.rego:74-78` | Omit `item.category` from line items -- guard `item.category` is undefined, rule skips | High |
| 7 | `expense_category` | `sofa.rego:80-84` | Same as #6 | High |
| 8 | `fund_type` | `sofa.rego:86-91` | Omit `item.fund_type` from line items -- guard `item.fund_type` is undefined | High |
| 9 | `net_movement_check` | `sofa.rego:109-112` | Omit `input.net_movement` -- guard `input.net_movement` is undefined | High |
| 10 | `fund_reconciliation` | `sofa.rego:118-124` | Omit any one of `opening`, `net_movement`, `closing` from a fund balance -- `is_number(null)` fails, rule skips that fund silently | High |
| 11 | `aggregate_reconciliation` | `sofa.rego:130-136` | Same pattern as #10 for reconciliation object | High |
| 12 | `variance_analysis` | `sofa.rego:170-178` | Omit `input.prior_period` or omit any of the three keys inside it -- `prior[k]` is undefined, rule skips | High |
| 13 | `unrestricted_balance` | `sofa.rego:184-188` | Omit `fund_balances.unrestricted` entirely -- nested `object.get` returns `{}`, then `is_number(null)` fails | High |

**So what for #2-4, #6-9:** The guard-then-validate pattern (`input.X` then `not regex.match(...)`) means a field that is **absent** passes both the required_field check (if it's not in `schema.required_fields`) AND the format check. If `currency` is removed from `required_fields` via data manipulation, currency format validation is entirely disabled.

**So what for #10-11:** A fund balance or reconciliation block can contain **non-numeric strings** for `opening`/`closing`/`net_movement` (e.g., `"TBD"`). The `is_number()` guard silently skips validation rather than flagging the type error.

### SoFREP Policy

| # | Rule Name | File:Line | Missing Field That Silences | Confidence |
|---|-----------|-----------|---------------------------|------------|
| 14 | `required_metadata` | `sofrep.rego:23-27` | Remove `data.schema.required_metadata` -- iteration produces nothing | High |
| 15 | `quadrant_presence` | `sofrep.rego:44-47` | Remove `data.schema.quadrants` -- iteration produces nothing, all quadrant checks disabled | High |
| 16 | `base_fields` | `sofrep.rego:56-62` | Remove `data.schema.base_fields` -- iteration produces nothing | High |
| 17 | `quadrant_fields` | `sofrep.rego:65-73` | Remove entries from `data.schema.quadrant_fields` -- missing key returns `[]`, no fields checked | High |
| 18 | `classification_enum` | `sofrep.rego:78-82` | Omit `input.classification` -- `object.get` returns `""`, guard `c != ""` fails, rule skips | High |
| 19 | `priority_enum` | `sofrep.rego:86-92` | Omit `priority` from items -- `object.get` returns `""`, guard fails | High |
| 20 | `likelihood_range` | `sofrep.rego:104-109` | Omit `likelihood` from at_risk items -- `object.get` returns `0`, and `_in_range(0, 1, 5)` fails... but the deny fires with value `0`. This is actually correct. However, omitting `impact` silently produces `risk_score = 0` in the risk matrix (line 181), underreporting risk. | Medium |
| 21 | `unique_ids` | `sofrep.rego:147-155` | Omit `id` from items -- `item1.id` is undefined, comprehension fails, no duplicate detected | High |
| 22 | `staleness` | `sofrep.rego:249-258` | Omit `reporting_period.end_date` -- `_end_date` is `""`, guard `_end_date != ""` fails, all staleness checks disabled | High |

---

## C. Data-Document Kill Switches (Q2)

| Kill Switch | Affected Rules | Effect | Confidence |
|-------------|---------------|--------|------------|
| `data.schema.required_fields = []` | SoFA `required_field` | All required-field checks disabled | High |
| `data.schema.line_required = []` | SoFA `line_required` | Line-item field checks disabled | High |
| `data.schema.fund_types = []` | SoFA `fund_type` | All fund types accepted (empty set, `not X in {}` is always true) -- **wait, this BLOCKS all fund types**. `fund_types` becomes `{}`, and `not item.fund_type in {}` is always true, so every item with a fund_type fires an error. This is the opposite of a kill switch; it's a **denial-of-service vector**. | High |
| `data.schema.income_categories = []` | SoFA `income_category` | Same DoS vector as above -- all income categories rejected | High |
| `data.thresholds.reconciliation_tolerance = 999999999` | SoFA rules 9-12, transfer netting | All reconciliation and netting checks pass regardless of mismatch | High |
| `data.thresholds.materiality_floor = 0` | SoFA `materiality` | All materiality warnings disabled (every `abs(amount) < 0` is false) | High |
| `data.thresholds.variance_limit = 999` | SoFA `variance_analysis` | All variance warnings disabled | High |
| `data.thresholds.going_concern_periods = 999` | SoFA `going_concern` | Going concern never fires (needs 999 consecutive negative periods) | High |
| `data.thresholds.staleness_days = 99999` | SoFREP staleness rules | All staleness warnings disabled | High |
| `data.thresholds.max_owner_items = 99999` | SoFREP `owner_overload` | Owner overload never fires | High |
| `data.thresholds.min_readiness_pct = 0` | SoFREP `low_readiness` | Readiness warning disabled | High |
| `data.schema.quadrants = []` | SoFREP rules 2-9, 11, 19 | Nearly all SoFREP validation disabled | High |

**So what:** Threshold values need minimum/maximum bounds enforced by a separate validation layer, or the policies need built-in range guards on threshold values.

---

## D. Type Confusion (Q3 / Cross-Cutting B)

**Finding D-1: `not object.get(item, f, "") != ""` double-negation is falsy-value-blind.**

- **File:** `sofrep.rego:26`, `sofrep.rego:33-34`, `sofrep.rego:61`
- **Confidence:** High

The pattern `not object.get(input, f, "") != ""` fires when the value equals `""`. But it does NOT fire when the value is `0`, `false`, `null`, or `[]` -- all of which are falsy but pass the `!= ""` check. A field set to `null` or `0` is treated as "present and valid" even though it's semantically empty. This matters for fields like `title`, `description`, and `owner` where `0` or `false` would be nonsensical.

**Finding D-2: SoFA `not input[f]` for required fields treats `0`, `false`, `""`, `[]`, `{}`, `null` as missing.**

- **File:** `sofa.rego:45`
- **Confidence:** High

The expression `not input[f]` evaluates to true when `input[f]` is any falsy value. If `net_movement` is legitimately `0`, the required_field rule fires an error claiming the field is missing. This is a **false positive** for numeric fields with valid zero values.

**Finding D-3: SoFREP `likelihood` defaults to `0` but `_in_range(0, 1, 5)` correctly rejects it.**

- **File:** `sofrep.rego:107-108`
- **Confidence:** Medium

This is actually well-handled -- a missing `likelihood` defaults to `0` which is out of range and produces an error. However, `impact` at line 179 defaults to `0` with no range check, silently producing `risk_score = 0` for items missing `impact`.

---

## E. Severity Gate Correctness (Cross-Cutting C)

**Finding E-1: SoFA `warnings` set includes `info` severity.**

- **File:** `sofa.rego:235`
- **Confidence:** High

`warnings := {d | some d in deny; d.severity in {"warning", "info"}}` -- This is intentional design (info rolled into warnings), but consumers who filter on `warning_count > 0` to decide action will be misled by info-level noise. The `info` severity from materiality (line 222) inflates the warning count.

**Finding E-2: SoFREP `valid` lacks `default` annotation.**

- **File:** `sofrep.rego:322`
- **Confidence:** High

SoFA has `default valid := false` (line 238) but SoFREP has `valid := count(errors) == 0` (line 322) without a `default` declaration. If `deny` is undefined (e.g., because `data.schema` is missing and no rule fires), `errors` is undefined, and `valid` is **undefined** -- not `true` and not `false`. A consumer checking `data.sofrep.standard.valid` gets no value. Depending on the consumer, this may be treated as falsy (safe) or may cause a crash. With SoFA's `default valid := false`, the same scenario returns `false` (safe-by-default). SoFREP lacks this protection.

---

## F. Duplicate Deny Entries (Cross-Cutting D)

**Finding F-1: SoFREP escalation rule can produce identical deny entries from multiple triggers.**

- **File:** `sofrep.rego:299-313`
- **Confidence:** Medium

Four separate rule bodies (lines 299, 303, 307, 311) produce the **identical** deny object: `{"msg": "escalation required: one or more escalation triggers active", "severity": "warning", "field": "escalation", "rule": "escalation_required"}`. Because `deny` is a **set**, identical objects are deduplicated. This is actually safe due to set semantics. No duplicate issue here.

**Finding F-2: SoFREP `unique_ids` rule produces O(n^2) duplicate findings.**

- **File:** `sofrep.rego:147-155`
- **Confidence:** High

If ID "X" appears in `working_well[0]` and `needed[0]`, the rule fires twice: once for `(q1=working_well, i=0, q2=needed, j=0)` and once for `(q1=needed, j=0, q2=working_well, i=0)`. Both produce `{"msg": "duplicate id 'X'..."}` -- identical strings, so set dedup saves us. But if the same ID appears 3+ times, the message is still identical for all pairs, so dedup still works. **No actual issue** due to set semantics, but the rule does O(n^2) work unnecessarily.

---

## G. Minimum Viable Valid Input (Cross-Cutting E)

### SoFA

The smallest passing input must satisfy `required_fields` (9 fields). The test fixture `_valid` at `sofa_test.rego:29-69` is 40 lines with 7 line items, fund balances, reconciliation, transfers, prior period data, and variance explanations. Stripping it to minimum:

```json
{
  "report_date": "2025-01-01", "entity_name": "X", "currency": "GBP",
  "accounting_basis": "accrual",
  "incoming_resources": [], "resources_expended": [],
  "net_movement": 0, "fund_balances": {},
  "reconciliation": {}
}
```

This passes because: empty arrays mean no line-item rules fire; `net_movement: 0` with zero computed income/expenditure is within tolerance; empty `fund_balances` and `reconciliation` objects have no numeric fields so `is_number(null)` guards skip all checks. **This is a skeleton that games the validator** -- a charity with zero income, zero expenditure, no funds, and no reconciliation is not a meaningful SoFA.

### SoFREP

Minimum passing input requires all 4 quadrants as non-empty arrays with items having all base and quadrant-specific fields. The structural requirements are much harder to game. However, an input with 1 item per quadrant (4 items total, all with minimal text values) passes all structural checks. The operational warnings (staleness, readiness, momentum) may fire but don't affect `valid`.

---

## Numbered Recommendations

1. **Add sentinel rules for missing data documents** (`sofa.rego:21`, `sofrep.rego:7`). Confidence: High. Without this, removing the data file silently disables all validation.

2. **Add `default valid := false` to SoFREP** (`sofrep.rego:322`). Confidence: High. Without this, undefined evaluation returns no value instead of safe-default false.

3. **Replace `not input[f]` with explicit key check for required fields** (`sofa.rego:45`). Confidence: High. The current pattern false-positives on `net_movement: 0` and other legitimate zero/falsy values.

4. **Add type-assertion rules for numeric fields** (`sofa.rego:120-122`, `sofa.rego:132-134`). Confidence: High. Non-numeric values in `opening`/`closing`/`net_movement` silently skip reconciliation instead of producing errors.

5. **Add range guards on threshold values** (`sofa.rego:37`, `sofrep.rego:7`). Confidence: High. Setting `reconciliation_tolerance` to a huge number or `materiality_floor` to 0 disables rules without trace.

6. **Fix double-negation falsy-value blindness in SoFREP** (`sofrep.rego:26,33,61`). Confidence: High. Fields set to `0`, `false`, or `null` pass as "present" when they are semantically empty.

7. **Add `impact` range validation in SoFREP** (`sofrep.rego:179`). Confidence: Medium. Missing `impact` defaults to `0`, silently producing `risk_score = 0` and underreporting risk.

8. **Add minimum-substance rules to SoFA** (`sofa.rego:43`). Confidence: Medium. An input with empty arrays for income/expenditure and empty objects for fund_balances/reconciliation passes all checks despite being financially meaningless.

9. **Separate `info` from `warning` in SoFA's `warnings` set** (`sofa.rego:235`). Confidence: Medium. Info-severity materiality findings inflate the warning count, misleading consumers.

10. **Guard category/fund_type rules against absent fields** (`sofa.rego:77,83,89`). Confidence: High. Omitting `category` or `fund_type` from a line item bypasses enum validation silently -- the item is accepted with no category at all.

11. **Add guard for missing `reporting_period.end_date` in SoFREP** (`sofrep.rego:247`). Confidence: High. A missing end_date disables all staleness checks across the entire policy.

12. **Add guard for missing item `id` fields in SoFREP** (`sofrep.rego:147`). Confidence: High. Items without `id` bypass duplicate detection, dependency resolution, and conflict detection.
