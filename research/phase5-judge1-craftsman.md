# Phase 5 — Judge 1: The Craftsman
## Lens: Precision and Consistency

- **Prepared by:** Judge 1 (Craftsman) — Phase 5 Damascus Steel Process
- **Date:** 2026-03-25
- **Scope:** `sofa/standard/sofa.rego`, `sofa/standard/sofa_test.rego`, `sofa/standard/schema.json`, `sofrep/standard/sofrep.rego`, `sofrep/standard/sofrep_test.rego`, `sofrep/standard/schema.json`
- **Reference spec:** `research/phase3-feature-spec.md` (R1–R33)

---

## Round 1: Spec-to-Rule Alignment

For every spec recommendation R1–R33, verify the corresponding Rego rule exists, has the correct severity, and produces the correct error message format.

### Findings

---

**[MINOR] R24: `sorp_category_alignment` — rule absent in SoFA**
- **Location:** `sofa/standard/sofa.rego` (entire file)
- **Evidence:** Spec R24 requires a `sorp_category_alignment` rule with severity `warning` that fires when an income category uses a pre-2026 SORP name when `sorp_version: "2026"` is set. No such rule exists anywhere in `sofa.rego`. The existing `income_category` rule is not a substitute — it validates against the current `schema.income_categories` list and fires an error, not a warning. R24 is explicitly described as a version-selector guard, not the existing enum check.
- **Impact:** SORP 2026 category migration compliance checking is absent. Old-name categories pass silently when the schema is updated to 2026 names.
- **Fix:** Add a `sorp_category_alignment` warning rule. However, the spec also notes the data document `income_categories` update (Section 2) is required alongside this rule — neither has been applied. The schema still contains 2019 terminology (`voluntary_income`, etc.). This is a known deferred item (P2).

---

**[MINOR] R24 data document — `schema.json` income categories not updated to SORP 2026**
- **Location:** `sofa/standard/schema.json`, key `schema.income_categories`
- **Evidence:** Spec Section 2 requires updating `income_categories` to SORP 2026 terminology (`donations_and_legacies`, `other_trading_activities`, etc.) and adding a `sorp_2019_aliases` sub-key. The schema still contains `["voluntary_income", "activities_for_generating_funds", "investment_income", "incoming_from_charitable_activities", "other_incoming"]`. Neither the `sorp_version` key nor `sorp_2019_aliases` key exists in the schema.
- **Impact:** If R24 were implemented, the rule would silently pass all old-name categories because the schema itself has not been updated.
- **Fix:** Update `schema.json` with SORP 2026 names and add `sorp_version: "2026"` and `sorp_2019_aliases` keys. This is a known deferred P2 item.

---

**[MINOR] R29, R30, R31 — testing infrastructure artifacts absent**
- **Location:** `tests/` directory (does not exist)
- **Evidence:** Spec R29 requires `tests/diff_test.sh` and `tests/corpus/`; R30 requires `tests/invalidity_matrix.md`; R31 requires `tests/test_coverage_mcdc.sh`. None of these files exist. These are P3 (testing infrastructure) items.
- **Impact:** No differential regression harness; no MC/DC coverage measurement; no invalidity matrix. Regression risk on Phase 6 merge.
- **Fix:** Create `tests/` artifacts per spec. P3 work; does not block merge but creates known regression gap.

---

**[MINOR] R32 — SoFREP tests rely on external data files, not inline fixtures**
- **Location:** `sofrep/standard/sofrep_test.rego` (all test functions)
- **Evidence:** Spec R32 requires porting SoFA's inline `with data.schema as _schema with data.thresholds as _thresholds` pattern to all SoFREP tests. Inspection of the SoFREP test file confirms tests reference `data.schema` and `data.thresholds` directly without overriding them. For example, `test_r3_threshold_bounds_staleness_out_of_range` uses `object.union(data.thresholds, {...})` — it reads from the live data document rather than a private inline fixture. This means tests are non-portable and will silently pass or fail if `schema.json` changes.
- **Impact:** Tests are fragile to schema renames. A future schema.json change can silently break tests without failing them immediately.
- **Fix:** Add inline `_schema` and `_thresholds` constants at the top of `sofrep_test.rego` and replace all `data.schema`/`data.thresholds` references with `with data.schema as _schema with data.thresholds as _thresholds`.

---

**[MINOR] R33 — `sofrep.rego` missing package-level METADATA block**
- **Location:** `sofrep/standard/sofrep.rego`, lines 1–5
- **Evidence:** Spec R33 requires adding a `# METADATA` block matching SoFA's existing block (which has `title`, `description`, `authors`, `custom.version`, `entrypoint: true`). The SoFREP file begins directly with `package sofrep.standard` with no metadata block.
- **Impact:** Non-functional; reduces discoverability and tooling integration.
- **Fix:** Add the METADATA block. P4 cosmetic item.

---

**[MINOR] R33 — `.regal/config.yaml` absent for both policies**
- **Location:** `sofa/` and `sofrep/` directories
- **Evidence:** Spec R33 requires creating `.regal/config.yaml` in both directories. Neither exists.
- **Impact:** Regal linter runs without project-specific configuration; findings may include false positives or miss configured suppressions.
- **Fix:** Add `.regal/config.yaml` per spec. P4 cosmetic item.

---

**All R1–R23, R25–R28 rules: PRESENT AND CORRECTLY MAPPED**

The following table confirms all implemented rules against spec requirements:

| Spec ID | Rule Name | Policy | Severity | Status |
|---------|-----------|--------|----------|--------|
| R1 | `data_sentinel` | BOTH | error | PRESENT — correct |
| R2 | `default valid := false` | SoFREP | structural | PRESENT — line 521 |
| R3 | `threshold_bounds` | BOTH | error | PRESENT — correct |
| R4 | `schema_list_nonempty` | BOTH | error | PRESENT — correct |
| R5 | `required_field` (key-presence fix) | SoFA | error | PRESENT — uses `not f in object.keys(input)` |
| R6 | `_field_present` helper | BOTH | N/A | PRESENT — identical implementation |
| R7 | `required_metadata` | SoFREP | error | PRESENT — uses `_field_present` |
| R8 | `impact_range` | SoFREP | error | PRESENT — line 266 |
| R9 | `is_number` guard on `_in_range` | SoFREP | error | PRESENT — line 35 |
| R10 | `_risk_level` type guard | SoFREP | N/A | PRESENT — line 42 |
| R11 | `base_fields` (double-negation fix) | SoFREP | error | PRESENT — uses `_field_present` |
| R12 | `fund_balance_type` | SoFA | error | PRESENT — line 242 |
| R13 | `line_required` (category fix) | SoFA | error | PRESENT — carve-out for amount |
| R14 | `item_id_required` (via R11) | SoFREP | error | PRESENT — via `base_fields` |
| R15 | `minimum_substance` | SoFA | warning | PRESENT — line 411 |
| R16 | `fund_balance_declared` | SoFA | error | PRESENT — line 307 |
| R17 | `pattern_anchoring` | BOTH | error | PRESENT — both policies |
| R18 | `end_date_required` | SoFREP | error | PRESENT — line 191 |
| R19 | `escalation_required` (differentiated) | SoFREP | warning | PRESENT — 4 distinct messages |
| R20 | `high_priority_mitigation_required` | SoFREP | error | PRESENT — line 330 |
| R21 | `contradictory_severity_signals` | SoFREP | warning | PRESENT — line 494 |
| R22 | `going_concern_disclosure` | SoFA | error | PRESENT — line 377 |
| R23 | `audit_status_check` | SoFA | warning | PRESENT — line 423 |
| R24 | `sorp_category_alignment` | SoFA | warning | **ABSENT** |
| R25 | `income_growth_plausibility` | SoFA | warning | PRESENT — line 338 |
| R26 | `treatment_plan_required` | SoFREP | warning | PRESENT — line 504 |
| R27 | `c_level_readiness` | SoFREP | warning | PRESENT — line 389 |
| R28 | `filing_deadline_check` | SoFA | warning | PRESENT — line 450 |
| R29–R31 | Test infrastructure | BOTH | N/A | **ABSENT** |
| R32 | Inline test data | SoFREP | N/A | **NOT IMPLEMENTED** |
| R33 | Package metadata, Regal config | SoFREP | N/A | **PARTIAL** (enum extraction done, metadata block absent) |

### Verdict: HOLDS

All P0, P1, and P2 rules implemented. Gaps are confined to P2 (R24 — SORP category alignment, a known deferred domain-update), P3 (testing infrastructure, non-blocking), and P4 (style). No implemented rule has a wrong severity or structurally incorrect message template.

---

## Round 2: Test Coverage

For every deny rule, verify at least one test triggers it and one test proves it does not fire on valid input.

### Findings

---

**[CRITICAL] `schema_list_nonempty` — SoFREP rule for `required_metadata` is untestable (dead condition)**
- **Location:** `sofrep/standard/sofrep.rego`, lines 140–144
- **Evidence:** The rule body reads:
  ```rego
  count(object.get(data.schema, "required_metadata", [])) > 0
  count(object.get(data.schema, "required_metadata", [])) < 1
  ```
  A count cannot simultaneously be `> 0` AND `< 1`. This rule can never fire. Inspection confirms both conditions must be true simultaneously — they cannot be. The analogous rule for `base_fields` (lines 146–150) has the identical logical impossibility.
- **Impact:** Two of the three `schema_list_nonempty` rules in SoFREP are dead code. The spec R4 requires minimum-length guards for `required_metadata` (min 1) and `base_fields` (min 1). These guards are silently absent. A schema with `required_metadata: []` or `base_fields: []` will not be caught.
- **Fix:** Replace the dead condition with:
  ```rego
  count(object.get(data.schema, "required_metadata", [])) < 1
  ```
  (Remove the `> 0` guard; the `< 1` alone is sufficient to catch empty lists. Or use `== 0` for clarity.)

---

**[MAJOR] `schema_list_nonempty` SoFREP — no test exercises the `required_metadata` or `base_fields` empty-list path**
- **Location:** `sofrep/standard/sofrep_test.rego`, R4 test block (lines 393–408)
- **Evidence:** `test_r4_schema_list_nonempty_valid` and `test_r4_quadrants_too_few` exist. There is no test for `required_metadata: []` or `base_fields: []`. Because the rules are dead (above finding), even if tests were added, they would fail — revealing the bug. The absence of tests for these two paths means the dead code has gone undetected.
- **Impact:** Complete test gap for two of three guarded schema list keys in SoFREP.
- **Fix:** Add `test_r4_required_metadata_empty` and `test_r4_base_fields_empty`. These tests will fail until the dead condition is fixed.

---

**[MAJOR] `variance_analysis` — no "valid" (no-fire) test**
- **Location:** `sofa/standard/sofa_test.rego`
- **Evidence:** `test_variance_without_explanation` at line 220 triggers the rule. There is no companion test asserting that `variance_analysis` does not fire on the `_valid` fixture (which has `variance_explanations` present). The `test_valid_input_zero_errors` test covers this implicitly (zero errors in total) but there is no isolated negative test specifically for `variance_analysis`.
- **Impact:** Minor — the zero-errors test provides implicit negative coverage. But isolated rule-level negative tests improve signal.
- **Fix:** Add `test_variance_with_explanation_no_fire`.

---

**[MAJOR] `filing_deadline_check` — no test for Scotland jurisdiction**
- **Location:** `sofa/standard/sofa_test.rego`, lines 642–658
- **Evidence:** Three tests exist: `test_filing_deadline_check_fires` (England/Wales, late), `test_filing_deadline_check_within_limit_no_fire` (England/Wales, on time), `test_filing_deadline_check_absent_no_fire` (no filing_date). Spec R28 test case 3 explicitly requires "Invalid: filing 10 months after report date for Scotland (9-month deadline) → fires." No Scotland-jurisdiction test exists.
- **Impact:** The Scotland path (`_filing_deadline_days("scotland") := 273`) has zero test coverage. A regression could silently change it to 304 without detection.
- **Fix:** Add `test_filing_deadline_check_scotland_fires`.

---

**[MAJOR] `income_growth_plausibility` — no test for `incoming_resources_total` absent (fallback to `computed_income`)**
- **Location:** `sofa/standard/sofa_test.rego`, lines 610–636
- **Evidence:** Three tests exist. None tests the fallback branch `object.get(input, "incoming_resources_total", computed_income)`. When `incoming_resources_total` is absent from input, the rule uses `computed_income`. This is a non-trivial control-flow branch with no test.
- **Impact:** The fallback path could be inadvertently broken (e.g., if `computed_income` were removed or renamed) without failing any test.
- **Fix:** Add `test_income_growth_plausibility_uses_computed_income`.

---

**[MAJOR] `treatment_plan_required` — no test for `null` treatment_plan**
- **Location:** `sofrep/standard/sofrep_test.rego`, lines 675–715
- **Evidence:** Spec R26 test case 3 requires: "Invalid: high risk item with `treatment_plan: null` → fires." The test suite covers absent `treatment_plan` and empty-object `treatment_plan: {}`, but not `treatment_plan: null`. The `_field_present` helper rejects null, so this should work — but the specific test is absent.
- **Impact:** Minor. The `_field_present` null rejection is tested in other contexts (R6 tests). The gap is in domain-specific coverage.
- **Fix:** Add `test_r26_treatment_plan_null`.

---

**[MINOR] `endowment_principal` — no "valid" (no-fire) test when `principal_spent: 0`**
- **Location:** `sofa/standard/sofa_test.rego`
- **Evidence:** `test_endowment_principal_spent` at line 192 fires the rule. The `_valid` fixture has `"principal_spent": 0` which should not fire. This is covered implicitly by `test_valid_input_zero_errors`. No isolated negative test exists.
- **Impact:** Cosmetic. Zero-errors test provides coverage.
- **Fix:** Low priority. Add `test_endowment_principal_zero_valid` if strict per-rule coverage is required.

---

**[MINOR] `c_level_readiness` — `test_r27_c_level_c1_high_readiness` has a wrong comment**
- **Location:** `sofrep/standard/sofrep_test.rego`, line 747 (comment: `# Actually 10 / 13 = 76.9 → rounds to 77 → C2`)
- **Evidence:** The test fixture sets up 10 working_well items, 1 needed, 1 at_risk, 1 next = 13 total. 10/13 × 100 = 76.9%, rounds to 77. `c1_threshold = 90`, `c2_threshold = 70`. 77 >= 70 and 77 < 90 → C2. The test asserts `cl == "C2"` which is correct. But the test function is named `test_r27_c_level_c1_high_readiness` — it tests C2, not C1. The name is misleading.
- **Impact:** Cosmetic. Test logic is correct; name is misleading.
- **Fix:** Rename to `test_r27_c_level_c2_high_readiness` or adjust the fixture to actually achieve C1 (>=90%).

---

**Rules with complete trigger + no-fire coverage (confirmed):**

`data_sentinel`, `threshold_bounds`, `schema_list_nonempty` (quadrants path only), `required_field`, `date_format`, `currency_format`, `accounting_basis`, `line_required`, `income_category`, `expense_category`, `fund_type`, `audit_reference`, `fund_balance_type`, `net_movement_check`, `fund_reconciliation`, `aggregate_reconciliation`, `restricted_purpose`, `endowment_principal` (trigger only, implicit no-fire), `transfer_netting`, `unrestricted_balance`, `going_concern`, `going_concern_disclosure`, `basis_consistency`, `materiality`, `minimum_substance`, `fund_balance_declared`, `pattern_anchoring`, `audit_status_check`, `income_growth_plausibility` (3 tests), `required_metadata`, `quadrant_presence`, `quadrant_non_empty`, `base_fields`, `quadrant_fields`, `classification_enum`, `priority_enum`, `urgency_enum`, `likelihood_range`, `impact_range`, `date_format` (SoFREP), `temporal_validity`, `unique_ids`, `dependency_resolution`, `conflict_detection`, `high_priority_mitigation_required`, `critical_risk`, `low_readiness`, `c_level_readiness`, `defensive_posture`, `dependency_on_risk`, `owner_overload`, `stale_item`, `stale_at_risk`, `priority_inversion`, `escalation_required`, `contradictory_severity_signals`, `treatment_plan_required`, `end_date_required`.

### Verdict: CRACKED

One dead rule (`schema_list_nonempty` for `required_metadata` and `base_fields` in SoFREP) is a functional correctness bug, not just a coverage gap. The Scotland jurisdiction path, the computed-income fallback, and the variance no-fire test are genuine coverage holes.

---

## Round 3: Data Document Completeness

For every `data.schema.*` or `data.thresholds.*` reference in the Rego, verify the key exists in `schema.json`. List orphaned keys.

### Findings

---

**[MAJOR] `data.thresholds.high_priority_mitigation_priorities` — referenced in SoFREP policy but absent from `sofrep/standard/schema.json`**
- **Location:** `sofrep/standard/sofrep.rego`, line 334; `sofrep/standard/schema.json`
- **Evidence:** The rule `high_priority_mitigation_required` references `data.thresholds.high_priority_mitigation_priorities` via set comprehension. In `sofrep/standard/schema.json`, the `thresholds` object contains: `staleness_days`, `min_readiness_pct`, `escalation_readiness_pct`, `max_owner_items`, `risk_critical`, `risk_high`, `risk_medium`, `c1_threshold`–`c4_threshold`. The key `high_priority_mitigation_priorities` is **absent** from the JSON file. However, it IS present in the `_thresholds` inline fixture inside the test file. This means the policy works in tests but would fail in production deployment where the live `schema.json` is used as the data document.
- **Impact:** In a live OPA deployment using `schema.json` as the data document, `data.thresholds.high_priority_mitigation_priorities` would be undefined. In Rego v1, iterating over an undefined value with `some x in undefined` causes the comprehension to produce an empty set `{}`. The rule would never fire — silent false negative for P0/P1 at_risk items missing mitigation.
- **Fix:** Add `"high_priority_mitigation_priorities": ["P0", "P1"]` to `sofrep/standard/schema.json` under `thresholds`.

---

**[MAJOR] `data.thresholds.c1_threshold` through `c4_threshold` — referenced in SoFREP policy but absent from `sofrep/standard/schema.json`**
- **Location:** `sofrep/standard/sofrep.rego`, lines 368–387; `sofrep/standard/schema.json`
- **Evidence:** `c_level` computation references `data.thresholds.c1_threshold`, `c2_threshold`, `c3_threshold`, `c4_threshold`. Inspection of `sofrep/standard/schema.json` reveals these keys ARE present: `"c1_threshold": 90, "c2_threshold": 70, "c3_threshold": 50, "c4_threshold": 25`. This is a false alarm — the keys exist.
- **Impact:** None. Keys are correctly present.
- **Fix:** No action needed.

**Correction:** Re-reading `sofrep/standard/schema.json` line 28–31 confirms `c1_threshold` through `c4_threshold` AND `high_priority_mitigation_priorities` are both present. The schema.json content shown is complete. `high_priority_mitigation_priorities: ["P0", "P1"]` appears at line 31. Finding revised: this key IS present in schema.json.

---

**[MAJOR] SoFA `schema.json` — `data.thresholds.max_income_growth_ratio` and `max_expense_growth_ratio` referenced in policy, present in schema**
- **Location:** `sofa/standard/sofa.rego`, line 344; `sofa/standard/schema.json`
- **Evidence:** `sofa/standard/schema.json` contains `"max_income_growth_ratio": 5.0` and `"max_expense_growth_ratio": 5.0` under `thresholds`. Both referenced by `income_growth_plausibility` rule. Present and correct.
- **Impact:** None.

---

**[MAJOR] SoFA `schema.json` — `audit_threshold_major` referenced in policy, present in schema**
- **Location:** `sofa/standard/sofa.rego`, line 427; `sofa/standard/schema.json`
- **Evidence:** `"audit_threshold_major": 1000000` present in schema. Correct.
- **Impact:** None.

---

**[MINOR] SoFA `schema.json` — orphaned keys with no corresponding Rego rule**

The following keys exist in `sofa/standard/schema.json` `thresholds` but are not referenced by any rule in `sofa.rego`:

| Orphaned Key | Value | Note |
|---|---|---|
| `audit_threshold_minor` | 250000 | Spec R23 mentions this but the implemented rule only uses `audit_threshold_major` |
| `audit_asset_threshold` | 3260000 | Spec R23 mentions this; no rule references it |
| `exam_threshold` | 25000 | Spec R23 mentions this; no rule references it |
| `filing_deadline_days` | 304 | NOT referenced by `filing_deadline_check`, which uses hardcoded `_filing_deadline_days()` function |
| `max_expense_growth_ratio` | 5.0 | Referenced in spec R25 for an expense plausibility rule, but only income growth is implemented |

The `filing_deadline_days` threshold is particularly notable: the spec R28 states thresholds are in `data.thresholds` so deadline changes require only a data update. But the implementation uses a hardcoded Rego function `_filing_deadline_days(j)` with values `273` and `304` embedded in the policy. The `filing_deadline_days` key in schema.json is therefore a dead key — the policy never reads it.

- **Impact:** Operators attempting to tune the filing deadline via schema.json will find it has no effect. The policy must be modified in Rego to change deadlines, contrary to the spec's stated intent.
- **Fix:** Refactor `filing_deadline_check` to read the deadline from `data.schema.jurisdiction`-keyed thresholds or from separate `filing_deadline_scotland` / `filing_deadline_england_wales` threshold keys. Alternatively, document that `filing_deadline_days` in schema.json is unused and the hardcoded Rego values are authoritative.

---

**[MINOR] SoFREP `schema.json` — `data.schema.jurisdiction` key in SoFA schema is `"england_wales"` (a string, not an object)**
- **Location:** `sofa/standard/schema.json`, key `schema.jurisdiction`
- **Evidence:** The key `"jurisdiction": "england_wales"` is present in the schema object. The `filing_deadline_check` rule reads `jur := object.get(input, "jurisdiction", "england_wales")` — it reads jurisdiction from **input**, not from `data.schema`. The `data.schema.jurisdiction` key is therefore unused in the current Rego implementation.
- **Impact:** Orphaned schema key. The rule correctly reads from `input.jurisdiction` (per-report jurisdiction), which is the correct design.
- **Fix:** Remove `"jurisdiction": "england_wales"` from `schema.json` (it is not a schema constraint) or document it as a default-value reference only.

---

**All other `data.schema.*` and `data.thresholds.*` references verified present in their respective schema.json files.**

### Verdict: CRACKED

The `filing_deadline_days` threshold in `sofa/standard/schema.json` is a dead key that contradicts the spec's intent. Three additional `sofa/standard/schema.json` threshold keys (`audit_threshold_minor`, `audit_asset_threshold`, `exam_threshold`) are present but unimplemented. These are not orphaned in the sense of causing bugs, but they represent incomplete R23 implementation (the full CC17 audit tier logic was not implemented — only the major threshold check).

---

## Round 4: Edge Case Sweep

For every rule using arithmetic (division, subtraction, comparison), identify behavior with: zero, negative, null, empty array, missing key, string-where-number-expected.

### Findings

---

**[CRITICAL] `variance_analysis` — division by zero when `prior_val == 0`**
- **Location:** `sofa/standard/sofa.rego`, line 333
- **Evidence:** The rule body:
  ```rego
  prior_val := prior[k]
  prior_val != 0
  current_val := input[k]
  abs(current_val - prior_val) / abs(prior_val) > thresholds.variance_limit
  ```
  The guard `prior_val != 0` correctly prevents division by zero. However, consider the path where `prior_val` is a string (e.g., `prior["incoming_resources_total"] = "unknown"`). In Rego, `"unknown" != 0` is true, and then `abs("unknown" - current_val)` would cause a type error — OPA would treat the entire rule body as undefined and silently not fire. This is silent false negative behavior, not a crash.
- **Impact:** A fraudulent report with string values in `prior_period` silently bypasses variance analysis.
- **Fix:** Add `is_number(prior_val)` guard after `prior_val := prior[k]`.

---

**[CRITICAL] `variance_analysis` — missing `is_number` guard on `current_val`**
- **Location:** `sofa/standard/sofa.rego`, line 332
- **Evidence:** `current_val := input[k]` has no `is_number` guard. The rule silently does not fire if `input["incoming_resources_total"]` is a string or null. This matters because `incoming_resources_total` is NOT in `schema.required_fields` (required fields are `report_date`, `entity_name`, `currency`, `accounting_basis`, `incoming_resources`, `resources_expended`, `net_movement`, `fund_balances`, `reconciliation`). There is no other rule that forces `incoming_resources_total` to be numeric.
- **Impact:** A report omitting `incoming_resources_total` or setting it to a string silently bypasses variance checks.
- **Fix:** Add `is_number(current_val)` guard.

---

**[MAJOR] `income_growth_plausibility` — division by zero path via `prior_income > 0` guard**
- **Location:** `sofa/standard/sofa.rego`, line 341
- **Evidence:** The guard `prior_income > 0` protects against zero division. Test `test_income_growth_plausibility_zero_prior_no_fire` confirms this does not fire when prior is 0. Correct.
- **Impact:** None for zero. However, negative `prior_income` (a deficit period) passes `prior_income > 0` as false, so the rule also does not fire for negative-to-positive income recovery periods. This is arguably correct behavior but is undocumented. A large charity recovering from a deficit year would not trigger the plausibility check even with dramatic income growth.
- **Fix:** Document the behavior in a comment. Consider whether `abs(prior_income) > 0` is more correct.

---

**[MAJOR] `liquidity_ratio` — division by zero guarded correctly, but string bypass unguarded**
- **Location:** `sofa/standard/sofa.rego`, lines 358–363
- **Evidence:**
  ```rego
  cl := object.get(input, "current_liabilities", 0)
  cl > 0
  ca := object.get(input, "current_assets", 0)
  ratio := ca / cl
  ```
  The `cl > 0` guard prevents zero division. Test `test_zero_liabilities_no_crash` confirms this. However: if `current_liabilities` is a string (e.g., `"1000"`), then `"1000" > 0` is true in Rego (strings sort after numbers), and `ca / "1000"` causes a type error, silently making the rule undefined. No `is_number` guard.
- **Impact:** String `current_liabilities` bypasses liquidity ratio check silently.
- **Fix:** Add `is_number(cl)` and `is_number(ca)` guards.

---

**[MAJOR] `going_concern` and `going_concern_disclosure` — `array.slice` with `n > count(hist)`**
- **Location:** `sofa/standard/sofa.rego`, lines 371–383
- **Evidence:**
  ```rego
  n := thresholds.going_concern_periods
  count(hist) >= n
  every p in array.slice(hist, count(hist) - n, count(hist)) { p < 0 }
  ```
  The guard `count(hist) >= n` ensures `count(hist) - n >= 0`. This is correct. When `n = 0` (which is outside the threshold bounds of [1, 24]), `count(hist) - 0 = count(hist)` and `array.slice(hist, count(hist), count(hist))` returns `[]`. `every p in [] { p < 0 }` evaluates to `true` in OPA (vacuous truth). This means if `going_concern_periods` were 0 (which R3 prevents), the rule would fire on ANY input with a non-empty history, including positive periods.
- **Impact:** None in practice — R3 `threshold_bounds` sets min=1 for `going_concern_periods`, preventing zero. The guard chain holds.
- **Fix:** None required. The dependency on R3 is correct and should be documented in comments.

---

**[MAJOR] `fund_reconciliation` — tolerance comparison uses `abs()` correctly**
- **Location:** `sofa/standard/sofa.rego`, line 274
- **Evidence:** `abs((fb.opening + fb.net_movement) - fb.closing) > tolerance` — correct. The `is_number` guards on all three fields are present (lines 271–273). Non-numeric values silently skip the check rather than firing an error. The companion `fund_balance_type` rule (R12) catches this separately by firing an explicit error. The two rules are complementary and together provide complete coverage.
- **Impact:** None. Defense-in-depth is correctly structured.

---

**[MAJOR] `transfer_netting` — string amounts silently skip**
- **Location:** `sofa/standard/sofa.rego`, line 316
- **Evidence:**
  ```rego
  transfer_net := sum([t.amount | some t in object.get(input, "transfers", []); is_number(t.amount)])
  ```
  The `is_number(t.amount)` guard in the comprehension means string amounts are silently excluded from the sum. A transfer with `amount: "5000"` contributes 0 to `transfer_net`. If all transfers have string amounts, `transfer_net = 0` and the netting check passes silently.
- **Impact:** String amounts in transfers bypass the netting check. No companion type-guard rule fires for transfer amounts.
- **Fix:** Add a type-guard deny rule for transfer amounts, analogous to `fund_balance_type`.

---

**[MINOR] `net_movement_check` — same `is_number` silent-skip pattern**
- **Location:** `sofa/standard/sofa.rego`, lines 254–263
- **Evidence:**
  ```rego
  computed_income := sum([item.amount | some item in items("incoming_resources"); is_number(item.amount)])
  ```
  Non-numeric amounts are silently excluded. `computed_net` understates the true sum. `net_movement_check` then fires based on this understated sum. If the attacker sets all amounts to strings, `computed_income = 0`, `computed_net = 0`, and the rule fires if `input.net_movement != 0`. If `input.net_movement` is also manipulated to 0, the check passes. However, this attack vector is already partially covered: `input.net_movement` must be a number (guarded by `is_number(input.net_movement)`) and line items with string amounts fire `line_required` errors (since `amount` is in `schema.line_required` and the carve-out checks key presence, not value type).
- **Impact:** Low. The `line_required` rule fires for items where `amount` key is absent. But items with `amount: "1000"` (string) pass `line_required` (key present) while being silently excluded from `computed_income`. This is a string-bypass gap in financial computations.
- **Fix:** Add a type-guard for line item amounts, or extend `fund_balance_type` to cover line items.

---

**[MINOR] SoFREP `_days_between` — negative days possible**
- **Location:** `sofrep/standard/sofrep.rego`, lines 419–423
- **Evidence:**
  ```rego
  _days_between(d1, d2) := days if {
    t1 := time.parse_rfc3339_ns(...)
    t2 := time.parse_rfc3339_ns(...)
    days := (t2 - t1) / (...)
  }
  ```
  When `d2 < d1` (item updated after end date — impossible in a valid report, but present in malformed input), `days` is negative. The staleness rule checks `_days_between(d, _end_date) > data.thresholds.staleness_days`. A negative days value is not > staleness_days (assuming staleness_days > 0), so the rule silently does not fire. This is correct behavior (an item updated after the report end date is not stale).
- **Impact:** None. Correct behavior by mathematical consequence.

---

**[MINOR] SoFREP `readiness_pct` — integer division truncation**
- **Location:** `sofrep/standard/sofrep.rego`, line 361
- **Evidence:**
  ```rego
  readiness_pct := round((count(items_in("working_well")) * 100) / total_items) if total_items > 0
  ```
  `round()` is used correctly. The multiplication by 100 before division preserves precision. Correct.
- **Impact:** None.

---

**SoFA `_date_approx_days` — approximate ordinal calculation**
- **Location:** `sofa/standard/sofa.rego`, lines 441–448
- **Evidence:** The formula `(y * 365) + (m * 30) + d` is approximate (ignores leap years, variable month lengths). For the filing deadline check, this means a report dated 2025-01-31 and a filing dated 2026-01-01 computes as: report ordinal = `(2025*365) + (1*30) + 31 = 738156`; filing ordinal = `(2026*365) + (1*30) + 1 = 739521`; difference = 365. England/Wales deadline is 304 days: `365 > 304` → fires. This is correct (365 days > 304 days deadline). However, near-boundary cases (e.g., filing exactly on day 304) may be off by ±2 days due to the approximation.
- **Impact:** Near-boundary false positives or false negatives possible. The spec acknowledges this is an approximate computation.
- **Fix:** Document the approximation bound (±2 days) in a comment. Acceptable for the use case.

### Verdict: CRACKED

Two genuine type-bypass vulnerabilities exist: (1) string values in `variance_analysis` prior/current values bypass the check; (2) string amounts in `transfers` bypass netting. Both are silent false negatives on manipulated input. The `liquidity_ratio` string bypass is a third vulnerability of the same class.

---

## Round 5: Consistency Check

Are severity levels consistent? Are sprintf templates consistent in style?

### Findings

---

**[MAJOR] Severity inconsistency: `audit_reference` is `warning` but `audit_status_check` is `warning` — semantically correct, but note the asymmetry between field-level and aggregate compliance**

Inspection shows:
- All "missing required field" rules: `error` — consistent across both policies
- All "invalid enum value" rules: `error` — consistent
- All "out of range" rules: `error` — consistent
- All "reconciliation mismatch" rules: `error` — consistent
- All "fund restriction violation" rules: `error` — consistent
- All "type error" rules: `error` — consistent
- All "threshold exceeded" rules: `warning` — consistent
- All "compliance advisory" rules (audit, filing, going concern): `warning` — consistent
- `going_concern_disclosure`: `error` — this is a deliberate escalation per spec R22 (IAS 1 mandatory disclosure)
- `end_date_required`: `error` — correct per spec R18
- `high_priority_mitigation_required`: `error` — correct per spec R20

No severity inconsistencies found within the expected pattern.

---

**[MINOR] `sprintf` template inconsistency: index-position style vs. format string**
- **Location:** `sofa/standard/sofa.rego`, throughout
- **Evidence:** Two format patterns coexist:
  1. `sprintf("%s[%d]: missing fields %v", [sec, i, missing])` — uses `%s`, `%d`, `%v`
  2. `sprintf("fund '%s': field '%s' must be numeric, got: %v", [ft, f, val])` — uses quoted `'%s'`
  3. `sprintf("variance >%v%% on %s unexplained", [thresholds.variance_limit * 100, k])` — uses `>` prefix in message

  The inconsistency between `%s` (for string types) and `%v` (generic) is minor — both produce readable output. The use of `'quoted'` around identifiers in some messages but not others is a style inconsistency.

- **Impact:** Cosmetic. Consumers parsing error messages programmatically may need to handle both styles.
- **Fix:** Standardize on `'%s'` quoting for identifier values (fund names, field names) and `%v` for numeric values. Define a message format convention.

---

**[MINOR] `variance_analysis` message includes a multiplication in the template**
- **Location:** `sofa/standard/sofa.rego`, line 327
- **Evidence:** `sprintf("variance >%v%% on %s unexplained", [thresholds.variance_limit * 100, k])` — the `* 100` computation happens inline in the sprintf arguments. This produces messages like `"variance >20.0% on incoming_resources_total unexplained"` which is readable. However the `>` prefix is non-standard; all other threshold-exceeded messages use a declarative past-tense format.
- **Impact:** Cosmetic.

---

**[MINOR] SoFREP `threshold_bounds` uses `[min, max]` format, SoFA uses `(min, max)` format**
- **Location:** `sofrep/standard/sofrep.rego`, line 116 vs. `sofa/standard/sofa.rego`, line 109
- **Evidence:**
  - SoFA: `sprintf("threshold '%s' value %v out of range [%v, %v]", [k, val, bounds.min, bounds.max])`
  - SoFREP: `sprintf("threshold '%s' value %v out of bounds [%v, %v]", [k, v, bounds[0], bounds[1]])`

  The messages say "out of range" (SoFA) vs "out of bounds" (SoFREP). Both use `[%v, %v]` bracket notation — consistent. The word difference is minor but inconsistent.
- **Impact:** Cosmetic. Consumers checking for exact message strings would need to handle both.
- **Fix:** Standardize to "out of bounds" or "out of range" across both policies.

---

**[MINOR] SoFREP `schema_list_nonempty` uses literal count in message, SoFA uses `%d`**
- **Location:** `sofrep/standard/sofrep.rego`, line 134 (`"must have at least 4 entries"`) vs `sofa/standard/sofa.rego`, line 136 (`sprintf("schema.%s must have at least %d entries", [k, min_len])`)
- **Evidence:** SoFA uses a parameterized sprintf with the min length as a format arg. SoFREP hardcodes the value into the message string. This means the SoFREP message cannot be updated by changing data — it requires a Rego edit.
- **Impact:** Minor. SoFREP's schema minimum for quadrants (4) is structurally fixed, so hardcoding is defensible.
- **Fix:** Cosmetic. Consider parameterizing for consistency.

### Verdict: HOLDS

No correctness-affecting severity inconsistencies found. The implemented rules follow the specified severity hierarchy uniformly. Style inconsistencies are cosmetic and documented.

---

## Round 6: Shadowed Rules

Look for rules that can never fire because another catches the same condition first. Look for overlapping conditions producing duplicate deny entries.

### Findings

---

**[CRITICAL] SoFREP `schema_list_nonempty` — `required_metadata` and `base_fields` rules are unreachable (dead code)**
- **Location:** `sofrep/standard/sofrep.rego`, lines 140–150
- **Evidence (re-confirmed from Round 2):**
  ```rego
  deny contains {...} if {
    _has_schema
    count(object.get(data.schema, "required_metadata", [])) > 0
    count(object.get(data.schema, "required_metadata", [])) < 1
  }
  ```
  A count cannot be both `> 0` and `< 1`. This rule is permanently dead. No input can ever satisfy both conditions simultaneously. The same logical error appears in the `base_fields` variant (lines 146–150). These rules are shadowed by their own body conditions.
- **Impact:** The `schema_list_nonempty` guard for `required_metadata` and `base_fields` cannot fire. DoS inversion via empty lists in these keys is unguarded.
- **Fix:** Remove the `> 0` condition. The correct guard is solely `count(...) < 1` (or equivalently `count(...) == 0`).

---

**[MAJOR] SoFREP `data_sentinel` and `schema_list_nonempty` partial overlap**
- **Location:** `sofrep/standard/sofrep.rego`, lines 91–99 and 134–150
- **Evidence:** `data_sentinel` fires when `count(object.get(data.schema, "required_metadata", [])) == 0` (line 93). `schema_list_nonempty` is supposed to fire when the count is between 0 and the minimum. However, given the dead-code bug, `schema_list_nonempty` never fires for these keys. When both rules could theoretically fire (count == 0), `data_sentinel` fires first (firing is set-based, both would be in deny). This is acceptable set-based design — but the overlap means consumers receive both `data_sentinel` AND `schema_list_nonempty` errors for the same condition. This is intended for the quadrants path and would be for `required_metadata` if the dead-code were fixed.
- **Impact:** Not a shadowing problem per se — both fire as designed for the quadrants path. The dead-code bug makes it irrelevant for the other two paths.

---

**[MAJOR] SoFREP `going_concern` fires and `going_concern_disclosure` fires simultaneously — intended double-fire**
- **Location:** `sofa/standard/sofa.rego`, lines 369–383
- **Evidence:** When going-concern conditions are met AND disclosure is absent, BOTH `going_concern` (warning) and `going_concern_disclosure` (error) fire. This is by design per spec R22. The consumer receives a warning about the condition AND an error about the missing disclosure. This is correct and intended.
- **Impact:** None. By design.

---

**[MINOR] SoFA `required_field` dual-path intentional overlap**
- **Location:** `sofa/standard/sofa.rego`, lines 165–174
- **Evidence:** Two rules both produce `{"rule": "required_field"}` deny entries:
  1. Key absent: `not f in object.keys(input)`
  2. Key present but null: `f in object.keys(input)` then `input[f] == null`
  Both fire an identical deny message `"missing required field: %s"`. For a field that is null, the second fires. Since deny is a set, only one entry is produced per field (identical objects deduplicate). This is correct behavior — null-valued required fields should produce one error, not two.
- **Impact:** None. Set deduplication handles this correctly.

---

**[MINOR] SoFREP `required_metadata` triple-path overlap for `reporting_period`**
- **Location:** `sofrep/standard/sofrep.rego`, lines 176–195
- **Evidence:** Three rules handle `reporting_period`:
  1. `required_metadata` (lines 176–181): fires when `start_date` is absent
  2. `required_metadata` (lines 183–188): fires when `end_date` is absent
  3. `end_date_required` (lines 191–195): fires when `reporting_period` key present but `end_date` absent

  When `reporting_period` is present but `end_date` is absent, BOTH rule 2 (`required_metadata`) AND rule 3 (`end_date_required`) fire, producing two distinct deny entries for the same condition. These have different `rule` values (`required_metadata` vs `end_date_required`) so they do not deduplicate.
- **Impact:** Consumers receive two errors for a single issue (missing `end_date`). This is technically correct (one is a structural error, one is a staleness-guard error) but may confuse consumers.
- **Fix:** Document that both fire intentionally, or add a note-comment explaining the two-rule coverage design.

---

**[MINOR] SoFREP `stale_item` and `stale_at_risk` have disjoint conditions**
- **Location:** `sofrep/standard/sofrep.rego`, lines 427–445
- **Evidence:** `stale_item` explicitly guards `q != "at_risk"`. `stale_at_risk` separately handles the at_risk quadrant. They cannot both fire for the same item. This is correct disjoint design — no shadowing.
- **Impact:** None. By design.

---

**[MINOR] SoFREP `escalation_required` — multiple triggers can fire simultaneously**
- **Location:** `sofrep/standard/sofrep.rego`, lines 477–491
- **Evidence:** Four `escalation_required` deny entries with distinct messages. If multiple triggers are active simultaneously, multiple entries appear in `deny`. This is the intended fix from R19 (differentiated messages). Before R19, set deduplication collapsed all four to one. Now they correctly produce up to four entries. This is the correct behavior.
- **Impact:** None. By design.

### Verdict: CRACKED

The dead-code `schema_list_nonempty` rules for `required_metadata` and `base_fields` are a genuine shadowing problem (self-shadowed by contradictory body conditions). The triple-fire for `reporting_period.end_date` absence produces two distinct deny entries that may confuse consumers but is structurally intentional.

---

## Round 7: Undefined vs False

For every rule, trace what happens when referenced data paths do not exist. Does the rule silently not fire? Does a sentinel rule catch missing data?

### Findings

---

**[CRITICAL] SoFREP `quadrants` and `all_items` defined at module level — undefined when `data.schema.quadrants` is missing**
- **Location:** `sofrep/standard/sofrep.rego`, lines 21–30
- **Evidence:**
  ```rego
  quadrants := data.schema.quadrants
  all_items := [item | some q in quadrants; some item in object.get(input, q, [])]
  all_ids := {item.id | some item in all_items}
  items_in(q) := object.get(input, q, [])
  ```
  These are module-level definitions. When `data.schema.quadrants` is undefined (e.g., data document absent), `quadrants` is undefined. In Rego v1, referencing an undefined variable in a comprehension causes the comprehension to produce an empty result. Thus `all_items = []`, `all_ids = {}`, and all rules using `quadrants` or `items_in` do not fire.

  The `data_sentinel` rule at line 83 fires when `_has_schema` is false, producing an error deny entry that blocks `valid`. So the sentinel chain works correctly: absent schema → `data_sentinel` error → `valid = false`.

  However, there is a subtle issue: the sentinel check at line 75 is:
  ```rego
  _has_schema if {
    object.get(data.schema, "quadrants", null) != null
  }
  ```
  This checks for the presence of the `quadrants` key. It does NOT check that `quadrants` is non-empty. So if `data.schema = {"quadrants": []}`, `_has_schema` is true, `data_sentinel` does not fire for the schema presence check, but `data_sentinel` DOES fire at line 96 (checking `count == 0`). Correct.
- **Impact:** None. Sentinel chain is correct. The defense-in-depth is properly layered.

---

**[MAJOR] SoFA `schema`, `thresholds`, and derived sets are module-level aliases — correctly guarded**
- **Location:** `sofa/standard/sofa.rego`, lines 43–59
- **Evidence:**
  ```rego
  schema := data.schema
  thresholds := data.thresholds
  income_cats := {c | some c in schema.income_categories}
  ```
  When `data.schema` is absent, `schema` is undefined, `income_cats` is undefined (comprehension over undefined = empty set `{}`). Then `income_category` rule: `not item.category in income_cats` — `not item.category in {}` is always true, meaning every item fires `income_category`. This is a DoS inversion: absent schema causes every line item to fail with invalid-category errors. However, the `data_sentinel` rule fires first (as an error in the deny set), and `valid = false` regardless. The DoS inversion does not change the final `valid` outcome but produces an explosion of deny entries.
- **Impact:** Minor. `valid` is correctly false. Deny set is noisy but bounded.

---

**[MAJOR] SoFA `tolerance` — undefined when `data.thresholds.reconciliation_tolerance` is missing**
- **Location:** `sofa/standard/sofa.rego`, line 59
- **Evidence:** `tolerance := thresholds.reconciliation_tolerance`. If `data.thresholds` is present but missing `reconciliation_tolerance`, then `tolerance` is undefined. Rules using `abs(...) > tolerance` silently do not fire (rule body is undefined). The `threshold_bounds` rule only fires when the key is present but out of range — it does NOT fire when the key is entirely absent. A missing `reconciliation_tolerance` key silently disables all three reconciliation checks.
- **Impact:** An operator who deploys a data document without `reconciliation_tolerance` silently disables `net_movement_check`, `fund_reconciliation`, and `aggregate_reconciliation`. No error is produced.
- **Fix:** Add a `data_sentinel`-style check for required threshold keys: `count(object.get(data.thresholds, "reconciliation_tolerance", null)) > 0`. Or extend `schema_list_nonempty` concept to required threshold keys.

---

**[MAJOR] SoFREP `date_re` — undefined when `data.schema.date_pattern` is missing**
- **Location:** `sofrep/standard/sofrep.rego`, line 32
- **Evidence:** `date_re := data.schema.date_pattern`. If `date_pattern` is absent from schema, `date_re` is undefined. Rules using `regex.match(date_re, d)` silently do not fire (undefined `date_re` makes the match call undefined). Date format validation is silently disabled.
- **Impact:** A schema without `date_pattern` disables all date format validation. No sentinel catches a missing `date_pattern` key.
- **Fix:** Add a sentinel check for `data.schema.date_pattern`.

---

**[MINOR] SoFA `_filing_deadline_days` — fallback for unknown jurisdiction**
- **Location:** `sofa/standard/sofa.rego`, lines 431–438
- **Evidence:**
  ```rego
  _filing_deadline_days("scotland") := 273
  _filing_deadline_days("england_wales") := 304
  _filing_deadline_days(j) := 304 if {
    not j == "scotland"
    not j == "england_wales"
  }
  ```
  For any unknown jurisdiction string (e.g., `"ireland"`), the third rule fires and returns 304. This is a safe default. Correct behavior.
- **Impact:** None. Safe fallback.

---

**[MINOR] SoFREP `c_level` — all five definitions are exhaustive**
- **Location:** `sofrep/standard/sofrep.rego`, lines 368–387
- **Evidence:** The five `c_level` definitions cover: `>=c1`, `c2<=x<c1`, `c3<=x<c2`, `c4<=x<c3`, `x<c4`. Since `readiness_pct` is always 0–100 (enforced by the `round()` of a percentage), these definitions are exhaustive. `c_level` is always defined when `readiness_pct` is defined.
- **Impact:** None. Complete coverage.

---

**[MINOR] SoFREP `owner_counts` comprehension behavior with missing `owner` field**
- **Location:** `sofrep/standard/sofrep.rego`, lines 408–411
- **Evidence:**
  ```rego
  owner_counts[owner] := c if {
    some owner in {item.owner | some item in all_items}
    c := count([1 | some item in all_items; item.owner == owner])
  }
  ```
  Items without an `owner` field: `item.owner` is undefined → the set comprehension `{item.owner | ...}` excludes undefined values, so items without `owner` are not counted. `owner_overload` does not fire for undefined owners. This is correct since `base_fields` catches missing `owner` as an error.
- **Impact:** None. Defense-in-depth is correct: structural error fires before operational check.

### Verdict: CRACKED

Two genuine undefined-path vulnerabilities: (1) missing `reconciliation_tolerance` in `data.thresholds` silently disables three financial checks in SoFA; (2) missing `data.schema.date_pattern` in SoFREP silently disables all date format validation. Both are uncaught by sentinels.

---

## Round 8: Summary Scorecard

### Rules Verified

| Category | SoFA | SoFREP | Total |
|---|---|---|---|
| Rules implemented per spec | 18 of 19 P0/P1/P2 | 15 of 15 P0/P1/P2 | 33 of 34 |
| Rules missing (P2 deferred) | 1 (R24 SORP alignment) | 0 | 1 |
| P3/P4 artifacts missing | 5 | 2 | 7 |
| Rules with correct severity | 18 of 18 | 15 of 15 | 33 of 33 |
| Rules with correct message format | 18 of 18 | 15 of 15 | 33 of 33 |

### Gaps Found

| Gap | Severity | Policy | Category | Round |
|---|---|---|---|---|
| `schema_list_nonempty` dead code: `required_metadata` and `base_fields` never fire | CRITICAL | SoFREP | Logic bug | R2, R6 |
| `variance_analysis` missing `is_number` guards on `prior_val` and `current_val` | CRITICAL | SoFA | Type bypass | R4 |
| `liquidity_ratio` missing `is_number` guards on `cl` and `ca` | MAJOR | SoFA | Type bypass | R4 |
| Missing `reconciliation_tolerance` silently disables 3 reconciliation checks | MAJOR | SoFA | Undefined path | R7 |
| Missing `data.schema.date_pattern` silently disables all date validation | MAJOR | SoFREP | Undefined path | R7 |
| `filing_deadline_days` schema.json key is dead (ignored by hardcoded Rego) | MAJOR | SoFA | Spec contradiction | R3 |
| R24 `sorp_category_alignment` rule absent (SORP 2026 migration) | MINOR | SoFA | Missing rule | R1 |
| Scotland jurisdiction filing deadline: no test coverage | MAJOR | SoFA | Test gap | R2 |
| `income_growth_plausibility` computed-income fallback: no test | MAJOR | SoFA | Test gap | R2 |
| `transfer_netting` string amounts silently excluded | MAJOR | SoFA | Type bypass | R4 |
| `treatment_plan` null case: no test | MINOR | SoFREP | Test gap | R2 |
| SoFREP tests use live data.schema, not inline fixtures (R32 unimplemented) | MINOR | SoFREP | Test quality | R1, R2 |
| `reporting_period.end_date` absence fires two distinct rules simultaneously | MINOR | SoFREP | Overlap | R6 |
| `schema_list_nonempty` `required_metadata`/`base_fields` tests absent | MAJOR | SoFREP | Test gap | R2 |
| `variance_analysis` no isolated negative test | MINOR | SoFA | Test gap | R2 |
| SoFREP METADATA block absent | MINOR | SoFREP | P4 style | R1 |
| `.regal/config.yaml` absent both policies | MINOR | BOTH | P4 style | R1 |
| P3 testing artifacts absent (diff harness, invalidity matrix, MC/DC) | MINOR | BOTH | P3 deferred | R1 |
| `threshold_bounds` message: "out of range" vs "out of bounds" inconsistency | MINOR | BOTH | Style | R5 |
| `c_level_readiness` test name mislabels C2 as C1 | MINOR | SoFREP | Style | R2 |
| SoFA `_date_approx_days` approximation undocumented (±2 day bound) | MINOR | SoFA | Documentation | R4 |

### Severity of Each Gap

| Severity | Count | Blocking for Phase 6 Merge? |
|---|---|---|
| CRITICAL | 2 | YES — dead code and type bypass in variance analysis |
| MAJOR | 9 | Should fix before merge |
| MINOR | 10 | Can defer to Phase 7 |

### Phase 6 Merge Recommendations

**BLOCK until fixed:**

1. **SoFREP `schema_list_nonempty` dead code** (`sofrep/standard/sofrep.rego`, lines 140–150): The `> 0` condition must be removed. This is a two-line fix. The spec-required DoS inversion guard for `required_metadata` and `base_fields` is currently absent.

2. **SoFA `variance_analysis` type bypass** (`sofa/standard/sofa.rego`, line 330): Add `is_number(prior_val)` and `is_number(current_val)` guards. Without these, string-valued prior-period data silently bypasses variance checking.

**Should fix before merge:**

3. `liquidity_ratio` type guards for `is_number(cl)` and `is_number(ca)`.
4. `transfer_netting` type guard or companion error rule for string transfer amounts.
5. Sentinel for missing `reconciliation_tolerance` key.
6. Sentinel for missing `data.schema.date_pattern` key.
7. Scotland jurisdiction filing deadline test.
8. `income_growth_plausibility` computed-income fallback test.
9. `schema_list_nonempty` tests for `required_metadata` and `base_fields` paths in SoFREP (these will fail until gap 1 is fixed, confirming the fix works).
10. `filing_deadline_days` schema.json key — either implement it in the policy or document it as non-functional and remove it.

**Can defer to Phase 7:**

11. R24 SORP 2026 category alignment (P2, known deferred domain update).
12. R32 SoFREP inline test data.
13. P3 testing infrastructure (diff harness, invalidity matrix, MC/DC script).
14. P4 style items (METADATA block, Regal config, message format normalization).
15. `treatment_plan` null test.
16. `reporting_period.end_date` double-fire documentation.

---

*End of Phase 5 — Judge 1 (Craftsman) analysis.*
