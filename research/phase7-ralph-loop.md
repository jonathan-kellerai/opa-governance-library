# Phase 7 — Ralph Loop: MINOR Finding Resolution

- **Date:** 2026-03-25
- **Scope:** All MINOR findings from Phase 5 judges (Craftsman, Oracle, Pilot)
- **Method:** 10 autonomous fix rounds with test verification after each

---

## Round Summary

| Round | Source | Finding | Files Changed | Tests Added |
|-------|--------|---------|---------------|-------------|
| 1 | Oracle | info+warning merge drowns genuine warnings in materiality noise | `sofa.rego` | 2 |
| 2 | Pilot | Rule names are machine IDs — add `title` field for human-readable names | `sofa.rego`, `sofrep.rego` | 2 |
| 3 | Craftsman | Cosmetic sprintf inconsistency ("out of bounds" vs "out of range") | `sofrep.rego` | 0 |
| 4 | Craftsman | Missing Scotland jurisdiction test for `filing_deadline_check` | `sofa_test.rego` | 2 |
| 5 | Craftsman | Missing test for `computed_income` fallback in `income_growth_plausibility` | `sofa_test.rego` | 2 |
| 6 | Pilot | Stale data detection — add `schema_effective_date` field and warning rule | `sofa.rego`, `schema.json` (SoFA) | 3 |
| 7 | Pilot | No `opa bench` baseline in repository | `bench.sh`, testdata files | 0 (benchmark script) |
| 8 | Pilot | String length caps on fields in error messages (truncate to 200 chars) | `sofa.rego`, `sofrep.rego` | 1 |
| 9 | Craftsman R33 | SoFREP missing package-level METADATA block | `sofrep.rego` | 0 |
| 10 | Pilot | SoFREP stale data detection — add `schema_effective_date` + rule | `sofrep.rego`, `schema.json` (SoFREP) | 3 |

---

## Round Details

### Round 1: Separate info from warnings in SoFA result

**Finding (Oracle):** SoFA merges info+warning into one `warnings` set, drowning genuine warnings in materiality noise.

**Fix:** Split `warnings` into two separate sets:
- `warnings` now contains only `severity == "warning"` entries
- `info_items` contains only `severity == "info"` entries
- `summary` now exposes `info_count` and `info` alongside existing `warning_count` and `warnings`

**Files:** `sofa/standard/sofa.rego` (result section)
**Tests added:** `test_info_items_separated_from_warnings`, `test_info_count_in_summary`
**Result:** 84/84 PASS

### Round 2: Add rule_titles lookup map for human-readable names

**Finding (Pilot):** Rule names (`data_sentinel`, `net_movement_check`) are machine IDs — non-technical auditors cannot interpret them.

**Fix:** Added `rule_titles` exported rule to both policies — a map from machine rule ID to human-readable title (e.g., `"data_sentinel"` -> `"Data Configuration Missing"`). Consumers can join deny entries against this map for display.

**Files:** `sofa/standard/sofa.rego`, `sofrep/standard/sofrep.rego`
**Tests added:** `test_rule_titles_map_exists` (both policies)
**Result:** 85/85 SoFA, 87/87 SoFREP PASS

### Round 3: Fix cosmetic sprintf inconsistency

**Finding (Craftsman):** SoFA uses `"out of range"` while SoFREP uses `"out of bounds"` for threshold_bounds messages.

**Fix:** Standardized SoFREP to use `"out of range"` to match SoFA.

**Files:** `sofrep/standard/sofrep.rego`
**Result:** 87/87 SoFREP PASS

### Round 4: Add Scotland jurisdiction test for filing_deadline_check

**Finding (Craftsman):** No test exercising the Scotland-specific 273-day filing deadline.

**Fix:** Added two tests:
- `test_filing_deadline_scotland_fires` — verifies Scotland's 273-day deadline fires correctly
- `test_filing_deadline_scotland_within_limit_no_fire` — verifies boundary case at exactly 273 days

Note: Tests must remove `filing_deadline_days` from thresholds to let the jurisdiction-specific `_filing_deadline_days("scotland")` default take effect.

**Files:** `sofa/standard/sofa_test.rego`
**Result:** 87/87 SoFA PASS

### Round 5: Add test for computed_income fallback

**Finding (Craftsman):** No test exercising the `computed_income` fallback path when `incoming_resources_total` is absent.

**Fix:** Added two tests:
- `test_income_growth_plausibility_computed_income_fallback` — fires when computed income from line items exceeds threshold
- `test_income_growth_plausibility_computed_income_fallback_no_fire` — no fire when ratio is within limits

**Files:** `sofa/standard/sofa_test.rego`
**Result:** 89/89 SoFA PASS

### Round 6: Schema staleness detection for SoFA

**Finding (Pilot):** No mechanism to detect stale schema data. If `schema.json` is outdated, the policy silently enforces obsolete rules.

**Fix:**
- Added `schema_effective_date` field to `sofa/standard/schema.json` (set to `"2025-01-01"`)
- Added `schema_staleness` warning rule: fires when `report_date` is >365 days after `schema_effective_date`
- Added entry to `rule_titles` map

**Files:** `sofa/standard/sofa.rego`, `sofa/standard/schema.json`
**Tests added:** `test_schema_staleness_fires_when_old`, `test_schema_staleness_no_fire_when_current`, `test_schema_staleness_no_fire_when_absent`
**Result:** 92/92 SoFA PASS

### Round 7: Benchmark script

**Finding (Pilot):** No `opa bench` baseline in the repository.

**Fix:** Created `bench.sh` — a benchmark script that:
- Runs `opa bench` against both policies with valid input fixtures
- Measures `summary` and `deny` query performance (ns/op, B/op, allocs/op)
- Reports test suite timing
- Created `sofa/standard/testdata/valid_input.json` and `sofrep/standard/testdata/valid_input.json`

**Verified:** Script runs successfully. SoFA summary: ~740K ns/op, SoFREP summary: ~2.4M ns/op.

### Round 8: String length truncation in error messages

**Finding (Pilot):** No string length caps on user-controlled fields in error messages. A 1MB field value produces multi-megabyte deny messages.

**Fix:**
- Added `_truncate(s)` helper to both policies — truncates strings >200 chars with `...[truncated, len=N]` suffix
- Applied `_truncate` to deny messages that embed user-controlled string values:
  - SoFA: `accounting_basis`, `income_category`, `expense_category`, `fund_type`
  - SoFREP: `classification_enum`, `priority_enum`, `urgency_enum`

**Files:** `sofa/standard/sofa.rego`, `sofrep/standard/sofrep.rego`
**Tests added:** `test_truncate_long_category_in_error_msg`
**Result:** 93/93 SoFA, 87/87 SoFREP PASS

### Round 9: SoFREP METADATA block

**Finding (Craftsman R33):** SoFREP missing package-level `# METADATA` block.

**Fix:** Added `# METADATA` block with `title`, `description`, `authors`, `custom.version`, `entrypoint` matching SoFA's format.

**Files:** `sofrep/standard/sofrep.rego`
**Result:** 87/87 SoFREP PASS

### Round 10: Schema staleness detection for SoFREP

**Finding (Pilot):** Same stale data detection gap as SoFA.

**Fix:**
- Added `schema_effective_date` field to `sofrep/standard/schema.json` (set to `"2026-01-01"`)
- Added `schema_staleness` warning rule: fires when `_end_date` (reporting period end) is >365 days after `schema_effective_date`
- Added entry to `rule_titles` map

**Files:** `sofrep/standard/sofrep.rego`, `sofrep/standard/schema.json`
**Tests added:** `test_schema_staleness_fires_when_old`, `test_schema_staleness_no_fire_when_current`, `test_schema_staleness_no_fire_when_absent`
**Result:** 90/90 SoFREP PASS

---

## Verified Oracle Finding: max_expense_growth_ratio

**Finding:** Verify `max_expense_growth_ratio` now has a consuming rule.
**Status:** Confirmed present. The `expense_growth_plausibility` rule (sofa.rego:368) consumes this threshold, and it is validated by `threshold_bounds` (sofa.rego:104). No action needed — this was resolved in Phase 6.

---

## Final Test Results

```
SoFA:  PASS: 93/93
SoFREP: PASS: 90/90
```

## Remaining Deferred Items (Not Addressed — P2/P3/P4)

These findings were explicitly out of scope for the Ralph Loop (MINOR priority only, implementation-ready):

- **R24 SORP 2026 category alignment** — P2, requires schema data migration + new rule
- **R29/R30/R31 testing infrastructure** — P3, requires `tests/` directory artifacts
- **R32 SoFREP test inline fixtures** — P3, requires rewriting all SoFREP tests
- **R33 `.regal/config.yaml`** — P4, Regal linter config
