# METADATA
# title: SoFA Standard — Definitive Validation Policy
# description: >
#   Synthesised from V1–V4. Data-driven via data.schema and data.thresholds.
#   Single structured deny set with severity-based triage.
#   Covers structural, financial, reconciliation, fund restriction, variance,
#   liquidity, going concern, audit trail, and materiality rules.
#   Phase 3 hardening: meta-validation, type guards, compliance rules.
# authors:
#   - name: SoFA Policy Team
# custom:
#   version: "2.0.0"
# entrypoint: true
package sofa.standard

import rego.v1

# ============================================================================
# 0. FIELD PRESENCE HELPER (R6)
# ============================================================================
# Returns true when a field is present and semantically non-empty.
# Handles OPA falsy-value edge cases: 0, false, null, "", [], {}.
# Callers that need zero-valid (e.g., numeric amount fields) must use
# `f in obj` directly, not _field_present.

_max_field_len := 200

_truncate(s) := s if {
	is_string(s)
	count(s) <= _max_field_len
}

_truncate(s) := sprintf("%s...[truncated, len=%d]", [substring(s, 0, _max_field_len), count(s)]) if {
	is_string(s)
	count(s) > _max_field_len
}

_truncate(s) := s if {
	not is_string(s)
}

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

# ============================================================================
# 1. DATA ALIASES
# ============================================================================

schema := data.schema

thresholds := data.thresholds

items(section) := object.get(input, section, [])

all_items := array.concat(items("incoming_resources"), items("resources_expended"))

income_cats := {c | some c in schema.income_categories}

expense_cats := {c | some c in schema.expense_categories}

all_cats := income_cats | expense_cats

fund_types := {f | some f in schema.fund_types}

tolerance := object.get(thresholds, "reconciliation_tolerance", 0.01)

# ============================================================================
# 2. META-VALIDATION — sentinel, bounds, list guards (R1, R3, R4, R17)
# ============================================================================

# R1: data_sentinel — fires when data.schema or data.thresholds is missing/empty
# Uses private helpers to detect missing data without referencing bare `data` in deny rules.
_schema_present if {
	is_object(data.schema)
	count(data.schema) > 0
}

_thresholds_present if {
	is_object(data.thresholds)
	count(data.thresholds) > 0
}

_schema_required_fields_present if {
	_schema_present
	count(object.get(schema, "required_fields", [])) > 0
}

deny contains {"msg": "data.schema is missing or empty", "severity": "error", "field": "data.schema", "rule": "data_sentinel"} if {
	not _schema_present
}

deny contains {"msg": "data.thresholds is missing or empty", "severity": "error", "field": "data.thresholds", "rule": "data_sentinel"} if {
	not _thresholds_present
}

deny contains {"msg": "data.schema.required_fields is empty", "severity": "error", "field": "data.schema.required_fields", "rule": "data_sentinel"} if {
	_schema_present
	not _schema_required_fields_present
}

# R3: threshold_bounds — validates thresholds against hard-coded ranges
_threshold_bounds := {
	"reconciliation_tolerance": {"min": 0, "max": 1000},
	"materiality_floor": {"min": 0, "max": 1000000},
	"variance_limit": {"min": 0.01, "max": 1.0},
	"going_concern_periods": {"min": 1, "max": 24},
	"min_unrestricted_balance": {"min": -10000000, "max": 0},
	"audit_threshold_major": {"min": 500000, "max": 5000000},
	"max_income_growth_ratio": {"min": 1.0, "max": 100.0},
	"max_expense_growth_ratio": {"min": 1.0, "max": 100.0},
	"filing_deadline_days": {"min": 30, "max": 730},
	"min_substance_items": {"min": 0, "max": 1000},
}

deny contains {"msg": sprintf("threshold '%s' value %v out of range [%v, %v]", [k, val, bounds.min, bounds.max]), "severity": "error", "field": k, "rule": "threshold_bounds"} if {
	_thresholds_present
	some k, bounds in _threshold_bounds
	val := object.get(thresholds, k, null)
	val != null
	is_number(val)
	val < bounds.min
}

deny contains {"msg": sprintf("threshold '%s' value %v out of range [%v, %v]", [k, val, bounds.min, bounds.max]), "severity": "error", "field": k, "rule": "threshold_bounds"} if {
	_thresholds_present
	some k, bounds in _threshold_bounds
	val := object.get(thresholds, k, null)
	val != null
	is_number(val)
	val > bounds.max
}

# R4: schema_list_nonempty — guards that schema lists have minimum entries
_schema_list_mins := {
	"required_fields": 1,
	"line_required": 1,
	"fund_types": 1,
	"income_categories": 1,
	"expense_categories": 1,
}

deny contains {"msg": sprintf("schema.%s must have at least %d entries", [k, min_len]), "severity": "error", "field": k, "rule": "schema_list_nonempty"} if {
	_schema_present
	some k, min_len in _schema_list_mins
	count(object.get(schema, k, [])) < min_len
}

# R17: pattern_anchoring — asserts regex patterns are anchored with ^ and $
deny contains {"msg": sprintf("schema.%s is not anchored (must start with ^ and end with $)", [k]), "severity": "error", "field": k, "rule": "pattern_anchoring"} if {
	_schema_present
	some k in ["date_pattern", "currency_pattern"]
	pat := object.get(schema, k, "")
	pat != ""
	not startswith(pat, "^")
}

deny contains {"msg": sprintf("schema.%s is not anchored (must start with ^ and end with $)", [k]), "severity": "error", "field": k, "rule": "pattern_anchoring"} if {
	_schema_present
	some k in ["date_pattern", "currency_pattern"]
	pat := object.get(schema, k, "")
	pat != ""
	not endswith(pat, "$")
}

# R35: schema_staleness — warns when report_date is far past schema_effective_date
_schema_effective_date := object.get(schema, "schema_effective_date", "")

deny contains {"msg": sprintf("schema may be stale: effective date %s predates report %s by >365 days", [_schema_effective_date, input.report_date]), "severity": "warning", "field": "data.schema", "rule": "schema_staleness"} if {
	_schema_present
	_schema_effective_date != ""
	input.report_date
	_days_between(_schema_effective_date, input.report_date) > 365
}

# ============================================================================
# 3. STRUCTURAL RULES — required fields, types, formats
# ============================================================================

# R5: Fix not input[f] -> not f in input (key-presence check)
# Note: null is treated as missing (key present but unset)
deny contains {"msg": sprintf("missing required field: %s", [f]), "severity": "error", "field": f, "rule": "required_field"} if {
	some f in schema.required_fields
	not f in object.keys(input)
}

deny contains {"msg": sprintf("missing required field: %s", [f]), "severity": "error", "field": f, "rule": "required_field"} if {
	some f in schema.required_fields
	f in object.keys(input)
	input[f] == null
}

deny contains {"msg": "report_date format invalid (expected YYYY-MM-DD)", "severity": "error", "field": "report_date", "rule": "date_format"} if {
	input.report_date
	not regex.match(schema.date_pattern, input.report_date)
}

deny contains {"msg": "currency must be 3-letter ISO code", "severity": "error", "field": "currency", "rule": "currency_format"} if {
	input.currency
	not regex.match(schema.currency_pattern, input.currency)
}

deny contains {"msg": sprintf("invalid accounting_basis '%s'", [_truncate(input.accounting_basis)]), "severity": "error", "field": "accounting_basis", "rule": "accounting_basis"} if {
	input.accounting_basis
	not input.accounting_basis in {b | some b in schema.accounting_bases}
}

# ============================================================================
# 4. LINE-ITEM RULES — required fields, categories, fund types, references
# ============================================================================

# R13: Fix line_required to use _field_present for non-numeric fields.
# Carve-out: "amount" uses key-presence check since amount: 0 is valid.
deny contains {"msg": sprintf("%s[%d]: missing fields %v", [sec, i, missing]), "severity": "error", "field": sec, "rule": "line_required"} if {
	some sec in ["incoming_resources", "resources_expended"]
	some i, item in items(sec)
	missing := {r |
		some r in schema.line_required
		r == "amount"
		not "amount" in object.keys(item)
	} | {r |
		some r in schema.line_required
		r != "amount"
		not _field_present(item, r)
	}
	count(missing) > 0
}

deny contains {"msg": sprintf("incoming_resources[%d]: invalid income category '%s'", [i, _truncate(item.category)]), "severity": "error", "field": "incoming_resources", "rule": "income_category"} if {
	some i, item in items("incoming_resources")
	item.category
	not item.category in income_cats
}

deny contains {"msg": sprintf("resources_expended[%d]: invalid expense category '%s'", [i, _truncate(item.category)]), "severity": "error", "field": "resources_expended", "rule": "expense_category"} if {
	some i, item in items("resources_expended")
	item.category
	not item.category in expense_cats
}

deny contains {"msg": sprintf("%s[%d]: invalid fund_type '%s'", [sec, i, _truncate(item.fund_type)]), "severity": "error", "field": sec, "rule": "fund_type"} if {
	some sec in ["incoming_resources", "resources_expended"]
	some i, item in items(sec)
	item.fund_type
	not item.fund_type in fund_types
}

deny contains {"msg": sprintf("%s[%d]: missing audit reference", [sec, i]), "severity": "warning", "field": sec, "rule": "audit_reference"} if {
	some sec in ["incoming_resources", "resources_expended"]
	some i, item in items(sec)
	not item.reference
}

# ============================================================================
# 5. TYPE GUARDS (R12)
# ============================================================================

# R12: fund_balance_type — fires when fund balance fields are present but non-numeric
deny contains {"msg": sprintf("fund '%s': field '%s' must be numeric, got: %v", [ft, f, val]), "severity": "error", "field": "fund_balances", "rule": "fund_balance_type"} if {
	some ft, fb in object.get(input, "fund_balances", {})
	some f in ["opening", "net_movement", "closing"]
	f in object.keys(fb)
	val := fb[f]
	not is_number(val)
}

# ============================================================================
# 6. MATHEMATICAL INTEGRITY — totals, net movement
# ============================================================================

computed_income := sum([item.amount | some item in items("incoming_resources"); is_number(item.amount)])

computed_expenditure := sum([item.amount | some item in items("resources_expended"); is_number(item.amount)])

computed_net := computed_income - computed_expenditure

deny contains {"msg": sprintf("net_movement %v != computed %v", [input.net_movement, computed_net]), "severity": "error", "field": "net_movement", "rule": "net_movement_check"} if {
	is_number(input.net_movement)
	abs(input.net_movement - computed_net) > tolerance
}

# ============================================================================
# 7. PER-FUND RECONCILIATION
# ============================================================================

deny contains {"msg": sprintf("fund '%s': opening(%v) + net_movement(%v) != closing(%v)", [ft, fb.opening, fb.net_movement, fb.closing]), "severity": "error", "field": "fund_balances", "rule": "fund_reconciliation"} if {
	some ft, fb in object.get(input, "fund_balances", {})
	is_number(object.get(fb, "opening", null))
	is_number(object.get(fb, "net_movement", null))
	is_number(object.get(fb, "closing", null))
	abs((fb.opening + fb.net_movement) - fb.closing) > tolerance
}

# ============================================================================
# 8. AGGREGATE RECONCILIATION
# ============================================================================

deny contains {"msg": sprintf("reconciliation mismatch: opening(%v) + net(%v) != closing(%v)", [r.opening_total, r.net_movement, r.closing_total]), "severity": "error", "field": "reconciliation", "rule": "aggregate_reconciliation"} if {
	r := object.get(input, "reconciliation", {})
	is_number(object.get(r, "opening_total", null))
	is_number(object.get(r, "net_movement", null))
	is_number(object.get(r, "closing_total", null))
	abs((r.opening_total + r.net_movement) - r.closing_total) > tolerance
}

# ============================================================================
# 9. FUND RESTRICTION RULES
# ============================================================================

deny contains {"msg": sprintf("restricted fund '%s': expenditure purpose '%s' not permitted", [ft, exp.purpose]), "severity": "error", "field": "fund_balances", "rule": "restricted_purpose"} if {
	some ft, fb in object.get(input, "fund_balances", {})
	permitted := object.get(fb, "permitted_purposes", [])
	count(permitted) > 0
	some exp in object.get(fb, "expenditures", [])
	not exp.purpose in {p | some p in permitted}
}

deny contains {"msg": sprintf("endowment '%s': principal_spent %v must be zero", [ft, fb.principal_spent]), "severity": "error", "field": "fund_balances", "rule": "endowment_principal"} if {
	some ft, fb in object.get(input, "fund_balances", {})
	object.get(fb, "principal_spent", 0) > 0
}

# R16: fund_balance_declared — fund_balances keys must be in declared fund_types
deny contains {"msg": sprintf("fund_balances key '%s' not in declared fund_types", [ft]), "severity": "error", "field": "fund_balances", "rule": "fund_balance_declared"} if {
	some ft, _ in object.get(input, "fund_balances", {})
	not ft in fund_types
}

# ============================================================================
# 10. TRANSFER NETTING
# ============================================================================

transfer_net := sum([t.amount | some t in object.get(input, "transfers", []); is_number(t.amount)])

deny contains {"msg": sprintf("inter-fund transfers net to %v, expected 0", [transfer_net]), "severity": "error", "field": "transfers", "rule": "transfer_netting"} if {
	transfers := object.get(input, "transfers", [])
	count(transfers) > 0
	every t in transfers { is_number(t.amount) }
	abs(transfer_net) > tolerance
}

deny contains {"msg": sprintf("transfer[%d]: amount must be numeric", [i]), "severity": "error", "field": "transfers", "rule": "transfer_netting_type"} if {
	some i, t in object.get(input, "transfers", [])
	"amount" in object.keys(t)
	not is_number(t.amount)
}

# ============================================================================
# 11. VARIANCE ANALYSIS
# ============================================================================

deny contains {"msg": sprintf("variance >%v%% on %s unexplained", [thresholds.variance_limit * 100, k]), "severity": "warning", "field": k, "rule": "variance_analysis"} if {
	prior := object.get(input, "prior_period", {})
	some k in ["incoming_resources_total", "resources_expended_total", "net_movement"]
	prior_val := prior[k]
	is_number(prior_val)
	prior_val != 0
	current_val := input[k]
	is_number(current_val)
	abs(current_val - prior_val) / abs(prior_val) > thresholds.variance_limit
	not object.get(input, "variance_explanations", {})[k]
}

# R25: income_growth_plausibility — Wirecard plausibility cap
deny contains {"msg": sprintf("income growth ratio %.1f exceeds plausibility threshold %.1f", [ratio, thresholds.max_income_growth_ratio]), "severity": "warning", "field": "incoming_resources_total", "rule": "income_growth_plausibility"} if {
	prior := object.get(input, "prior_period", {})
	prior_income := object.get(prior, "incoming_resources_total", 0)
	prior_income > 0
	current_income := object.get(input, "incoming_resources_total", computed_income)
	ratio := current_income / prior_income
	ratio > thresholds.max_income_growth_ratio
}

# expense_growth_plausibility — Wirecard defense (expense side)
deny contains {"msg": sprintf("expense growth ratio %.1f exceeds plausibility threshold %.1f", [ratio, thresholds.max_expense_growth_ratio]), "severity": "warning", "field": "resources_expended_total", "rule": "expense_growth_plausibility"} if {
	prior := object.get(input, "prior_period", {})
	prior_expense := object.get(prior, "resources_expended_total", 0)
	prior_expense > 0
	current_expense := object.get(input, "resources_expended_total", computed_expenditure)
	ratio := current_expense / prior_expense
	ratio > thresholds.max_expense_growth_ratio
}

# ============================================================================
# 12. LIQUIDITY
# ============================================================================

deny contains {"msg": sprintf("negative unrestricted closing balance: %v", [fb.closing]), "severity": "warning", "field": "fund_balances", "rule": "unrestricted_balance"} if {
	fb := object.get(object.get(input, "fund_balances", {}), "unrestricted", {})
	is_number(object.get(fb, "closing", null))
	fb.closing < thresholds.min_unrestricted_balance
}

deny contains {"msg": sprintf("current ratio %.2f < 1.0 — liquidity risk", [ratio]), "severity": "warning", "field": "current_liabilities", "rule": "liquidity_ratio"} if {
	cl := object.get(input, "current_liabilities", 0)
	is_number(cl)
	cl > 0
	ca := object.get(input, "current_assets", 0)
	is_number(ca)
	ratio := ca / cl
	ratio < 1.0
}

# ============================================================================
# 13. GOING CONCERN
# ============================================================================

deny contains {"msg": "going concern: negative net_movement for consecutive periods", "severity": "warning", "field": "historical_net_movements", "rule": "going_concern"} if {
	hist := object.get(input, "historical_net_movements", [])
	n := thresholds.going_concern_periods
	count(hist) >= n
	every p in array.slice(hist, count(hist) - n, count(hist)) { p < 0 }
}

# R22: going_concern_disclosure — IAS 1 requires disclosure narrative
deny contains {"msg": "going concern warning triggered: going_concern_disclosure narrative required", "severity": "error", "field": "going_concern_disclosure", "rule": "going_concern_disclosure"} if {
	hist := object.get(input, "historical_net_movements", [])
	n := thresholds.going_concern_periods
	count(hist) >= n
	every p in array.slice(hist, count(hist) - n, count(hist)) { p < 0 }
	not _field_present(input, "going_concern_disclosure")
}

# ============================================================================
# 14. ACCRUAL / CASH BASIS CONSISTENCY
# ============================================================================

deny contains {"msg": "mixed basis: accrued items present under cash accounting", "severity": "error", "field": "accounting_basis", "rule": "basis_consistency"} if {
	object.get(input, "accounting_basis", "") == "cash"
	count(object.get(input, "accrued_items", [])) > 0
}

# ============================================================================
# 15. MATERIALITY (info severity)
# ============================================================================

deny contains {"msg": sprintf("%s[%d]: amount %v below materiality floor %v", [sec, i, item.amount, thresholds.materiality_floor]), "severity": "info", "field": sec, "rule": "materiality"} if {
	some sec in ["incoming_resources", "resources_expended"]
	some i, item in items(sec)
	is_number(item.amount)
	abs(item.amount) < thresholds.materiality_floor
}

# ============================================================================
# 16. MINIMUM SUBSTANCE (R15)
# ============================================================================

# R15: minimum_substance — fires when line item count is below configurable threshold
# Default min_substance_items: 0 (disabled). Set > 0 to enforce.
deny contains {"msg": "report has no line items: minimum substance requirement not met", "severity": "warning", "field": "incoming_resources", "rule": "minimum_substance"} if {
	min_items := object.get(thresholds, "min_substance_items", 0)
	min_items > 0
	total_line_items := count(items("incoming_resources")) + count(items("resources_expended"))
	total_line_items < min_items
}

# ============================================================================
# 17. COMPLIANCE — audit status, filing deadline
# ============================================================================

# R23: audit_status_check — CC17 audit consistency
deny contains {"msg": sprintf("audit_status '%s' inconsistent with income %v: statutory audit required above %v", [s, computed_income, thresholds.audit_threshold_major]), "severity": "warning", "field": "audit_status", "rule": "audit_status_check"} if {
	s := object.get(input, "audit_status", "")
	s != ""
	s != "audit"
	computed_income > thresholds.audit_threshold_major
}

# CC17: audit_threshold_minor — independent examination required above minor threshold
deny contains {"msg": sprintf("audit_status '%s' inconsistent: income %v exceeds independent examination threshold %v", [s, computed_income, object.get(thresholds, "audit_threshold_minor", 250000)]), "severity": "warning", "field": "audit_status", "rule": "audit_threshold_minor"} if {
	s := object.get(input, "audit_status", "")
	s != ""
	s == "none"
	minor := object.get(thresholds, "audit_threshold_minor", 250000)
	computed_income > minor
}

# CC17: audit_asset_threshold — gross asset threshold triggers audit
deny contains {"msg": sprintf("audit_status '%s' inconsistent: total_assets %v exceeds asset audit threshold %v with income above %v", [s, ta, asset_thresh, minor]), "severity": "warning", "field": "audit_status", "rule": "audit_asset_threshold"} if {
	s := object.get(input, "audit_status", "")
	s != ""
	s != "audit"
	ta := object.get(input, "total_assets", 0)
	is_number(ta)
	asset_thresh := object.get(thresholds, "audit_asset_threshold", 3260000)
	ta > asset_thresh
	minor := object.get(thresholds, "audit_threshold_minor", 250000)
	computed_income > minor
}

# CC17: exam_threshold — below exam threshold, no external scrutiny required
deny contains {"msg": sprintf("audit_status '%s' may be unnecessary: income %v below examination threshold %v", [s, computed_income, exam_thresh]), "severity": "info", "field": "audit_status", "rule": "exam_threshold"} if {
	s := object.get(input, "audit_status", "")
	s in {"audit", "independent_examination"}
	exam_thresh := object.get(thresholds, "exam_threshold", 25000)
	computed_income < exam_thresh
}

# R28: filing_deadline_check — CC17/OSCR filing deadline
_filing_deadline_days("scotland") := 273

_filing_deadline_days("england_wales") := 304

_filing_deadline_days(j) := 304 if {
	not j == "scotland"
	not j == "england_wales"
}

# Date parsing helper: compute days between two YYYY-MM-DD dates using RFC3339
_day_ns := ((24 * 60) * 60) * 1000000000

_days_between(d1, d2) := days if {
	t1 := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [d1]))
	t2 := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [d2]))
	days := (t2 - t1) / _day_ns
}

deny contains {"msg": sprintf("filing_date %s may exceed %d-day deadline for %s jurisdiction", [fd, deadline, jur]), "severity": "warning", "field": "filing_date", "rule": "filing_deadline_check"} if {
	fd := object.get(input, "filing_date", "")
	fd != ""
	rd := object.get(input, "report_date", "")
	rd != ""
	jur := object.get(input, "jurisdiction", "england_wales")
	deadline := object.get(thresholds, "filing_deadline_days", _filing_deadline_days(jur))
	_days_between(rd, fd) > deadline
}

# ============================================================================
# 18. DENY CAP — truncate output when deny count exceeds threshold
# ============================================================================

_max_deny := object.get(thresholds, "max_deny_entries", 100)

_deny_truncated if count(deny) > _max_deny

_capped_deny := {d |
	some i, d in array.slice(sort(deny), 0, _max_deny)
} if {
	_deny_truncated
}

_capped_deny := deny if {
	not _deny_truncated
}

_truncation_entry contains {"msg": sprintf("output truncated: %d additional findings suppressed", [count(deny) - _max_deny]), "severity": "info", "field": "_truncation", "rule": "deny_cap"} if {
	_deny_truncated
}

# ============================================================================
# 19. RULE TITLE LOOKUP — human-readable labels for machine rule IDs
# ============================================================================

rule_titles := {
	"data_sentinel": "Data Configuration Missing",
	"threshold_bounds": "Threshold Value Out of Range",
	"schema_list_nonempty": "Schema List Below Minimum",
	"pattern_anchoring": "Regex Pattern Not Anchored",
	"required_field": "Required Field Missing",
	"date_format": "Date Format Invalid",
	"currency_format": "Currency Code Invalid",
	"accounting_basis": "Accounting Basis Invalid",
	"line_required": "Line Item Missing Required Fields",
	"income_category": "Invalid Income Category",
	"expense_category": "Invalid Expense Category",
	"fund_type": "Invalid Fund Type",
	"audit_reference": "Missing Audit Reference",
	"fund_balance_type": "Fund Balance Field Type Error",
	"net_movement_check": "Net Movement Reconciliation Failure",
	"fund_reconciliation": "Fund Balance Reconciliation Failure",
	"aggregate_reconciliation": "Aggregate Reconciliation Failure",
	"restricted_purpose": "Restricted Fund Purpose Violation",
	"endowment_principal": "Endowment Principal Spending Violation",
	"fund_balance_declared": "Undeclared Fund Type in Balances",
	"transfer_netting": "Inter-Fund Transfer Netting Failure",
	"transfer_netting_type": "Transfer Amount Type Error",
	"variance_analysis": "Unexplained Variance",
	"income_growth_plausibility": "Income Growth Plausibility Warning",
	"expense_growth_plausibility": "Expense Growth Plausibility Warning",
	"unrestricted_balance": "Negative Unrestricted Balance",
	"liquidity_ratio": "Liquidity Ratio Below Threshold",
	"going_concern": "Going Concern Warning",
	"going_concern_disclosure": "Going Concern Disclosure Required",
	"basis_consistency": "Mixed Accounting Basis",
	"materiality": "Below Materiality Floor",
	"minimum_substance": "Minimum Substance Not Met",
	"audit_status_check": "Audit Status Inconsistency",
	"audit_threshold_minor": "Independent Examination Required",
	"audit_asset_threshold": "Asset Audit Threshold Exceeded",
	"exam_threshold": "Examination May Be Unnecessary",
	"filing_deadline_check": "Filing Deadline May Be Exceeded",
	"schema_staleness": "Schema May Be Stale",
	"deny_cap": "Output Truncated",
}

# ============================================================================
# 20. RESULT
# ============================================================================

errors := {d | some d in deny; d.severity == "error"}

warnings := {d | some d in deny; d.severity == "warning"}

info_items := {d | some d in deny; d.severity == "info"}

default valid := false

valid if count(errors) == 0

summary := {
	"valid": valid,
	"error_count": count(errors),
	"warning_count": count(warnings),
	"info_count": count(info_items),
	"errors": {d | some d in _capped_deny; d.severity == "error"} | {d | some d in _truncation_entry},
	"warnings": {d | some d in _capped_deny; d.severity == "warning"} | {d | some d in _truncation_entry},
	"info": {d | some d in _capped_deny; d.severity == "info"},
	"deny_count": count(deny),
}
