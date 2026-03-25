package sofa.standard_test

import data.sofa.standard as policy
import rego.v1

# --- Schema + thresholds (inline for test isolation) ---

_schema := {
	"required_fields": ["report_date", "entity_name", "currency", "accounting_basis", "incoming_resources", "resources_expended", "net_movement", "fund_balances", "reconciliation"],
	"date_pattern": "^\\d{4}-\\d{2}-\\d{2}$",
	"currency_pattern": "^[A-Z]{3}$",
	"fund_types": ["unrestricted", "restricted", "endowment", "designated"],
	"income_categories": ["voluntary_income", "activities_for_generating_funds", "investment_income", "incoming_from_charitable_activities", "other_incoming"],
	"expense_categories": ["costs_of_generating_funds", "charitable_activities", "governance_costs", "support_costs", "other_expenditure"],
	"line_required": ["description", "amount", "category", "fund_type"],
	"accounting_bases": ["accrual", "cash"],
	"jurisdiction": "england_wales",
}

_thresholds := {
	"materiality_floor": 100,
	"variance_limit": 0.20,
	"min_unrestricted_balance": 0,
	"reconciliation_tolerance": 0.01,
	"going_concern_periods": 2,
	"audit_threshold_major": 1000000,
	"audit_threshold_minor": 250000,
	"audit_asset_threshold": 3260000,
	"exam_threshold": 25000,
	"filing_deadline_days": 304,
	"min_substance_items": 0,
	"max_income_growth_ratio": 5.0,
	"max_expense_growth_ratio": 5.0,
}

# --- Minimal valid input fixture ---

_valid := {
	"report_date": "2025-03-31",
	"entity_name": "Test Charity",
	"currency": "GBP",
	"accounting_basis": "accrual",
	"incoming_resources": [
		{"description": "Donations", "amount": 60000, "category": "voluntary_income", "fund_type": "unrestricted", "reference": "INC-001"},
		{"description": "Grant", "amount": 40000, "category": "incoming_from_charitable_activities", "fund_type": "restricted", "reference": "INC-002"},
		{"description": "Dividends", "amount": 5000, "category": "investment_income", "fund_type": "endowment", "reference": "INC-003"},
	],
	"resources_expended": [
		{"description": "Programmes", "amount": 35000, "category": "charitable_activities", "fund_type": "unrestricted", "reference": "EXP-001"},
		{"description": "Restoration", "amount": 25000, "category": "charitable_activities", "fund_type": "restricted", "reference": "EXP-002"},
		{"description": "Fundraising", "amount": 5000, "category": "costs_of_generating_funds", "fund_type": "unrestricted", "reference": "EXP-003"},
		{"description": "Audit", "amount": 3000, "category": "governance_costs", "fund_type": "unrestricted", "reference": "EXP-004"},
	],
	"net_movement": 37000,
	"fund_balances": {
		"unrestricted": {"opening": 120000, "closing": 137000, "net_movement": 17000},
		"restricted": {
			"opening": 50000, "closing": 65000, "net_movement": 15000,
			"permitted_purposes": ["heritage_restoration", "community_outreach"],
			"expenditures": [{"purpose": "heritage_restoration", "amount": 25000}],
		},
		"endowment": {"opening": 200000, "closing": 205000, "net_movement": 5000, "principal_spent": 0},
	},
	"reconciliation": {"opening_total": 370000, "net_movement": 37000, "closing_total": 407000},
	"transfers": [
		{"from": "unrestricted", "to": "restricted", "amount": 2000},
		{"from": "restricted", "to": "unrestricted", "amount": -2000},
	],
	"current_assets": 95000,
	"current_liabilities": 30000,
	"historical_net_movements": [15000, 22000],
	"prior_period": {
		"incoming_resources_total": 95000,
		"resources_expended_total": 62000,
		"net_movement": 33000,
	},
	"variance_explanations": {"incoming_resources_total": "One-off Heritage Lottery grant"},
}

# ============================================================================
# 1. Valid input passes — zero errors
# ============================================================================

test_valid_input_valid_true if {
	policy.valid with input as _valid with data.schema as _schema with data.thresholds as _thresholds
}

test_valid_input_zero_errors if {
	d := policy.errors with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	count(d) == 0
}

# ============================================================================
# 2. Missing required field -> error
# ============================================================================

test_missing_required_field if {
	bad := object.remove(_valid, ["entity_name"])
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "required_field"
	d.field == "entity_name"
	d.severity == "error"
}

# ============================================================================
# 3. Invalid income category -> error
# ============================================================================

test_invalid_income_category if {
	bad := object.union(_valid, {"incoming_resources": [{"description": "X", "amount": 1000, "category": "alchemy", "fund_type": "unrestricted", "reference": "X-001"}]})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "income_category"
	d.severity == "error"
}

# ============================================================================
# 4. Invalid expense category -> error
# ============================================================================

test_invalid_expense_category if {
	bad := object.union(_valid, {"resources_expended": [{"description": "X", "amount": 500, "category": "wizardry", "fund_type": "unrestricted", "reference": "X-002"}]})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "expense_category"
	d.severity == "error"
}

# ============================================================================
# 5. Invalid fund type -> error
# ============================================================================

test_invalid_fund_type if {
	bad := object.union(_valid, {"incoming_resources": [{"description": "X", "amount": 1000, "category": "voluntary_income", "fund_type": "imaginary", "reference": "X-003"}]})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "fund_type"
	d.severity == "error"
}

# ============================================================================
# 6. Net movement mismatch -> error
# ============================================================================

test_net_movement_mismatch if {
	bad := object.union(_valid, {"net_movement": 99999})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "net_movement_check"
	d.severity == "error"
}

# ============================================================================
# 7. Per-fund reconciliation failure -> error
# ============================================================================

test_fund_reconciliation_failure if {
	bad := object.union(_valid, {"fund_balances": object.union(
		_valid.fund_balances,
		{"unrestricted": {"opening": 120000, "closing": 999999, "net_movement": 17000}},
	)})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "fund_reconciliation"
	d.severity == "error"
}

# ============================================================================
# 8. Aggregate reconciliation failure -> error
# ============================================================================

test_aggregate_reconciliation_failure if {
	bad := object.union(_valid, {"reconciliation": {"opening_total": 370000, "net_movement": 37000, "closing_total": 999999}})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "aggregate_reconciliation"
	d.severity == "error"
}

# ============================================================================
# 9. Restricted fund expenditure on non-permitted purpose -> error
# ============================================================================

test_restricted_purpose_violation if {
	bad := object.union(_valid, {"fund_balances": object.union(
		_valid.fund_balances,
		{"restricted": object.union(_valid.fund_balances.restricted, {"expenditures": [{"purpose": "marketing", "amount": 5000}]})},
	)})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "restricted_purpose"
	d.severity == "error"
}

# ============================================================================
# 10. Endowment principal spent -> error
# ============================================================================

test_endowment_principal_spent if {
	bad := object.union(_valid, {"fund_balances": object.union(
		_valid.fund_balances,
		{"endowment": {"opening": 200000, "closing": 205000, "net_movement": 5000, "principal_spent": 5000}},
	)})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "endowment_principal"
	d.severity == "error"
}

# ============================================================================
# 11. Transfer non-zero net -> error
# ============================================================================

test_transfer_netting_failure if {
	bad := object.union(_valid, {"transfers": [
		{"from": "unrestricted", "to": "restricted", "amount": 5000},
		{"from": "restricted", "to": "unrestricted", "amount": 3000},
	]})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "transfer_netting"
	d.severity == "error"
}

# ============================================================================
# 12. Variance >20% without explanation -> warning
# ============================================================================

test_variance_without_explanation if {
	stripped := object.remove(_valid, ["variance_explanations"])
	bad := object.union(stripped, {
		"incoming_resources_total": 105000,
		"prior_period": {
			"incoming_resources_total": 50000,
			"resources_expended_total": 62000,
			"net_movement": 33000,
		},
		"variance_explanations": {},
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "variance_analysis"
	d.severity == "warning"
}

# ============================================================================
# 13. Negative unrestricted closing -> warning
# ============================================================================

test_negative_unrestricted_closing if {
	bad := object.union(_valid, {"fund_balances": object.union(
		_valid.fund_balances,
		{"unrestricted": {"opening": 120000, "closing": -500, "net_movement": -120500}},
	)})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "unrestricted_balance"
	d.severity == "warning"
}

# ============================================================================
# 14. Going concern (2+ negative periods) -> warning
# ============================================================================

test_going_concern if {
	bad := object.union(_valid, {"historical_net_movements": [-3000, -1500]})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "going_concern"
	d.severity == "warning"
}

# ============================================================================
# 15. Cash basis with accrued items -> error
# ============================================================================

test_cash_basis_with_accruals if {
	bad := object.union(_valid, {
		"accounting_basis": "cash",
		"accrued_items": [{"description": "Prepaid rent"}],
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "basis_consistency"
	d.severity == "error"
}

# ============================================================================
# 16. Missing audit reference -> warning
# ============================================================================

test_missing_audit_reference if {
	bad := object.union(_valid, {"incoming_resources": [{"description": "No-ref donation", "amount": 5000, "category": "voluntary_income", "fund_type": "unrestricted"}]})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "audit_reference"
	d.severity == "warning"
}

# ============================================================================
# 17. Materiality floor -> info
# ============================================================================

test_materiality_info if {
	bad := object.union(_valid, {
		"resources_expended": [{"description": "Tiny purchase", "amount": 5, "category": "governance_costs", "fund_type": "unrestricted", "reference": "EXP-T01"}],
		"net_movement": 104995,
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "materiality"
	d.severity == "info"
}

# ============================================================================
# 18. Division-by-zero safety (current_liabilities = 0)
# ============================================================================

test_zero_liabilities_no_crash if {
	safe := object.union(_valid, {"current_liabilities": 0})
	violations := policy.deny with input as safe with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "liquidity_ratio")
}

_has_rule(violations, rule) if {
	some d in violations
	d.rule == rule
}

# ============================================================================
# R1: data_sentinel — meta-validation
# ============================================================================

test_data_sentinel_no_schema if {
	some d in policy.deny with input as _valid with data.schema as {} with data.thresholds as _thresholds
	d.rule == "data_sentinel"
	d.severity == "error"
}

test_data_sentinel_no_thresholds if {
	some d in policy.deny with input as _valid with data.schema as _schema with data.thresholds as {}
	d.rule == "data_sentinel"
	d.severity == "error"
}

test_data_sentinel_empty_required_fields if {
	bad_schema := object.union(_schema, {"required_fields": []})
	some d in policy.deny with input as _valid with data.schema as bad_schema with data.thresholds as _thresholds
	d.rule == "data_sentinel"
}

test_data_sentinel_valid_data_no_fire if {
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "data_sentinel")
}

# ============================================================================
# R3: threshold_bounds — meta-validation
# ============================================================================

test_threshold_bounds_tolerance_too_high if {
	bad_thresh := object.union(_thresholds, {"reconciliation_tolerance": 999999})
	some d in policy.deny with input as _valid with data.schema as _schema with data.thresholds as bad_thresh
	d.rule == "threshold_bounds"
}

test_threshold_bounds_variance_too_low if {
	bad_thresh := object.union(_thresholds, {"variance_limit": 0.001})
	some d in policy.deny with input as _valid with data.schema as _schema with data.thresholds as bad_thresh
	d.rule == "threshold_bounds"
}

test_threshold_bounds_valid_no_fire if {
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "threshold_bounds")
}

test_threshold_bounds_materiality_zero_valid if {
	ok_thresh := object.union(_thresholds, {"materiality_floor": 0})
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as ok_thresh
	not _has_rule(violations, "threshold_bounds")
}

# ============================================================================
# R4: schema_list_nonempty — meta-validation
# ============================================================================

test_schema_list_nonempty_fund_types_empty if {
	bad_schema := object.union(_schema, {"fund_types": []})
	some d in policy.deny with input as _valid with data.schema as bad_schema with data.thresholds as _thresholds
	d.rule == "schema_list_nonempty"
}

test_schema_list_nonempty_valid_no_fire if {
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "schema_list_nonempty")
}

test_schema_list_nonempty_single_required_field_ok if {
	ok_schema := object.union(_schema, {"required_fields": ["report_date"]})
	violations := policy.deny with input as _valid with data.schema as ok_schema with data.thresholds as _thresholds
	not _has_rule(violations, "schema_list_nonempty")
}

# ============================================================================
# R5: required_field — key-presence fix (net_movement: 0 is valid)
# ============================================================================

test_required_field_net_movement_zero_valid if {
	ok := object.union(_valid, {"net_movement": 0})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_required_field_error(violations, "net_movement")
}

test_required_field_key_absent if {
	bad := object.remove(_valid, ["net_movement"])
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "required_field"
	d.field == "net_movement"
}

test_required_field_empty_object_present if {
	ok := object.union(_valid, {"fund_balances": {}})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_required_field_error(violations, "fund_balances")
}

_has_required_field_error(violations, field) if {
	some d in violations
	d.rule == "required_field"
	d.field == field
}

# ============================================================================
# R12: fund_balance_type — type guard for fund balance fields
# ============================================================================

test_fund_balance_type_string_opening if {
	bad := object.union(_valid, {"fund_balances": object.union(
		_valid.fund_balances,
		{"unrestricted": {"opening": "TBD", "closing": 137000, "net_movement": 17000}},
	)})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "fund_balance_type"
	d.severity == "error"
}

test_fund_balance_type_zero_valid if {
	ok := object.union(_valid, {"fund_balances": object.union(
		_valid.fund_balances,
		{"unrestricted": {"opening": 0, "closing": 17000, "net_movement": 17000}},
	)})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "fund_balance_type")
}

test_fund_balance_type_null_closing if {
	bad := object.union(_valid, {"fund_balances": object.union(
		_valid.fund_balances,
		{"unrestricted": {"opening": 120000, "closing": null, "net_movement": 17000}},
	)})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "fund_balance_type"
}

# ============================================================================
# R13: line_required — category_required via _field_present
# ============================================================================

test_line_required_category_absent if {
	bad := object.union(_valid, {"incoming_resources": [{"description": "Donation", "amount": 1000, "fund_type": "unrestricted", "reference": "INC-X"}]})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "line_required"
}

test_line_required_category_null if {
	bad := object.union(_valid, {"incoming_resources": [{"description": "Donation", "amount": 1000, "category": null, "fund_type": "unrestricted", "reference": "INC-X"}]})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "line_required"
}

test_line_required_amount_zero_valid if {
	ok := object.union(_valid, {
		"incoming_resources": [{"description": "Zero donation", "amount": 0, "category": "voluntary_income", "fund_type": "unrestricted", "reference": "INC-Z"}],
		"net_movement": -68000,
	})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_line_required_for_amount(violations)
}

_has_line_required_for_amount(violations) if {
	some d in violations
	d.rule == "line_required"
	contains(d.msg, "amount")
}

# ============================================================================
# R15: minimum_substance — warning when line items below threshold
# ============================================================================

test_minimum_substance_disabled_default if {
	ok := object.union(_valid, {"incoming_resources": [], "resources_expended": [], "net_movement": 0})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "minimum_substance")
}

test_minimum_substance_fires_when_enabled if {
	thresh := object.union(_thresholds, {"min_substance_items": 1})
	bad := object.union(_valid, {"incoming_resources": [], "resources_expended": [], "net_movement": 0})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as thresh
	d.rule == "minimum_substance"
	d.severity == "warning"
}

test_minimum_substance_passes_with_items if {
	thresh := object.union(_thresholds, {"min_substance_items": 1})
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as thresh
	not _has_rule(violations, "minimum_substance")
}

# ============================================================================
# R16: fund_balance_declared — fund_balances keys must be in fund_types
# ============================================================================

test_fund_balance_declared_shadow_fund if {
	bad := object.union(_valid, {"fund_balances": object.union(
		_valid.fund_balances,
		{"shadow_fund": {"opening": 0, "closing": 0, "net_movement": 0}},
	)})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "fund_balance_declared"
	d.severity == "error"
}

test_fund_balance_declared_valid_no_fire if {
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "fund_balance_declared")
}

# ============================================================================
# R17: pattern_anchoring — regex patterns must be anchored
# ============================================================================

test_pattern_anchoring_unanchored_date if {
	bad_schema := object.union(_schema, {"date_pattern": "\\d{4}-\\d{2}-\\d{2}"})
	some d in policy.deny with input as _valid with data.schema as bad_schema with data.thresholds as _thresholds
	d.rule == "pattern_anchoring"
}

test_pattern_anchoring_valid_no_fire if {
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "pattern_anchoring")
}

# ============================================================================
# R22: going_concern_disclosure — IAS 1 disclosure requirement
# ============================================================================

test_going_concern_disclosure_fires if {
	bad := object.union(_valid, {"historical_net_movements": [-3000, -1500]})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "going_concern_disclosure"
	d.severity == "error"
}

test_going_concern_disclosure_present_no_fire if {
	ok := object.union(_valid, {
		"historical_net_movements": [-3000, -1500],
		"going_concern_disclosure": "The charity has secured emergency funding from the Heritage Lottery",
	})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "going_concern_disclosure")
}

test_going_concern_disclosure_empty_string_fires if {
	bad := object.union(_valid, {
		"historical_net_movements": [-3000, -1500],
		"going_concern_disclosure": "",
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "going_concern_disclosure"
}

test_going_concern_disclosure_not_triggered_positive if {
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "going_concern_disclosure")
}

# ============================================================================
# R23: audit_status_check — CC17 audit consistency
# ============================================================================

test_audit_status_check_fires if {
	bad := object.union(_valid, {
		"audit_status": "none",
		"incoming_resources": [{"description": "Big grant", "amount": 1200000, "category": "voluntary_income", "fund_type": "unrestricted", "reference": "INC-BIG"}],
		"resources_expended": [],
		"net_movement": 1200000,
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "audit_status_check"
	d.severity == "warning"
}

test_audit_status_check_audit_ok if {
	ok := object.union(_valid, {
		"audit_status": "audit",
		"incoming_resources": [{"description": "Big grant", "amount": 1200000, "category": "voluntary_income", "fund_type": "unrestricted", "reference": "INC-BIG"}],
		"resources_expended": [],
		"net_movement": 1200000,
	})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "audit_status_check")
}

test_audit_status_check_absent_no_fire if {
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "audit_status_check")
}

# ============================================================================
# R25: income_growth_plausibility — Wirecard plausibility cap
# ============================================================================

test_income_growth_plausibility_fires if {
	bad := object.union(_valid, {
		"incoming_resources_total": 600000,
		"prior_period": object.union(_valid.prior_period, {"incoming_resources_total": 95000}),
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "income_growth_plausibility"
	d.severity == "warning"
}

test_income_growth_plausibility_normal_no_fire if {
	ok := object.union(_valid, {
		"incoming_resources_total": 120000,
		"prior_period": object.union(_valid.prior_period, {"incoming_resources_total": 95000}),
	})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "income_growth_plausibility")
}

test_income_growth_plausibility_zero_prior_no_fire if {
	ok := object.union(_valid, {
		"incoming_resources_total": 999999,
		"prior_period": object.union(_valid.prior_period, {"incoming_resources_total": 0}),
	})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "income_growth_plausibility")
}

# ============================================================================
# PHASE 7 — Round 5: computed_income fallback in income_growth_plausibility
# ============================================================================

test_income_growth_plausibility_computed_income_fallback if {
	# When incoming_resources_total is absent, computed_income is used as fallback.
	# Prior period income: 20000. Computed income from line items: 105000 (60k+40k+5k).
	# Ratio: 105000/20000 = 5.25 > 5.0 threshold -> fires.
	stripped := object.remove(_valid, ["incoming_resources_total"])
	bad := object.union(stripped, {
		"prior_period": object.union(_valid.prior_period, {"incoming_resources_total": 20000}),
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "income_growth_plausibility"
	d.severity == "warning"
}

test_income_growth_plausibility_computed_income_fallback_no_fire if {
	# When incoming_resources_total is absent and computed income is within range
	# Computed income: 105000. Prior: 95000. Ratio: 1.105 < 5.0 -> no fire
	stripped := object.remove(_valid, ["incoming_resources_total"])
	bad := object.union(stripped, {
		"prior_period": object.union(_valid.prior_period, {"incoming_resources_total": 95000}),
	})
	violations := policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "income_growth_plausibility")
}

# ============================================================================
# R28: filing_deadline_check — CC17/OSCR filing deadline
# ============================================================================

test_filing_deadline_check_fires if {
	bad := object.union(_valid, {"filing_date": "2026-03-15"})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "filing_deadline_check"
	d.severity == "warning"
}

test_filing_deadline_check_within_limit_no_fire if {
	ok := object.union(_valid, {"filing_date": "2025-12-15"})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "filing_deadline_check")
}

test_filing_deadline_check_absent_no_fire if {
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "filing_deadline_check")
}

# ============================================================================
# PHASE 7 — Round 4: Scotland jurisdiction filing deadline
# ============================================================================

test_filing_deadline_scotland_fires if {
	# Scotland deadline is 273 days (vs 304 for England/Wales).
	# Remove filing_deadline_days from thresholds to let jurisdiction-specific default take effect.
	# report_date: 2025-03-31, filing_date: 2025-12-30 = 274 days -> fires for Scotland
	scot_thresh := object.remove(_thresholds, ["filing_deadline_days"])
	bad := object.union(_valid, {
		"filing_date": "2025-12-30",
		"jurisdiction": "scotland",
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as scot_thresh
	d.rule == "filing_deadline_check"
	d.severity == "warning"
	contains(d.msg, "scotland")
}

test_filing_deadline_scotland_within_limit_no_fire if {
	# 273 days from 2025-03-31 = 2025-12-29. At boundary -> no fire
	scot_thresh := object.remove(_thresholds, ["filing_deadline_days"])
	ok := object.union(_valid, {
		"filing_date": "2025-12-29",
		"jurisdiction": "scotland",
	})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as scot_thresh
	not _has_rule(violations, "filing_deadline_check")
}

# ============================================================================
# PHASE 6 REGRESSION TESTS — Fix 1: is_number guards on variance_analysis
# ============================================================================

test_variance_analysis_string_values_no_crash if {
	bad := object.union(_valid, {
		"incoming_resources_total": "not_a_number",
		"prior_period": {
			"incoming_resources_total": "also_not_a_number",
			"resources_expended_total": 62000,
			"net_movement": 33000,
		},
		"variance_explanations": {},
	})
	violations := policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "variance_analysis")
}

test_variance_analysis_string_prior_no_fire if {
	bad := object.union(_valid, {
		"incoming_resources_total": 105000,
		"prior_period": {
			"incoming_resources_total": "TBD",
			"resources_expended_total": 62000,
			"net_movement": 33000,
		},
		"variance_explanations": {},
	})
	violations := policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "variance_analysis")
}

# ============================================================================
# PHASE 6 REGRESSION TESTS — Fix 2: is_number guards on liquidity_ratio
# ============================================================================

test_liquidity_ratio_string_values_no_crash if {
	bad := object.union(_valid, {
		"current_assets": "pending",
		"current_liabilities": "pending",
	})
	violations := policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "liquidity_ratio")
}

test_liquidity_ratio_string_liabilities_no_fire if {
	bad := object.union(_valid, {
		"current_assets": 50000,
		"current_liabilities": "TBD",
	})
	violations := policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "liquidity_ratio")
}

# ============================================================================
# PHASE 6 REGRESSION TESTS — Fix 3: is_number guards on transfer_netting
# ============================================================================

test_transfer_netting_string_amount_type_error if {
	bad := object.union(_valid, {"transfers": [
		{"from": "unrestricted", "to": "restricted", "amount": "five thousand"},
		{"from": "restricted", "to": "unrestricted", "amount": -5000},
	]})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "transfer_netting_type"
	d.severity == "error"
}

test_transfer_netting_all_string_amounts_no_netting_rule if {
	bad := object.union(_valid, {"transfers": [
		{"from": "unrestricted", "to": "restricted", "amount": "5000"},
		{"from": "restricted", "to": "unrestricted", "amount": "-5000"},
	]})
	violations := policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "transfer_netting")
}

# ============================================================================
# PHASE 6 REGRESSION TESTS — Fix 4: _days_between RFC3339 accuracy
# ============================================================================

test_filing_deadline_cross_year_boundary if {
	# report_date: 2025-03-31, filing_date: 2026-06-01
	# That is 427 days apart. England/Wales deadline is 304 days, so this should fire.
	bad := object.union(_valid, {"filing_date": "2026-06-01"})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "filing_deadline_check"
	d.severity == "warning"
}

test_filing_deadline_exact_boundary_no_fire if {
	# report_date: 2025-03-31, filing_date: 2026-01-29
	# That is 304 days apart. Should NOT fire (equal to deadline, not exceeding).
	ok := object.union(_valid, {"filing_date": "2026-01-29"})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "filing_deadline_check")
}

# ============================================================================
# PHASE 6 REGRESSION TESTS — Fix 5: expense_growth_plausibility
# ============================================================================

test_expense_growth_plausibility_fires if {
	bad := object.union(_valid, {
		"resources_expended_total": 400000,
		"prior_period": object.union(_valid.prior_period, {"resources_expended_total": 62000}),
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "expense_growth_plausibility"
	d.severity == "warning"
}

test_expense_growth_plausibility_normal_no_fire if {
	ok := object.union(_valid, {
		"resources_expended_total": 80000,
		"prior_period": object.union(_valid.prior_period, {"resources_expended_total": 62000}),
	})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "expense_growth_plausibility")
}

test_expense_growth_plausibility_zero_prior_no_fire if {
	ok := object.union(_valid, {
		"resources_expended_total": 999999,
		"prior_period": object.union(_valid.prior_period, {"resources_expended_total": 0}),
	})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "expense_growth_plausibility")
}

# ============================================================================
# PHASE 6 REGRESSION TESTS — Fix 6: filing_deadline_days wired from thresholds
# ============================================================================

test_filing_deadline_uses_threshold_value if {
	# Set a custom filing_deadline_days of 30 in thresholds.
	# Filing 60 days after report_date should then fire.
	short_thresh := object.union(_thresholds, {"filing_deadline_days": 30})
	bad := object.union(_valid, {"filing_date": "2025-06-15"})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as short_thresh
	d.rule == "filing_deadline_check"
	d.severity == "warning"
}

# ============================================================================
# PHASE 6 REGRESSION TESTS — Fix 7: sentinel collision resistance
# ============================================================================

test_sentinel_collision_string_value if {
	# An input field with value "__MISSING__" should NOT be treated as absent
	# with the new object sentinel
	ok := object.union(_valid, {"entity_name": "__MISSING__"})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_required_field_error(violations, "entity_name")
}

# ============================================================================
# PHASE 6 REGRESSION TESTS — Fix 8: reconciliation_tolerance default
# ============================================================================

test_reconciliation_tolerance_default_when_missing if {
	# Remove reconciliation_tolerance from thresholds — should default to 0.01
	no_tol := object.remove(_thresholds, ["reconciliation_tolerance"])

	# A valid input should still pass with default tolerance
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as no_tol
	not _has_rule(violations, "net_movement_check")
	not _has_rule(violations, "fund_reconciliation")
	not _has_rule(violations, "aggregate_reconciliation")
}

test_reconciliation_tolerance_default_catches_mismatch if {
	# Remove reconciliation_tolerance, provide mismatched net_movement
	no_tol := object.remove(_thresholds, ["reconciliation_tolerance"])
	bad := object.union(_valid, {"net_movement": 99999})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as no_tol
	d.rule == "net_movement_check"
	d.severity == "error"
}

# ============================================================================
# PHASE 6 REGRESSION TESTS — Fix 9: deny cap
# ============================================================================

test_deny_cap_summary_has_deny_count if {
	s := policy.summary with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	is_number(s.deny_count)
}

test_deny_cap_no_truncation_under_limit if {
	s := policy.summary with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule_in_set(s.errors, "deny_cap")
	not _has_rule_in_set(s.warnings, "deny_cap")
}

_has_rule_in_set(s, rule) if {
	some d in s
	d.rule == rule
}

# ============================================================================
# PHASE 6 REGRESSION TESTS — Fix 10: CC17 audit threshold keys wired
# ============================================================================

test_audit_threshold_minor_fires if {
	bad := object.union(_valid, {
		"audit_status": "none",
		"incoming_resources": [{"description": "Mid grant", "amount": 300000, "category": "voluntary_income", "fund_type": "unrestricted", "reference": "INC-MID"}],
		"resources_expended": [],
		"net_movement": 300000,
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "audit_threshold_minor"
	d.severity == "warning"
}

test_audit_threshold_minor_below_no_fire if {
	ok := object.union(_valid, {"audit_status": "none"})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "audit_threshold_minor")
}

test_audit_asset_threshold_fires if {
	bad := object.union(_valid, {
		"audit_status": "independent_examination",
		"total_assets": 4000000,
		"incoming_resources": [{"description": "Big grant", "amount": 300000, "category": "voluntary_income", "fund_type": "unrestricted", "reference": "INC-BIG"}],
		"resources_expended": [],
		"net_movement": 300000,
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "audit_asset_threshold"
	d.severity == "warning"
}

test_audit_asset_threshold_no_fire_low_assets if {
	ok := object.union(_valid, {
		"audit_status": "independent_examination",
		"total_assets": 1000000,
	})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "audit_asset_threshold")
}

test_exam_threshold_fires if {
	bad := object.union(_valid, {
		"audit_status": "audit",
		"incoming_resources": [{"description": "Tiny", "amount": 5000, "category": "voluntary_income", "fund_type": "unrestricted", "reference": "INC-T"}],
		"resources_expended": [],
		"net_movement": 5000,
	})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "exam_threshold"
	d.severity == "info"
}

test_exam_threshold_no_fire_above if {
	ok := object.union(_valid, {"audit_status": "audit"})
	violations := policy.deny with input as ok with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "exam_threshold")
}

# ============================================================================
# PHASE 7 — Round 1: info/warning separation
# ============================================================================

test_info_items_separated_from_warnings if {
	bad := object.union(_valid, {
		"resources_expended": [{"description": "Tiny purchase", "amount": 5, "category": "governance_costs", "fund_type": "unrestricted", "reference": "EXP-T01"}],
		"net_movement": 104995,
	})
	s := policy.summary with input as bad with data.schema as _schema with data.thresholds as _thresholds
	count(s.info) > 0
	# info items should NOT appear in warnings
	every w in s.warnings {
		w.severity == "warning"
	}
	every i in s.info {
		i.severity == "info"
	}
}

test_info_count_in_summary if {
	s := policy.summary with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	is_number(s.info_count)
}

# ============================================================================
# PHASE 7 — Round 2: rule_titles lookup map
# ============================================================================

test_rule_titles_map_exists if {
	titles := policy.rule_titles with data.schema as _schema with data.thresholds as _thresholds
	count(titles) > 0
	titles.data_sentinel == "Data Configuration Missing"
	titles.net_movement_check == "Net Movement Reconciliation Failure"
}

# ============================================================================
# PHASE 7 — Round 6: schema_staleness detection
# ============================================================================

test_schema_staleness_fires_when_old if {
	# Schema effective date 2023-01-01, report date 2025-03-31 = >365 days gap
	stale_schema := object.union(_schema, {"schema_effective_date": "2023-01-01"})
	some d in policy.deny with input as _valid with data.schema as stale_schema with data.thresholds as _thresholds
	d.rule == "schema_staleness"
	d.severity == "warning"
}

test_schema_staleness_no_fire_when_current if {
	# Schema effective date 2025-01-01, report date 2025-03-31 = 89 days -> no fire
	fresh_schema := object.union(_schema, {"schema_effective_date": "2025-01-01"})
	violations := policy.deny with input as _valid with data.schema as fresh_schema with data.thresholds as _thresholds
	not _has_rule(violations, "schema_staleness")
}

test_schema_staleness_no_fire_when_absent if {
	# No schema_effective_date -> no fire
	violations := policy.deny with input as _valid with data.schema as _schema with data.thresholds as _thresholds
	not _has_rule(violations, "schema_staleness")
}

# ============================================================================
# PHASE 7 — Round 8: string length truncation in error messages
# ============================================================================

test_truncate_long_category_in_error_msg if {
	# A 250-char category string should be truncated in the deny message
	long_cat := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bad := object.union(_valid, {"incoming_resources": [{"description": "X", "amount": 1000, "category": long_cat, "fund_type": "unrestricted", "reference": "X-001"}]})
	some d in policy.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.rule == "income_category"
	contains(d.msg, "truncated")
}
