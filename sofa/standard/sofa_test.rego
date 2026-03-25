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
}

_thresholds := {
	"materiality_floor": 100,
	"variance_limit": 0.20,
	"min_unrestricted_balance": 0,
	"reconciliation_tolerance": 0.01,
	"going_concern_periods": 2,
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
