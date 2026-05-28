package audit_trail_test

import data.audit_trail as audit_trail
import rego.v1

# -- fixture: minimal valid audit trail --
_valid := {
	"report_date": "2025-12-31",
	"entity_name": "Test Charity",
	"currency": "GBP",
	"accounting_basis": "accrual",
	"incoming_resources": [
		{"description": "Donations", "amount": 50000, "fund_type": "unrestricted", "category": "donations"},
		{"description": "Grant", "amount": 30000, "fund_type": "restricted", "category": "grants"},
	],
	"resources_expended": [
		{"description": "Programmes", "amount": 35000, "fund_type": "unrestricted", "category": "charitable_activities"},
		{"description": "Admin", "amount": 5000, "fund_type": "unrestricted", "category": "governance"},
	],
	"net_movement": 40000,
	"fund_balances": {
		"unrestricted": {"opening": 100000, "closing": 110000},
		"restricted": {"opening": 50000, "closing": 80000},
	},
	"reconciliation": {"opening_total": 150000, "net_movement": 40000, "closing_total": 190000},
	"historical_net_movements": [5000, 3000],
}

_schema := {
	"required_fields": ["report_date", "entity_name", "currency", "incoming_resources", "resources_expended", "net_movement", "fund_balances"],
	"date_pattern": "^\\d{4}-\\d{2}-\\d{2}$",
	"currency_pattern": "^[A-Z]{3}$",
	"fund_types": ["unrestricted", "restricted", "endowment"],
	"income_categories": ["donations", "grants", "investment_income", "trading_income", "other_income"],
	"expense_categories": ["charitable_activities", "governance", "fundraising", "support_costs", "other_expenditure"],
	"line_required": ["description", "amount", "fund_type", "category"],
	"accounting_bases": ["accrual", "cash"],
}

_thresholds := {
	"materiality_floor": 100,
	"variance_limit": 0.20,
	"min_unrestricted_balance": 0,
	"reconciliation_tolerance": 0.01,
	"going_concern_periods": 2,
}

_data := {"schema": _schema, "thresholds": _thresholds}

# 1. Valid input passes
test_valid_input if {
	audit_trail.valid with input as _valid with data.schema as _schema with data.thresholds as _thresholds
}

# 2. Missing required field triggers error
test_missing_required_field if {
	bad := object.remove(_valid, ["entity_name"])
	some d in audit_trail.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.field == "entity_name"
	d.severity == "error"
}

# 3. Invalid category detected
test_invalid_category if {
	bad := object.union(_valid, {"incoming_resources": [{"description": "X", "amount": 100, "fund_type": "unrestricted", "category": "alchemy"}]})
	some d in audit_trail.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	contains(d.msg, "invalid category")
}

# 4. Net movement mismatch caught
test_net_movement_mismatch if {
	bad := object.union(_valid, {"net_movement": 99999})
	some d in audit_trail.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.field == "net_movement"
	d.severity == "error"
}

# 5. Reconciliation mismatch caught
test_reconciliation_mismatch if {
	bad := object.union(_valid, {"reconciliation": {"opening_total": 150000, "net_movement": 40000, "closing_total": 999999}})
	some d in audit_trail.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	d.field == "reconciliation"
	d.severity == "error"
}

# 6. Going concern fires on consecutive negative movements
test_going_concern if {
	bad := object.union(_valid, {"historical_net_movements": [-100, -200, -50]})
	some d in audit_trail.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	contains(d.msg, "going concern")
}

# 7. Materiality info fires for small amounts
test_materiality_info if {
	bad := object.union(_valid, {
		"resources_expended": [{"description": "Tiny", "amount": 5, "fund_type": "unrestricted", "category": "governance"}],
		"net_movement": 79995,
	})
	some d in audit_trail.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	contains(d.msg, "materiality")
}

# 8. Fund type cross-reference catches orphaned type
test_fund_type_cross_ref if {
	bad := object.union(_valid, {
		"incoming_resources": [{"description": "Gift", "amount": 5000, "fund_type": "endowment", "category": "donations"}],
		"fund_balances": {"unrestricted": {"opening": 100000, "closing": 110000}},
	})
	some d in audit_trail.deny with input as bad with data.schema as _schema with data.thresholds as _thresholds
	contains(d.msg, "absent from fund_balances")
}
