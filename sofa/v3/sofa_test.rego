package sofa.v3_test

import data.sofa.v3 as policy

import rego.v1

# --- Minimal valid SoFA input ---

_valid_input := {
	"funds": [
		{
			"name": "General",
			"type": "unrestricted",
			"debits": 50000,
			"credits": 50000,
			"closing_balance": 12000,
			"expenditures": [],
		},
	],
	"transfers": [],
	"incoming_resources": [{"description": "Donations", "amount": 50000, "reference": "DON-001"}],
	"resources_expended": [{"description": "Salaries", "amount": 38000, "reference": "EXP-001"}],
	"incoming_resources_total": 50000,
	"resources_expended_total": 38000,
	"net_movement": 12000,
	"accounting_basis": "accrual",
	"current_assets": 80000,
	"current_liabilities": 40000,
	"historical_net_movements": [5000, 12000],
}

# 1. Valid input produces no violations
test_valid_input_passes if {
	policy.valid with input as _valid_input
}

# 2. Double-entry imbalance detected
test_double_entry_imbalance if {
	bad := json.patch(_valid_input, [{"op": "replace", "path": "/funds/0/credits", "value": 49000}])
	"double-entry imbalance: debits != credits" in policy.violations with input as bad
}

# 3. Restricted fund expenditure on wrong purpose
test_restricted_fund_violation if {
	restricted_input := json.patch(_valid_input, [{"op": "add", "path": "/funds/-", "value": {
		"name": "ChildWelfare",
		"type": "restricted",
		"debits": 10000,
		"credits": 10000,
		"closing_balance": 5000,
		"permitted_purposes": ["child_welfare", "education"],
		"expenditures": [{"purpose": "marketing", "amount": 2000}],
	}}])
	some v in policy.violations with input as restricted_input
	startswith(v, "restricted fund 'ChildWelfare'")
}

# 4. Endowment principal spent
test_endowment_principal_spent if {
	endow_input := json.patch(_valid_input, [{"op": "add", "path": "/funds/-", "value": {
		"name": "SmithEndowment",
		"type": "endowment",
		"debits": 5000,
		"credits": 5000,
		"closing_balance": 100000,
		"principal_spent": 500,
		"expenditures": [],
	}}])
	some v in policy.violations with input as endow_input
	startswith(v, "endowment 'SmithEndowment'")
}

# 5. Inter-fund transfers don't net to zero
test_transfers_not_zero if {
	bad := json.patch(_valid_input, [{"op": "replace", "path": "/transfers", "value": [
		{"from": "General", "to": "Restricted", "amount": 5000},
		{"from": "Restricted", "to": "General", "amount": -3000},
	]}])
	"inter-fund transfers do not net to zero" in policy.violations with input as bad
}

# 6. Variance >20% without explanation
test_variance_requires_explanation if {
	bad := json.patch(_valid_input, [{
		"op": "add", "path": "/prior_period",
		"value": {
			"incoming_resources_total": 30000,
			"resources_expended_total": 38000,
			"net_movement": 12000,
		},
	}])
	some v in policy.violations with input as bad
	contains(v, "variance >20%")
}

# 7. Missing audit reference on line item
test_missing_reference if {
	bad := json.patch(_valid_input, [{"op": "replace", "path": "/incoming_resources", "value": [
		{"description": "Anon donation", "amount": 1000},
	]}])
	some v in policy.violations with input as bad
	contains(v, "missing audit reference")
}

# 8. Going concern flag on consecutive negative movements
test_going_concern if {
	bad := json.patch(_valid_input, [
		{"op": "replace", "path": "/historical_net_movements", "value": [-3000, -1500]},
	])
	"going concern: net_movement negative for 2+ consecutive periods" in policy.violations with input as bad
}

# 9. Cash basis with accrued items flags inconsistency
test_cash_basis_with_accruals if {
	bad := json.patch(_valid_input, [
		{"op": "replace", "path": "/accounting_basis", "value": "cash"},
		{"op": "add", "path": "/accrued_items", "value": [{"description": "Prepaid rent"}]},
	])
	"mixed basis: accruals present under cash basis" in policy.violations with input as bad
}

# 10. Negative unrestricted closing balance
test_negative_unrestricted_balance if {
	bad := json.patch(_valid_input, [{"op": "replace", "path": "/funds/0/closing_balance", "value": -500}])
	"unrestricted closing balance is not positive" in policy.violations with input as bad
}
