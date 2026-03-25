# METADATA
# title: SoFA Validator Tests
# description: |
#   Comprehensive test suite for the SoFA v1 validation policy.
#   Covers structural completeness, category validation, mathematical
#   integrity, balance reconciliation, temporal validity, non-negativity,
#   and the happy path (fully valid report).
package sofa.v1_test

import rego.v1

import data.sofa.v1 as sofa

# ============================================================================
# HELPERS — Reusable fixture fragments
# ============================================================================

# A minimal but fully valid SoFA input document. Tests that need to break
# specific rules can override individual fields using the `with` keyword.
_valid_input := {
	"reporting_period": {
		"start_date": "2024-01-01",
		"end_date": "2024-12-31",
	},
	"income": [
		{
			"description": "Individual donations",
			"category": "voluntary_income",
			"amount": 50000,
		},
		{
			"description": "Grant from XYZ Foundation",
			"category": "voluntary_income",
			"amount": 30000,
		},
		{
			"description": "Shop sales",
			"category": "activities_for_generating_funds",
			"amount": 10000,
		},
		{
			"description": "Bank interest",
			"category": "investment_income",
			"amount": 500,
		},
		{
			"description": "Service fees",
			"category": "incoming_from_charitable_activities",
			"amount": 5000,
		},
		{
			"description": "Miscellaneous",
			"category": "other_incoming",
			"amount": 500,
		},
	],
	"expenditure": [
		{
			"description": "Programme delivery",
			"category": "charitable_activities",
			"amount": 60000,
		},
		{
			"description": "Fundraising costs",
			"category": "costs_of_generating_funds",
			"amount": 5000,
		},
		{
			"description": "Audit and legal",
			"category": "governance_costs",
			"amount": 3000,
		},
		{
			"description": "Bank charges",
			"category": "other_expenditure",
			"amount": 200,
		},
	],
	"totals": {
		"total_income": 96000,
		"total_expenditure": 68200,
		"net_movement": 27800,
	},
	"funds": [
		{
			"name": "General Fund",
			"type": "unrestricted",
			"opening_balance": 100000,
			"net_movement": 20000,
			"closing_balance": 120000,
		},
		{
			"name": "Building Fund",
			"type": "restricted",
			"opening_balance": 50000,
			"net_movement": 7800,
			"closing_balance": 57800,
		},
	],
}

# ============================================================================
# TEST 1: Fully valid report produces zero errors
# ============================================================================

test_valid_report_has_no_errors if {
	result := sofa.errors with input as _valid_input
	count(result) == 0
}

test_valid_report_is_valid if {
	sofa.valid with input as _valid_input
}

# ============================================================================
# TEST 2: Missing required sections trigger structural errors
# ============================================================================

test_missing_income_section if {
	bad_input := object.remove(_valid_input, ["income"])
	result := sofa.errors with input as bad_input

	# Should report the missing 'income' section.
	some msg in result
	contains(msg, "income")
	contains(msg, "Missing required top-level section")
}

test_missing_multiple_sections if {
	bad_input := object.remove(_valid_input, ["income", "funds"])
	result := sofa.errors with input as bad_input

	# At least two structural errors.
	count([msg |
		some msg in result
		contains(msg, "Missing required top-level section")
	]) >= 2
}

# ============================================================================
# TEST 3: Invalid income category
# ============================================================================

test_invalid_income_category if {
	bad_income := [{
		"description": "Mystery income",
		"category": "dark_money",
		"amount": 1000,
	}]
	bad_input := object.union(_valid_input, {
		"income": bad_income,
		"totals": object.union(_valid_input.totals, {
			"total_income": 1000,
			"total_expenditure": 68200,
			"net_movement": 1000 - 68200,
		}),
	})
	result := sofa.errors with input as bad_input

	# Should flag "dark_money" as invalid.
	some msg in result
	contains(msg, "dark_money")
	contains(msg, "INCOME")
}

# ============================================================================
# TEST 4: Invalid expenditure category
# ============================================================================

test_invalid_expenditure_category if {
	bad_expenditure := [{
		"description": "CEO bonus",
		"category": "executive_compensation",
		"amount": 500,
	}]
	bad_input := object.union(_valid_input, {
		"expenditure": bad_expenditure,
		"totals": object.union(_valid_input.totals, {
			"total_income": 96000,
			"total_expenditure": 500,
			"net_movement": 96000 - 500,
		}),
	})
	result := sofa.errors with input as bad_input

	some msg in result
	contains(msg, "executive_compensation")
	contains(msg, "EXPENDITURE")
}

# ============================================================================
# TEST 5: Invalid fund type
# ============================================================================

test_invalid_fund_type if {
	bad_funds := [{
		"name": "Slush Fund",
		"type": "secret",
		"opening_balance": 10000,
		"net_movement": 0,
		"closing_balance": 10000,
	}]
	bad_input := object.union(_valid_input, {"funds": bad_funds})
	result := sofa.errors with input as bad_input

	some msg in result
	contains(msg, "secret")
	contains(msg, "FUND")
}

# ============================================================================
# TEST 6: Mathematical integrity — incorrect total_income
# ============================================================================

test_incorrect_total_income if {
	bad_input := object.union(_valid_input, {"totals": object.union(
		_valid_input.totals,
		{"total_income": 999999},
	)})
	result := sofa.errors with input as bad_input

	some msg in result
	contains(msg, "MATH")
	contains(msg, "total_income")
}

# ============================================================================
# TEST 7: Mathematical integrity — incorrect net_movement
# ============================================================================

test_incorrect_net_movement if {
	bad_input := object.union(_valid_input, {"totals": object.union(
		_valid_input.totals,
		{"net_movement": 0},
	)})
	result := sofa.errors with input as bad_input

	some msg in result
	contains(msg, "MATH")
	contains(msg, "net_movement")
}

# ============================================================================
# TEST 8: Balance reconciliation failure
# ============================================================================

test_reconciliation_failure if {
	bad_funds := [{
		"name": "General Fund",
		"type": "unrestricted",
		"opening_balance": 100000,
		"net_movement": 20000,
		"closing_balance": 999999,
	}]
	bad_input := object.union(_valid_input, {"funds": bad_funds})
	result := sofa.errors with input as bad_input

	some msg in result
	contains(msg, "RECONCILIATION")
	contains(msg, "General Fund")
}

# ============================================================================
# TEST 9: Temporal validity — end before start
# ============================================================================

test_end_date_before_start_date if {
	bad_input := object.union(_valid_input, {"reporting_period": {
		"start_date": "2024-12-31",
		"end_date": "2024-01-01",
	}})
	result := sofa.errors with input as bad_input

	some msg in result
	contains(msg, "TEMPORAL")
	contains(msg, "strictly after")
}

# ============================================================================
# TEST 10: Temporal validity — malformed date
# ============================================================================

test_malformed_date if {
	bad_input := object.union(_valid_input, {"reporting_period": {
		"start_date": "not-a-date",
		"end_date": "2024-12-31",
	}})
	result := sofa.errors with input as bad_input

	some msg in result
	contains(msg, "TEMPORAL")
	contains(msg, "not-a-date")
}

# ============================================================================
# TEST 11: Non-negativity — negative income amount
# ============================================================================

test_negative_income_amount if {
	bad_income := [{
		"description": "Refund (wrong sign)",
		"category": "voluntary_income",
		"amount": -500,
	}]
	bad_input := object.union(_valid_input, {
		"income": bad_income,
		"totals": object.union(_valid_input.totals, {
			"total_income": -500,
			"total_expenditure": 68200,
			"net_movement": -500 - 68200,
		}),
	})
	result := sofa.errors with input as bad_input

	some msg in result
	contains(msg, "NON-NEGATIVE")
	contains(msg, "Income item")
}

# ============================================================================
# TEST 12: Non-negativity — negative expenditure amount
# ============================================================================

test_negative_expenditure_amount if {
	bad_expenditure := [{
		"description": "Credit (wrong sign)",
		"category": "charitable_activities",
		"amount": -100,
	}]
	bad_input := object.union(_valid_input, {
		"expenditure": bad_expenditure,
		"totals": object.union(_valid_input.totals, {
			"total_income": 96000,
			"total_expenditure": -100,
			"net_movement": 96000 - -100,
		}),
	})
	result := sofa.errors with input as bad_input

	some msg in result
	contains(msg, "NON-NEGATIVE")
	contains(msg, "Expenditure item")
}

# ============================================================================
# TEST 13: Non-negativity — negative fund opening balance
# ============================================================================

test_negative_opening_balance if {
	bad_funds := [{
		"name": "Deficit Fund",
		"type": "unrestricted",
		"opening_balance": -5000,
		"net_movement": 5000,
		"closing_balance": 0,
	}]
	bad_input := object.union(_valid_input, {"funds": bad_funds})
	result := sofa.errors with input as bad_input

	some msg in result
	contains(msg, "NON-NEGATIVE")
	contains(msg, "opening_balance")
}

# ============================================================================
# TEST 14: Structural — income item missing required fields
# ============================================================================

test_income_item_missing_fields if {
	# An income item with no category or amount.
	bad_income := [{"description": "Orphan line item"}]
	bad_input := object.union(_valid_input, {
		"income": bad_income,
		"totals": object.union(_valid_input.totals, {
			"total_income": 0,
			"total_expenditure": 68200,
			"net_movement": 0 - 68200,
		}),
	})
	result := sofa.errors with input as bad_input

	# Should report missing 'category' and missing 'amount'.
	count([msg |
		some msg in result
		contains(msg, "STRUCTURAL")
		contains(msg, "Income item at index 0")
	]) >= 2
}

# ============================================================================
# TEST 15: Summary report structure
# ============================================================================

test_summary_contains_expected_keys if {
	result := sofa.summary with input as _valid_input
	result.valid == true
	result.error_count == 0
	is_number(result.computed_total_income)
	is_number(result.computed_total_expenditure)
	is_number(result.computed_net_movement)
}
