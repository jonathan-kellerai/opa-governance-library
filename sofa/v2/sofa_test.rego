package sofa.v2_test

import data.sofa.v2 as sofa
import rego.v1

# ---------------------------------------------------------------------------
# Minimal valid input fixture
# ---------------------------------------------------------------------------

_valid_input := {
	"report_date": "2025-12-31",
	"entity_name": "Test Charity",
	"currency": "GBP",
	"fiscal_year": 2025,
	"incoming_resources": [
		{"description": "Annual donations", "amount": 50000, "fund_type": "unrestricted", "category": "donations"},
		{"description": "Restricted grant", "amount": 30000, "fund_type": "restricted", "category": "grants"},
	],
	"resources_expended": [
		{"description": "Programme costs", "amount": 40000, "fund_type": "unrestricted", "category": "charitable_activities"},
	],
	"net_movement": 40000,
	"fund_balances": {
		"unrestricted": 120000,
		"restricted": 80000,
	},
}

# ---------------------------------------------------------------------------
# 1. Valid input produces no errors
# ---------------------------------------------------------------------------

test_valid_input_no_errors if {
	count(sofa.errors) == 0 with input as _valid_input
}

test_valid_report_flag if {
	sofa.report.valid with input as _valid_input
}

# ---------------------------------------------------------------------------
# 2. Unknown top-level fields rejected
# ---------------------------------------------------------------------------

test_unknown_top_level_field if {
	bad := object.union(_valid_input, {"bogus_field": true})
	some msg in sofa.errors with input as bad
	contains(msg, "unknown top-level fields")
}

# ---------------------------------------------------------------------------
# 3. Missing required line-item fields
# ---------------------------------------------------------------------------

test_missing_line_item_fields if {
	bad := object.union(_valid_input, {
		"incoming_resources": [{"description": "Incomplete"}],
	})
	some msg in sofa.errors with input as bad
	contains(msg, "missing required fields")
}

# ---------------------------------------------------------------------------
# 4. Invalid category rejected
# ---------------------------------------------------------------------------

test_invalid_category if {
	bad := object.union(_valid_input, {
		"incoming_resources": [
			{"description": "Bad", "amount": 100, "fund_type": "unrestricted", "category": "magic_money"},
		],
	})
	some msg in sofa.errors with input as bad
	contains(msg, "invalid category")
}

# ---------------------------------------------------------------------------
# 5. Cross-reference: fund_type not in fund_balances
# ---------------------------------------------------------------------------

test_fund_type_cross_ref if {
	bad := object.union(_valid_input, {
		"incoming_resources": [
			{"description": "Endowment gift", "amount": 5000, "fund_type": "endowment", "category": "donations"},
		],
		"fund_balances": {"unrestricted": 120000},
	})
	some msg in sofa.errors with input as bad
	contains(msg, "missing from fund_balances")
}

# ---------------------------------------------------------------------------
# 6. Net movement mismatch detected
# ---------------------------------------------------------------------------

test_net_movement_mismatch if {
	bad := object.union(_valid_input, {"net_movement": 99999})
	some msg in sofa.errors with input as bad
	contains(msg, "!= computed")
}

# ---------------------------------------------------------------------------
# 7. Materiality warning fires for small amounts
# ---------------------------------------------------------------------------

test_materiality_warning if {
	small := object.union(_valid_input, {
		"resources_expended": [
			{"description": "Tiny cost", "amount": 5, "fund_type": "unrestricted", "category": "governance"},
		],
	})
	some msg in sofa.warnings with input as small
	contains(msg, "below materiality threshold")
}

# ---------------------------------------------------------------------------
# 8. Prior period structure validated
# ---------------------------------------------------------------------------

test_prior_period_validation if {
	bad := object.union(_valid_input, {
		"prior_period": {
			"incoming_resources": [{"description": "Old item"}],
		},
	})
	some msg in sofa.errors with input as bad
	contains(msg, "prior_period")
	contains(msg, "missing required fields")
}
