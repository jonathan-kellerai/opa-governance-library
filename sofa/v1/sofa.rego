# METADATA
# title: Statement of Financial Activity (SoFA) Validator
# description: |
#   Comprehensive validation policy for Statement of Financial Activity (SoFA)
#   reports. SoFA reports are financial statements used by nonprofits, charities,
#   and other organisations to disclose:
#
#     - Incoming resources (donations, grants, trading, investments)
#     - Resources expended (charitable activities, governance, fundraising)
#     - Net movement in funds (surplus or deficit)
#     - Fund balances (restricted vs unrestricted, opening vs closing)
#     - Reconciliation (opening + net movement = closing)
#
#   This is the V1 NARRATIVE/COMPREHENSIVE policy. It prioritises readability,
#   verbose error messages, and extensive helper rules over brevity.
#
#   Validation categories:
#     1. Structural completeness — all required sections present
#     2. Income categorisation — valid income categories
#     3. Expenditure categorisation — valid expenditure categories
#     4. Fund type validation — recognised fund types
#     5. Mathematical integrity — totals sum correctly
#     6. Balance reconciliation — opening + net = closing per fund
#     7. Temporal validity — reporting period dates are well-formed
#     8. Non-negativity — certain fields must be >= 0
#
# authors:
#   - name: SoFA Policy Team
# custom:
#   version: "1.0.0"
#   approach: narrative
package sofa.v1

import rego.v1

# ============================================================================
# CONSTANTS — Allowed Categories and Fund Types
# ============================================================================

# Valid categories for incoming resources.
# These correspond to the standard SoFA income headings used by charities.
valid_income_categories := {
	"voluntary_income",
	"activities_for_generating_funds",
	"investment_income",
	"incoming_from_charitable_activities",
	"other_incoming",
}

# Valid categories for resources expended.
# These correspond to the standard SoFA expenditure headings.
valid_expenditure_categories := {
	"costs_of_generating_funds",
	"charitable_activities",
	"governance_costs",
	"other_expenditure",
}

# Recognised fund types across the charity sector.
valid_fund_types := {
	"restricted",
	"unrestricted",
	"endowment",
	"designated",
}

# ============================================================================
# TOP-LEVEL REQUIRED SECTIONS
# ============================================================================

# Every SoFA report must contain these top-level keys.
required_sections := {
	"reporting_period",
	"income",
	"expenditure",
	"funds",
	"totals",
}

# ============================================================================
# TOLERANCE — Floating Point Comparison
# ============================================================================

# Financial calculations may involve floating point arithmetic. We allow a
# small tolerance (one penny / one cent) when comparing computed sums to
# stated totals so that benign rounding differences do not trigger false
# positives.
tolerance := 0.01

# ============================================================================
# MAIN ENTRY POINTS
# ============================================================================

# METADATA
# title: Overall SoFA validity
# description: |
#   The report is valid when there are zero errors. This is the top-level
#   decision rule that consumers should query.
# entrypoint: true
default valid := false

valid if count(errors) == 0

# METADATA
# title: Collected errors
# description: |
#   A set of human-readable error strings. Each string describes exactly one
#   validation failure. An empty set means the report is valid.
# entrypoint: true
errors contains msg if some msg in structural_errors

errors contains msg if some msg in income_errors

errors contains msg if some msg in expenditure_errors

errors contains msg if some msg in fund_errors

errors contains msg if some msg in math_errors

errors contains msg if some msg in reconciliation_errors

errors contains msg if some msg in temporal_errors

errors contains msg if some msg in non_negativity_errors

# ============================================================================
# 1. STRUCTURAL COMPLETENESS
# ============================================================================

# Check that every required top-level section is present in the input.
structural_errors contains msg if {
	some section in required_sections
	not _has_key(input, section)
	msg := sprintf(
		"STRUCTURAL: Missing required top-level section '%s'. Every SoFA report must include: %s.",
		[section, concat(", ", sort(required_sections))],
	)
}

# Income must be provided as an array of line items, not a scalar or object.
structural_errors contains "STRUCTURAL: The 'income' section must be a non-empty array of line items." if {
	_has_key(input, "income")
	not is_array(input.income)
}

structural_errors contains "STRUCTURAL: The 'income' section must be a non-empty array of line items." if {
	_has_key(input, "income")
	is_array(input.income)
	count(input.income) == 0
}

# Expenditure must be provided as an array of line items.
structural_errors contains "STRUCTURAL: The 'expenditure' section must be a non-empty array of line items." if {
	_has_key(input, "expenditure")
	not is_array(input.expenditure)
}

structural_errors contains "STRUCTURAL: The 'expenditure' section must be a non-empty array of line items." if {
	_has_key(input, "expenditure")
	is_array(input.expenditure)
	count(input.expenditure) == 0
}

# Funds must be provided as an array.
structural_errors contains "STRUCTURAL: The 'funds' section must be a non-empty array of fund records." if {
	_has_key(input, "funds")
	not is_array(input.funds)
}

structural_errors contains "STRUCTURAL: The 'funds' section must be a non-empty array of fund records." if {
	_has_key(input, "funds")
	is_array(input.funds)
	count(input.funds) == 0
}

# Each income line item must carry a description, category, and amount.
structural_errors contains msg if {
	_has_key(input, "income")
	is_array(input.income)
	some i, item in input.income
	not _has_key(item, "description")
	msg := sprintf(
		"STRUCTURAL: Income item at index %d is missing a 'description' field.",
		[i],
	)
}

structural_errors contains msg if {
	_has_key(input, "income")
	is_array(input.income)
	some i, item in input.income
	not _has_key(item, "category")
	msg := sprintf(
		"STRUCTURAL: Income item at index %d is missing a 'category' field.",
		[i],
	)
}

structural_errors contains msg if {
	_has_key(input, "income")
	is_array(input.income)
	some i, item in input.income
	not _has_key(item, "amount")
	msg := sprintf(
		"STRUCTURAL: Income item at index %d is missing an 'amount' field.",
		[i],
	)
}

# Each expenditure line item must carry a description, category, and amount.
structural_errors contains msg if {
	_has_key(input, "expenditure")
	is_array(input.expenditure)
	some i, item in input.expenditure
	not _has_key(item, "description")
	msg := sprintf(
		"STRUCTURAL: Expenditure item at index %d is missing a 'description' field.",
		[i],
	)
}

structural_errors contains msg if {
	_has_key(input, "expenditure")
	is_array(input.expenditure)
	some i, item in input.expenditure
	not _has_key(item, "category")
	msg := sprintf(
		"STRUCTURAL: Expenditure item at index %d is missing a 'category' field.",
		[i],
	)
}

structural_errors contains msg if {
	_has_key(input, "expenditure")
	is_array(input.expenditure)
	some i, item in input.expenditure
	not _has_key(item, "amount")
	msg := sprintf(
		"STRUCTURAL: Expenditure item at index %d is missing an 'amount' field.",
		[i],
	)
}

# Each fund must have a name, type, opening_balance, and closing_balance.
structural_errors contains msg if {
	_has_key(input, "funds")
	is_array(input.funds)
	some i, fund in input.funds
	some required_field in {"name", "type", "opening_balance", "closing_balance"}
	not _has_key(fund, required_field)
	msg := sprintf(
		"STRUCTURAL: Fund at index %d is missing required field '%s'.",
		[i, required_field],
	)
}

# ============================================================================
# 2. INCOME CATEGORISATION
# ============================================================================

# Every income item must use a recognised category.
income_errors contains msg if {
	_has_key(input, "income")
	is_array(input.income)
	some i, item in input.income
	_has_key(item, "category")
	not item.category in valid_income_categories
	msg := sprintf(
		"INCOME: Item at index %d ('%s') has invalid category '%s'. Valid categories are: %s.",
		[
			i,
			object.get(item, "description", "<no description>"),
			item.category,
			concat(", ", sort(valid_income_categories)),
		],
	)
}

# ============================================================================
# 3. EXPENDITURE CATEGORISATION
# ============================================================================

# Every expenditure item must use a recognised category.
expenditure_errors contains msg if {
	_has_key(input, "expenditure")
	is_array(input.expenditure)
	some i, item in input.expenditure
	_has_key(item, "category")
	not item.category in valid_expenditure_categories
	msg := sprintf(
		"EXPENDITURE: Item at index %d ('%s') has invalid category '%s'. Valid categories are: %s.",
		[
			i,
			object.get(item, "description", "<no description>"),
			item.category,
			concat(", ", sort(valid_expenditure_categories)),
		],
	)
}

# ============================================================================
# 4. FUND TYPE VALIDATION
# ============================================================================

# Every fund must declare a recognised fund type.
fund_errors contains msg if {
	_has_key(input, "funds")
	is_array(input.funds)
	some i, fund in input.funds
	_has_key(fund, "type")
	not fund.type in valid_fund_types
	msg := sprintf(
		"FUND: Fund at index %d ('%s') has invalid type '%s'. Valid types are: %s.",
		[
			i,
			object.get(fund, "name", "<unnamed>"),
			fund.type,
			concat(", ", sort(valid_fund_types)),
		],
	)
}

# ============================================================================
# 5. MATHEMATICAL INTEGRITY
# ============================================================================

# Compute the actual sum of all income line items.
_computed_total_income := sum([item.amount |
	some item in input.income
	_has_key(item, "amount")
])

# Compute the actual sum of all expenditure line items.
_computed_total_expenditure := sum([item.amount |
	some item in input.expenditure
	_has_key(item, "amount")
])

# The net movement is income minus expenditure.
_computed_net_movement := _computed_total_income - _computed_total_expenditure

# -- Validate stated total_income against the computed sum --
math_errors contains msg if {
	_has_key(input, "totals")
	_has_key(input.totals, "total_income")
	_has_key(input, "income")
	is_array(input.income)
	diff := abs(input.totals.total_income - _computed_total_income)
	diff > tolerance
	msg := sprintf(
		"MATH: Stated total_income (%v) does not match the sum of income items (%v). Difference: %v.",
		[input.totals.total_income, _computed_total_income, diff],
	)
}

# -- Validate stated total_expenditure against the computed sum --
math_errors contains msg if {
	_has_key(input, "totals")
	_has_key(input.totals, "total_expenditure")
	_has_key(input, "expenditure")
	is_array(input.expenditure)
	diff := abs(input.totals.total_expenditure - _computed_total_expenditure)
	diff > tolerance
	msg := sprintf(
		"MATH: Stated total_expenditure (%v) does not match the sum of expenditure items (%v). Difference: %v.",
		[input.totals.total_expenditure, _computed_total_expenditure, diff],
	)
}

# -- Validate stated net_movement against computed (income - expenditure) --
math_errors contains msg if {
	_has_key(input, "totals")
	_has_key(input.totals, "net_movement")
	_has_key(input, "income")
	_has_key(input, "expenditure")
	is_array(input.income)
	is_array(input.expenditure)
	diff := abs(input.totals.net_movement - _computed_net_movement)
	diff > tolerance
	msg := sprintf(
		"MATH: Stated net_movement (%v) does not equal total_income (%v) minus total_expenditure (%v) = %v. Difference: %v.",
		[
			input.totals.net_movement,
			_computed_total_income,
			_computed_total_expenditure,
			_computed_net_movement,
			diff,
		],
	)
}

# ============================================================================
# 6. BALANCE RECONCILIATION
# ============================================================================

# For each fund, opening_balance + net_movement must equal closing_balance.
# This is the fundamental accounting equation for fund-based reporting.
reconciliation_errors contains msg if {
	_has_key(input, "funds")
	is_array(input.funds)
	some i, fund in input.funds
	_has_key(fund, "opening_balance")
	_has_key(fund, "closing_balance")
	_has_key(fund, "net_movement")
	expected_closing := fund.opening_balance + fund.net_movement
	diff := abs(fund.closing_balance - expected_closing)
	diff > tolerance
	msg := sprintf(
		"RECONCILIATION: Fund '%s' (index %d) fails balance reconciliation. opening_balance (%v) + net_movement (%v) = %v, but closing_balance is stated as %v. Difference: %v.",
		[
			object.get(fund, "name", "<unnamed>"),
			i,
			fund.opening_balance,
			fund.net_movement,
			expected_closing,
			fund.closing_balance,
			diff,
		],
	)
}

# ============================================================================
# 7. TEMPORAL VALIDITY
# ============================================================================

# The reporting_period must have both start_date and end_date.
temporal_errors contains "TEMPORAL: The 'reporting_period' section must contain a 'start_date' field." if {
	_has_key(input, "reporting_period")
	not _has_key(input.reporting_period, "start_date")
}

temporal_errors contains "TEMPORAL: The 'reporting_period' section must contain an 'end_date' field." if {
	_has_key(input, "reporting_period")
	not _has_key(input.reporting_period, "end_date")
}

# Dates must be valid RFC 3339 / ISO 8601 date strings that OPA can parse.
temporal_errors contains msg if {
	_has_key(input, "reporting_period")
	_has_key(input.reporting_period, "start_date")
	not _is_valid_date(input.reporting_period.start_date)
	msg := sprintf(
		"TEMPORAL: start_date '%s' is not a valid date. Use YYYY-MM-DD format (e.g. '2024-01-01').",
		[input.reporting_period.start_date],
	)
}

temporal_errors contains msg if {
	_has_key(input, "reporting_period")
	_has_key(input.reporting_period, "end_date")
	not _is_valid_date(input.reporting_period.end_date)
	msg := sprintf(
		"TEMPORAL: end_date '%s' is not a valid date. Use YYYY-MM-DD format (e.g. '2024-12-31').",
		[input.reporting_period.end_date],
	)
}

# The end_date must be strictly after the start_date.
temporal_errors contains msg if {
	_has_key(input, "reporting_period")
	_has_key(input.reporting_period, "start_date")
	_has_key(input.reporting_period, "end_date")
	_is_valid_date(input.reporting_period.start_date)
	_is_valid_date(input.reporting_period.end_date)
	start_ns := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [input.reporting_period.start_date]))
	end_ns := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [input.reporting_period.end_date]))
	end_ns <= start_ns
	msg := sprintf(
		"TEMPORAL: end_date ('%s') must be strictly after start_date ('%s').",
		[input.reporting_period.end_date, input.reporting_period.start_date],
	)
}

# ============================================================================
# 8. NON-NEGATIVITY CONSTRAINTS
# ============================================================================

# Income amounts must be non-negative (you cannot have negative donations
# in a SoFA — refunds are modelled as expenditure or adjustments).
non_negativity_errors contains msg if {
	_has_key(input, "income")
	is_array(input.income)
	some i, item in input.income
	_has_key(item, "amount")
	item.amount < 0
	msg := sprintf(
		"NON-NEGATIVE: Income item at index %d ('%s') has a negative amount (%v). Income amounts must be >= 0.",
		[i, object.get(item, "description", "<no description>"), item.amount],
	)
}

# Expenditure amounts must be non-negative (expenditure is always a positive
# outflow; credits or recoveries are modelled as income).
non_negativity_errors contains msg if {
	_has_key(input, "expenditure")
	is_array(input.expenditure)
	some i, item in input.expenditure
	_has_key(item, "amount")
	item.amount < 0
	msg := sprintf(
		"NON-NEGATIVE: Expenditure item at index %d ('%s') has a negative amount (%v). Expenditure amounts must be >= 0.",
		[i, object.get(item, "description", "<no description>"), item.amount],
	)
}

# Opening and closing fund balances must be non-negative.
non_negativity_errors contains msg if {
	_has_key(input, "funds")
	is_array(input.funds)
	some i, fund in input.funds
	_has_key(fund, "opening_balance")
	fund.opening_balance < 0
	msg := sprintf(
		"NON-NEGATIVE: Fund '%s' (index %d) has a negative opening_balance (%v). Fund balances must be >= 0.",
		[object.get(fund, "name", "<unnamed>"), i, fund.opening_balance],
	)
}

non_negativity_errors contains msg if {
	_has_key(input, "funds")
	is_array(input.funds)
	some i, fund in input.funds
	_has_key(fund, "closing_balance")
	fund.closing_balance < 0
	msg := sprintf(
		"NON-NEGATIVE: Fund '%s' (index %d) has a negative closing_balance (%v). Fund balances must be >= 0.",
		[object.get(fund, "name", "<unnamed>"), i, fund.closing_balance],
	)
}

# ============================================================================
# HELPER RULES
# ============================================================================

# _has_key checks whether an object contains a given key.
# This avoids undefined-reference errors when accessing optional fields.
_has_key(obj, key) if {
	_ := obj[key]
}

# _is_valid_date checks whether a string is a parseable date in YYYY-MM-DD
# format. We append a time component to make it RFC 3339 compatible for OPA's
# built-in time.parse_rfc3339_ns.
_is_valid_date(date_str) if {
	is_string(date_str)
	regex.match(`^\d{4}-\d{2}-\d{2}$`, date_str)
	time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [date_str]))
}

# ============================================================================
# SUMMARY REPORT (convenience)
# ============================================================================

# A structured summary that consumers can use for programmatic inspection
# rather than parsing error strings.
summary := {
	"valid": valid,
	"error_count": count(errors),
	"errors": errors,
	"computed_total_income": _computed_total_income,
	"computed_total_expenditure": _computed_total_expenditure,
	"computed_net_movement": _computed_net_movement,
}
