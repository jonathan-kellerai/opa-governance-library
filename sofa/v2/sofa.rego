# METADATA
# title: SoFA V2 — Structural/Schema Validation
# description: |
#   Validates Statement of Financial Activity reports via schema enforcement.
#   Covers field sets, types, enums, cross-references, completeness, materiality,
#   and comparative period consistency.
# authors:
#   - name: Jonathan
# schemas:
#   - input: schema.sofa
package sofa.v2

import rego.v1

# -- Schema sets -------------------------------------------------------------

_top_fields := {"report_date", "entity_name", "currency", "fiscal_year",
	"incoming_resources", "resources_expended", "net_movement",
	"fund_balances", "reconciliation", "prior_period", "notes"}

_line_required := {"description", "amount", "fund_type", "category"}
_line_optional := {"notes", "date", "reference", "restricted"}
_fund_types := {"unrestricted", "restricted", "endowment"}
_sections := {"incoming_resources", "resources_expended"}
_categories := {"donations", "grants", "investment_income", "trading_income",
	"other_income", "charitable_activities", "governance", "fundraising",
	"support_costs", "other_expenditure"}
_materiality := 100

# -- Helpers ------------------------------------------------------------------

_unknown(obj, allowed) := {k | some k, _ in obj; not k in allowed}
_items(s) := input[s] if { s in _sections; is_array(input[s]) }

# -- Top-level schema ---------------------------------------------------------

# METADATA
# entrypoint: true
errors contains msg if {
	u := _unknown(input, _top_fields); count(u) > 0
	msg := sprintf("unknown top-level fields: %v", [u])
}
errors contains "report_date is required" if not input.report_date
errors contains "entity_name is required" if not input.entity_name
errors contains "report_date must be YYYY-MM-DD" if {
	input.report_date; not regex.match(`^\d{4}-\d{2}-\d{2}$`, input.report_date)
}
errors contains "currency must be a 3-letter code" if {
	input.currency; not regex.match(`^[A-Z]{3}$`, input.currency)
}
errors contains msg if {
	some s in _sections; input[s]; not is_array(input[s])
	msg := sprintf("%s must be an array", [s])
}

# -- Line-item validation ----------------------------------------------------

errors contains msg if {
	some s in _sections; items := _items(s); some i, item in items
	m := _line_required - {k | some k, _ in item}; count(m) > 0
	msg := sprintf("%s[%d]: missing required fields %v", [s, i, m])
}
errors contains msg if {
	some s in _sections; items := _items(s); some i, item in items
	u := _unknown(item, _line_required | _line_optional); count(u) > 0
	msg := sprintf("%s[%d]: unknown fields %v", [s, i, u])
}
errors contains msg if {
	some s in _sections; items := _items(s); some i, item in items
	not is_number(item.amount)
	msg := sprintf("%s[%d]: amount must be a number", [s, i])
}
errors contains msg if {
	some s in _sections; items := _items(s); some i, item in items
	not item.category in _categories
	msg := sprintf("%s[%d]: invalid category '%s'", [s, i, item.category])
}
errors contains msg if {
	some s in _sections; items := _items(s); some i, item in items
	not item.fund_type in _fund_types
	msg := sprintf("%s[%d]: invalid fund_type '%s'", [s, i, item.fund_type])
}

# -- Cross-reference integrity -----------------------------------------------

_ref_funds contains item.fund_type if {
	some s in _sections; items := _items(s); some _, item in items; item.fund_type
}
errors contains msg if {
	some ft in _ref_funds; not input.fund_balances[ft]
	msg := sprintf("fund_type '%s' referenced but missing from fund_balances", [ft])
}

# -- Net movement reconciliation ---------------------------------------------

_total(s) := sum([item.amount | items := _items(s); some _, item in items; is_number(item.amount)])
computed_net_movement := _total("incoming_resources") - _total("resources_expended")

errors contains msg if {
	input.net_movement; is_number(input.net_movement)
	abs(input.net_movement - computed_net_movement) > 0.01
	msg := sprintf("net_movement %v != computed %v", [input.net_movement, computed_net_movement])
}

# -- Completeness scoring ----------------------------------------------------

completeness_pct := round(score * 100) / 100 if {
	n := count([1 | some s in _sections; items := _items(s); some _, _ in items])
	n > 0
	filled := count([1 |
		some s in _sections; items := _items(s)
		some _, item in items; some f in _line_optional; item[f]
	])
	score := (filled / (n * count(_line_optional))) * 100
}
default completeness_pct := 0

# -- Materiality warnings ----------------------------------------------------

warnings contains msg if {
	some s in _sections; items := _items(s); some i, item in items
	is_number(item.amount); abs(item.amount) < _materiality
	msg := sprintf("%s[%d]: amount %v below materiality threshold %v", [s, i, item.amount, _materiality])
}

# -- Comparative period validation --------------------------------------------

errors contains msg if {
	input.prior_period; some s in _sections
	is_array(input.prior_period[s]); some i, item in input.prior_period[s]
	m := _line_required - {k | some k, _ in item}; count(m) > 0
	msg := sprintf("prior_period.%s[%d]: missing required fields %v", [s, i, m])
}

# -- Summary ------------------------------------------------------------------

# METADATA
# entrypoint: true
report := {
	"valid": count(errors) == 0,
	"errors": errors,
	"warnings": warnings,
	"completeness_pct": completeness_pct,
	"computed_net_movement": computed_net_movement,
}
