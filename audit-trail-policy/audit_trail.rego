# METADATA
# title: Audit Trail Policy (Dense/Data-Driven)
# description: >
#   Maximum rules in minimum lines. Data-driven, no helpers, single deny set.
#   Every line earns its place. The distilled essence of audit-trail validation.
# authors:
#   - name: Policy Author
# entrypoint: true
package audit_trail

import rego.v1

# --- data aliases ---
_s := data.schema
_t := data.thresholds
_items(section) := object.get(input, section, [])
_all_items := array.concat(_items("incoming_resources"), _items("resources_expended"))
_cats := {c | some c in array.concat(_s.income_categories, _s.expense_categories)}
_ftypes := {f | some f in _s.fund_types}

# --- deny: single structured violation set ---

deny contains {"msg": sprintf("missing required field: %s", [f]), "severity": "error", "field": f} if {
	some f in _s.required_fields
	not input[f]
}

deny contains {"msg": "report_date format invalid", "severity": "error", "field": "report_date"} if {
	input.report_date
	not regex.match(_s.date_pattern, input.report_date)
}

deny contains {"msg": "currency must be 3-letter ISO code", "severity": "error", "field": "currency"} if {
	input.currency
	not regex.match(_s.currency_pattern, input.currency)
}

deny contains {"msg": sprintf("invalid accounting_basis '%s'", [input.accounting_basis]), "severity": "error", "field": "accounting_basis"} if {
	input.accounting_basis
	not input.accounting_basis in {b | some b in _s.accounting_bases}
}

deny contains {"msg": sprintf("%s[%d]: missing %v", [sec, i, missing]), "severity": "error", "field": sec} if {
	some sec in ["incoming_resources", "resources_expended"]
	some i, item in _items(sec)
	missing := {r | some r in _s.line_required; not item[r]}
	count(missing) > 0
}

deny contains {"msg": sprintf("%s[%d]: invalid category '%s'", [sec, i, item.category]), "severity": "error", "field": sec} if {
	some sec in ["incoming_resources", "resources_expended"]
	some i, item in _items(sec)
	item.category
	not item.category in _cats
}

deny contains {"msg": sprintf("%s[%d]: invalid fund_type '%s'", [sec, i, item.fund_type]), "severity": "error", "field": sec} if {
	some sec in ["incoming_resources", "resources_expended"]
	some i, item in _items(sec)
	item.fund_type
	not item.fund_type in _ftypes
}

deny contains {"msg": sprintf("net_movement %v != computed %v", [input.net_movement, computed]), "severity": "error", "field": "net_movement"} if {
	computed := sum([i.amount | some i in _items("incoming_resources"); is_number(i.amount)]) - sum([e.amount | some e in _items("resources_expended"); is_number(e.amount)])
	input.net_movement
	abs(input.net_movement - computed) > _t.reconciliation_tolerance
}

deny contains {"msg": sprintf("reconciliation mismatch: opening(%v) + net(%v) != closing(%v)", [r.opening_total, r.net_movement, r.closing_total]), "severity": "error", "field": "reconciliation"} if {
	r := input.reconciliation
	abs((r.opening_total + r.net_movement) - r.closing_total) > _t.reconciliation_tolerance
}

deny contains {"msg": sprintf("fund_type '%s' in line items but absent from fund_balances", [ft]), "severity": "error", "field": "fund_balances"} if {
	some item in _all_items
	ft := item.fund_type
	not input.fund_balances[ft]
}

deny contains {"msg": sprintf("unrestricted closing balance %v <= minimum %v", [input.fund_balances.unrestricted.closing, _t.min_unrestricted_balance]), "severity": "warning", "field": "fund_balances"} if {
	input.fund_balances.unrestricted.closing
	input.fund_balances.unrestricted.closing <= _t.min_unrestricted_balance
}

deny contains {"msg": sprintf("variance >%v%% on %s (%v vs %v) unexplained", [_t.variance_limit * 100, k, input[k], input.prior_period[k]]), "severity": "warning", "field": k} if {
	some k in ["incoming_resources_total", "resources_expended_total", "net_movement"]
	input.prior_period[k] != 0
	abs(input[k] - input.prior_period[k]) / abs(input.prior_period[k]) > _t.variance_limit
	not input.variance_explanations[k]
}

deny contains {"msg": "going concern: negative net_movement for consecutive periods", "severity": "warning", "field": "historical_net_movements"} if {
	h := object.get(input, "historical_net_movements", [])
	n := _t.going_concern_periods
	count(h) >= n
	every p in array.slice(h, count(h) - n, count(h)) { p < 0 }
}

deny contains {"msg": sprintf("%s[%d]: amount %v below materiality floor %v", [sec, i, item.amount, _t.materiality_floor]), "severity": "info", "field": sec} if {
	some sec in ["incoming_resources", "resources_expended"]
	some i, item in _items(sec)
	is_number(item.amount)
	abs(item.amount) < _t.materiality_floor
}

# --- result ---
default valid := false

valid if count(deny) == 0

errors := {d | some d in deny; d.severity == "error"}
warnings := {d | some d in deny; d.severity in {"warning", "info"}}
