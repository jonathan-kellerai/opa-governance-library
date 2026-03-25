# METADATA
# title: SoFA Standard — Definitive Validation Policy
# description: >
#   Synthesised from V1–V4. Data-driven via data.schema and data.thresholds.
#   Single structured deny set with severity-based triage.
#   Covers structural, financial, reconciliation, fund restriction, variance,
#   liquidity, going concern, audit trail, and materiality rules.
# authors:
#   - name: SoFA Policy Team
# custom:
#   version: "1.0.0"
# entrypoint: true
package sofa.standard

import rego.v1

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

tolerance := thresholds.reconciliation_tolerance

# ============================================================================
# 2. STRUCTURAL RULES — required fields, types, formats
# ============================================================================

deny contains {"msg": sprintf("missing required field: %s", [f]), "severity": "error", "field": f, "rule": "required_field"} if {
	some f in schema.required_fields
	not input[f]
}

deny contains {"msg": "report_date format invalid (expected YYYY-MM-DD)", "severity": "error", "field": "report_date", "rule": "date_format"} if {
	input.report_date
	not regex.match(schema.date_pattern, input.report_date)
}

deny contains {"msg": "currency must be 3-letter ISO code", "severity": "error", "field": "currency", "rule": "currency_format"} if {
	input.currency
	not regex.match(schema.currency_pattern, input.currency)
}

deny contains {"msg": sprintf("invalid accounting_basis '%s'", [input.accounting_basis]), "severity": "error", "field": "accounting_basis", "rule": "accounting_basis"} if {
	input.accounting_basis
	not input.accounting_basis in {b | some b in schema.accounting_bases}
}

# ============================================================================
# 3. LINE-ITEM RULES — required fields, categories, fund types, references
# ============================================================================

deny contains {"msg": sprintf("%s[%d]: missing fields %v", [sec, i, missing]), "severity": "error", "field": sec, "rule": "line_required"} if {
	some sec in ["incoming_resources", "resources_expended"]
	some i, item in items(sec)
	missing := {r | some r in schema.line_required; not item[r]}
	count(missing) > 0
}

deny contains {"msg": sprintf("incoming_resources[%d]: invalid income category '%s'", [i, item.category]), "severity": "error", "field": "incoming_resources", "rule": "income_category"} if {
	some i, item in items("incoming_resources")
	item.category
	not item.category in income_cats
}

deny contains {"msg": sprintf("resources_expended[%d]: invalid expense category '%s'", [i, item.category]), "severity": "error", "field": "resources_expended", "rule": "expense_category"} if {
	some i, item in items("resources_expended")
	item.category
	not item.category in expense_cats
}

deny contains {"msg": sprintf("%s[%d]: invalid fund_type '%s'", [sec, i, item.fund_type]), "severity": "error", "field": sec, "rule": "fund_type"} if {
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
# 4. MATHEMATICAL INTEGRITY — totals, net movement
# ============================================================================

computed_income := sum([item.amount | some item in items("incoming_resources"); is_number(item.amount)])

computed_expenditure := sum([item.amount | some item in items("resources_expended"); is_number(item.amount)])

computed_net := computed_income - computed_expenditure

deny contains {"msg": sprintf("net_movement %v != computed %v", [input.net_movement, computed_net]), "severity": "error", "field": "net_movement", "rule": "net_movement_check"} if {
	input.net_movement
	abs(input.net_movement - computed_net) > tolerance
}

# ============================================================================
# 5. PER-FUND RECONCILIATION
# ============================================================================

deny contains {"msg": sprintf("fund '%s': opening(%v) + net_movement(%v) != closing(%v)", [ft, fb.opening, fb.net_movement, fb.closing]), "severity": "error", "field": "fund_balances", "rule": "fund_reconciliation"} if {
	some ft, fb in object.get(input, "fund_balances", {})
	is_number(object.get(fb, "opening", null))
	is_number(object.get(fb, "net_movement", null))
	is_number(object.get(fb, "closing", null))
	abs((fb.opening + fb.net_movement) - fb.closing) > tolerance
}

# ============================================================================
# 6. AGGREGATE RECONCILIATION
# ============================================================================

deny contains {"msg": sprintf("reconciliation mismatch: opening(%v) + net(%v) != closing(%v)", [r.opening_total, r.net_movement, r.closing_total]), "severity": "error", "field": "reconciliation", "rule": "aggregate_reconciliation"} if {
	r := object.get(input, "reconciliation", {})
	is_number(object.get(r, "opening_total", null))
	is_number(object.get(r, "net_movement", null))
	is_number(object.get(r, "closing_total", null))
	abs((r.opening_total + r.net_movement) - r.closing_total) > tolerance
}

# ============================================================================
# 7. FUND RESTRICTION RULES
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

# ============================================================================
# 8. TRANSFER NETTING
# ============================================================================

transfer_net := sum([t.amount | some t in object.get(input, "transfers", []); is_number(t.amount)])

deny contains {"msg": sprintf("inter-fund transfers net to %v, expected 0", [transfer_net]), "severity": "error", "field": "transfers", "rule": "transfer_netting"} if {
	count(object.get(input, "transfers", [])) > 0
	abs(transfer_net) > tolerance
}

# ============================================================================
# 9. VARIANCE ANALYSIS
# ============================================================================

deny contains {"msg": sprintf("variance >%v%% on %s unexplained", [thresholds.variance_limit * 100, k]), "severity": "warning", "field": k, "rule": "variance_analysis"} if {
	prior := object.get(input, "prior_period", {})
	some k in ["incoming_resources_total", "resources_expended_total", "net_movement"]
	prior_val := prior[k]
	prior_val != 0
	current_val := input[k]
	abs(current_val - prior_val) / abs(prior_val) > thresholds.variance_limit
	not object.get(input, "variance_explanations", {})[k]
}

# ============================================================================
# 10. LIQUIDITY
# ============================================================================

deny contains {"msg": sprintf("negative unrestricted closing balance: %v", [fb.closing]), "severity": "warning", "field": "fund_balances", "rule": "unrestricted_balance"} if {
	fb := object.get(object.get(input, "fund_balances", {}), "unrestricted", {})
	is_number(object.get(fb, "closing", null))
	fb.closing < thresholds.min_unrestricted_balance
}

deny contains {"msg": sprintf("current ratio %.2f < 1.0 — liquidity risk", [ratio]), "severity": "warning", "field": "current_liabilities", "rule": "liquidity_ratio"} if {
	cl := object.get(input, "current_liabilities", 0)
	cl > 0
	ca := object.get(input, "current_assets", 0)
	ratio := ca / cl
	ratio < 1.0
}

# ============================================================================
# 11. GOING CONCERN
# ============================================================================

deny contains {"msg": "going concern: negative net_movement for consecutive periods", "severity": "warning", "field": "historical_net_movements", "rule": "going_concern"} if {
	hist := object.get(input, "historical_net_movements", [])
	n := thresholds.going_concern_periods
	count(hist) >= n
	every p in array.slice(hist, count(hist) - n, count(hist)) { p < 0 }
}

# ============================================================================
# 12. ACCRUAL / CASH BASIS CONSISTENCY
# ============================================================================

deny contains {"msg": "mixed basis: accrued items present under cash accounting", "severity": "error", "field": "accounting_basis", "rule": "basis_consistency"} if {
	object.get(input, "accounting_basis", "") == "cash"
	count(object.get(input, "accrued_items", [])) > 0
}

# ============================================================================
# 13. MATERIALITY (info severity)
# ============================================================================

deny contains {"msg": sprintf("%s[%d]: amount %v below materiality floor %v", [sec, i, item.amount, thresholds.materiality_floor]), "severity": "info", "field": sec, "rule": "materiality"} if {
	some sec in ["incoming_resources", "resources_expended"]
	some i, item in items(sec)
	is_number(item.amount)
	abs(item.amount) < thresholds.materiality_floor
}

# ============================================================================
# 14. RESULT
# ============================================================================

errors := {d | some d in deny; d.severity == "error"}

warnings := {d | some d in deny; d.severity in {"warning", "info"}}

default valid := false

valid if count(errors) == 0

summary := {
	"valid": valid,
	"error_count": count(errors),
	"warning_count": count(warnings),
	"errors": errors,
	"warnings": warnings,
}
