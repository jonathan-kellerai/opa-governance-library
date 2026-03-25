# METADATA
# title: SoFA V3 — Financial Logic Validation
# description: >
#   Pure business rules for Statement of Financial Activity reports.
#   Double-entry integrity, fund restrictions, variance, liquidity, going concern.
# authors:
#   - name: Policy Author
# entrypoint: true
package sofa.v3

import rego.v1

# --- Helpers ---

_funds := input.funds

_line_items := array.concat(
	object.get(input, "incoming_resources", []),
	object.get(input, "resources_expended", []),
)

# --- 1. Double-entry integrity: total debits == total credits ---

total_debits := sum([f.debits | some f in _funds])

total_credits := sum([f.credits | some f in _funds])

# METADATA
# title: double_entry_balanced
# description: Total debits must equal total credits across all funds.
default double_entry_balanced := false

double_entry_balanced if total_debits == total_credits

violations contains "double-entry imbalance: debits != credits" if not double_entry_balanced

# --- 2. Fund restriction enforcement ---

violations contains msg if {
	some f in _funds
	f.type == "restricted"
	some exp in f.expenditures
	not exp.purpose in f.permitted_purposes
	msg := sprintf("restricted fund '%s': expenditure '%s' not in permitted purposes", [f.name, exp.purpose])
}

violations contains msg if {
	some f in _funds
	f.type == "endowment"
	f.principal_spent > 0
	msg := sprintf("endowment '%s': principal cannot be spent (spent: %v)", [f.name, f.principal_spent])
}

# --- 3. Inter-fund transfers net to zero ---

transfer_net := sum([t.amount | some t in object.get(input, "transfers", [])])

violations contains "inter-fund transfers do not net to zero" if transfer_net != 0

# --- 4. Variance analysis (>20% vs prior period) ---

violations contains msg if {
	prior := input.prior_period
	some key in ["incoming_resources_total", "resources_expended_total", "net_movement"]
	current_val := input[key]
	prior_val := prior[key]
	prior_val != 0
	variance := abs(current_val - prior_val) / abs(prior_val)
	variance > 0.20
	not input.variance_explanations[key]
	msg := sprintf("variance >20%% on '%s' (%v vs %v) requires explanation", [key, current_val, prior_val])
}

# --- 5. Liquidity rules ---

violations contains "unrestricted closing balance is not positive" if {
	some f in _funds
	f.type == "unrestricted"
	f.closing_balance <= 0
}

violations contains msg if {
	ratio := input.current_assets / input.current_liabilities
	ratio < 1.0
	msg := sprintf("current ratio %.2f < 1.0 — liquidity risk", [ratio])
}

# --- 6. Accounting basis consistency ---

valid_bases := {"accrual", "cash"}

violations contains msg if {
	basis := input.accounting_basis
	not basis in valid_bases
	msg := sprintf("invalid accounting_basis '%s'; must be accrual or cash", [basis])
}

violations contains "mixed basis: accruals present under cash basis" if {
	input.accounting_basis == "cash"
	count(object.get(input, "accrued_items", [])) > 0
}

# --- 7. Audit trail — every line item needs a reference ---

violations contains msg if {
	some i, item in _line_items
	not item.reference
	msg := sprintf("line item %d ('%s') missing audit reference", [i, object.get(item, "description", "unknown")])
}

# --- 8. Going concern — negative net_movement for 2+ consecutive periods ---

violations contains "going concern: net_movement negative for 2+ consecutive periods" if {
	periods := object.get(input, "historical_net_movements", [])
	count(periods) >= 2
	every p in array.slice(periods, count(periods) - 2, count(periods)) {
		p < 0
	}
}

# --- Result ---

default valid := false

valid if count(violations) == 0
