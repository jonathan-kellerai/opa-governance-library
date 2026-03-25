# METADATA
# title: SoFREP V3 — Operational Logic
# description: >
#   Battle-readiness rules for Status of Forces Reports.
#   Risk matrix, readiness, momentum, dependency chains, owner load,
#   staleness, priority inversion, escalation triggers.
# authors:
#   - name: Policy Author
# entrypoint: true
package sofrep.v3

import rego.v1

# --- Helpers ---

_quadrants := ["working_well", "needed", "at_risk", "next"]

_items(q) := object.get(input, q, [])

_all_items := [item |
	some q in _quadrants
	some item in _items(q)
]

_end_date := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [input.reporting_period.end_date]))

_day_ns := ((24 * 60) * 60) * 1000000000

_item_age_days(item) := days if {
	updated := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [item.last_updated]))
	days := (_end_date - updated) / _day_ns
}

_all_item_ids := {item.id | some item in _all_items}

# --- 1. Risk matrix ---

risk_matrix := {entry |
	some item in _items("at_risk")
	score := item.impact * item.likelihood
	level := _risk_level(score)
	entry := {"id": item.id, "title": item.title, "risk_score": score, "risk_level": level}
}

_risk_level(s) := "critical" if s >= 20

_risk_level(s) := "high" if {
	s >= 12
	s < 20
}

_risk_level(s) := "medium" if {
	s >= 6
	s < 12
}

_risk_level(s) := "low" if s < 6

has_critical_risks if {
	some entry in risk_matrix
	entry.risk_level == "critical"
}

violations contains "critical risks present in risk matrix" if has_critical_risks

# --- 2. Readiness score ---

readiness_score := (count(_items("working_well")) / count(_all_items)) * 100

violations contains sprintf("readiness %.0f%% < 50%%", [readiness_score]) if readiness_score < 50

# --- 3. Momentum analysis ---

violations contains "defensive posture: more at_risk items than planned next actions" if {
	count(_items("at_risk")) > count(_items("next"))
}

# --- 4. Dependency chain validation ---

violations contains msg if {
	some item in _items("next")
	some dep in object.get(item, "dependencies", [])
	not dep in _all_item_ids
	msg := sprintf("next item '%s' depends on non-existent '%s'", [item.id, dep])
}

violations contains msg if {
	some item in _items("next")
	some dep in object.get(item, "dependencies", [])
	some ar in _items("at_risk")
	ar.id == dep
	msg := sprintf("next item '%s' depends on at_risk item '%s'", [item.id, dep])
}

# --- 5. Owner coverage ---

violations contains msg if {
	some item in _all_items
	not item.owner
	msg := sprintf("item '%s' has no owner", [item.id])
}

owner_load := {owner: n |
	some item in _all_items
	owner := item.owner
	n := count([1 |
		some i in _all_items
		i.owner == owner
	])
}

violations contains msg if {
	some owner, n in owner_load
	n > 5
	msg := sprintf("owner '%s' overloaded with %d items (max 5)", [owner, n])
}

# --- 6. Staleness ---

stale_items := {item.id |
	some item in _all_items
	_item_age_days(item) > 14
}

violations contains msg if {
	some item in _items("at_risk")
	item.id in stale_items
	msg := sprintf("at_risk item '%s' is stale (>14 days)", [item.id])
}

# --- 7. Priority inversion ---

_needed_critical_priorities := {item.id |
	some item in _items("needed")
	item.priority in {"P0", "P1"}
}

_next_critical_priorities := {item.priority |
	some item in _items("next")
	item.priority in {"P0", "P1"}
}

violations contains msg if {
	some item in _items("needed")
	item.priority in {"P0", "P1"}
	not item.priority in _next_critical_priorities
	msg := sprintf("priority inversion: %s needed item '%s' has no matching priority in next", [item.priority, item.id])
}

# --- 8. Escalation triggers ---

escalation_required if has_critical_risks

escalation_required if readiness_score < 30

escalation_required if {
	count(_items("at_risk")) > count(_all_items) / 2
}

escalation_required if {
	some item in _items("needed")
	item.priority == "P0"
	_item_age_days(item) > 7
}

violations contains "escalation required: one or more trigger conditions met" if escalation_required

# --- Result ---

default valid := false

valid if count(violations) == 0
