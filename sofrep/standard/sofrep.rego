package sofrep.standard

import rego.v1

# ─── Helpers ──────────────────────────────────────────────────────────────────

quadrants := data.schema.quadrants

all_items := [item |
	some q in quadrants
	some item in object.get(input, q, [])
]

all_ids := {item.id | some item in all_items}

items_in(q) := object.get(input, q, [])

date_re := data.schema.date_pattern

# ─── Layer 1: Structural (errors) ────────────────────────────────────────────

# 1. Required metadata
deny contains {"msg": sprintf("missing required metadata field: %s", [f]), "severity": "error", "field": f, "rule": "required_metadata"} if {
	some f in data.schema.required_metadata
	f != "reporting_period"
	not object.get(input, f, "") != ""
}

deny contains {"msg": "missing required metadata field: reporting_period", "severity": "error", "field": "reporting_period", "rule": "required_metadata"} if {
	some f in data.schema.required_metadata
	f == "reporting_period"
	rp := object.get(input, "reporting_period", {})
	not object.get(rp, "start_date", "") != ""
}

deny contains {"msg": "missing required metadata field: reporting_period", "severity": "error", "field": "reporting_period", "rule": "required_metadata"} if {
	some f in data.schema.required_metadata
	f == "reporting_period"
	rp := object.get(input, "reporting_period", {})
	not object.get(rp, "end_date", "") != ""
}

# 2. Quadrant presence — must exist and be non-empty arrays
deny contains {"msg": sprintf("quadrant '%s' is missing", [q]), "severity": "error", "field": q, "rule": "quadrant_presence"} if {
	some q in quadrants
	not q in object.keys(input)
}

deny contains {"msg": sprintf("quadrant '%s' must be a non-empty array", [q]), "severity": "error", "field": q, "rule": "quadrant_non_empty"} if {
	some q in quadrants
	q in object.keys(input)
	count(object.get(input, q, [])) == 0
}

# 3. Base item fields
deny contains {"msg": sprintf("%s item '%s' missing base field: %s", [q, id, f]), "severity": "error", "field": f, "rule": "base_fields"} if {
	some q in quadrants
	some item in items_in(q)
	id := object.get(item, "id", "<no-id>")
	some f in data.schema.base_fields
	not object.get(item, f, "") != ""
}

# 4. Quadrant-specific fields
deny contains {"msg": sprintf("%s item '%s' missing field: %s", [q, id, f]), "severity": "error", "field": f, "rule": "quadrant_fields"} if {
	some q in quadrants
	qf := object.get(data.schema.quadrant_fields, q, [])
	some item in items_in(q)
	id := object.get(item, "id", "<no-id>")
	some f in qf
	val := object.get(item, f, "__MISSING__")
	val == "__MISSING__"
}

# ─── Layer 2: Type / Enum (errors) ───────────────────────────────────────────

# 5. Classification enum
deny contains {"msg": sprintf("invalid classification: %s", [c]), "severity": "error", "field": "classification", "rule": "classification_enum"} if {
	c := object.get(input, "classification", "")
	c != ""
	not c in {x | some x in data.schema.enums.classification}
}

# 6. Priority enum
deny contains {"msg": sprintf("%s item '%s' invalid priority: %s", [q, id, p]), "severity": "error", "field": "priority", "rule": "priority_enum"} if {
	some q in quadrants
	some item in items_in(q)
	id := object.get(item, "id", "<no-id>")
	p := object.get(item, "priority", "")
	p != ""
	not p in {x | some x in data.schema.enums.priority}
}

# 7. Urgency enum (needed items only)
deny contains {"msg": sprintf("needed item '%s' invalid urgency: %s", [id, u]), "severity": "error", "field": "urgency", "rule": "urgency_enum"} if {
	some item in items_in("needed")
	id := object.get(item, "id", "<no-id>")
	u := object.get(item, "urgency", "")
	u != ""
	not u in {x | some x in data.schema.enums.urgency}
}

# 8. Likelihood range (at_risk items, 1-5)
deny contains {"msg": sprintf("at_risk item '%s' likelihood must be 1-5, got: %v", [id, l]), "severity": "error", "field": "likelihood", "rule": "likelihood_range"} if {
	some item in items_in("at_risk")
	id := object.get(item, "id", "<no-id>")
	l := object.get(item, "likelihood", 0)
	not _in_range(l, 1, 5)
}

_in_range(v, lo, hi) if {
	v >= lo
	v <= hi
}

# 9. Date format validation
deny contains {"msg": sprintf("%s item '%s' invalid date format for last_updated: %s", [q, id, d]), "severity": "error", "field": "last_updated", "rule": "date_format"} if {
	some q in quadrants
	some item in items_in(q)
	id := object.get(item, "id", "<no-id>")
	d := object.get(item, "last_updated", "")
	d != ""
	not regex.match(date_re, d)
}

deny contains {"msg": sprintf("next item '%s' invalid date format for target_date: %s", [id, d]), "severity": "error", "field": "target_date", "rule": "date_format"} if {
	some item in items_in("next")
	id := object.get(item, "id", "<no-id>")
	d := object.get(item, "target_date", "")
	d != ""
	not regex.match(date_re, d)
}

# 10. Temporal validity — end_date > start_date
deny contains {"msg": sprintf("reporting_period end_date (%s) must be after start_date (%s)", [ed, sd]), "severity": "error", "field": "reporting_period", "rule": "temporal_validity"} if {
	rp := object.get(input, "reporting_period", {})
	sd := object.get(rp, "start_date", "")
	ed := object.get(rp, "end_date", "")
	sd != ""
	ed != ""
	ed <= sd
}

# ─── Layer 3: Cross-quadrant integrity (errors) ──────────────────────────────

# 11. Unique IDs across all quadrants
deny contains {"msg": sprintf("duplicate id '%s' found across quadrants", [id]), "severity": "error", "field": "id", "rule": "unique_ids"} if {
	some q1 in quadrants
	some i, item1 in items_in(q1)
	some q2 in quadrants
	some j, item2 in items_in(q2)
	item1.id == item2.id
	[q1, i] != [q2, j]
	id := item1.id
}

# 12. Dependency resolution — next items' deps must reference existing ids
deny contains {"msg": sprintf("next item '%s' has unresolved dependency: %s", [id, dep]), "severity": "error", "field": "dependencies", "rule": "dependency_resolution"} if {
	some item in items_in("next")
	id := object.get(item, "id", "<no-id>")
	some dep in object.get(item, "dependencies", [])
	not dep in all_ids
}

# 13. Conflict detection — same id in working_well AND at_risk
deny contains {"msg": sprintf("conflict: id '%s' appears in both working_well and at_risk", [id]), "severity": "error", "field": "id", "rule": "conflict_detection"} if {
	ww_ids := {item.id | some item in items_in("working_well")}
	ar_ids := {item.id | some item in items_in("at_risk")}
	some id in (ww_ids & ar_ids)
}

# ─── Layer 4: Operational intelligence (warnings) ────────────────────────────

# 14. Risk matrix
risk_matrix contains {"id": id, "title": t, "risk_score": rs, "risk_level": rl} if {
	some item in items_in("at_risk")
	id := object.get(item, "id", "<no-id>")
	t := object.get(item, "title", "")
	imp := object.get(item, "impact", 0)
	lik := object.get(item, "likelihood", 0)
	rs := imp * lik
	rl := _risk_level(rs)
}

_risk_level(s) := "critical" if s >= data.thresholds.risk_critical

_risk_level(s) := "high" if {
	s < data.thresholds.risk_critical
	s >= data.thresholds.risk_high
}

_risk_level(s) := "medium" if {
	s < data.thresholds.risk_high
	s >= data.thresholds.risk_medium
}

_risk_level(s) := "low" if s < data.thresholds.risk_medium

deny contains {"msg": sprintf("critical risk: '%s' (score=%d)", [r.id, r.risk_score]), "severity": "warning", "field": "at_risk", "rule": "critical_risk"} if {
	some r in risk_matrix
	r.risk_level == "critical"
}

# 15. Readiness score
total_items := count(all_items)

readiness_pct := 0 if total_items == 0

readiness_pct := round((count(items_in("working_well")) * 100) / total_items) if total_items > 0

deny contains {"msg": sprintf("readiness at %d%% is below minimum %d%%", [readiness_pct, data.thresholds.min_readiness_pct]), "severity": "warning", "field": "readiness", "rule": "low_readiness"} if {
	readiness_pct < data.thresholds.min_readiness_pct
}

# 16. Momentum — defensive posture
deny contains {"msg": "defensive posture: more at_risk items than next items", "severity": "warning", "field": "momentum", "rule": "defensive_posture"} if {
	count(items_in("at_risk")) > count(items_in("next"))
}

# 17. Dependency-on-risk
deny contains {"msg": sprintf("next item '%s' depends on at_risk item '%s'", [nid, dep]), "severity": "warning", "field": "dependencies", "rule": "dependency_on_risk"} if {
	ar_ids := {item.id | some item in items_in("at_risk")}
	some item in items_in("next")
	nid := object.get(item, "id", "<no-id>")
	some dep in object.get(item, "dependencies", [])
	dep in ar_ids
}

# 18. Owner overload
owner_counts[owner] := c if {
	some owner in {item.owner | some item in all_items}
	c := count([1 | some item in all_items; item.owner == owner])
}

deny contains {"msg": sprintf("owner '%s' has %d items (max %d)", [owner, c, data.thresholds.max_owner_items]), "severity": "warning", "field": "owner", "rule": "owner_overload"} if {
	some owner, c in owner_counts
	c > data.thresholds.max_owner_items
}

# 19. Staleness
_days_between(d1, d2) := days if {
	t1 := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [d1]))
	t2 := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [d2]))
	days := (t2 - t1) / (((24 * 60) * 60) * 1000000000)
}

_end_date := object.get(object.get(input, "reporting_period", {}), "end_date", "")

deny contains {"msg": sprintf("%s item '%s' is stale (last updated %s)", [q, id, d]), "severity": "warning", "field": "last_updated", "rule": "stale_item"} if {
	some q in quadrants
	q != "at_risk"
	some item in items_in(q)
	id := object.get(item, "id", "<no-id>")
	d := object.get(item, "last_updated", "")
	d != ""
	_end_date != ""
	_days_between(d, _end_date) > data.thresholds.staleness_days
}

deny contains {"msg": sprintf("at_risk item '%s' is stale (last updated %s)", [id, d]), "severity": "warning", "field": "last_updated", "rule": "stale_at_risk"} if {
	some item in items_in("at_risk")
	id := object.get(item, "id", "<no-id>")
	d := object.get(item, "last_updated", "")
	d != ""
	_end_date != ""
	_days_between(d, _end_date) > data.thresholds.staleness_days
}

# 20. Priority inversion — P0/P1 needed items not actioned by any next item
deny contains {"msg": sprintf("priority inversion: critical need '%s' (%s) has no next item actioning it", [id, p]), "severity": "warning", "field": "priority", "rule": "priority_inversion"} if {
	some item in items_in("needed")
	id := object.get(item, "id", "<no-id>")
	p := object.get(item, "priority", "")
	p in {"P0", "P1"}
	actioned_ids := {dep | some nx in items_in("next"); some dep in object.get(nx, "dependencies", [])}
	not id in actioned_ids
}

# 21. Escalation triggers
_has_critical_risk if {
	some r in risk_matrix
	r.risk_level == "critical"
}

_high_at_risk_pct if {
	total_items > 0
	(count(items_in("at_risk")) * 100) / total_items > 50
}

_p0_stale if {
	some item in items_in("needed")
	object.get(item, "priority", "") == "P0"
	d := object.get(item, "last_updated", "")
	d != ""
	_end_date != ""
	_days_between(d, _end_date) > data.thresholds.staleness_days
}

deny contains {"msg": "escalation required: one or more escalation triggers active", "severity": "warning", "field": "escalation", "rule": "escalation_required"} if {
	_has_critical_risk
}

deny contains {"msg": "escalation required: one or more escalation triggers active", "severity": "warning", "field": "escalation", "rule": "escalation_required"} if {
	readiness_pct < data.thresholds.escalation_readiness_pct
}

deny contains {"msg": "escalation required: one or more escalation triggers active", "severity": "warning", "field": "escalation", "rule": "escalation_required"} if {
	_high_at_risk_pct
}

deny contains {"msg": "escalation required: one or more escalation triggers active", "severity": "warning", "field": "escalation", "rule": "escalation_required"} if {
	_p0_stale
}

# ─── Results ──────────────────────────────────────────────────────────────────

errors := {d | some d in deny; d.severity == "error"}

warnings := {d | some d in deny; d.severity in {"warning", "info"}}

valid := count(errors) == 0

summary := {
	"valid": valid,
	"error_count": count(errors),
	"warning_count": count(warnings),
	"errors": errors,
	"warnings": warnings,
	"risk_matrix": risk_matrix,
	"readiness_pct": readiness_pct,
}
