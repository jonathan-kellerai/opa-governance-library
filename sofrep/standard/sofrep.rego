package sofrep.standard

import rego.v1

# ─── Helpers ──────────────────────────────────────────────────────────────────

# R6: Field presence helper — handles all OPA falsy-value edge cases
_sentinel := {"__sentinel__": true}

_field_present(obj, field) if {
	val := object.get(obj, field, _sentinel)
	val != _sentinel
	not val == null
	not val == ""
	not val == 0
	not val == false
	not val == []
	not val == {}
}

quadrants := data.schema.quadrants

all_items := [item |
	some q in quadrants
	some item in object.get(input, q, [])
]

all_ids := {item.id | some item in all_items}

items_in(q) := object.get(input, q, [])

date_re := data.schema.date_pattern

# R9/R8: Type-guarded range check — is_number prevents string comparison bypass
_in_range(v, lo, hi) if {
	is_number(v)
	v >= lo
	v <= hi
}

# R10: Type guard for risk level thresholds
_risk_level(s) := "critical" if {
	is_number(s)
	s >= data.thresholds.risk_critical
}

_risk_level(s) := "high" if {
	is_number(s)
	s < data.thresholds.risk_critical
	s >= data.thresholds.risk_high
}

_risk_level(s) := "medium" if {
	is_number(s)
	s < data.thresholds.risk_high
	s >= data.thresholds.risk_medium
}

_risk_level(s) := "low" if {
	is_number(s)
	s < data.thresholds.risk_medium
}

# R33: Extracted enum sets
_classification_values := {x | some x in data.schema.enums.classification}

_priority_values := {x | some x in data.schema.enums.priority}

_urgency_values := {x | some x in data.schema.enums.urgency}

# ─── Layer 0: Meta-validation ────────────────────────────────────────────────

# R1: Data sentinel — blocks valid when data document is absent or stripped
# Uses sentinel key checks to detect absent data document without traversing data root
_has_schema if {
	object.get(data.schema, "quadrants", null) != null
}

_has_thresholds if {
	object.get(data.thresholds, "staleness_days", null) != null
}

deny contains {"msg": "data.schema is missing or empty", "severity": "error", "field": "data.schema", "rule": "data_sentinel", "fix": "Provide a schema.json with quadrants, required_metadata, base_fields, and enums"} if {
	not _has_schema
}

deny contains {"msg": "data.thresholds is missing or empty", "severity": "error", "field": "data.thresholds", "rule": "data_sentinel", "fix": "Provide thresholds in schema.json with staleness_days, min_readiness_pct, and risk levels"} if {
	not _has_thresholds
}

deny contains {"msg": "data.schema.required_metadata is missing or empty", "severity": "error", "field": "data.schema.required_metadata", "rule": "data_sentinel", "fix": "Add a non-empty required_metadata array to schema.json"} if {
	_has_schema
	count(object.get(data.schema, "required_metadata", [])) == 0
}

deny contains {"msg": "data.schema.quadrants is missing or empty", "severity": "error", "field": "data.schema.quadrants", "rule": "data_sentinel", "fix": "Add a non-empty quadrants array to schema.json"} if {
	_has_schema
	count(object.get(data.schema, "quadrants", [])) == 0
}

deny contains {"msg": "data.schema.date_pattern is missing", "severity": "error", "field": "data.schema.date_pattern", "rule": "data_sentinel", "fix": "Add a date_pattern regex string to schema.json (e.g. '^\\\\d{4}-\\\\d{2}-\\\\d{2}$')"} if {
	_has_schema
	object.get(data.schema, "date_pattern", "") == ""
}

# R3: Threshold bounds — hard-coded range guards for all numeric thresholds
_sofrep_threshold_bounds := {
	"staleness_days": [1, 365],
	"min_readiness_pct": [0, 100],
	"escalation_readiness_pct": [0, 100],
	"max_owner_items": [1, 100],
	"risk_critical": [1, 25],
	"risk_high": [1, 25],
	"risk_medium": [1, 25],
	"c1_threshold": [0, 100],
	"c2_threshold": [0, 100],
	"c3_threshold": [0, 100],
	"c4_threshold": [0, 100],
}

deny contains {"msg": sprintf("threshold '%s' value %v out of bounds [%v, %v]", [k, v, bounds[0], bounds[1]]), "severity": "error", "field": k, "rule": "threshold_bounds", "fix": sprintf("Set threshold '%s' to a value between %v and %v", [k, bounds[0], bounds[1]])} if {
	_has_thresholds
	some k, bounds in _sofrep_threshold_bounds
	v := object.get(data.thresholds, k, null)
	v != null
	is_number(v)
	not _in_range(v, bounds[0], bounds[1])
}

deny contains {"msg": sprintf("threshold '%s' must be numeric, got: %v", [k, v]), "severity": "error", "field": k, "rule": "threshold_bounds", "fix": sprintf("Change threshold '%s' to a numeric value", [k])} if {
	_has_thresholds
	some k, _ in _sofrep_threshold_bounds
	v := object.get(data.thresholds, k, null)
	v != null
	not is_number(v)
}

# R4: Schema list nonempty — guards against emptied-out schema lists
deny contains {"msg": "data.schema.quadrants must have at least 4 entries", "severity": "error", "field": "data.schema.quadrants", "rule": "schema_list_nonempty", "fix": "Ensure schema.json quadrants contains all 4 entries: working_well, needed, at_risk, next"} if {
	_has_schema
	count(object.get(data.schema, "quadrants", [])) < 4
	count(object.get(data.schema, "quadrants", [])) > 0
}

deny contains {"msg": "data.schema.required_metadata must have at least 1 entry", "severity": "error", "field": "data.schema.required_metadata", "rule": "schema_list_nonempty", "fix": "Add at least one field name to schema.json required_metadata array"} if {
	_has_schema
	count(object.get(data.schema, "required_metadata", [])) < 1
}

deny contains {"msg": "data.schema.base_fields must have at least 1 entry", "severity": "error", "field": "data.schema.base_fields", "rule": "schema_list_nonempty", "fix": "Add at least one field name to schema.json base_fields array"} if {
	_has_schema
	count(object.get(data.schema, "base_fields", [])) < 1
}

# R34: Schema versioning — warn when schema version doesn't match policy expectation
_expected_schema_version := "1.0.0"

_actual_schema_version := v if {
	v := data._schema_version
} else := ""

deny contains {"msg": sprintf("schema version mismatch: policy expects '%s' but schema has '%s'", [_expected_schema_version, _actual_schema_version]), "severity": "warning", "field": "_schema_version", "rule": "schema_version_check", "fix": "Update schema.json _schema_version or update the policy to match"} if {
	_actual_schema_version != ""
	_actual_schema_version != _expected_schema_version
}

deny contains {"msg": sprintf("schema version missing: policy expects '%s' but _schema_version is not set", [_expected_schema_version]), "severity": "warning", "field": "_schema_version", "rule": "schema_version_check", "fix": "Add '_schema_version' field to your schema.json"} if {
	_actual_schema_version == ""
}

# R17: Pattern anchoring — meta-validation for regex patterns
deny contains {"msg": sprintf("schema.%s is not anchored (must start with ^ and end with $)", [k]), "severity": "error", "field": k, "rule": "pattern_anchoring", "fix": sprintf("Add ^ prefix and $ suffix to schema.%s regex pattern", [k])} if {
	some k in ["date_pattern"]
	pat := object.get(data.schema, k, "")
	pat != ""
	not startswith(pat, "^")
}

deny contains {"msg": sprintf("schema.%s is not anchored (must start with ^ and end with $)", [k]), "severity": "error", "field": k, "rule": "pattern_anchoring", "fix": sprintf("Add ^ prefix and $ suffix to schema.%s regex pattern", [k])} if {
	some k in ["date_pattern"]
	pat := object.get(data.schema, k, "")
	pat != ""
	not endswith(pat, "$")
}

# ─── Layer 1: Structural (errors) ────────────────────────────────────────────

# 1. Required metadata — R7: uses _field_present to fix double-negation
deny contains {"msg": sprintf("missing required metadata field: %s", [f]), "severity": "error", "field": f, "rule": "required_metadata", "fix": sprintf("Add the '%s' field to your report input", [f])} if {
	some f in data.schema.required_metadata
	f != "reporting_period"
	not _field_present(input, f)
}

deny contains {"msg": "missing required metadata field: reporting_period", "severity": "error", "field": "reporting_period", "rule": "required_metadata", "fix": "Add reporting_period with start_date and end_date (YYYY-MM-DD) to your report"} if {
	some f in data.schema.required_metadata
	f == "reporting_period"
	rp := object.get(input, "reporting_period", {})
	not _field_present(rp, "start_date")
}

deny contains {"msg": "missing required metadata field: reporting_period", "severity": "error", "field": "reporting_period", "rule": "required_metadata", "fix": "Add reporting_period with start_date and end_date (YYYY-MM-DD) to your report"} if {
	some f in data.schema.required_metadata
	f == "reporting_period"
	rp := object.get(input, "reporting_period", {})
	not _field_present(rp, "end_date")
}

# R18: Staleness guard — error when reporting_period exists but end_date is absent
deny contains {"msg": "reporting_period.end_date is required for staleness validation", "severity": "error", "field": "reporting_period", "rule": "end_date_required", "fix": "Add end_date (YYYY-MM-DD) to reporting_period"} if {
	"reporting_period" in object.keys(input)
	rp := object.get(input, "reporting_period", {})
	not _field_present(rp, "end_date")
}

# 2. Quadrant presence — must exist and be non-empty arrays
deny contains {"msg": sprintf("quadrant '%s' is missing", [q]), "severity": "error", "field": q, "rule": "quadrant_presence", "fix": sprintf("Add the '%s' quadrant array to your report input", [q])} if {
	some q in quadrants
	not q in object.keys(input)
}

deny contains {"msg": sprintf("quadrant '%s' must be a non-empty array", [q]), "severity": "error", "field": q, "rule": "quadrant_non_empty", "fix": sprintf("Add at least one item to the '%s' quadrant", [q])} if {
	some q in quadrants
	q in object.keys(input)
	count(object.get(input, q, [])) == 0
}

# 3. Base item fields — R11: uses _field_present to fix double-negation
deny contains {"msg": sprintf("%s item '%s' missing base field: %s", [q, id, f]), "severity": "error", "field": f, "rule": "base_fields", "fix": sprintf("Add the '%s' field to item '%s' in quadrant '%s'", [f, id, q])} if {
	some q in quadrants
	some item in items_in(q)
	id := object.get(item, "id", "<no-id>")
	some f in data.schema.base_fields
	not _field_present(item, f)
}

# 4. Quadrant-specific fields
deny contains {"msg": sprintf("%s item '%s' missing field: %s", [q, id, f]), "severity": "error", "field": f, "rule": "quadrant_fields", "fix": sprintf("Add the '%s' field to item '%s' in quadrant '%s'", [f, id, q])} if {
	some q in quadrants
	qf := object.get(data.schema.quadrant_fields, q, [])
	some item in items_in(q)
	id := object.get(item, "id", "<no-id>")
	some f in qf
	val := object.get(item, f, _sentinel)
	val == _sentinel
}

# ─── Layer 2: Type / Enum (errors) ───────────────────────────────────────────

# 5. Classification enum
deny contains {"msg": sprintf("invalid classification: %s", [c]), "severity": "error", "field": "classification", "rule": "classification_enum", "fix": "Use a valid classification: UNCLASSIFIED, CUI, CONFIDENTIAL, SECRET, or TOP_SECRET"} if {
	c := object.get(input, "classification", "")
	c != ""
	not c in _classification_values
}

# 6. Priority enum
deny contains {"msg": sprintf("%s item '%s' invalid priority: %s", [q, id, p]), "severity": "error", "field": "priority", "rule": "priority_enum", "fix": "Use a valid priority: P0, P1, P2, P3, or P4"} if {
	some q in quadrants
	some item in items_in(q)
	id := object.get(item, "id", "<no-id>")
	p := object.get(item, "priority", "")
	p != ""
	not p in _priority_values
}

# 7. Urgency enum (needed items only)
deny contains {"msg": sprintf("needed item '%s' invalid urgency: %s", [id, u]), "severity": "error", "field": "urgency", "rule": "urgency_enum", "fix": "Use a valid urgency: critical, high, medium, or low"} if {
	some item in items_in("needed")
	id := object.get(item, "id", "<no-id>")
	u := object.get(item, "urgency", "")
	u != ""
	not u in _urgency_values
}

# 8. Likelihood range (at_risk items, 1-5)
deny contains {"msg": sprintf("at_risk item '%s' likelihood must be 1-5, got: %v", [id, l]), "severity": "error", "field": "likelihood", "rule": "likelihood_range", "fix": "Set likelihood to an integer between 1 and 5"} if {
	some item in items_in("at_risk")
	id := object.get(item, "id", "<no-id>")
	l := object.get(item, "likelihood", 0)
	not _in_range(l, 1, 5)
}

# R8: Impact range (at_risk items, 1-5)
deny contains {"msg": sprintf("at_risk item '%s' impact must be 1-5, got: %v", [id, v]), "severity": "error", "field": "impact", "rule": "impact_range", "fix": "Set impact to an integer between 1 and 5"} if {
	some item in items_in("at_risk")
	id := object.get(item, "id", "<no-id>")
	v := object.get(item, "impact", 0)
	not _in_range(v, 1, 5)
}

# 9. Date format validation
deny contains {"msg": sprintf("%s item '%s' invalid date format for last_updated: %s", [q, id, d]), "severity": "error", "field": "last_updated", "rule": "date_format", "fix": "Use YYYY-MM-DD date format (e.g. 2026-03-25)"} if {
	some q in quadrants
	some item in items_in(q)
	id := object.get(item, "id", "<no-id>")
	d := object.get(item, "last_updated", "")
	d != ""
	not regex.match(date_re, d)
}

deny contains {"msg": sprintf("next item '%s' invalid date format for target_date: %s", [id, d]), "severity": "error", "field": "target_date", "rule": "date_format", "fix": "Use YYYY-MM-DD date format (e.g. 2026-03-25)"} if {
	some item in items_in("next")
	id := object.get(item, "id", "<no-id>")
	d := object.get(item, "target_date", "")
	d != ""
	not regex.match(date_re, d)
}

# 10. Temporal validity — end_date > start_date
deny contains {"msg": sprintf("reporting_period end_date (%s) must be after start_date (%s)", [ed, sd]), "severity": "error", "field": "reporting_period", "rule": "temporal_validity", "fix": "Ensure end_date is chronologically after start_date"} if {
	rp := object.get(input, "reporting_period", {})
	sd := object.get(rp, "start_date", "")
	ed := object.get(rp, "end_date", "")
	sd != ""
	ed != ""
	ed <= sd
}

# ─── Layer 3: Cross-quadrant integrity (errors) ──────────────────────────────

# 11. Unique IDs across all quadrants — O(n) set-vs-list comparison
_all_id_list := [item.id | some item in all_items]

_has_duplicate_ids if {
	count(_all_id_list) != count(all_ids)
}

_duplicate_ids contains id if {
	_has_duplicate_ids
	some id in all_ids
	count([1 | some x in _all_id_list; x == id]) > 1
}

deny contains {"msg": sprintf("duplicate id '%s' found across quadrants", [id]), "severity": "error", "field": "id", "rule": "unique_ids", "fix": sprintf("Ensure id '%s' appears in only one quadrant item", [id])} if {
	some id in _duplicate_ids
}

# 12. Dependency resolution — next items' deps must reference existing ids
deny contains {"msg": sprintf("next item '%s' has unresolved dependency: %s", [id, dep]), "severity": "error", "field": "dependencies", "rule": "dependency_resolution", "fix": sprintf("Add item '%s' to a quadrant or remove it from '%s' dependencies", [dep, id])} if {
	some item in items_in("next")
	id := object.get(item, "id", "<no-id>")
	some dep in object.get(item, "dependencies", [])
	not dep in all_ids
}

# 13. Conflict detection — same id in working_well AND at_risk
deny contains {"msg": sprintf("conflict: id '%s' appears in both working_well and at_risk", [id]), "severity": "error", "field": "id", "rule": "conflict_detection", "fix": sprintf("Move item '%s' to only one quadrant — it cannot be both working_well and at_risk", [id])} if {
	ww_ids := {item.id | some item in items_in("working_well")}
	ar_ids := {item.id | some item in items_in("at_risk")}
	some id in (ww_ids & ar_ids)
}

# R20: Severity-gated mitigation — P0/P1 at_risk items must have mitigation
deny contains {"msg": sprintf("at_risk item '%s' has priority %s: mitigation plan is required", [id, p]), "severity": "error", "field": "mitigation", "rule": "high_priority_mitigation_required", "fix": sprintf("Add a 'mitigation' field describing the risk mitigation plan for item '%s'", [id])} if {
	some item in items_in("at_risk")
	id := object.get(item, "id", "<no-id>")
	p := object.get(item, "priority", "")
	p in {x | some x in data.thresholds.high_priority_mitigation_priorities}
	not _field_present(item, "mitigation")
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

deny contains {"msg": sprintf("critical risk: '%s' (score=%d)", [r.id, r.risk_score]), "severity": "warning", "field": "at_risk", "rule": "critical_risk", "fix": sprintf("Reduce impact or likelihood for item '%s', or add a treatment_plan with mitigation strategy", [r.id])} if {
	some r in risk_matrix
	r.risk_level == "critical"
}

# 15. Readiness score
total_items := count(all_items)

readiness_pct := 0 if total_items == 0

readiness_pct := round((count(items_in("working_well")) * 100) / total_items) if total_items > 0

deny contains {"msg": sprintf("readiness at %d%% is below minimum %d%%", [readiness_pct, data.thresholds.min_readiness_pct]), "severity": "warning", "field": "readiness", "rule": "low_readiness", "fix": "Increase working_well items or resolve at_risk/needed items to raise readiness percentage"} if {
	readiness_pct < data.thresholds.min_readiness_pct
}

# R27: C-level readiness (SORTS/DRRS)
c_level := "C1" if readiness_pct >= data.thresholds.c1_threshold

c_level := "C2" if {
	readiness_pct < data.thresholds.c1_threshold
	readiness_pct >= data.thresholds.c2_threshold
}

c_level := "C3" if {
	readiness_pct < data.thresholds.c2_threshold
	readiness_pct >= data.thresholds.c3_threshold
}

c_level := "C4" if {
	readiness_pct < data.thresholds.c3_threshold
	readiness_pct >= data.thresholds.c4_threshold
}

c_level := "C5" if {
	readiness_pct < data.thresholds.c4_threshold
}

deny contains {"msg": sprintf("readiness %d%% is C4/C5 — unit not mission capable", [readiness_pct]), "severity": "warning", "field": "readiness", "rule": "c_level_readiness", "fix": "Increase working_well items to achieve at least C3 readiness (50%+)"} if {
	c_level in {"C4", "C5"}
}

# 16. Momentum — defensive posture
deny contains {"msg": "defensive posture: more at_risk items than next items", "severity": "warning", "field": "momentum", "rule": "defensive_posture", "fix": "Add more next (action) items to address at_risk items and shift to an offensive posture"} if {
	count(items_in("at_risk")) > count(items_in("next"))
}

# 17. Dependency-on-risk
deny contains {"msg": sprintf("next item '%s' depends on at_risk item '%s'", [nid, dep]), "severity": "warning", "field": "dependencies", "rule": "dependency_on_risk", "fix": sprintf("Resolve at_risk item '%s' or remove it from '%s' dependencies", [dep, nid])} if {
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

deny contains {"msg": sprintf("owner '%s' has %d items (max %d)", [owner, c, data.thresholds.max_owner_items]), "severity": "warning", "field": "owner", "rule": "owner_overload", "fix": sprintf("Redistribute items from '%s' to other owners to stay within the %d-item limit", [owner, data.thresholds.max_owner_items])} if {
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

deny contains {"msg": sprintf("%s item '%s' is stale (last updated %s)", [q, id, d]), "severity": "warning", "field": "last_updated", "rule": "stale_item", "fix": sprintf("Update last_updated on item '%s' in quadrant '%s' to a recent date", [id, q])} if {
	some q in quadrants
	q != "at_risk"
	some item in items_in(q)
	id := object.get(item, "id", "<no-id>")
	d := object.get(item, "last_updated", "")
	d != ""
	_end_date != ""
	_days_between(d, _end_date) > data.thresholds.staleness_days
}

deny contains {"msg": sprintf("at_risk item '%s' is stale (last updated %s)", [id, d]), "severity": "warning", "field": "last_updated", "rule": "stale_at_risk", "fix": sprintf("Update last_updated on at_risk item '%s' to reflect current assessment status", [id])} if {
	some item in items_in("at_risk")
	id := object.get(item, "id", "<no-id>")
	d := object.get(item, "last_updated", "")
	d != ""
	_end_date != ""
	_days_between(d, _end_date) > data.thresholds.staleness_days
}

# 20. Priority inversion — P0/P1 needed items not actioned by any next item
deny contains {"msg": sprintf("priority inversion: critical need '%s' (%s) has no next item actioning it", [id, p]), "severity": "warning", "field": "priority", "rule": "priority_inversion", "fix": sprintf("Add a next item with '%s' in its dependencies to action this critical need", [id])} if {
	some item in items_in("needed")
	id := object.get(item, "id", "<no-id>")
	p := object.get(item, "priority", "")
	p in {"P0", "P1"}
	actioned_ids := {dep | some nx in items_in("next"); some dep in object.get(nx, "dependencies", [])}
	not id in actioned_ids
}

# 21. Escalation triggers — R19: differentiated messages per trigger
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

deny contains {"msg": "escalation required: critical risk item present", "severity": "warning", "field": "escalation", "rule": "escalation_required", "fix": "Escalate to command — a critical risk item requires immediate leadership attention"} if {
	_has_critical_risk
}

deny contains {"msg": "escalation required: readiness below escalation threshold", "severity": "warning", "field": "escalation", "rule": "escalation_required", "fix": "Escalate to command — readiness is critically low and requires intervention"} if {
	readiness_pct < data.thresholds.escalation_readiness_pct
}

deny contains {"msg": "escalation required: at_risk items exceed 50% of total", "severity": "warning", "field": "escalation", "rule": "escalation_required", "fix": "Escalate to command — majority of items are at risk, resolve or mitigate at_risk items"} if {
	_high_at_risk_pct
}

deny contains {"msg": "escalation required: P0 needed item is stale", "severity": "warning", "field": "escalation", "rule": "escalation_required", "fix": "Escalate to command — a P0 critical need has gone unaddressed past the staleness threshold"} if {
	_p0_stale
}

# R21: Contradictory severity signals — urgency/priority mismatch on needed items
deny contains {"msg": sprintf("contradictory signals: item '%s' has priority P0/P1 but urgency low/medium", [id]), "severity": "warning", "field": "urgency", "rule": "contradictory_severity_signals", "fix": sprintf("Align urgency with priority for item '%s' — P0/P1 items should have critical or high urgency", [id])} if {
	some item in items_in("needed")
	id := object.get(item, "id", "<no-id>")
	p := object.get(item, "priority", "")
	u := object.get(item, "urgency", "")
	p in {"P0", "P1"}
	u in {"low", "medium"}
}

# R26: Treatment plan required — ISO 31000 for critical/high risk items
deny contains {"msg": sprintf("at_risk item '%s' has %s risk (score=%d): structured treatment_plan required", [id, rl, rs]), "severity": "warning", "field": "treatment_plan", "rule": "treatment_plan_required", "fix": sprintf("Add a treatment_plan to item '%s' with strategy, responsible_owner, target_date, and status", [id])} if {
	some r in risk_matrix
	r.risk_level in {"critical", "high"}
	id := r.id
	rs := r.risk_score
	rl := r.risk_level
	item := [i | some i in items_in("at_risk"); i.id == id][0]
	not _field_present(item, "treatment_plan")
}

# ─── Results ──────────────────────────────────────────────────────────────────

default max_deny_entries := 100

max_deny_entries := data.thresholds.max_deny_entries if {
	is_number(data.thresholds.max_deny_entries)
}

errors := {d | some d in deny; d.severity == "error"}

warnings := {d | some d in deny; d.severity in {"warning", "info"}}

# Capped deny set — consumers should use deny_capped when deny could be large
_deny_is_capped if {
	count(deny) > max_deny_entries
}

deny_capped contains d if {
	not _deny_is_capped
	some d in deny
}

deny_capped contains d if {
	_deny_is_capped
	_deny_as_array := sort([d2 | some d2 in deny])
	some i, d in _deny_as_array
	i < max_deny_entries
}

deny_capped contains {"msg": sprintf("output truncated: %d total findings exceed cap of %d", [count(deny), max_deny_entries]), "severity": "error", "field": "_meta", "rule": "deny_cap", "fix": "Reduce violations or increase max_deny_entries threshold"} if {
	_deny_is_capped
}

# R2: Default valid to false — closes third-state gap when data is absent
default valid := false

valid if count(errors) == 0

summary := {
	"valid": valid,
	"error_count": count(errors),
	"warning_count": count(warnings),
	"errors": errors,
	"warnings": warnings,
	"risk_matrix": risk_matrix,
	"readiness_pct": readiness_pct,
	"c_level": c_level,
	"deny_capped": deny_capped,
}
