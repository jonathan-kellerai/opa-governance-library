package sofrep.standard_test

import rego.v1

import data.sofrep.standard

# ─── Test fixtures ────────────────────────────────────────────────────────────

base_item(id, owner) := {
	"id": id,
	"title": sprintf("Title %s", [id]),
	"description": sprintf("Desc %s", [id]),
	"owner": owner,
	"priority": "P2",
	"last_updated": "2026-03-20",
}

valid_input := {
	"unit": "Platform Engineering Squad",
	"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-25"},
	"classification": "UNCLASSIFIED",
	"author": "SSG Rivera",
	"working_well": [
		object.union(base_item("WW-001", "SGT Chen"), {"evidence": "Dashboard shows 98.7%"}),
		object.union(base_item("WW-002", "CPL Okafor"), {"evidence": "Trivy gate active"}),
		object.union(base_item("WW-003", "SPC Davis"), {"evidence": "MTTA under 5m"}),
	],
	"needed": [
		object.union(base_item("ND-001", "CPL Okafor"), {"justification": "STIG finding", "urgency": "critical", "priority": "P0"}),
		object.union(base_item("ND-002", "SPC Davis"), {"justification": "Storage at 78%", "urgency": "high", "priority": "P1"}),
	],
	"at_risk": [
		object.union(base_item("AR-001", "SGT Chen"), {"impact": 4, "likelihood": 3, "mitigation": "Staged rollout", "priority": "P1"}),
		object.union(base_item("AR-002", "SPC Davis"), {"impact": 5, "likelihood": 2, "mitigation": "HA replica ready", "priority": "P1"}),
	],
	"next": [
		object.union(base_item("NX-001", "CPL Okafor"), {"target_date": "2026-04-10", "dependencies": ["ND-001"], "assigned_to": "CPL Okafor", "priority": "P0"}),
		object.union(base_item("NX-002", "SGT Chen"), {"target_date": "2026-04-05", "dependencies": ["AR-001"], "assigned_to": "SGT Chen", "priority": "P1"}),
		object.union(base_item("NX-003", "SPC Davis"), {"target_date": "2026-04-15", "dependencies": ["ND-002"], "assigned_to": "SPC Davis", "priority": "P1"}),
	],
}

# ─── 1. Valid input → valid true ─────────────────────────────────────────────

test_valid_input if {
	standard.valid with input as valid_input
}

# ─── 2. Zero errors ─────────────────────────────────────────────────────────

test_zero_errors if {
	count(standard.errors) == 0 with input as valid_input
}

# ─── 3. Missing metadata field → error ──────────────────────────────────────

test_missing_metadata if {
	inp := object.remove(valid_input, ["author"])
	some d in standard.deny with input as inp
	d.rule == "required_metadata"
	d.severity == "error"
}

# ─── 4. Missing quadrant → error ────────────────────────────────────────────

test_missing_quadrant if {
	inp := object.remove(valid_input, ["at_risk"])
	some d in standard.deny with input as inp
	d.rule == "quadrant_presence"
	d.severity == "error"
}

# ─── 5. Empty quadrant → error ──────────────────────────────────────────────

test_empty_quadrant if {
	inp := object.union(valid_input, {"working_well": []})
	some d in standard.deny with input as inp
	d.rule == "quadrant_non_empty"
	d.severity == "error"
}

# ─── 6. Missing base field → error ──────────────────────────────────────────

test_missing_base_field if {
	bad_item := object.union(object.remove(base_item("WW-X", "SGT Chen"), ["title"]), {"evidence": "test"})
	inp := object.union(valid_input, {"working_well": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "base_fields"
	d.field == "title"
	d.severity == "error"
}

# ─── 7. Missing quadrant-specific field → error ─────────────────────────────

test_missing_quadrant_specific_field if {
	bad_item := base_item("WW-X", "SGT Chen")
	inp := object.union(valid_input, {"working_well": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "quadrant_fields"
	d.field == "evidence"
	d.severity == "error"
}

# ─── 8. Invalid classification → error ──────────────────────────────────────

test_invalid_classification if {
	inp := object.union(valid_input, {"classification": "COSMIC_TOP_SECRET"})
	some d in standard.deny with input as inp
	d.rule == "classification_enum"
	d.severity == "error"
}

# ─── 9. Invalid priority → error ────────────────────────────────────────────

test_invalid_priority if {
	bad_item := object.union(base_item("WW-X", "SGT Chen"), {"evidence": "test", "priority": "P9"})
	inp := object.union(valid_input, {"working_well": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "priority_enum"
	d.severity == "error"
}

# ─── 10. Invalid urgency → error ────────────────────────────────────────────

test_invalid_urgency if {
	bad_item := object.union(base_item("ND-X", "SGT Chen"), {"justification": "test", "urgency": "extreme"})
	inp := object.union(valid_input, {"needed": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "urgency_enum"
	d.severity == "error"
}

# ─── 11. Likelihood out of range → error ────────────────────────────────────

test_likelihood_out_of_range if {
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 3, "likelihood": 7, "mitigation": "test"})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "likelihood_range"
	d.severity == "error"
}

# ─── 12. Invalid date format → error ────────────────────────────────────────

test_invalid_date_format if {
	bad_item := object.union(base_item("WW-X", "SGT Chen"), {"evidence": "test", "last_updated": "03-20-2026"})
	inp := object.union(valid_input, {"working_well": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "date_format"
	d.severity == "error"
}

# ─── 13. End before start → error ───────────────────────────────────────────

test_end_before_start if {
	inp := object.union(valid_input, {"reporting_period": {"start_date": "2026-03-25", "end_date": "2026-03-01"}})
	some d in standard.deny with input as inp
	d.rule == "temporal_validity"
	d.severity == "error"
}

# ─── 14. Duplicate IDs → error ──────────────────────────────────────────────

test_duplicate_ids if {
	dup_item := object.union(base_item("WW-001", "SGT Chen"), {"justification": "test", "urgency": "low"})
	inp := object.union(valid_input, {"needed": [dup_item]})
	some d in standard.deny with input as inp
	d.rule == "unique_ids"
	d.severity == "error"
}

# ─── 15. Unresolved dependency → error ──────────────────────────────────────

test_unresolved_dependency if {
	bad_item := object.union(base_item("NX-X", "SGT Chen"), {"target_date": "2026-04-10", "dependencies": ["GHOST-999"], "assigned_to": "SGT Chen"})
	inp := object.union(valid_input, {"next": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "dependency_resolution"
	d.severity == "error"
}

# ─── 16. Conflict detection → error ─────────────────────────────────────────

test_conflict_detection if {
	conflict_item_ww := object.union(base_item("CONFLICT-001", "SGT Chen"), {"evidence": "test"})
	conflict_item_ar := object.union(base_item("CONFLICT-001", "SGT Chen"), {"impact": 3, "likelihood": 2, "mitigation": "test"})
	inp := object.union(valid_input, {
		"working_well": array.concat(valid_input.working_well, [conflict_item_ww]),
		"at_risk": array.concat(valid_input.at_risk, [conflict_item_ar]),
	})
	some d in standard.deny with input as inp
	d.rule == "conflict_detection"
	d.severity == "error"
}

# ─── 17. Critical risk → warning ────────────────────────────────────────────

test_critical_risk if {
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 5, "likelihood": 5, "mitigation": "none", "priority": "P0"})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "critical_risk"
	d.severity == "warning"
}

# ─── 18. Low readiness → warning ────────────────────────────────────────────

test_low_readiness if {
	# 1 working_well out of many items → low readiness
	inp := object.union(valid_input, {"working_well": [object.union(base_item("WW-001", "SGT Chen"), {"evidence": "test"})]})
	pct := standard.readiness_pct with input as inp
	pct < data.thresholds.min_readiness_pct
	some d in standard.deny with input as inp
	d.rule == "low_readiness"
	d.severity == "warning"
}

# ─── 19. Defensive posture → warning ────────────────────────────────────────

test_defensive_posture if {
	many_ar := [
		object.union(base_item("AR-A", "SGT Chen"), {"impact": 2, "likelihood": 2, "mitigation": "test"}),
		object.union(base_item("AR-B", "SGT Chen"), {"impact": 2, "likelihood": 2, "mitigation": "test"}),
		object.union(base_item("AR-C", "SGT Chen"), {"impact": 2, "likelihood": 2, "mitigation": "test"}),
		object.union(base_item("AR-D", "SGT Chen"), {"impact": 2, "likelihood": 2, "mitigation": "test"}),
	]
	one_next := [object.union(base_item("NX-A", "SGT Chen"), {"target_date": "2026-04-10", "dependencies": [], "assigned_to": "SGT Chen"})]
	inp := object.union(valid_input, {"at_risk": many_ar, "next": one_next})
	some d in standard.deny with input as inp
	d.rule == "defensive_posture"
	d.severity == "warning"
}

# ─── 20. Dependency on at_risk → warning ────────────────────────────────────

test_dependency_on_risk if {
	# NX-002 depends on AR-001 in valid_input
	some d in standard.deny with input as valid_input
	d.rule == "dependency_on_risk"
	d.severity == "warning"
}

# ─── 21. Owner overload → warning ───────────────────────────────────────────

test_owner_overload if {
	overloaded := [
		object.union(base_item("OL-1", "SGT Chen"), {"evidence": "test"}),
		object.union(base_item("OL-2", "SGT Chen"), {"evidence": "test"}),
		object.union(base_item("OL-3", "SGT Chen"), {"evidence": "test"}),
		object.union(base_item("OL-4", "SGT Chen"), {"evidence": "test"}),
		object.union(base_item("OL-5", "SGT Chen"), {"evidence": "test"}),
		object.union(base_item("OL-6", "SGT Chen"), {"evidence": "test"}),
	]
	inp := object.union(valid_input, {"working_well": overloaded})
	some d in standard.deny with input as inp
	d.rule == "owner_overload"
	d.severity == "warning"
}

# ─── 22. Stale item → warning ───────────────────────────────────────────────

test_stale_item if {
	stale_item := object.union(base_item("WW-X", "SGT Chen"), {"evidence": "test", "last_updated": "2026-02-01"})
	inp := object.union(valid_input, {"working_well": [stale_item]})
	some d in standard.deny with input as inp
	d.rule == "stale_item"
	d.severity == "warning"
}

# ─── 23. Stale at_risk item → warning (stale_at_risk rule) ──────────────────

test_stale_at_risk if {
	stale_ar := object.union(base_item("AR-X", "SGT Chen"), {"impact": 3, "likelihood": 2, "mitigation": "test", "last_updated": "2026-02-01"})
	inp := object.union(valid_input, {"at_risk": [stale_ar]})
	some d in standard.deny with input as inp
	d.rule == "stale_at_risk"
	d.severity == "warning"
}

# ─── 24. Priority inversion → warning ───────────────────────────────────────

test_priority_inversion if {
	# P0 needed item with no next item referencing it
	orphan_need := object.union(base_item("ND-ORPHAN", "SGT Chen"), {"justification": "critical gap", "urgency": "critical", "priority": "P0"})
	inp := object.union(valid_input, {"needed": array.concat(valid_input.needed, [orphan_need])})
	some d in standard.deny with input as inp
	d.rule == "priority_inversion"
	d.severity == "warning"
	contains(d.msg, "ND-ORPHAN")
}

# ─── 25. Escalation trigger → warning ───────────────────────────────────────

test_escalation_trigger if {
	# Critical risk triggers escalation
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 5, "likelihood": 5, "mitigation": "none", "priority": "P0"})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "escalation_required"
	d.severity == "warning"
}

# ─── 26. Division-safe: empty quadrants don't crash readiness ────────────────

test_empty_quadrants_readiness_safe if {
	# Even though empty quadrants generate errors, readiness should not crash
	inp := object.union(valid_input, {
		"working_well": [],
		"needed": [],
		"at_risk": [],
		"next": [],
	})
	r := standard.readiness_pct with input as inp
	r == 0
}
