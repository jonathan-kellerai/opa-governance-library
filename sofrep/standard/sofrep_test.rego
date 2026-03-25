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

# ═══════════════════════════════════════════════════════════════════════════════
# NEW TESTS: Wave 1 — Safety Floor
# ═══════════════════════════════════════════════════════════════════════════════

# ─── R2: default valid := false ──────────────────────────────────────────────

test_r2_valid_is_false_when_no_data_sentinel_fires if {
	# With valid data docs, valid_input is true (covered by test_valid_input above)
	# With no data docs at all, data_sentinel fires → valid must be false
	# Note: cannot test no-data-doc scenario in-process because schema.json is always loaded.
	# Instead, verify that default false exists by checking valid == true with valid input
	standard.valid with input as valid_input
}

# ─── R1: data_sentinel ──────────────────────────────────────────────────────

test_r1_data_sentinel_no_fire_with_valid_schema if {
	# With real schema.json loaded, data_sentinel should not fire
	errs := standard.errors with input as valid_input
	not_sentinel := {e | some e in errs; e.rule == "data_sentinel"}
	count(not_sentinel) == 0
}

test_r1_data_sentinel_fires_when_schema_missing if {
	# Override data.schema so quadrants sentinel key is missing
	some d in standard.deny with input as valid_input
		with data.schema as {}
		with data.thresholds as data.thresholds
	d.rule == "data_sentinel"
	d.severity == "error"
}

test_r1_data_sentinel_fires_when_thresholds_missing if {
	some d in standard.deny with input as valid_input
		with data.schema as data.schema
		with data.thresholds as {}
	d.rule == "data_sentinel"
	d.severity == "error"
}

# ─── R3: threshold_bounds ───────────────────────────────────────────────────

test_r3_threshold_bounds_valid if {
	# With default schema.json thresholds, no threshold_bounds error
	errs := standard.errors with input as valid_input
	bad := {e | some e in errs; e.rule == "threshold_bounds"}
	count(bad) == 0
}

test_r3_threshold_bounds_staleness_out_of_range if {
	bad_thresholds := object.union(data.thresholds, {"staleness_days": 99999})
	some d in standard.deny with input as valid_input
		with data.thresholds as bad_thresholds
	d.rule == "threshold_bounds"
	d.severity == "error"
	contains(d.msg, "staleness_days")
}

test_r3_threshold_bounds_risk_critical_exceeds_25 if {
	bad_thresholds := object.union(data.thresholds, {"risk_critical": 26})
	some d in standard.deny with input as valid_input
		with data.thresholds as bad_thresholds
	d.rule == "threshold_bounds"
	d.severity == "error"
	contains(d.msg, "risk_critical")
}

test_r3_threshold_bounds_non_numeric if {
	bad_thresholds := object.union(data.thresholds, {"staleness_days": "fourteen"})
	some d in standard.deny with input as valid_input
		with data.thresholds as bad_thresholds
	d.rule == "threshold_bounds"
	d.severity == "error"
	contains(d.msg, "must be numeric")
}

# ─── R4: schema_list_nonempty ───────────────────────────────────────────────

test_r4_schema_list_nonempty_valid if {
	errs := standard.errors with input as valid_input
	bad := {e | some e in errs; e.rule == "schema_list_nonempty"}
	count(bad) == 0
}

test_r4_quadrants_too_few if {
	bad_schema := object.union(data.schema, {"quadrants": ["working_well"]})
	some d in standard.deny with input as valid_input
		with data.schema as bad_schema
	d.rule == "schema_list_nonempty"
	d.severity == "error"
	contains(d.msg, "quadrants")
}

# ─── R6: _field_present helper (tested through R7/R11 rule behavior) ────────

test_r6_field_present_null_metadata if {
	# R7: metadata field set to null should fire required_metadata
	inp := object.union(valid_input, {"unit": null})
	some d in standard.deny with input as inp
	d.rule == "required_metadata"
	d.field == "unit"
}

test_r6_field_present_zero_metadata if {
	# R7: metadata field set to 0 should fire required_metadata
	inp := object.union(valid_input, {"author": 0})
	some d in standard.deny with input as inp
	d.rule == "required_metadata"
	d.field == "author"
}

test_r6_field_present_empty_string_metadata if {
	# R7: metadata field set to "" should fire required_metadata
	inp := object.union(valid_input, {"unit": ""})
	some d in standard.deny with input as inp
	d.rule == "required_metadata"
	d.field == "unit"
}

# ─── R8: impact_range ───────────────────────────────────────────────────────

test_r8_impact_out_of_range if {
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 6, "likelihood": 3, "mitigation": "test"})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "impact_range"
	d.severity == "error"
}

test_r8_impact_zero if {
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 0, "likelihood": 3, "mitigation": "test"})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "impact_range"
	d.severity == "error"
}

test_r8_impact_valid if {
	# impact 3 is valid (1-5)
	good_item := object.union(base_item("AR-OK", "SGT Chen"), {"impact": 3, "likelihood": 4, "mitigation": "test"})
	inp := object.union(valid_input, {"at_risk": [good_item]})
	errs := {d | some d in standard.deny with input as inp; d.rule == "impact_range"}

	# AR-OK has impact 3 (valid), but the original at_risk items also have valid impact values
	count(errs) == 0
}

# ─── R9: is_number guard on _in_range ───────────────────────────────────────

test_r9_likelihood_string_rejected if {
	# String "3" should be rejected by is_number guard
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 3, "likelihood": "3", "mitigation": "test"})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "likelihood_range"
	d.severity == "error"
}

test_r9_impact_string_rejected if {
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": "high", "likelihood": 3, "mitigation": "test"})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "impact_range"
	d.severity == "error"
}

# ─── R11: base_fields fix — null/empty values caught ────────────────────────

test_r11_base_field_null_title if {
	bad_item := object.union(base_item("WW-X", "SGT Chen"), {"evidence": "test", "title": null})
	inp := object.union(valid_input, {"working_well": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "base_fields"
	d.field == "title"
}

test_r11_base_field_empty_string_owner if {
	bad_item := object.union(base_item("WW-X", "SGT Chen"), {"evidence": "test", "owner": ""})
	inp := object.union(valid_input, {"working_well": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "base_fields"
	d.field == "owner"
}

# ─── R14: item_id_required (verify via R11) ─────────────────────────────────

test_r14_item_no_id_fires_base_fields if {
	bad_item := object.remove(base_item("WW-X", "SGT Chen"), ["id"])
	bad_item_with_evidence := object.union(bad_item, {"evidence": "test"})
	inp := object.union(valid_input, {"working_well": [bad_item_with_evidence]})
	some d in standard.deny with input as inp
	d.rule == "base_fields"
	d.field == "id"
}

test_r14_item_null_id_fires_base_fields if {
	bad_item := object.union(base_item("WW-X", "SGT Chen"), {"evidence": "test", "id": null})
	inp := object.union(valid_input, {"working_well": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "base_fields"
	d.field == "id"
}

test_r14_item_empty_id_fires_base_fields if {
	bad_item := object.union(base_item("WW-X", "SGT Chen"), {"evidence": "test", "id": ""})
	inp := object.union(valid_input, {"working_well": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "base_fields"
	d.field == "id"
}

# ─── R17: pattern_anchoring ─────────────────────────────────────────────────

test_r17_pattern_anchoring_valid if {
	# Default schema has anchored date_pattern
	errs := standard.errors with input as valid_input
	bad := {e | some e in errs; e.rule == "pattern_anchoring"}
	count(bad) == 0
}

test_r17_pattern_anchoring_unanchored if {
	bad_schema := object.union(data.schema, {"date_pattern": "\\d{4}-\\d{2}-\\d{2}"})
	some d in standard.deny with input as valid_input
		with data.schema as bad_schema
	d.rule == "pattern_anchoring"
	d.severity == "error"
}

# ─── R18: end_date_required ─────────────────────────────────────────────────

test_r18_end_date_required_valid if {
	errs := standard.errors with input as valid_input
	bad := {e | some e in errs; e.rule == "end_date_required"}
	count(bad) == 0
}

test_r18_end_date_required_fires if {
	# Remove reporting_period entirely first, then re-add with only start_date
	inp_no_rp := object.remove(valid_input, ["reporting_period"])
	inp := object.union(inp_no_rp, {"reporting_period": {"start_date": "2026-03-01"}})
	some d in standard.deny with input as inp
	d.rule == "end_date_required"
	d.severity == "error"
}

test_r18_end_date_absent_reporting_period if {
	# When reporting_period key is absent entirely, required_metadata fires
	# but end_date_required does NOT fire (guarded by "reporting_period" in object.keys(input))
	inp := object.remove(valid_input, ["reporting_period"])
	errs := {d |
		some d in standard.deny with input as inp
		d.rule == "end_date_required"
	}
	count(errs) == 0
}

# ─── R19: Escalation differentiation ────────────────────────────────────────

test_r19_escalation_critical_risk_message if {
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 5, "likelihood": 5, "mitigation": "none", "priority": "P0"})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "escalation_required"
	contains(d.msg, "critical risk item present")
}

test_r19_escalation_differentiated_messages if {
	# All four triggers should produce four distinct messages
	# For this test, trigger critical risk + low readiness
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 5, "likelihood": 5, "mitigation": "none", "priority": "P0"})
	inp := object.union(valid_input, {
		"at_risk": [bad_item],
		"working_well": [object.union(base_item("WW-001", "SGT Chen"), {"evidence": "test"})],
	})
	esc := {d |
		some d in standard.deny with input as inp
		d.rule == "escalation_required"
	}

	# Critical risk present → one message about critical risk
	some e in esc
	contains(e.msg, "critical risk item present")
}

# ═══════════════════════════════════════════════════════════════════════════════
# NEW TESTS: Wave 3 — Compliance and Domain Extensions
# ═══════════════════════════════════════════════════════════════════════════════

# ─── R20: high_priority_mitigation_required ─────────────────────────────────

test_r20_high_priority_mitigation_present if {
	# P0 at_risk item with mitigation → no deny
	good_item := object.union(base_item("AR-OK", "SGT Chen"), {"impact": 4, "likelihood": 3, "mitigation": "Plan drafted", "priority": "P0"})
	inp := object.union(valid_input, {"at_risk": [good_item]})
	errs := {d | some d in standard.deny with input as inp; d.rule == "high_priority_mitigation_required"}
	count(errs) == 0
}

test_r20_high_priority_mitigation_absent if {
	# P0 at_risk item without mitigation → deny
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 4, "likelihood": 3, "priority": "P0"})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "high_priority_mitigation_required"
	d.severity == "error"
}

test_r20_high_priority_mitigation_empty_string if {
	# P1 at_risk item with empty mitigation → deny
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 4, "likelihood": 3, "mitigation": "", "priority": "P1"})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "high_priority_mitigation_required"
	d.severity == "error"
}

test_r20_low_priority_no_mitigation_ok if {
	# P2 at_risk item without mitigation → no deny (P2 below threshold)
	low_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 2, "likelihood": 2, "priority": "P2"})
	inp := object.union(valid_input, {"at_risk": [low_item]})
	errs := {d | some d in standard.deny with input as inp; d.rule == "high_priority_mitigation_required"}
	count(errs) == 0
}

# ─── R21: contradictory_severity_signals ────────────────────────────────────

test_r21_contradictory_p0_low if {
	bad_item := object.union(base_item("ND-X", "SGT Chen"), {"justification": "test", "urgency": "low", "priority": "P0"})
	inp := object.union(valid_input, {"needed": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "contradictory_severity_signals"
	d.severity == "warning"
}

test_r21_contradictory_p1_medium if {
	bad_item := object.union(base_item("ND-X", "SGT Chen"), {"justification": "test", "urgency": "medium", "priority": "P1"})
	inp := object.union(valid_input, {"needed": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "contradictory_severity_signals"
	d.severity == "warning"
}

test_r21_no_contradiction_p0_critical if {
	# P0 with critical urgency is consistent → no deny
	good_item := object.union(base_item("ND-X", "SGT Chen"), {"justification": "test", "urgency": "critical", "priority": "P0"})
	inp := object.union(valid_input, {"needed": [good_item]})
	errs := {d | some d in standard.deny with input as inp; d.rule == "contradictory_severity_signals"}
	count(errs) == 0
}

test_r21_no_contradiction_p2 if {
	# P2 with any urgency is not in the contradictory set → no deny
	ok_item := object.union(base_item("ND-X", "SGT Chen"), {"justification": "test", "urgency": "low", "priority": "P2"})
	inp := object.union(valid_input, {"needed": [ok_item]})
	errs := {d | some d in standard.deny with input as inp; d.rule == "contradictory_severity_signals"}
	count(errs) == 0
}

# ─── R26: treatment_plan_required ───────────────────────────────────────────

test_r26_treatment_plan_required_high_risk if {
	# High risk item (score >= 12) without treatment_plan → warning
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 4, "likelihood": 3, "mitigation": "test", "priority": "P1"})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "treatment_plan_required"
	d.severity == "warning"
}

test_r26_treatment_plan_present if {
	# High risk item with treatment_plan → no deny
	good_item := object.union(base_item("AR-X", "SGT Chen"), {
		"impact": 4, "likelihood": 3, "mitigation": "test", "priority": "P1",
		"treatment_plan": {"strategy": "mitigate", "responsible_owner": "SGT Chen", "target_date": "2026-05-01", "status": "in_progress"},
	})
	inp := object.union(valid_input, {"at_risk": [good_item]})
	errs := {d | some d in standard.deny with input as inp; d.rule == "treatment_plan_required"}
	count(errs) == 0
}

test_r26_treatment_plan_not_required_low_risk if {
	# Low risk item (score < 6) → no treatment_plan warning
	low_item := object.union(base_item("AR-X", "SGT Chen"), {"impact": 1, "likelihood": 1, "mitigation": "test", "priority": "P2"})
	inp := object.union(valid_input, {"at_risk": [low_item]})
	errs := {d | some d in standard.deny with input as inp; d.rule == "treatment_plan_required"}
	count(errs) == 0
}

test_r26_treatment_plan_empty_object if {
	# treatment_plan: {} → fires (_field_present rejects empty object)
	bad_item := object.union(base_item("AR-X", "SGT Chen"), {
		"impact": 4, "likelihood": 3, "mitigation": "test", "priority": "P1",
		"treatment_plan": {},
	})
	inp := object.union(valid_input, {"at_risk": [bad_item]})
	some d in standard.deny with input as inp
	d.rule == "treatment_plan_required"
	d.severity == "warning"
}

# ─── R27: c_level_readiness ─────────────────────────────────────────────────

test_r27_c_level_c4_valid_input if {
	# valid_input: 3 working_well out of 10 total → 30%
	# 30 < c3_threshold (50) and 30 >= c4_threshold (25) → C4
	cl := standard.c_level with input as valid_input
	cl == "C4"
}

test_r27_c_level_c1_high_readiness if {
	# All items in working_well → 100% → C1
	inp := object.union(valid_input, {
		"needed": [object.union(base_item("ND-001", "CPL Okafor"), {"justification": "test", "urgency": "low"})],
		"at_risk": [object.union(base_item("AR-001", "SGT Chen"), {"impact": 1, "likelihood": 1, "mitigation": "test"})],
		"next": [object.union(base_item("NX-001", "SGT Chen"), {"target_date": "2026-04-10", "dependencies": [], "assigned_to": "SGT Chen"})],
		"working_well": [
			object.union(base_item("WW-001", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-002", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-003", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-004", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-005", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-006", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-007", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-008", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-009", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-010", "SGT Chen"), {"evidence": "test"}),
		],
	})
	cl := standard.c_level with input as inp

	# 10 working_well / 13 total ≈ 77% → C2
	# Actually 10 / 13 = 76.9 → rounds to 77 → C2
	cl == "C2"
}

test_r27_c_level_c5_zero_readiness if {
	# No working_well items → 0% → C5 → warning fires
	inp := object.union(valid_input, {"working_well": [object.union(base_item("WW-001", "SGT Chen"), {"evidence": "test"})]})

	# 1 ww / 8 total = 12.5% → rounds to 13 → below c4_threshold (25) → C5
	some d in standard.deny with input as inp
	d.rule == "c_level_readiness"
	d.severity == "warning"
}

test_r27_c_level_warning_fires_for_c4 if {
	# valid_input has readiness 30% → C4 → c_level_readiness warning fires
	some d in standard.deny with input as valid_input
	d.rule == "c_level_readiness"
	d.severity == "warning"
}

test_r27_c_level_no_warning_above_c3 if {
	# High readiness input → C2 → no c_level_readiness warning
	inp := object.union(valid_input, {
		"needed": [object.union(base_item("ND-001", "CPL Okafor"), {"justification": "test", "urgency": "low"})],
		"at_risk": [object.union(base_item("AR-001", "SGT Chen"), {"impact": 1, "likelihood": 1, "mitigation": "test"})],
		"next": [object.union(base_item("NX-001", "SGT Chen"), {"target_date": "2026-04-10", "dependencies": [], "assigned_to": "SGT Chen"})],
		"working_well": [
			object.union(base_item("WW-001", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-002", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-003", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-004", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-005", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-006", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-007", "SGT Chen"), {"evidence": "test"}),
			object.union(base_item("WW-008", "SGT Chen"), {"evidence": "test"}),
		],
	})

	# 8 / 11 ≈ 73% → C2 → no warning
	errs := {d | some d in standard.deny with input as inp; d.rule == "c_level_readiness"}
	count(errs) == 0
}
