# METADATA
# title: SoFREP Validator Tests
# description: |
#   Test suite for the SoFREP policy. Covers structural completeness,
#   item schema, quadrant-specific rules, cross-quadrant integrity,
#   temporal validity, classification, staleness detection, and risk scoring.
package sofrep.v1_test

import rego.v1

import data.sofrep.v1 as sofrep

# ============================================================================
# HELPER: Build a complete valid SoFREP input for test cases to modify.
# ============================================================================

valid_input := {
	"unit": "Platform Engineering Squad",
	"author": "CPT Jane Doe",
	"classification": "CONFIDENTIAL",
	"mission_statement": "Deliver reliable platform services",
	"operational_tempo": "high",
	"reporting_period": {
		"start": "2026-03-01",
		"end": "2026-03-15",
	},
	"working_well": [{
		"id": "WW-001",
		"title": "CI/CD Pipeline",
		"description": "All pipelines green, <5min avg build time",
		"status": "healthy",
		"owner": "SFC Smith",
		"priority": "P1",
		"last_updated": "2026-03-14",
		"evidence": "99.8% success rate over last 14 days, Grafana dashboard link",
	}],
	"needed": [{
		"id": "ND-001",
		"title": "Dedicated DBA Support",
		"description": "Database performance tuning expertise required",
		"status": "open",
		"owner": "CPT Doe",
		"priority": "P2",
		"last_updated": "2026-03-10",
		"justification": "Query latency up 40% month-over-month with no internal expertise",
		"urgency": "high",
	}],
	"at_risk": [{
		"id": "AR-001",
		"title": "Kubernetes Cluster Capacity",
		"description": "Node pool at 87% utilization, scaling limits approaching",
		"status": "degraded",
		"owner": "SGT Johnson",
		"priority": "P1",
		"last_updated": "2026-03-13",
		"impact": 4,
		"likelihood": 3,
		"mitigation": "Requesting additional node pool allocation from cloud team",
	}],
	"next": [{
		"id": "NX-001",
		"title": "Deploy Observability Stack v2",
		"description": "Roll out OpenTelemetry collector and new dashboards",
		"status": "planned",
		"owner": "SGT Lee",
		"priority": "P1",
		"last_updated": "2026-03-12",
		"target_date": "2026-03-25",
		"dependencies": ["WW-001"],
		"assigned_to": "SGT Lee",
	}],
}

# ============================================================================
# TEST 1: A fully valid SoFREP passes all checks.
# ============================================================================
test_valid_report_passes if {
	sofrep.valid with input as valid_input
}

# ============================================================================
# TEST 2: Missing metadata fields produce violations.
# ============================================================================
test_missing_metadata_unit if {
	inp := object.remove(valid_input, ["unit"])
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	"metadata: 'unit' field is required" in violations
}

test_missing_metadata_author if {
	inp := object.remove(valid_input, ["author"])
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	"metadata: 'author' field is required" in violations
}

# ============================================================================
# TEST 3: Invalid classification is rejected.
# ============================================================================
test_invalid_classification if {
	inp := object.union(valid_input, {"classification": "ULTRA_SECRET"})
	not sofrep.valid with input as inp
}

# ============================================================================
# TEST 4: Missing quadrant produces a structural violation.
# ============================================================================
test_missing_quadrant if {
	inp := object.remove(valid_input, ["at_risk"])
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	some msg in violations
	contains(msg, "quadrant 'at_risk' is missing")
}

# ============================================================================
# TEST 5: Empty quadrant is rejected.
# ============================================================================
test_empty_quadrant if {
	inp := object.union(valid_input, {"working_well": []})
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	some msg in violations
	contains(msg, "quadrant 'working_well' must contain at least one item")
}

# ============================================================================
# TEST 6: Item missing a base field produces a violation.
# ============================================================================
test_item_missing_base_field if {
	bad_item := object.remove(valid_input.working_well[0], ["owner"])
	inp := object.union(valid_input, {"working_well": [bad_item]})
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	some msg in violations
	contains(msg, "missing required field 'owner'")
}

# ============================================================================
# TEST 7: working_well item missing evidence is rejected.
# ============================================================================
test_working_well_missing_evidence if {
	bad_item := object.remove(valid_input.working_well[0], ["evidence"])
	inp := object.union(valid_input, {"working_well": [bad_item]})
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	some msg in violations
	contains(msg, "missing required 'evidence' field")
}

# ============================================================================
# TEST 8: Duplicate id across quadrants is a cross-quadrant violation.
# ============================================================================
test_duplicate_id_across_quadrants if {
	# Give the at_risk item the same id as the working_well item.
	dup_ar := object.union(valid_input.at_risk[0], {"id": "WW-001"})
	inp := object.union(valid_input, {"at_risk": [dup_ar]})
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	some msg in violations
	contains(msg, "duplicate id 'WW-001'")
}

# ============================================================================
# TEST 9: Invalid dependency in next item is flagged.
# ============================================================================
test_invalid_dependency if {
	bad_next := object.union(valid_input.next[0], {"dependencies": ["NONEXISTENT-999"]})
	inp := object.union(valid_input, {"next": [bad_next]})
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	some msg in violations
	contains(msg, "dependency 'NONEXISTENT-999'")
}

# ============================================================================
# TEST 10: Reporting period end before start is a temporal violation.
# ============================================================================
test_reporting_period_end_before_start if {
	inp := object.union(valid_input, {"reporting_period": {
		"start": "2026-03-15",
		"end": "2026-03-01",
	}})
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	some msg in violations
	contains(msg, "reporting_period.end")
}

# ============================================================================
# TEST 11: Stale items are detected.
# ============================================================================
test_stale_item_detected if {
	# Set last_updated to 60 days before reporting_period.end
	stale_ww := object.union(valid_input.working_well[0], {"last_updated": "2026-01-10"})
	inp := object.union(valid_input, {"working_well": [stale_ww]})
	stale := sofrep.stale_items with input as inp
	count(stale) > 0
}

# ============================================================================
# TEST 12: Critical risk scoring flags high-risk items.
# ============================================================================
test_critical_risk_detected if {
	# impact=5, likelihood=5 => risk_score=25 >= 20 (critical threshold)
	critical_ar := object.union(valid_input.at_risk[0], {"impact": 5, "likelihood": 5})
	inp := object.union(valid_input, {"at_risk": [critical_ar]})
	crits := sofrep.critical_risks with input as inp
	count(crits) > 0
}

# ============================================================================
# TEST 13: Non-critical risk is NOT flagged as critical.
# ============================================================================
test_non_critical_risk_not_flagged if {
	# impact=2, likelihood=2 => risk_score=4 < 20 (safe)
	safe_ar := object.union(valid_input.at_risk[0], {"impact": 2, "likelihood": 2})
	inp := object.union(valid_input, {"at_risk": [safe_ar]})
	crits := sofrep.critical_risks with input as inp
	count(crits) == 0
}

# ============================================================================
# TEST 14: at_risk item missing mitigation is rejected.
# ============================================================================
test_at_risk_missing_mitigation if {
	bad_ar := object.remove(valid_input.at_risk[0], ["mitigation"])
	inp := object.union(valid_input, {"at_risk": [bad_ar]})
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	some msg in violations
	contains(msg, "missing required 'mitigation' field")
}

# ============================================================================
# TEST 15: needed item missing justification is rejected.
# ============================================================================
test_needed_missing_justification if {
	bad_nd := object.remove(valid_input.needed[0], ["justification"])
	inp := object.union(valid_input, {"needed": [bad_nd]})
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	some msg in violations
	contains(msg, "missing required 'justification' field")
}

# ============================================================================
# TEST 16: next item missing assigned_to is rejected.
# ============================================================================
test_next_missing_assigned_to if {
	bad_nx := object.remove(valid_input.next[0], ["assigned_to"])
	inp := object.union(valid_input, {"next": [bad_nx]})
	not sofrep.valid with input as inp
	violations := sofrep.violations with input as inp
	some msg in violations
	contains(msg, "missing required 'assigned_to' field")
}
