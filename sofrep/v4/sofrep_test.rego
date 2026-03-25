package sofrep.v4_test

import rego.v1

import data.sofrep.v4

# Minimal valid item factory for reuse across tests
base_item(id, owner) := {"id": id, "title": "T", "description": "D", "owner": owner, "priority": "P1", "last_updated": "2026-03-14"}

# Test 1: Valid input produces no errors
test_valid_input if {
	inp := {
		"unit": "Test", "author": "A", "classification": "UNCLASSIFIED",
		"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
		"working_well": [object.union(base_item("WW-1", "O1"), {"evidence": "ok"})],
		"needed": [object.union(base_item("ND-1", "O2"), {"justification": "j", "urgency": "high"})],
		"at_risk": [object.union(base_item("AR-1", "O3"), {"impact": "i", "likelihood": 2, "mitigation": "m"})],
		"next": [object.union(base_item("NX-1", "O4"), {"target_date": "2026-04-01", "dependencies": ["WW-1"]})],
	}
	results := v4.deny with input as inp
	errors := {d | some d in results; d.severity == "error"}
	count(errors) == 0
}

# Test 2: Missing metadata detected
test_missing_metadata if {
	inp := {
		"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
		"working_well": [], "needed": [], "at_risk": [], "next": [],
	}
	results := v4.deny with input as inp
	metadata_errors := {d | some d in results; d.rule == "metadata"}
	count(metadata_errors) >= 3
}

# Test 3: Missing base field
test_missing_base_field if {
	inp := {
		"unit": "T", "author": "A", "classification": "UNCLASSIFIED",
		"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
		"working_well": [{"id": "WW-1", "title": "T", "evidence": "e"}],
		"needed": [], "at_risk": [], "next": [],
	}
	results := v4.deny with input as inp
	base_errors := {d | some d in results; d.rule == "base_field"}
	count(base_errors) > 0
}

# Test 4: Invalid enum value
test_invalid_enum if {
	inp := {
		"unit": "T", "author": "A", "classification": "COSMIC_TOP_SECRET",
		"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
		"working_well": [], "needed": [], "at_risk": [], "next": [],
	}
	results := v4.deny with input as inp
	enum_errors := {d | some d in results; d.rule == "enum"}
	count(enum_errors) > 0
}

# Test 5: Duplicate ID across quadrants
test_duplicate_id if {
	inp := {
		"unit": "T", "author": "A", "classification": "UNCLASSIFIED",
		"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
		"working_well": [object.union(base_item("DUP-1", "O1"), {"evidence": "e"})],
		"needed": [object.union(base_item("DUP-1", "O2"), {"justification": "j", "urgency": "low"})],
		"at_risk": [], "next": [],
	}
	results := v4.deny with input as inp
	dup_errors := {d | some d in results; d.rule == "unique_id"}
	count(dup_errors) > 0
}

# Test 6: Unresolved dependency
test_unresolved_dependency if {
	inp := {
		"unit": "T", "author": "A", "classification": "UNCLASSIFIED",
		"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
		"working_well": [], "needed": [],
		"at_risk": [],
		"next": [object.union(base_item("NX-1", "O1"), {"target_date": "2026-04-01", "dependencies": ["GHOST-99"]})],
	}
	results := v4.deny with input as inp
	dep_errors := {d | some d in results; d.rule == "dependency"}
	count(dep_errors) > 0
}

# Test 7: Conflict between working_well and at_risk
test_conflict_detection if {
	inp := {
		"unit": "T", "author": "A", "classification": "UNCLASSIFIED",
		"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
		"working_well": [object.union(base_item("CONF-1", "O1"), {"evidence": "e"})],
		"needed": [],
		"at_risk": [object.union(base_item("CONF-1", "O1"), {"impact": "i", "likelihood": 2, "mitigation": "m"})],
		"next": [],
	}
	results := v4.deny with input as inp
	conflict_errors := {d | some d in results; d.rule == "conflict"}
	count(conflict_errors) > 0
}

# Test 8: Critical risk threshold
test_risk_critical if {
	inp := {
		"unit": "T", "author": "A", "classification": "UNCLASSIFIED",
		"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
		"working_well": [],
		"needed": [],
		"at_risk": [object.union(base_item("AR-1", "O1"), {"impact": "i", "likelihood": 5, "mitigation": "m"})],
		"next": [],
	}
	results := v4.deny with input as inp
	crit_errors := {d | some d in results; d.rule == "risk_critical"}
	count(crit_errors) > 0
}

# Test 9: Owner overload detection
test_owner_overload if {
	items := [object.union(base_item(sprintf("WW-%d", [i]), "OVERLOADED"), {"evidence": "e"}) | some i in numbers.range(1, 6)]
	inp := {
		"unit": "T", "author": "A", "classification": "UNCLASSIFIED",
		"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
		"working_well": items,
		"needed": [], "at_risk": [], "next": [],
	}
	results := v4.deny with input as inp
	overload_errors := {d | some d in results; d.rule == "owner_overload"}
	count(overload_errors) > 0
}

# Test 10: Readiness above threshold for valid input
test_readiness_above_threshold if {
	inp := {
		"unit": "T", "author": "A", "classification": "UNCLASSIFIED",
		"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
		"working_well": [object.union(base_item("WW-1", "O1"), {"evidence": "ok"})],
		"needed": [], "at_risk": [], "next": [],
	}
	v4.ready with input as inp
}
