package sofrep.v2_test

import rego.v1

import data.sofrep.v2

# -- Helpers: minimal valid items per quadrant ---------------------------------

_base(id) := {
	"id": id,
	"title": "Test",
	"description": "Desc",
	"owner": "Owner",
	"priority": "P2",
	"last_updated": "2026-03-14",
}

_ww(id) := object.union(_base(id), {"evidence": "Proof"})

_nd(id) := object.union(_base(id), {"justification": "Reason", "urgency": "high"})

_ar(id) := object.union(_base(id), {"impact": "Outage", "likelihood": 3, "mitigation": "Plan"})

_nx(id, deps) := object.union(_base(id), {"target_date": "2026-04-01", "dependencies": deps, "assigned_to": "Owner"})

_meta := {
	"unit": "TestUnit",
	"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
	"classification": "UNCLASSIFIED",
	"author": "Tester",
}

_valid_input := object.union(_meta, {
	"working_well": [_ww("WW-1")],
	"needed": [_nd("ND-1")],
	"at_risk": [_ar("AR-1")],
	"next": [_nx("NX-1", ["WW-1"])],
})

# -- 1. Valid input passes -----------------------------------------------------

test_valid_input_passes if {
	v2.valid with input as _valid_input
}

# -- 2. Unknown top-level fields detected -------------------------------------

test_unknown_fields_detected if {
	inp := object.union(_valid_input, {"rogue_field": true})
	result := v2.unknown_fields with input as inp
	"rogue_field" in result
}

# -- 3. Missing metadata caught -----------------------------------------------

test_missing_metadata if {
	inp := object.remove(_valid_input, ["unit", "author"])
	errors := v2.metadata_errors with input as inp
	"missing required field: unit" in errors
	"missing required field: author" in errors
}

# -- 4. Missing quadrant-specific field caught ---------------------------------

test_missing_quadrant_field if {
	bad_ww := object.remove(_ww("WW-BAD"), ["evidence"])
	inp := object.union(_meta, {
		"working_well": [bad_ww],
		"needed": [_nd("ND-1")],
		"at_risk": [_ar("AR-1")],
		"next": [_nx("NX-1", ["ND-1"])],
	})
	errors := v2.quadrant_field_errors with input as inp
	count(errors) > 0
}

# -- 5. Invalid priority format caught ----------------------------------------

test_invalid_priority if {
	bad := object.union(_ww("WW-BAD"), {"priority": "P9"})
	inp := object.union(_meta, {
		"working_well": [bad],
		"needed": [],
		"at_risk": [],
		"next": [],
	})
	errors := v2.type_errors with input as inp
	count(errors) > 0
}

# -- 6. Duplicate IDs detected ------------------------------------------------

test_duplicate_ids if {
	inp := object.union(_meta, {
		"working_well": [_ww("DUPE")],
		"needed": [_nd("DUPE")],
		"at_risk": [],
		"next": [],
	})
	dupes := v2.duplicate_ids with input as inp
	"DUPE" in dupes
}

# -- 7. Unresolved dependency caught -------------------------------------------

test_unresolved_dependency if {
	inp := object.union(_meta, {
		"working_well": [_ww("WW-1")],
		"needed": [],
		"at_risk": [],
		"next": [_nx("NX-1", ["GHOST"])],
	})
	errors := v2.unresolved_dependencies with input as inp
	count(errors) > 0
}

# -- 8. Conflict detection: same ID in working_well and at_risk ----------------

test_conflict_detection if {
	inp := object.union(_meta, {
		"working_well": [_ww("CLASH")],
		"needed": [],
		"at_risk": [_ar("CLASH")],
		"next": [],
	})
	result := v2.conflicts with input as inp
	count(result) > 0
}

# -- 9. Likelihood out of range caught -----------------------------------------

test_likelihood_out_of_range if {
	bad_ar := object.union(_ar("AR-BAD"), {"likelihood": 7})
	inp := object.union(_meta, {
		"working_well": [],
		"needed": [],
		"at_risk": [bad_ar],
		"next": [],
	})
	errors := v2.type_errors with input as inp
	count(errors) > 0
}

# -- 10. Invalid urgency caught ------------------------------------------------

test_invalid_urgency if {
	bad_nd := object.union(_nd("ND-BAD"), {"urgency": "extreme"})
	inp := object.union(_meta, {
		"working_well": [],
		"needed": [bad_nd],
		"at_risk": [],
		"next": [],
	})
	errors := v2.type_errors with input as inp
	count(errors) > 0
}
