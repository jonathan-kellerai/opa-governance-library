package sofrep.v3_test

import data.sofrep.v3 as policy

import rego.v1

# --- Minimal valid input (no violations) ---

_valid_input := {
	"reporting_period": {"start_date": "2026-03-01", "end_date": "2026-03-15"},
	"working_well": [
		{"id": "ww-1", "title": "CI stable", "owner": "alice", "priority": "P2", "last_updated": "2026-03-10"},
		{"id": "ww-2", "title": "Monitoring OK", "owner": "bob", "priority": "P2", "last_updated": "2026-03-12"},
		{"id": "ww-3", "title": "Velocity good", "owner": "carol", "priority": "P3", "last_updated": "2026-03-08"},
		{"id": "ww-4", "title": "Deploys smooth", "owner": "dave", "priority": "P2", "last_updated": "2026-03-12"},
	],
	"needed": [{"id": "nd-1", "title": "Connection pool", "owner": "dave", "priority": "P2", "last_updated": "2026-03-11"}],
	"at_risk": [{"id": "ar-1", "title": "Minor tech debt", "owner": "eve", "impact": 2, "likelihood": 2, "priority": "P3", "last_updated": "2026-03-10"}],
	"next": [
		{"id": "nx-1", "title": "Pool impl", "owner": "frank", "priority": "P2", "dependencies": ["nd-1"], "last_updated": "2026-03-12"},
		{"id": "nx-2", "title": "Tech debt fix", "owner": "eve", "priority": "P3", "dependencies": [], "last_updated": "2026-03-13"},
	],
}

# 1. Valid input passes
test_valid_input_passes if {
	policy.valid with input as _valid_input
}

# 2. Critical risk triggers violation
test_critical_risk_flagged if {
	bad := json.patch(_valid_input, [{"op": "replace", "path": "/at_risk/0", "value": {
		"id": "ar-1", "title": "Auth SPOF", "owner": "eve",
		"impact": 5, "likelihood": 4, "priority": "P0", "last_updated": "2026-03-10",
	}}])
	"critical risks present in risk matrix" in policy.violations with input as bad
}

# 3. Low readiness flagged
test_low_readiness if {
	bad := json.patch(_valid_input, [{"op": "replace", "path": "/working_well", "value": [{"id": "ww-1", "title": "One thing", "owner": "alice", "priority": "P2", "last_updated": "2026-03-10"}]}])
	some v in policy.violations with input as bad
	contains(v, "< 50%")
}

# 4. Defensive posture when at_risk > next
test_defensive_posture if {
	bad := json.patch(_valid_input, [{"op": "replace", "path": "/at_risk", "value": [
		{"id": "ar-1", "title": "Risk A", "owner": "a", "impact": 2, "likelihood": 2, "priority": "P3", "last_updated": "2026-03-10"},
		{"id": "ar-2", "title": "Risk B", "owner": "b", "impact": 2, "likelihood": 2, "priority": "P3", "last_updated": "2026-03-10"},
		{"id": "ar-3", "title": "Risk C", "owner": "c", "impact": 2, "likelihood": 2, "priority": "P3", "last_updated": "2026-03-10"},
	]}])
	"defensive posture: more at_risk items than planned next actions" in policy.violations with input as bad
}

# 5. Dependency on non-existent item
test_dependency_nonexistent if {
	bad := json.patch(_valid_input, [{"op": "replace", "path": "/next/0/dependencies", "value": ["ghost-99"]}])
	some v in policy.violations with input as bad
	contains(v, "non-existent 'ghost-99'")
}

# 6. Dependency on at_risk item
test_dependency_at_risk if {
	bad := json.patch(_valid_input, [{"op": "replace", "path": "/next/0/dependencies", "value": ["ar-1"]}])
	some v in policy.violations with input as bad
	contains(v, "depends on at_risk item 'ar-1'")
}

# 7. Missing owner flagged
test_missing_owner if {
	bad := json.patch(_valid_input, [{"op": "remove", "path": "/working_well/0/owner"}])
	some v in policy.violations with input as bad
	contains(v, "has no owner")
}

# 8. Overloaded owner flagged
test_overloaded_owner if {
	# Give alice 6 items across quadrants
	bad := json.patch(_valid_input, [
		{"op": "replace", "path": "/working_well", "value": [
			{"id": "ww-1", "title": "A", "owner": "alice", "priority": "P2", "last_updated": "2026-03-10"},
			{"id": "ww-2", "title": "B", "owner": "alice", "priority": "P2", "last_updated": "2026-03-12"},
			{"id": "ww-3", "title": "C", "owner": "alice", "priority": "P3", "last_updated": "2026-03-08"},
		]},
		{"op": "replace", "path": "/needed", "value": [{"id": "nd-1", "title": "D", "owner": "alice", "priority": "P2", "last_updated": "2026-03-11"}]},
		{"op": "replace", "path": "/next", "value": [
			{"id": "nx-1", "title": "E", "owner": "alice", "priority": "P2", "dependencies": [], "last_updated": "2026-03-12"},
			{"id": "nx-2", "title": "F", "owner": "alice", "priority": "P3", "dependencies": [], "last_updated": "2026-03-13"},
		]},
	])
	some v in policy.violations with input as bad
	contains(v, "overloaded")
}

# 9. Stale at_risk item flagged
test_stale_at_risk if {
	bad := json.patch(_valid_input, [{"op": "replace", "path": "/at_risk/0/last_updated", "value": "2026-02-20"}])
	some v in policy.violations with input as bad
	contains(v, "stale")
}

# 10. Priority inversion flagged
test_priority_inversion if {
	bad := json.patch(_valid_input, [
		{"op": "replace", "path": "/needed", "value": [{"id": "nd-1", "title": "Critical need", "owner": "dave", "priority": "P1", "last_updated": "2026-03-11"}]},
		{"op": "replace", "path": "/next", "value": [{"id": "nx-1", "title": "Low pri work", "owner": "frank", "priority": "P3", "dependencies": [], "last_updated": "2026-03-12"}]},
	])
	some v in policy.violations with input as bad
	contains(v, "priority inversion")
}

# 11. Escalation triggers on critical risk
test_escalation_on_critical if {
	bad := json.patch(_valid_input, [{"op": "replace", "path": "/at_risk/0", "value": {
		"id": "ar-1", "title": "Auth SPOF", "owner": "eve",
		"impact": 5, "likelihood": 5, "priority": "P0", "last_updated": "2026-03-10",
	}}])
	"escalation required: one or more trigger conditions met" in policy.violations with input as bad
}
