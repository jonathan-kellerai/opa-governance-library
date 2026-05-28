# METADATA
# title: Circuit Breaker Policy (Dense/Data-Driven)
# description: Validates circuit-breaker structure, enums, cross-references, risk scoring, and readiness.
# authors:
#   - name: Platform Engineering
# schemas:
#   - input: schema.input
package circuit_breaker

import rego.v1

quadrants := data.schema.quadrants
all_items := {item | some quad in quadrants; some item in input[quad]}
all_ids := {item.id | some item in all_items}

# --- Required metadata ---
deny contains {"msg": sprintf("missing metadata field: %s", [field]), "severity": "error", "field": field, "rule": "metadata"} if {
	some field in data.schema.required_metadata
	not input[field]
}

# --- Base field validation per item ---
deny contains {"msg": sprintf("%s item %v missing base field: %s", [quad, idx, field]), "severity": "error", "field": sprintf("%s[%d].%s", [quad, idx, field]), "rule": "base_field"} if {
	some quad in quadrants
	some idx, item in input[quad]
	some field in data.schema.base_fields
	not item[field]
}

# --- Quadrant-specific field validation ---
deny contains {"msg": sprintf("%s item %v missing required field: %s", [quad, idx, field]), "severity": "error", "field": sprintf("%s[%d].%s", [quad, idx, field]), "rule": "quadrant_field"} if {
	some quad in quadrants
	some idx, item in input[quad]
	some field in data.schema.quadrant_fields[quad]
	not item[field]
}

# --- Enum validation ---
deny contains {"msg": sprintf("invalid %s value: %v", [enum_name, val]), "severity": "error", "field": enum_name, "rule": "enum"} if {
	enum_map := {"classification": input.classification}
	some enum_name, val in enum_map
	not val in data.schema.enums[enum_name]
}

deny contains {"msg": sprintf("%s item %d has invalid %s: %v", [quad, idx, enum_name, val]), "severity": "error", "field": sprintf("%s[%d].%s", [quad, idx, enum_name]), "rule": "enum"} if {
	item_enums := {"priority": true, "urgency": true, "likelihood": true}
	some quad in quadrants
	some idx, item in input[quad]
	some enum_name in item_enums
	val := item[enum_name]
	not val in data.schema.enums[enum_name]
}

# --- Unique ID enforcement ---
deny contains {"msg": sprintf("duplicate id: %s", [item.id]), "severity": "error", "field": "id", "rule": "unique_id"} if {
	some quad_a in quadrants
	some idx_a, item in input[quad_a]
	some quad_b in quadrants
	some idx_b, other in input[quad_b]
	item.id == other.id
	sprintf("%s:%d", [quad_a, idx_a]) < sprintf("%s:%d", [quad_b, idx_b])
}

# --- Dependency resolution (next items only) ---
deny contains {"msg": sprintf("next item %s has unresolved dependency: %s", [item.id, dep]), "severity": "error", "field": sprintf("next.%s.dependencies", [item.id]), "rule": "dependency"} if {
	some item in input.next
	some dep in item.dependencies
	not dep in all_ids
}

# --- Conflict: working_well ∩ at_risk ---
deny contains {"msg": sprintf("item %s appears in both working_well and at_risk", [item.id]), "severity": "warning", "field": item.id, "rule": "conflict"} if {
	ww_ids := {item.id | some item in input.working_well}
	ar_ids := {item.id | some item in input.at_risk}
	some item in all_items
	item.id in ww_ids
	item.id in ar_ids
}

# --- Risk scoring: flag critical ---
deny contains {"msg": sprintf("at_risk item %s has critical likelihood: %d", [item.id, item.likelihood]), "severity": "critical", "field": sprintf("at_risk.%s.likelihood", [item.id]), "rule": "risk_critical"} if {
	some item in input.at_risk
	item.likelihood >= data.thresholds.risk_critical_threshold
}

# --- Staleness detection ---
deny contains {"msg": sprintf("%s item %s is stale (last updated: %s)", [quad, item.id, item.last_updated]), "severity": "warning", "field": sprintf("%s.%s.last_updated", [quad, item.id]), "rule": "staleness"} if {
	some quad in quadrants
	some item in input[quad]
	ns_updated := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [item.last_updated]))
	ns_now := time.now_ns()
	ns_now - ns_updated > (((data.thresholds.staleness_days * 24) * 60) * 60) * 1000000000
}

# --- Owner overload ---
all_owners := {item.owner | some item in all_items}

owner_counts[owner] := cnt if {
	some owner in all_owners
	cnt := count([1 | some item in all_items; item.owner == owner])
}

deny contains {"msg": sprintf("owner %s has %d items (max %d)", [owner, cnt, data.thresholds.max_owner_items]), "severity": "warning", "field": "owner", "rule": "owner_overload"} if {
	some owner, cnt in owner_counts
	cnt > data.thresholds.max_owner_items
}

# --- Readiness computation ---
errors := count({d | some d in deny; d.severity == "error"})
readiness := 1.0 - (errors / count(all_items)) if count(all_items) > 0
readiness := 0.0 if count(all_items) == 0
ready if readiness >= data.thresholds.readiness_threshold

# --- Summary ---
default valid := false

valid if count(deny) == 0
report := {"valid": valid, "deny": deny, "readiness": readiness, "ready": ready, "item_count": count(all_items)}
