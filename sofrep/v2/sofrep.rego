# METADATA
# title: SoFREP V2 — Structural/Schema Validation
# description: >
#   Validates Status of Forces Report structure, enforcing schema shape,
#   required fields per quadrant, type constraints, unique IDs, dependency
#   resolution, conflict detection, and completeness scoring.
# authors:
#   - name: Jonathan
# related_resources:
#   - ref: https://github.com/jonathans_macbook/opa-rego
#     description: SoFREP policy repository
package sofrep.v2

import rego.v1

# -- Schema sets ---------------------------------------------------------------

allowed_top_level := {"unit", "reporting_period", "classification", "author", "working_well", "needed", "at_risk", "next"}

quadrant_names := {"working_well", "needed", "at_risk", "next"}

base_fields := {"id", "title", "description", "owner", "priority", "last_updated"}

extra_fields := {
	"working_well": {"evidence"},
	"needed": {"justification", "urgency"},
	"at_risk": {"impact", "likelihood", "mitigation"},
	"next": {"target_date", "dependencies", "assigned_to"},
}

enrichment_fields := {"notes", "tags", "metrics"}

valid_urgencies := {"critical", "high", "medium", "low"}

# -- Helpers -------------------------------------------------------------------

date_pattern := `^\d{4}-\d{2}-\d{2}$`

priority_pattern := `^P[0-4]$`

items_for(q) := input[q]

all_ids := {item.id | some q in quadrant_names; some item in items_for(q)}

# -- Unknown top-level fields --------------------------------------------------

unknown_fields contains field if {
	some field in object.keys(input)
	not field in allowed_top_level
}

# -- Required metadata ---------------------------------------------------------

metadata_errors contains "missing required field: unit" if {
	not input.unit
}

metadata_errors contains "missing required field: classification" if {
	not input.classification
}

metadata_errors contains "missing required field: author" if {
	not input.author
}

metadata_errors contains "missing required field: reporting_period" if {
	not input.reporting_period
}

metadata_errors contains "missing required field: reporting_period.start_date" if {
	input.reporting_period
	not input.reporting_period.start_date
}

metadata_errors contains "missing required field: reporting_period.end_date" if {
	input.reporting_period
	not input.reporting_period.end_date
}

# -- Base item schema ----------------------------------------------------------

base_schema_errors contains msg if {
	some q in quadrant_names
	some i, item in items_for(q)
	some field in base_fields
	not field in object.keys(item)
	msg := sprintf("%s[%d]: missing base field '%s'", [q, i, field])
}

# -- Quadrant-specific required fields -----------------------------------------

quadrant_field_errors contains msg if {
	some q in quadrant_names
	some i, item in items_for(q)
	some field in extra_fields[q]
	not field in object.keys(item)
	msg := sprintf("%s[%d]: missing required field '%s'", [q, i, field])
}

# -- Type checking -------------------------------------------------------------

type_errors contains msg if {
	some q in quadrant_names
	some i, item in items_for(q)
	not regex.match(priority_pattern, item.priority)
	msg := sprintf("%s[%d]: priority '%s' must match P0-P4", [q, i, item.priority])
}

type_errors contains msg if {
	some q in quadrant_names
	some i, item in items_for(q)
	not regex.match(date_pattern, item.last_updated)
	msg := sprintf("%s[%d]: last_updated '%s' must be YYYY-MM-DD", [q, i, item.last_updated])
}

type_errors contains msg if {
	some i, item in items_for("at_risk")
	not is_number(item.likelihood)
	msg := sprintf("at_risk[%d]: likelihood must be a number", [i])
}

type_errors contains msg if {
	some i, item in items_for("at_risk")
	is_number(item.likelihood)
	item.likelihood < 1
	msg := sprintf("at_risk[%d]: likelihood must be >= 1", [i])
}

type_errors contains msg if {
	some i, item in items_for("at_risk")
	is_number(item.likelihood)
	item.likelihood > 5
	msg := sprintf("at_risk[%d]: likelihood must be <= 5", [i])
}

type_errors contains msg if {
	some i, item in items_for("needed")
	not item.urgency in valid_urgencies
	msg := sprintf("needed[%d]: urgency '%s' must be one of {critical, high, medium, low}", [i, item.urgency])
}

type_errors contains msg if {
	some i, item in items_for("next")
	not regex.match(date_pattern, item.target_date)
	msg := sprintf("next[%d]: target_date '%s' must be YYYY-MM-DD", [i, item.target_date])
}

# -- Unique ID enforcement -----------------------------------------------------

_id_list := [item.id | some q in quadrant_names; some item in items_for(q)]

duplicate_ids contains id if {
	some i, id in _id_list
	some j, other in _id_list
	i != j
	id == other
}

# -- Dependency resolution -----------------------------------------------------

unresolved_dependencies contains msg if {
	some i, item in items_for("next")
	some dep in item.dependencies
	not dep in all_ids
	msg := sprintf("next[%d]: dependency '%s' not found", [i, dep])
}

# -- Conflict detection --------------------------------------------------------

conflicts contains msg if {
	some ww_item in items_for("working_well")
	some ar_item in items_for("at_risk")
	ww_item.id == ar_item.id
	msg := sprintf("id '%s' appears in both working_well and at_risk", [ww_item.id])
}

# -- Completeness scoring ------------------------------------------------------

_total_possible := count(_id_list) * count(enrichment_fields)

_filled := count([true |
	some q in quadrant_names
	some item in items_for(q)
	some field in enrichment_fields
	object.get(item, field, null) != null
])

completeness_pct := round((_filled * 100) / _total_possible) if {
	_total_possible > 0
}

default completeness_pct := 0

# -- Aggregate report ---------------------------------------------------------

all_errors := ((((metadata_errors | base_schema_errors) | quadrant_field_errors) | type_errors) | unresolved_dependencies) | conflicts

default valid := false

valid if {
	count(unknown_fields) == 0
	count(all_errors) == 0
	count(duplicate_ids) == 0
}

report := {
	"valid": valid,
	"errors": all_errors,
	"unknown_fields": unknown_fields,
	"duplicate_ids": duplicate_ids,
	"completeness_pct": completeness_pct,
}
