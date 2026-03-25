# METADATA
# title: SoFREP — Status of Forces Report Validator (V1 Narrative)
# description: |
#   Comprehensive OPA/Rego policy for validating a SoFREP (Status of Forces Report),
#   a military/operational battle report with four quadrants:
#     GREEN  — Working Well (on track, delivering, healthy)
#     AMBER  — Needed (missing, required, gaps)
#     RED    — At Risk (threatened, degraded, could fail)
#     BLUE   — Next (upcoming actions, priorities, planned moves)
#
#   This is the V1 NARRATIVE implementation: verbose, readable, well-documented,
#   with clear section comments and descriptive helper rules.
# authors:
#   - name: Platform Engineering
# entrypoint: true
package sofrep.v1

import rego.v1

# ============================================================================
# CONSTANTS
# ============================================================================

# The four quadrant names that every SoFREP must contain.
quadrant_names := {"working_well", "needed", "at_risk", "next"}

# Valid classification levels for military/operational reports.
valid_classifications := {"UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"}

# Valid priority designators from P0 (highest) through P4 (lowest).
valid_priorities := {"P0", "P1", "P2", "P3", "P4"}

# Valid operational tempo levels.
valid_tempos := {"high", "medium", "low"}

# Valid urgency levels for "needed" quadrant items.
valid_urgencies := {"critical", "high", "medium", "low"}

# Maximum number of days before an item is considered stale,
# measured from the reporting period end date.
staleness_threshold_days := 30

# Risk score threshold: impact * likelihood >= this value is critical.
critical_risk_threshold := 20

# ============================================================================
# SECTION 1: TOP-LEVEL VALIDITY
# ============================================================================

# The report is valid when there are zero violations across all checks.
default valid := false

valid if {
	count(violations) == 0
}

# Aggregate every category of violation into a single set.
violations contains msg if {
	some msg in metadata_violations
}

violations contains msg if {
	some msg in quadrant_structure_violations
}

violations contains msg if {
	some msg in item_schema_violations
}

violations contains msg if {
	some msg in quadrant_specific_violations
}

violations contains msg if {
	some msg in cross_quadrant_violations
}

violations contains msg if {
	some msg in temporal_violations
}

violations contains msg if {
	some msg in classification_violations
}

# ============================================================================
# SECTION 2: METADATA VALIDATION
# ============================================================================

# Every SoFREP must include a unit/team identifier.
metadata_violations contains "metadata: 'unit' field is required" if {
	not input.unit
}

# The report must identify who authored or commanded the report.
metadata_violations contains "metadata: 'author' field is required" if {
	not input.author
}

# A reporting period with start and end dates must be present.
metadata_violations contains "metadata: 'reporting_period' field is required" if {
	not input.reporting_period
}

metadata_violations contains "metadata: 'reporting_period.start' is required" if {
	input.reporting_period
	not input.reporting_period.start
}

metadata_violations contains "metadata: 'reporting_period.end' is required" if {
	input.reporting_period
	not input.reporting_period.end
}

# Classification level must be present.
metadata_violations contains "metadata: 'classification' field is required" if {
	not input.classification
}

# ============================================================================
# SECTION 3: CLASSIFICATION VALIDATION
# ============================================================================

# The classification value must be one of the recognised levels.
classification_violations contains msg if {
	input.classification
	not input.classification in valid_classifications
	msg := sprintf(
		"classification: '%s' is not valid; must be one of: %v",
		[input.classification, valid_classifications],
	)
}

# ============================================================================
# SECTION 4: QUADRANT STRUCTURAL COMPLETENESS
# ============================================================================

# Every one of the four quadrants must be present in the input document.
quadrant_structure_violations contains msg if {
	some name in quadrant_names
	not input[name]
	msg := sprintf("structure: quadrant '%s' is missing from the report", [name])
}

# No quadrant may be empty — each must contain at least one item.
quadrant_structure_violations contains msg if {
	some name in quadrant_names
	input[name]
	count(input[name]) == 0
	msg := sprintf("structure: quadrant '%s' must contain at least one item", [name])
}

# ============================================================================
# SECTION 5: COMMON ITEM SCHEMA VALIDATION
# ============================================================================

# Every item in every quadrant must have the base fields:
#   id, title, description, status, owner, priority, last_updated

# Helper: list of required base fields for all items.
base_item_fields := {"id", "title", "description", "status", "owner", "priority", "last_updated"}

# Validate base fields across all quadrants.
item_schema_violations contains msg if {
	some qname in quadrant_names
	input[qname]
	some idx, item in input[qname]
	some field in base_item_fields
	not has_field(item, field)
	msg := sprintf(
		"item_schema: %s[%d] (id: %v) is missing required field '%s'",
		[qname, idx, object.get(item, "id", "<no id>"), field],
	)
}

# Priority must be a valid P0–P4 value.
item_schema_violations contains msg if {
	some qname in quadrant_names
	input[qname]
	some idx, item in input[qname]
	item.priority
	not item.priority in valid_priorities
	msg := sprintf(
		"item_schema: %s[%d] (id: '%s') has invalid priority '%s'; must be one of %v",
		[qname, idx, item.id, item.priority, valid_priorities],
	)
}

# ============================================================================
# SECTION 6: QUADRANT-SPECIFIC FIELD VALIDATION
# ============================================================================

# --- 6a: WORKING WELL (GREEN) ---
# Items in working_well must have an 'evidence' field proving they are on track.
quadrant_specific_violations contains msg if {
	input.working_well
	some idx, item in input.working_well
	not has_field(item, "evidence")
	msg := sprintf(
		"working_well[%d] (id: '%s'): missing required 'evidence' field — must prove it's actually working",
		[idx, object.get(item, "id", "<no id>")],
	)
}

# --- 6b: NEEDED (AMBER) ---
# Items in needed must have a 'justification' explaining why it's required.
quadrant_specific_violations contains msg if {
	input.needed
	some idx, item in input.needed
	not has_field(item, "justification")
	msg := sprintf(
		"needed[%d] (id: '%s'): missing required 'justification' field",
		[idx, object.get(item, "id", "<no id>")],
	)
}

# Items in needed must have an 'urgency' level.
quadrant_specific_violations contains msg if {
	input.needed
	some idx, item in input.needed
	not has_field(item, "urgency")
	msg := sprintf(
		"needed[%d] (id: '%s'): missing required 'urgency' field",
		[idx, object.get(item, "id", "<no id>")],
	)
}

# Urgency must be one of the valid levels.
quadrant_specific_violations contains msg if {
	input.needed
	some idx, item in input.needed
	item.urgency
	not item.urgency in valid_urgencies
	msg := sprintf(
		"needed[%d] (id: '%s'): urgency '%s' is not valid; must be one of %v",
		[idx, item.id, item.urgency, valid_urgencies],
	)
}

# --- 6c: AT RISK (RED) ---
# Items in at_risk must have an 'impact' field describing what breaks if this fails.
quadrant_specific_violations contains msg if {
	input.at_risk
	some idx, item in input.at_risk
	not has_field(item, "impact")
	msg := sprintf(
		"at_risk[%d] (id: '%s'): missing required 'impact' field",
		[idx, object.get(item, "id", "<no id>")],
	)
}

# Items in at_risk must have a 'likelihood' score (1–5).
quadrant_specific_violations contains msg if {
	input.at_risk
	some idx, item in input.at_risk
	not has_field(item, "likelihood")
	msg := sprintf(
		"at_risk[%d] (id: '%s'): missing required 'likelihood' field (1-5 scale)",
		[idx, object.get(item, "id", "<no id>")],
	)
}

# Likelihood must be an integer between 1 and 5.
quadrant_specific_violations contains msg if {
	input.at_risk
	some idx, item in input.at_risk
	item.likelihood
	not is_valid_likelihood(item.likelihood)
	msg := sprintf(
		"at_risk[%d] (id: '%s'): likelihood must be an integer between 1 and 5, got %v",
		[idx, item.id, item.likelihood],
	)
}

# Items in at_risk must have a 'mitigation' field describing countermeasures.
quadrant_specific_violations contains msg if {
	input.at_risk
	some idx, item in input.at_risk
	not has_field(item, "mitigation")
	msg := sprintf(
		"at_risk[%d] (id: '%s'): missing required 'mitigation' field",
		[idx, object.get(item, "id", "<no id>")],
	)
}

# --- 6d: NEXT (BLUE) ---
# Items in next must have a 'target_date' for when the action is due.
quadrant_specific_violations contains msg if {
	input.next
	some idx, item in input.next
	not has_field(item, "target_date")
	msg := sprintf(
		"next[%d] (id: '%s'): missing required 'target_date' field",
		[idx, object.get(item, "id", "<no id>")],
	)
}

# Items in next must have a 'dependencies' array listing prerequisite item ids.
quadrant_specific_violations contains msg if {
	input.next
	some idx, item in input.next
	not has_field(item, "dependencies")
	msg := sprintf(
		"next[%d] (id: '%s'): missing required 'dependencies' field (array of item ids)",
		[idx, object.get(item, "id", "<no id>")],
	)
}

# Items in next must have an 'assigned_to' field naming who is responsible.
quadrant_specific_violations contains msg if {
	input.next
	some idx, item in input.next
	not has_field(item, "assigned_to")
	msg := sprintf(
		"next[%d] (id: '%s'): missing required 'assigned_to' field",
		[idx, object.get(item, "id", "<no id>")],
	)
}

# ============================================================================
# SECTION 7: CROSS-QUADRANT INTEGRITY
# ============================================================================

# Collect all item ids across all quadrants into a single set for lookups.
all_item_ids contains item.id if {
	some qname in quadrant_names
	input[qname]
	some item in input[qname]
	item.id
}

# 7a: No item may appear in both working_well and at_risk — logical contradiction.
cross_quadrant_violations contains msg if {
	input.working_well
	input.at_risk
	some ww_item in input.working_well
	some ar_item in input.at_risk
	ww_item.id == ar_item.id
	msg := sprintf(
		"cross_quadrant: item id '%s' appears in both 'working_well' and 'at_risk' — contradictory status",
		[ww_item.id],
	)
}

# 7b: No duplicate ids across any quadrants.
cross_quadrant_violations contains msg if {
	some q1 in quadrant_names
	some q2 in quadrant_names
	q1 < q2
	input[q1]
	input[q2]
	some item1 in input[q1]
	some item2 in input[q2]
	item1.id
	item1.id == item2.id
	msg := sprintf(
		"cross_quadrant: duplicate id '%s' found in both '%s' and '%s'",
		[item1.id, q1, q2],
	)
}

# 7c: Dependencies in "next" items must reference existing ids from any quadrant.
cross_quadrant_violations contains msg if {
	input.next
	some idx, item in input.next
	item.dependencies
	some dep in item.dependencies
	not dep in all_item_ids
	msg := sprintf(
		"cross_quadrant: next[%d] (id: '%s') has dependency '%s' that does not match any item id in the report",
		[idx, item.id, dep],
	)
}

# ============================================================================
# SECTION 8: TEMPORAL VALIDITY
# ============================================================================

# Reporting period end date must be after start date.
temporal_violations contains msg if {
	input.reporting_period
	input.reporting_period.start
	input.reporting_period.end
	is_valid_date(input.reporting_period.start)
	is_valid_date(input.reporting_period.end)
	not date_after(input.reporting_period.end, input.reporting_period.start)
	msg := sprintf(
		"temporal: reporting_period.end (%s) must be after reporting_period.start (%s)",
		[input.reporting_period.end, input.reporting_period.start],
	)
}

# Reporting period start must be a valid date.
temporal_violations contains msg if {
	input.reporting_period
	input.reporting_period.start
	not is_valid_date(input.reporting_period.start)
	msg := sprintf(
		"temporal: reporting_period.start '%s' is not a valid YYYY-MM-DD date",
		[input.reporting_period.start],
	)
}

# Reporting period end must be a valid date.
temporal_violations contains msg if {
	input.reporting_period
	input.reporting_period.end
	not is_valid_date(input.reporting_period.end)
	msg := sprintf(
		"temporal: reporting_period.end '%s' is not a valid YYYY-MM-DD date",
		[input.reporting_period.end],
	)
}

# Validate last_updated on every item is a valid date.
temporal_violations contains msg if {
	some qname in quadrant_names
	input[qname]
	some idx, item in input[qname]
	item.last_updated
	not is_valid_date(item.last_updated)
	msg := sprintf(
		"temporal: %s[%d] (id: '%s') has invalid last_updated date '%s'",
		[qname, idx, item.id, item.last_updated],
	)
}

# ============================================================================
# SECTION 9: STALENESS DETECTION
# ============================================================================

# Flag items whose last_updated is more than 30 days before reporting_period.end.
stale_items contains info if {
	input.reporting_period
	input.reporting_period.end
	is_valid_date(input.reporting_period.end)
	some qname in quadrant_names
	input[qname]
	some idx, item in input[qname]
	item.last_updated
	is_valid_date(item.last_updated)
	days_between(item.last_updated, input.reporting_period.end) > staleness_threshold_days
	info := {
		"quadrant": qname,
		"index": idx,
		"id": item.id,
		"last_updated": item.last_updated,
		"days_stale": days_between(item.last_updated, input.reporting_period.end),
	}
}

# ============================================================================
# SECTION 10: RISK SCORING
# ============================================================================

# Calculate risk scores for all at_risk items that have numeric impact and likelihood.
risk_scores contains score_info if {
	input.at_risk
	some idx, item in input.at_risk
	is_number(item.impact)
	is_number(item.likelihood)
	risk_val := item.impact * item.likelihood
	score_info := {
		"index": idx,
		"id": item.id,
		"impact": item.impact,
		"likelihood": item.likelihood,
		"risk_score": risk_val,
		"critical": risk_val >= critical_risk_threshold,
	}
}

# Identify items that breach the critical risk threshold.
critical_risks contains info if {
	some info in risk_scores
	info.critical == true
}

# ============================================================================
# SECTION 11: REPORT SUMMARY (informational, not blocking)
# ============================================================================

# Provide a summary object for consumers of this policy.
summary := {
	"valid": valid,
	"violation_count": count(violations),
	"violations": violations,
	"stale_item_count": count(stale_items),
	"stale_items": stale_items,
	"critical_risk_count": count(critical_risks),
	"critical_risks": critical_risks,
	"risk_scores": risk_scores,
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Check whether an object has a given key with a non-null value.
has_field(obj, key) if {
	_ = obj[key]
}

# Validate that a string is a well-formed YYYY-MM-DD date.
# OPA's time.parse_ns will succeed only for valid dates.
is_valid_date(date_str) if {
	time.parse_ns("2006-01-02", date_str)
}

# Return true if date_a is strictly after date_b (both YYYY-MM-DD strings).
date_after(date_a, date_b) if {
	ns_a := time.parse_ns("2006-01-02", date_a)
	ns_b := time.parse_ns("2006-01-02", date_b)
	ns_a > ns_b
}

# Calculate the number of whole days between two YYYY-MM-DD date strings.
# Returns a non-negative integer representing |date_b - date_a| in days.
days_between(date_a, date_b) := days if {
	ns_a := time.parse_ns("2006-01-02", date_a)
	ns_b := time.parse_ns("2006-01-02", date_b)
	diff := ns_b - ns_a
	abs_diff := _abs(diff)
	days := abs_diff / (((24 * 60) * 60) * 1000000000)
}

# Absolute value helper.
_abs(x) := x if {
	x >= 0
}

_abs(x) := 0 - x if {
	x < 0
}

# Validate likelihood is an integer between 1 and 5 inclusive.
is_valid_likelihood(val) if {
	is_number(val)
	val >= 1
	val <= 5
}
