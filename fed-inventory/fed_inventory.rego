# METADATA
# title: Federal AI Use-Case Inventory Policy (OMB 2025)
# description: >
#   Advisory conformance policy for the OMB 2025 Federal AI Use-Case Inventory disclosure schema.
#   Validates field presence and field validity (enum membership, basic format) only.
#   DOES NOT assess substantive compliance or adequacy — callers are responsible for enforcement decisions.
# authors:
#   - name: Platform Engineering
# schemas:
#   - input: schema.input
package fed.inventory

import rego.v1

# --- data aliases ---
_s := data.schema

# --- helper: is field non-empty? ---
_has(field) if {
	input[field]
	trim_space(input[field]) != ""
}

# --- helper: is withheld? (Yes – Disclosure Risk | Yes – Prohibited by Law) ---
_is_withheld if startswith(input.is_withheld, "Yes")

# --- ALWAYS-REQUIRED (9 fields) ---
deny contains {"msg": sprintf("missing required field: %s", [field]), "severity": "error", "field": field, "rule": "required"} if {
	some field in _s.always_required
	not _has(field)
}

# --- CONDITIONAL TIER A (5 fields) — required when not withheld AND stage in {Pre-deployment, Pilot, Deployed} ---
deny contains {"msg": sprintf("missing tier A field: %s (required when is_withheld=No and stage in {Pre-deployment, Pilot, Deployed})", [field]), "severity": "error", "field": field, "rule": "tier_a"} if {
	not _is_withheld
	some field in _s.conditional_tier_a
	not _has(field)
	_has("development_stage")
	input.development_stage in _s.tier_a_stages
}

# --- CONDITIONAL TIER B (7 fields) — required when not withheld AND stage in {Pilot, Deployed} ---
deny contains {"msg": sprintf("missing tier B field: %s (required when is_withheld=No and stage in {Pilot, Deployed})", [field]), "severity": "error", "field": field, "rule": "tier_b"} if {
	not _is_withheld
	some field in _s.conditional_tier_b
	not _has(field)
	_has("development_stage")
	input.development_stage in _s.tier_b_stages
}

# --- CONDITIONAL vendor_name — required when stage in {Pilot, Deployed} AND contracting_usage in {Vendor Purchased, Contracting and In House} ---
deny contains {"msg": "missing vendor_name (required when stage in {Pilot, Deployed} AND contracting_usage in {Vendor Purchased, Contracting and In House})", "severity": "error", "field": "vendor_name", "rule": "vendor_name"} if {
	_has("development_stage")
	input.development_stage in _s.vendor_required_stages
	_has("contracting_usage")
	input.contracting_usage in _s.vendor_required_contracting
	not _has("vendor_name")
}

# --- CONDITIONAL system_name_ato — required when stage in {Pilot, Deployed} AND have_ato=Yes ---
deny contains {"msg": "missing system_name_ato (required when stage in {Pilot, Deployed} AND have_ato=Yes)", "severity": "error", "field": "system_name_ato", "rule": "system_name_ato"} if {
	_has("development_stage")
	input.development_stage in _s.ato_required_stages
	_has("have_ato")
	input.have_ato == "Yes"
	not _has("system_name_ato")
}

# --- CONDITIONAL HI_justification — required when is_high_impact == "Presumed High-Impact, but Not High-impact" ---
deny contains {"msg": "missing HI_justification (required when is_high_impact == 'Presumed High-Impact, but Not High-impact')", "severity": "error", "field": "HI_justification", "rule": "hi_justification"} if {
	_has("is_high_impact")
	input.is_high_impact == "Presumed High-Impact, but Not High-impact"
	not _has("HI_justification")
}

# --- CONDITIONAL TIER C (9 hi_* fields) — required when is_high_impact=High-impact AND stage=Deployed ---
deny contains {"msg": sprintf("missing tier C field: %s (required when is_high_impact=High-impact AND stage=Deployed)", [field]), "severity": "error", "field": field, "rule": "tier_c"} if {
	_has("is_high_impact")
	input.is_high_impact == "High-impact"
	_has("development_stage")
	input.development_stage in _s.hi_tier_c_stages
	some field in _s.hi_tier_c_fields
	not _has(field)
}

# --- ENUM VALIDITY — warn when field is present but value not in allowed set ---
deny contains {"msg": sprintf("invalid is_withheld value: '%s' (allowed: %v)", [input.is_withheld, _s.enums.is_withheld]), "severity": "warning", "field": "is_withheld", "rule": "enum"} if {
	_has("is_withheld")
	not input.is_withheld in _s.enums.is_withheld
}

deny contains {"msg": sprintf("invalid development_stage value: '%s' (allowed: %v)", [input.development_stage, _s.enums.development_stage]), "severity": "warning", "field": "development_stage", "rule": "enum"} if {
	_has("development_stage")
	not input.development_stage in _s.enums.development_stage
}

deny contains {"msg": sprintf("invalid is_high_impact value: '%s' (allowed: %v)", [input.is_high_impact, _s.enums.is_high_impact]), "severity": "warning", "field": "is_high_impact", "rule": "enum"} if {
	_has("is_high_impact")
	not input.is_high_impact in _s.enums.is_high_impact
}

# topic_area enum validation — accepts canonical values OR any "Other" variant (e.g., "Other – Economic & Financial")
# Real Federal Reserve data uses free-text "Other – ..." values that extend the canonical set
deny contains {"msg": sprintf("invalid topic_area value: '%s' (allowed: %v or 'Other' variants)", [input.topic_area, _s.enums.topic_area]), "severity": "warning", "field": "topic_area", "rule": "enum"} if {
	_has("topic_area")
	not input.topic_area in _s.enums.topic_area
	not startswith(input.topic_area, "Other")
}

deny contains {"msg": sprintf("invalid classification value: '%s' (allowed: %v)", [input.classification, _s.enums.classification]), "severity": "warning", "field": "classification", "rule": "enum"} if {
	_has("classification")
	not input.classification in _s.enums.classification
}

deny contains {"msg": sprintf("invalid contracting_usage value: '%s' (allowed: %v)", [input.contracting_usage, _s.enums.contracting_usage]), "severity": "warning", "field": "contracting_usage", "rule": "enum"} if {
	_has("contracting_usage")
	not input.contracting_usage in _s.enums.contracting_usage
}

deny contains {"msg": sprintf("invalid have_ato value: '%s' (allowed: %v)", [input.have_ato, _s.enums.have_ato]), "severity": "warning", "field": "have_ato", "rule": "enum"} if {
	_has("have_ato")
	not input.have_ato in _s.enums.have_ato
}

deny contains {"msg": sprintf("invalid has_pii value: '%s' (allowed: %v)", [input.has_pii, _s.enums.has_pii]), "severity": "warning", "field": "has_pii", "rule": "enum"} if {
	_has("has_pii")
	not input.has_pii in _s.enums.has_pii
}

deny contains {"msg": sprintf("invalid has_custom_code value: '%s' (allowed: %v)", [input.has_custom_code, _s.enums.has_custom_code]), "severity": "warning", "field": "has_custom_code", "rule": "enum"} if {
	_has("has_custom_code")
	not input.has_custom_code in _s.enums.has_custom_code
}

# --- FORMAT checks (basic) ---
# NOTE: demographic_features and hi_* fields are complex/multi-select enums — presence checks only (above), no enum validation to avoid false positives

deny contains {"msg": "contact_email format invalid (missing @)", "severity": "warning", "field": "contact_email", "rule": "format"} if {
	_has("contact_email")
	not contains(input.contact_email, "@")
}

deny contains {"msg": "id field is empty or whitespace-only", "severity": "warning", "field": "id", "rule": "format"} if {
	input.id
	trim_space(input.id) == ""
}

# --- COTS VARIANT VALIDATION (separate entrypoint for consolidated COTS records) ---
# Detects COTS records by presence of "Agency Use (Y/N)?" field
# COTS schema: Agency, AI Use Case, Agency Use (Y/N)?, Name of Commercial Product or Service Used, Estimated # of Licenses/Users
# All validations are advisory (warnings) — no error-level severity for COTS

# helper: is this a COTS record?
_is_cots if input["Agency Use (Y/N)?"]

# helper: is COTS field non-empty?
_cots_has(field) if {
	input[field]
	trim_space(input[field]) != ""
}

# COTS: always-required fields (3 fields)
cots_deny contains {"msg": sprintf("COTS: missing required field: %s", [field]), "severity": "warning", "field": field, "rule": "cots_required"} if {
	_is_cots
	some field in _s.cots.required_always
	not _cots_has(field)
}

# COTS: required-if-used fields (2 fields) — when "Agency Use (Y/N)?" == "Y"
cots_deny contains {"msg": sprintf("COTS: missing required field for used product: %s (required when Agency Use (Y/N)? == Y)", [field]), "severity": "warning", "field": field, "rule": "cots_required_if_used"} if {
	_is_cots
	input["Agency Use (Y/N)?"] == "Y"
	some field in _s.cots.required_if_used
	not _cots_has(field)
}

# COTS: enum validation for "Agency Use (Y/N)?"
cots_deny contains {"msg": sprintf("COTS: invalid Agency Use value: '%s' (allowed: %v)", [input["Agency Use (Y/N)?"], _s.cots.enums["Agency Use (Y/N)?"]]), "severity": "warning", "field": "Agency Use (Y/N)?", "rule": "cots_enum"} if {
	_is_cots
	_cots_has("Agency Use (Y/N)?")
	not input["Agency Use (Y/N)?"] in _s.cots.enums["Agency Use (Y/N)?"]
}

# COTS: summary entrypoint
cots_summary := {"valid": count(cots_deny) == 0, "deny": cots_deny, "warning_count": count(cots_deny)} if {
	_is_cots
}

# --- summary ---
default valid := false

valid if count(deny) == 0

errors := {d | some d in deny; d.severity == "error"}

warnings := {d | some d in deny; d.severity == "warning"}

summary := {"valid": valid, "deny": deny, "error_count": count(errors), "warning_count": count(warnings)}
