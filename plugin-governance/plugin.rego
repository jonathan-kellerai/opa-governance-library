# METADATA
# title: Plugin Governance Policy — Claude Code Plugin Compliance
# description: >
#   Validates Claude Code plugin structure, agent manifest compliance,
#   skill completeness, governance flags, and SICA enforcement requirements.
#   Data-driven via data.schema and data.thresholds.
#   Single structured deny set with severity-based triage.
#   Covers manifest, agent, skill, and governance validation.
# authors:
#   - name: Platform Engineering
# custom:
#   version: "1.0.0"
#   domain: "plugin-governance"
#   enforcement: "sica-continuous"
# entrypoint: true
package plugins.standard

import rego.v1

# ============================================================================
# 0. FIELD PRESENCE HELPER
# ============================================================================
# Returns true when a field is present and semantically non-empty.
# Handles OPA falsy-value edge cases: 0, false, null, "", [], {}.

_max_field_len := 200

_truncate(s) := s if {
	is_string(s)
	count(s) <= _max_field_len
}

_truncate(s) := sprintf("%s...[truncated, len=%d]", [substring(s, 0, _max_field_len), count(s)]) if {
	is_string(s)
	count(s) > _max_field_len
}

_truncate(s) := s if {
	not is_string(s)
}

_sentinel := {"__sentinel__": true}

_field_present(obj, field) if {
	val := object.get(obj, field, _sentinel)
	val != _sentinel
	not val == null
	not val == ""
	not val == 0
	not val == false
	not val == []
	not val == {}
}

# ============================================================================
# 1. DATA ALIASES
# ============================================================================

schema := data.schema

thresholds := data.thresholds

agents := object.get(input, "agents", [])

skills := object.get(input, "skills", [])

plugin := object.get(input, "plugin", {})

governance := object.get(input, "governance", {})

# ============================================================================
# 2. META-VALIDATION — sentinel, bounds, list guards (R1, R3, R4)
# ============================================================================

# R1: data_sentinel — fires when data.schema or data.thresholds is missing/empty
_schema_present if {
	is_object(data.schema)
	count(data.schema) > 0
}

_thresholds_present if {
	is_object(data.thresholds)
	count(data.thresholds) > 0
}

deny contains {"msg": "data.schema is missing or empty", "severity": "error", "field": "data.schema", "rule": "data_sentinel"} if {
	not _schema_present
}

deny contains {"msg": "data.thresholds is missing or empty", "severity": "error", "field": "data.thresholds", "rule": "data_sentinel"} if {
	not _thresholds_present
}

# R3: Threshold keys completeness
_required_threshold_keys := {
	"min_description_length",
	"max_agent_turns",
	"min_agent_turns",
	"min_keyword_count",
	"max_deny_entries",
	"min_skill_tool_count",
}

deny contains {
	"msg": sprintf("data.thresholds is missing required key: %s", [k]),
	"severity": "error",
	"field": sprintf("data.thresholds.%s", [k]),
	"rule": "threshold_bounds",
} if {
	_thresholds_present
	some k in _required_threshold_keys
	not k in object.keys(thresholds)
}

# R4: Schema list nonempty guards
_required_schema_lists := {
	"allowed_models",
	"required_plugin_fields",
	"required_agent_fields",
	"required_skill_fields",
	"allowed_cost_tiers",
	"allowed_effort_levels",
}

deny contains {
	"msg": sprintf("data.schema.%s must be a non-empty list", [k]),
	"severity": "error",
	"field": sprintf("data.schema.%s", [k]),
	"rule": "schema_list_nonempty",
} if {
	_schema_present
	some k in _required_schema_lists
	count(object.get(schema, k, [])) == 0
}

# ============================================================================
# 3. PLUGIN MANIFEST VALIDATION (R5–R9)
# ============================================================================

_plugin_present if {
	is_object(input.plugin)
	count(input.plugin) > 0
}

# R5: Plugin manifest required fields
deny contains {"msg": "input.plugin is missing or empty — plugin manifest is required", "severity": "error", "field": "input.plugin", "rule": "plugin_present"} if {
	not _plugin_present
}

deny contains {
	"msg": sprintf("plugin manifest is missing required field: %s", [f]),
	"severity": "error",
	"field": sprintf("input.plugin.%s", [f]),
	"rule": "plugin_required_fields",
} if {
	_plugin_present
	_schema_present
	some f in schema.required_plugin_fields
	not _field_present(plugin, f)
}

# R6: Plugin name format (kebab-case)
_name_pattern := `^[a-z][a-z0-9-]+[a-z0-9]$`

deny contains {
	"msg": sprintf("plugin.name %q must be kebab-case (lowercase alphanumeric and hyphens, e.g. my-plugin)", [_truncate(object.get(plugin, "name", ""))]),
	"severity": "error",
	"field": "input.plugin.name",
	"rule": "plugin_name_format",
} if {
	_plugin_present
	nm := object.get(plugin, "name", "")
	is_string(nm)
	count(nm) > 0
	not regex.match(_name_pattern, nm)
}

# R7: Plugin version format (semver)
_semver_pattern := `^\d+\.\d+\.\d+$`

deny contains {
	"msg": sprintf("plugin.version %q must be semver format (e.g. 1.0.0)", [_truncate(object.get(plugin, "version", ""))]),
	"severity": "error",
	"field": "input.plugin.version",
	"rule": "plugin_version_format",
} if {
	_plugin_present
	ver := object.get(plugin, "version", "")
	is_string(ver)
	count(ver) > 0
	not regex.match(_semver_pattern, ver)
}

# R8: Plugin description minimum length
deny contains {
	"msg": sprintf("plugin.description is too short (%d chars) — minimum %d required", [count(d), thresholds.min_description_length]),
	"severity": "warning",
	"field": "input.plugin.description",
	"rule": "plugin_description_length",
} if {
	_plugin_present
	_thresholds_present
	d := object.get(plugin, "description", "")
	is_string(d)
	count(d) < thresholds.min_description_length
}

# R9: Plugin keywords minimum count
deny contains {
	"msg": sprintf("plugin.keywords has only %d entries — minimum %d required for discoverability", [count(kws), thresholds.min_keyword_count]),
	"severity": "warning",
	"field": "input.plugin.keywords",
	"rule": "plugin_keywords_count",
} if {
	_plugin_present
	_thresholds_present
	kws := object.get(plugin, "keywords", [])
	count(kws) < thresholds.min_keyword_count
}

# ============================================================================
# 4. AGENT COMPLIANCE (R10–R15)
# ============================================================================

_allowed_models := {m | some m in schema.allowed_models}

# R10: Agent required fields (key-presence check — value may be false/0/[] legitimately)
deny contains {
	"msg": sprintf("agent[%d] (%s) is missing required field: %s", [i, _truncate(object.get(a, "name", "unnamed")), f]),
	"severity": "error",
	"field": sprintf("input.agents[%d].%s", [i, f]),
	"rule": "agent_required_fields",
} if {
	_schema_present
	some i, a in agents
	some f in schema.required_agent_fields
	not f in object.keys(a)
}

# R11: Agent model must be in allowed set
deny contains {
	"msg": sprintf("agent[%d] (%s) uses disallowed model %q — allowed: %s", [i, _truncate(object.get(a, "name", "unnamed")), m, concat(", ", _allowed_models)]),
	"severity": "error",
	"field": sprintf("input.agents[%d].model", [i]),
	"rule": "agent_model_allowed",
} if {
	_schema_present
	some i, a in agents
	m := object.get(a, "model", "")
	is_string(m)
	count(m) > 0
	not m in _allowed_models
}

# R12a: Agent maxTurns below minimum
deny contains {
	"msg": sprintf("agent[%d] (%s) maxTurns %d is below minimum %d", [i, _truncate(object.get(a, "name", "unnamed")), t, thresholds.min_agent_turns]),
	"severity": "warning",
	"field": sprintf("input.agents[%d].maxTurns", [i]),
	"rule": "agent_turns_bounds",
} if {
	_thresholds_present
	some i, a in agents
	t := object.get(a, "maxTurns", 0)
	is_number(t)
	t < thresholds.min_agent_turns
}

# R12b: Agent maxTurns above maximum
deny contains {
	"msg": sprintf("agent[%d] (%s) maxTurns %d exceeds maximum %d", [i, _truncate(object.get(a, "name", "unnamed")), t, thresholds.max_agent_turns]),
	"severity": "warning",
	"field": sprintf("input.agents[%d].maxTurns", [i]),
	"rule": "agent_turns_bounds",
} if {
	_thresholds_present
	some i, a in agents
	t := object.get(a, "maxTurns", 0)
	is_number(t)
	t > thresholds.max_agent_turns
}

# R13: Agent description minimum length
deny contains {
	"msg": sprintf("agent[%d] (%s) description is too short (%d chars) — minimum %d required", [i, _truncate(object.get(a, "name", "unnamed")), count(d), thresholds.min_description_length]),
	"severity": "warning",
	"field": sprintf("input.agents[%d].description", [i]),
	"rule": "agent_description_length",
} if {
	_thresholds_present
	some i, a in agents
	d := object.get(a, "description", "")
	is_string(d)
	count(d) < thresholds.min_description_length
}

# R14: Agent metadata required keys
_required_metadata_keys := {"oracle.task_type", "koth.domain", "cost_tier", "effort_level"}

deny contains {
	"msg": sprintf("agent[%d] (%s) metadata is missing key: %s", [i, _truncate(object.get(a, "name", "unnamed")), mk]),
	"severity": "warning",
	"field": sprintf("input.agents[%d].metadata.%s", [i, mk]),
	"rule": "agent_metadata_complete",
} if {
	some i, a in agents
	meta := object.get(a, "metadata", {})
	some mk in _required_metadata_keys
	not _field_present(meta, mk)
}

# R15: Agent cost_tier must be in allowed set
_allowed_cost_tiers := {t | some t in schema.allowed_cost_tiers}

deny contains {
	"msg": sprintf("agent[%d] (%s) cost_tier %q is not in allowed set: %s", [i, _truncate(object.get(a, "name", "unnamed")), ct, concat(", ", _allowed_cost_tiers)]),
	"severity": "warning",
	"field": sprintf("input.agents[%d].metadata.cost_tier", [i]),
	"rule": "agent_cost_tier_valid",
} if {
	_schema_present
	some i, a in agents
	meta := object.get(a, "metadata", {})
	ct := object.get(meta, "cost_tier", "")
	is_string(ct)
	count(ct) > 0
	not ct in _allowed_cost_tiers
}

# ============================================================================
# 5. SKILL COMPLIANCE (R16–R18)
# ============================================================================

# R16: Skill required fields (key-presence check — user_invocable may legitimately be false)
deny contains {
	"msg": sprintf("skill[%d] (%s) is missing required field: %s", [i, _truncate(object.get(s, "name", "unnamed")), f]),
	"severity": "error",
	"field": sprintf("input.skills[%d].%s", [i, f]),
	"rule": "skill_required_fields",
} if {
	_schema_present
	some i, s in skills
	some f in schema.required_skill_fields
	not f in object.keys(s)
}

# R17: Skill allowed_tools minimum count
deny contains {
	"msg": sprintf("skill[%d] (%s) has %d allowed_tools — minimum %d required for meaningful scope", [i, _truncate(object.get(s, "name", "unnamed")), count(ts), thresholds.min_skill_tool_count]),
	"severity": "info",
	"field": sprintf("input.skills[%d].allowed_tools", [i]),
	"rule": "skill_tool_count",
} if {
	_thresholds_present
	some i, s in skills
	ts := object.get(s, "allowed_tools", [])
	count(ts) < thresholds.min_skill_tool_count
}

# R18: Skill user_invocable must be explicitly set (not absent)
deny contains {
	"msg": sprintf("skill[%d] (%s) must explicitly declare user_invocable (true or false)", [i, _truncate(object.get(s, "name", "unnamed"))]),
	"severity": "warning",
	"field": sprintf("input.skills[%d].user_invocable", [i]),
	"rule": "skill_invocable_explicit",
} if {
	some i, s in skills
	_ = object.get(s, "user_invocable", _sentinel)
	object.get(s, "user_invocable", _sentinel) == _sentinel
}

# ============================================================================
# 6. GOVERNANCE COMPLIANCE (R19–R21)
# ============================================================================

# R19: SICA enforcement must be enabled
deny contains {
	"msg": "governance.sica_enabled must be true — all plugins require continuous SICA improvement monitoring",
	"severity": "error",
	"field": "input.governance.sica_enabled",
	"rule": "governance_sica_required",
} if {
	not object.get(governance, "sica_enabled", false) == true
}

# R20: Output validation must be enabled
deny contains {
	"msg": "governance.output_validation must be true — all plugins require Rego output validation",
	"severity": "error",
	"field": "input.governance.output_validation",
	"rule": "governance_output_validation",
} if {
	not object.get(governance, "output_validation", false) == true
}

# R21: Rego version must be valid semver
deny contains {
	"msg": sprintf("governance.rego_version %q must be semver format (e.g. 1.0.0)", [_truncate(object.get(governance, "rego_version", ""))]),
	"severity": "error",
	"field": "input.governance.rego_version",
	"rule": "governance_rego_version",
} if {
	rv := object.get(governance, "rego_version", "")
	not regex.match(_semver_pattern, rv)
}

# ============================================================================
# 7. RULE TITLES LOOKUP
# ============================================================================

rule_titles := {
	"data_sentinel": "Data Document Sentinel",
	"threshold_bounds": "Threshold Keys Completeness",
	"schema_list_nonempty": "Schema List Non-Empty Guard",
	"plugin_present": "Plugin Manifest Presence",
	"plugin_required_fields": "Plugin Required Fields",
	"plugin_name_format": "Plugin Name Kebab-Case Format",
	"plugin_version_format": "Plugin Version Semver Format",
	"plugin_description_length": "Plugin Description Minimum Length",
	"plugin_keywords_count": "Plugin Keywords Count",
	"agent_required_fields": "Agent Required Fields",
	"agent_model_allowed": "Agent Model Allowlist",
	"agent_turns_bounds": "Agent maxTurns Bounds",
	"agent_description_length": "Agent Description Minimum Length",
	"agent_metadata_complete": "Agent Metadata Completeness",
	"agent_cost_tier_valid": "Agent Cost Tier Validity",
	"skill_required_fields": "Skill Required Fields",
	"skill_tool_count": "Skill Minimum Tool Count",
	"skill_invocable_explicit": "Skill User-Invocable Explicit Flag",
	"governance_sica_required": "Governance SICA Enforcement",
	"governance_output_validation": "Governance Output Validation",
	"governance_rego_version": "Governance Rego Version",
}
