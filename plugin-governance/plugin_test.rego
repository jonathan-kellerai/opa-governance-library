package plugins.standard_test

import rego.v1

# ============================================================================
# TEST FIXTURES
# ============================================================================

_valid_plugin := {
	"name": "my-plugin",
	"version": "1.2.3",
	"description": "A well-formed plugin that satisfies all governance requirements",
	"author": {"name": "Test Author", "email": "test@example.com"},
	"keywords": ["research", "synthesis", "code"],
}

_valid_agent := {
	"name": "my-agent",
	"description": "An agent that searches and synthesizes code intelligence across repositories",
	"model": "sonnet",
	"maxTurns": 15,
	"allowed_tools": ["mcp__example__tool_a"],
	"user_invocable": false,
	"metadata": {
		"oracle.task_type": "research",
		"koth.domain": "general",
		"cost_tier": "medium",
		"effort_level": "medium",
	},
}

_valid_skill := {
	"name": "my-skill",
	"description": "A skill for code search and synthesis using Sourcegraph",
	"model": "sonnet",
	"allowed_tools": ["mcp__example__tool_a"],
	"user_invocable": false,
}

_valid_governance := {
	"sica_enabled": true,
	"output_validation": true,
	"rego_version": "1.0.0",
}

_valid_input := {
	"plugin": _valid_plugin,
	"agents": [_valid_agent],
	"skills": [_valid_skill],
	"governance": _valid_governance,
}

# ============================================================================
# META-VALIDATION TESTS
# ============================================================================

test_data_sentinel_fires_on_missing_schema if {
	result := data.plugins.standard.deny with data.schema as {} with data.thresholds as {"min_description_length": 40, "max_agent_turns": 50, "min_agent_turns": 5, "min_keyword_count": 3, "max_deny_entries": 100, "min_skill_tool_count": 1} with input as _valid_input
	some e in result
	e.rule == "data_sentinel"
	e.field == "data.schema"
}

test_data_sentinel_fires_on_missing_thresholds if {
	result := data.plugins.standard.deny with data.schema as {"required_plugin_fields": ["name"], "required_agent_fields": ["name"], "required_skill_fields": ["name"], "allowed_models": ["sonnet"], "allowed_cost_tiers": ["low"], "allowed_effort_levels": ["low"]} with data.thresholds as {} with input as _valid_input
	some e in result
	e.rule == "data_sentinel"
	e.field == "data.thresholds"
}

test_threshold_bounds_catches_missing_key if {
	result := data.plugins.standard.deny with data.schema as {"required_plugin_fields": ["name", "version", "description", "author", "keywords"], "required_agent_fields": ["name", "description", "model", "maxTurns", "allowed_tools", "user_invocable", "metadata"], "required_skill_fields": ["name", "description", "model", "allowed_tools", "user_invocable"], "allowed_models": ["haiku", "sonnet", "opus"], "allowed_cost_tiers": ["low", "medium", "high"], "allowed_effort_levels": ["low", "medium", "high"]} with data.thresholds as {"min_description_length": 40, "max_agent_turns": 50, "min_agent_turns": 5, "min_keyword_count": 3, "max_deny_entries": 100} with input as _valid_input
	some e in result
	e.rule == "threshold_bounds"
	e.field == "data.thresholds.min_skill_tool_count"
}

# ============================================================================
# PLUGIN MANIFEST TESTS
# ============================================================================

test_clean_valid_plugin_has_no_deny if {
	result := data.plugins.standard.deny with input as _valid_input
	count(result) == 0
}

test_plugin_name_invalid_format_fires if {
	bad_input := object.union(_valid_input, {"plugin": object.union(_valid_plugin, {"name": "My_Plugin"})})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "plugin_name_format"
}

test_plugin_name_valid_kebab_passes if {
	bad_input := object.union(_valid_input, {"plugin": object.union(_valid_plugin, {"name": "my-plugin"})})
	result := data.plugins.standard.deny with input as bad_input
	not any_rule(result, "plugin_name_format")
}

test_plugin_version_invalid_fires if {
	bad_input := object.union(_valid_input, {"plugin": object.union(_valid_plugin, {"version": "v1.0"})})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "plugin_version_format"
}

test_plugin_description_too_short_fires if {
	bad_input := object.union(_valid_input, {"plugin": object.union(_valid_plugin, {"description": "Short"})})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "plugin_description_length"
}

test_plugin_keywords_too_few_fires if {
	bad_input := object.union(_valid_input, {"plugin": object.union(_valid_plugin, {"keywords": ["one"]})})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "plugin_keywords_count"
}

# ============================================================================
# AGENT COMPLIANCE TESTS
# ============================================================================

test_agent_disallowed_model_fires if {
	bad_agent := object.union(_valid_agent, {"model": "gpt-4"})
	bad_input := object.union(_valid_input, {"agents": [bad_agent]})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "agent_model_allowed"
}

test_agent_turns_too_low_fires if {
	bad_agent := object.union(_valid_agent, {"maxTurns": 2})
	bad_input := object.union(_valid_input, {"agents": [bad_agent]})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "agent_turns_bounds"
}

test_agent_turns_too_high_fires if {
	bad_agent := object.union(_valid_agent, {"maxTurns": 100})
	bad_input := object.union(_valid_input, {"agents": [bad_agent]})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "agent_turns_bounds"
}

test_agent_missing_metadata_fires if {
	# object.union does a deep merge — build bad_agent inline to force metadata: {}
	bad_agent := {
		"name": "my-agent",
		"description": "An agent that searches and synthesizes code intelligence across repositories",
		"model": "sonnet",
		"maxTurns": 15,
		"allowed_tools": ["mcp__example__tool_a"],
		"user_invocable": false,
		"metadata": {},
	}
	bad_input := object.union(_valid_input, {"agents": [bad_agent]})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "agent_metadata_complete"
}

test_agent_invalid_cost_tier_fires if {
	bad_meta := object.union(_valid_agent.metadata, {"cost_tier": "free"})
	bad_agent := object.union(_valid_agent, {"metadata": bad_meta})
	bad_input := object.union(_valid_input, {"agents": [bad_agent]})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "agent_cost_tier_valid"
}

# ============================================================================
# SKILL COMPLIANCE TESTS
# ============================================================================

test_skill_missing_required_field_fires if {
	bad_skill := {"name": "no-desc-skill", "model": "sonnet", "allowed_tools": ["Read"], "user_invocable": false}
	bad_input := object.union(_valid_input, {"skills": [bad_skill]})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "skill_required_fields"
	e.field == "input.skills[0].description"
}

test_skill_no_tools_fires if {
	bad_skill := object.union(_valid_skill, {"allowed_tools": []})
	bad_input := object.union(_valid_input, {"skills": [bad_skill]})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "skill_tool_count"
}

test_skill_missing_invocable_fires if {
	bad_skill := {"name": "implicit-skill", "description": "A skill without explicit user_invocable setting", "model": "sonnet", "allowed_tools": ["Read"]}
	bad_input := object.union(_valid_input, {"skills": [bad_skill]})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "skill_invocable_explicit"
}

# ============================================================================
# GOVERNANCE TESTS
# ============================================================================

test_governance_sica_disabled_fires if {
	bad_gov := object.union(_valid_governance, {"sica_enabled": false})
	bad_input := object.union(_valid_input, {"governance": bad_gov})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "governance_sica_required"
}

test_governance_output_validation_disabled_fires if {
	bad_gov := object.union(_valid_governance, {"output_validation": false})
	bad_input := object.union(_valid_input, {"governance": bad_gov})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "governance_output_validation"
}

test_governance_bad_rego_version_fires if {
	bad_gov := object.union(_valid_governance, {"rego_version": "v1"})
	bad_input := object.union(_valid_input, {"governance": bad_gov})
	result := data.plugins.standard.deny with input as bad_input
	some e in result
	e.rule == "governance_rego_version"
}

# ============================================================================
# HELPER
# ============================================================================

any_rule(result, r) if {
	some e in result
	e.rule == r
}
