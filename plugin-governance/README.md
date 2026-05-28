# Plugin Governance

**A meta-validation policy that validates the structural correctness of plugin, agent, and skill definitions before they are trusted.**

---

- **Repository:** `jonathan-kellerai/opa-governance-library`
- **Pillar:** `plugin-governance`
- **Package:** `plugins.standard`
- **Entrypoint root:** `data.plugins.standard.*`
- **Policy language:** Rego (`import rego.v1`)

---

## What this pillar is

`plugin-governance` is a *policy that validates other definitions*. Where most
policies decide whether a runtime request is allowed, this one decides whether a
plugin, agent, or skill *definition* is well-formed enough to be trusted. It is a
governance gate that runs before a plugin is released — the policy equivalent of
a structural linter for plugin manifests.

The single Rego module
([`plugin.rego`](./plugin.rego)) declares the package `plugins.standard`
([`plugin.rego:16`](./plugin.rego)) and is marked as a metadata `entrypoint`
([`plugin.rego:15`](./plugin.rego)). Callers evaluate it against a candidate
plugin definition and receive a structured set of denial findings.

## The meta-validation concept

Meta-validation means a policy whose subject of evaluation is itself another
definition. Section 2 of the module
([`plugin.rego:71`–`134`](./plugin.rego)) is titled "META-VALIDATION" and checks
that the *governing reference data* — the schema and threshold documents — is
itself present and complete before any downstream rule runs. A plugin definition
is only considered validated once it has passed every check in the module; until
then it must be treated as untrusted.

## Fail-secure sentinel guards

The policy denies by default whenever the reference data it depends on is absent
or incomplete. Three guard rules implement this fail-secure posture:

| Rule name | Where | What it guards |
|-----------|-------|----------------|
| `data_sentinel` | [`plugin.rego:86`, `plugin.rego:90`](./plugin.rego) | Fires when `data.schema` or `data.thresholds` is missing or empty |
| `threshold_bounds` | [`plugin.rego:104`](./plugin.rego) | Fires when any required key is absent from `data.thresholds` |
| `schema_list_nonempty` | [`plugin.rego:125`](./plugin.rego) | Fires when any required `data.schema` list is empty |

The `_sentinel` object ([`plugin.rego:42`](./plugin.rego)) is the mechanism
behind the fail-secure design: `object.get` is called with `_sentinel` as its
default, so the policy can distinguish "field absent" from "field present but
falsy". The presence helper `_field_present`
([`plugin.rego:44`–`53`](./plugin.rego)) uses this to treat `0`, `false`, `null`,
`""`, `[]`, and `{}` correctly rather than collapsing them to "missing".

`threshold_bounds` checks for six required keys —
`min_description_length`, `max_agent_turns`, `min_agent_turns`,
`min_keyword_count`, `max_deny_entries`, `min_skill_tool_count`
([`plugin.rego:95`–`102`](./plugin.rego)). `schema_list_nonempty` checks six
required schema lists — `allowed_models`, `required_plugin_fields`,
`required_agent_fields`, `required_skill_fields`, `allowed_cost_tiers`,
`allowed_effort_levels` ([`plugin.rego:116`–`123`](./plugin.rego)). If the
operator supplies no data document at all, every dependent rule is skipped and
`data_sentinel` denies — the policy never silently passes an unvalidated
definition.

## Tool-allowlist enforcement

Each agent and skill declares an `allowed_tools` list — the set of tools it is
permitted to invoke. The policy constrains this list so a definition cannot ship
with an empty or under-specified tool scope:

- **Skills** must declare at least `min_skill_tool_count` tools. Rule
  `skill_tool_count` ([`plugin.rego:348`](./plugin.rego)) emits an `info`-severity
  finding when a skill has fewer than the configured minimum (default `1`, from
  [`input.example.json` / data thresholds]).
- **Skills** must include `allowed_tools` among their required fields. Rule
  `skill_required_fields` ([`plugin.rego:335`](./plugin.rego)) denies when any key
  listed in `schema.required_skill_fields` is absent — and `allowed_tools` is one
  of those required keys.
- **Agents** must include `allowed_tools` among their required fields. Rule
  `agent_required_fields` ([`plugin.rego:228`](./plugin.rego)) enforces the same
  presence check against `schema.required_agent_fields`.

The tool names that appear in the example inputs — `mcp__example__tool_a`,
`mcp__example__tool_b`, and similar
([`input.example.json:19`–`21`](./input.example.json)) — are illustrative
placeholders only. Real callers substitute their own concrete tool identifiers;
the policy validates the *shape and count* of `allowed_tools`, not the specific
names.

## Public entrypoint rules

The module exposes one primary entrypoint and one lookup table.

### `deny`

`deny` is a partial set of structured findings. Evaluating
`data.plugins.standard.deny` returns zero or more objects, each shaped:

```json
{
  "msg": "human-readable explanation",
  "severity": "error" | "warning" | "info",
  "field": "input.plugin.name",
  "rule": "plugin_name_format"
}
```

An empty `deny` set means the candidate definition passed every check. The
`field` value is a dotted JSON path to the offending input or data location, and
`rule` is a stable machine identifier suitable for triage and suppression.

The module groups its rules into six concern areas:

| Area | Rules | Module section |
|------|-------|----------------|
| Meta-validation | `data_sentinel`, `threshold_bounds`, `schema_list_nonempty` | [`plugin.rego:71`](./plugin.rego) |
| Plugin manifest | `plugin_present`, `plugin_required_fields`, `plugin_name_format`, `plugin_version_format`, `plugin_description_length`, `plugin_keywords_count` | [`plugin.rego:136`](./plugin.rego) |
| Agent compliance | `agent_required_fields`, `agent_model_allowed`, `agent_turns_bounds`, `agent_description_length`, `agent_metadata_complete`, `agent_cost_tier_valid` | [`plugin.rego:221`](./plugin.rego) |
| Skill compliance | `skill_required_fields`, `skill_tool_count`, `skill_invocable_explicit` | [`plugin.rego:330`](./plugin.rego) |
| Governance compliance | `governance_sica_required`, `governance_output_validation`, `governance_rego_version` | [`plugin.rego:372`](./plugin.rego) |

### `rule_titles`

`rule_titles` ([`plugin.rego:411`](./plugin.rego)) is a static object mapping
each `rule` identifier to a human-readable title — for example
`plugin_name_format` maps to "Plugin Name Kebab-Case Format". Callers evaluate
`data.plugins.standard.rule_titles` to render denial findings in a report.

## Input contract: `schema.json` and `input.example.json`

A caller passes a single JSON object describing the plugin definition to be
validated. The object has four top-level sections, all aliased near the top of
the module ([`plugin.rego:55`–`69`](./plugin.rego)):

- `plugin` — the plugin manifest (`name`, `version`, `description`, `author`,
  `keywords`).
- `agents` — a list of agent definitions.
- `skills` — a list of skill definitions.
- `governance` — governance flags (`sica_enabled`, `output_validation`,
  `rego_version`).

[`input.example.json`](./input.example.json) is a complete, valid example: a
plugin manifest, two agents, two skills, and a governance block that satisfies
every rule.

[`schema.json`](./schema.json) is the **data document** loaded as `data.schema`
and `data.thresholds`. It is *not* a JSON Schema validator file — it is the
operator-supplied reference data the policy reads:

- `data.schema` ([`schema.json:3`–`13`](./schema.json)) — the allowed-value sets
  and required-field lists (`allowed_models`, `required_plugin_fields`,
  `allowed_cost_tiers`, and so on).
- `data.thresholds` ([`schema.json:14`–`21`](./schema.json)) — the numeric
  bounds (`min_description_length: 40`, `min_agent_turns: 5`,
  `max_agent_turns: 50`, `min_keyword_count: 3`, `min_skill_tool_count: 1`,
  `max_deny_entries: 100`).

Because the policy reads these from data, an operator or admin can tighten or
relax governance without editing Rego.

## Run it

From the repository root, evaluate the `deny` entrypoint against the example
input:

```bash
opa eval \
  --data plugin-governance/ \
  --input plugin-governance/input.example.json \
  'data.plugins.standard.deny'
```

The example input is well-formed, so `deny` evaluates to an empty set.

Run the test suite:

```bash
opa test plugin-governance/
```

## Tests

The test suite ([`plugin_test.rego`](./plugin_test.rego)) is in package
`plugins.standard_test` and exercises the module across the meta-validation,
plugin-manifest, agent-compliance, skill-compliance, and governance concern
areas. It builds on shared fixtures — `_valid_plugin`, `_valid_agent`,
`_valid_skill`, `_valid_governance`, and the composed `_valid_input`
([`plugin_test.rego:9`–`51`](./plugin_test.rego)) — and includes
`test_clean_valid_plugin_has_no_deny`
([`plugin_test.rego:82`](./plugin_test.rego)), which asserts that a clean
definition produces zero denials. Each remaining case mutates one field of the
valid input and asserts that the corresponding rule fires.

## Reviewing findings

A reviewer or admin triages `deny` output by `severity`:

- `error` — structural defects that block a release (missing required fields,
  disallowed models, invalid version strings, disabled governance flags).
- `warning` — quality and completeness concerns (short descriptions,
  out-of-bounds turn counts, incomplete agent metadata).
- `info` — advisory findings (skill tool count below the recommended minimum).

An operator integrating this pillar into a release pipeline typically fails the
build on any `error` finding and surfaces `warning` and `info` findings as
review notes.
