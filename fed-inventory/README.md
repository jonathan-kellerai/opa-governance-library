# Federal AI Use-Case Inventory Policy

An advisory [Open Policy Agent](https://www.openpolicyagent.org/) (Rego) conformance policy
for the OMB 2025 Federal AI Use-Case Inventory disclosure schema.
The policy checks field completeness and field validity only.
It does **not** assess substantive program adequacy or prove compliance with any statute or regulation.

> **Advisory only.** The policies are advisory only: they emit structured `deny` decisions, and
> the *caller* is responsible for enforcing them (a CI gate, an intake script, a data-quality dashboard).

Part of [`jonathan-kellerai/opa-governance-library`](https://github.com/jonathan-kellerai/opa-governance-library).

- **Package:** `fed.inventory`
- **Schema version:** `fed-inventory@2025`, sourced from the OMB data dictionary, retrieved 2026-06-18
- **Rego version:** `rego.v1` (`fed_inventory.rego:13`)
- **Design goal:** field-presence + enum-validity checks for all 35 OMB inventory fields; one `deny` set; no helper sprawl

---

## Source attribution

This policy encodes the schema published by the U.S. Office of Management and Budget for the
2025 Federal AI Use-Case Inventory.
The authoritative schema sources are:

- **OMB 2025 Federal Agency AI Use-Case Inventory** (GitHub):
  <https://github.com/ombegov/2025-Federal-Agency-AI-Use-Case-Inventory>
  — `Validation/data_dictionary.md` and `Validation/data_dictionary.json` define the 35 fields,
  their conditionality tiers, and the allowed enum strings.
- **Federal Reserve AI Use-Case Inventory (2025)**:
  <https://www.federalreserve.gov/AI-use-case-inventory-2025.htm>
  — the Federal Reserve discloses approximately 39 use cases on its own page following the
  same schema convention.
  Note: the Federal Reserve is **not** part of the OMB 56-agency dataset; it reports independently.
  Fed use cases are valid inputs to this policy when mapped onto the OMB schema.

The "56" figure is the OMB agency count across the government-wide inventory, not a use-case count.

---

## Schema version and update procedure

**Current version:** `fed-inventory@2025` (retrieved 2026-06-18 from the OMB data dictionary).

The OMB inventory schema is re-published at least annually.
To bump to a newer edition:

1. Re-fetch `Validation/data_dictionary.md` and `Validation/data_dictionary.json` from
   <https://github.com/ombegov/2025-Federal-Agency-AI-Use-Case-Inventory>.
2. Diff the 35-field list against `data.json:schema`.
   Add, remove, or rename fields in `always_required`, `conditional_tier_a`, `conditional_tier_b`,
   `vendor_name`/`system_name_ato`/`HI_justification` conditions, and `hi_tier_c_fields`
   to match the new dictionary.
3. Diff the enum sets in `data.json:schema.enums` against the new dictionary's allowed values.
   Preserve exact strings, including en-dashes (e.g. `"Yes – Disclosure Risk"`).
4. Update the conditionality stage sets (`tier_a_stages`, `tier_b_stages`,
   `vendor_required_stages`, `ato_required_stages`, `hi_tier_c_stages`) if stage names changed.
5. Bump the schema version tag in this file, in `AGENTS.md`, and in `opa-governance-library/README.md`.
6. Re-run the test suite (`opa test fed-inventory/ -v`) and confirm all tests still pass.
7. Run `bash scripts/check-sanitization.sh` and confirm it exits `0`.

---

## What this pillar is

The policy ingests one JSON object representing a single AI use-case inventory record and
reports every way that record fails the OMB schema's field-presence and field-validity rules.
It is deliberately narrow: it checks whether required fields are present and whether enumerated
fields carry recognized values.
It does **not** evaluate whether the substantive content of any field is accurate or adequate.

Validation is **data-driven**.
All field lists, conditionality stage sets, and enum vocabularies live in `data.json` under
`data.schema`; the Rego logic stays stable between schema versions.

---

## The 35 fields

The OMB data dictionary defines 35 fields organized by conditionality tier.
The table below lists every field with its tier and — where applicable — the
allowed enum values encoded in `data.json`.

### Always-required (9 fields)

These nine fields must be present on every record regardless of `is_withheld` or
`development_stage` (`data.json:3–13`, rule `required` at `fed_inventory.rego:28`).

| Field | Notes |
|-------|-------|
| `agency` | Agency code |
| `agency_name` | Agency full name |
| `id` | Record identifier; must be non-empty (`fed_inventory.rego:140`) |
| `use_case_name` | Human-readable use-case name |
| `agency_bureau` | Bureau or sub-agency |
| `contact_email` | Contact address; basic `@` format check (`fed_inventory.rego:135`) |
| `is_withheld` | Disclosure status — see enum below |
| `development_stage` | Lifecycle stage — see enum below |
| `is_high_impact` | High-impact designation — see enum below |

### Conditional tier A (5 fields)

Required when `is_withheld` does **not** start with `"Yes"` AND `development_stage` is
`Pre-deployment`, `Pilot`, or `Deployed` (`fed_inventory.rego:34`, `data.json:96–100`).

| Field | Notes |
|-------|-------|
| `topic_area` | Subject-matter category — see enum below |
| `classification` | AI technique classification — see enum below |
| `problem_solved` | Free-text description |
| `benefits` | Free-text description |
| `system_outputs` | Free-text description |

### Conditional tier B (7 fields)

Required when `is_withheld` does **not** start with `"Yes"` AND `development_stage` is
`Pilot` or `Deployed` (`fed_inventory.rego:43`, `data.json:101–104`).

| Field | Notes |
|-------|-------|
| `operational_date` | Date field (no format validation beyond non-empty) |
| `contracting_usage` | Procurement method — see enum below |
| `have_ato` | Authority to Operate status — see enum below |
| `data_description` | Free-text description |
| `has_pii` | PII flag — see enum below |
| `demographic_features` | Complex/multi-select; presence-only check (see Limitations) |
| `has_custom_code` | Custom code flag — see enum below |

### Conditional: `vendor_name`

Required when `development_stage` is `Pilot` or `Deployed` AND `contracting_usage` is
`"Vendor Purchased"` or `"Contracting and In House"` (`fed_inventory.rego:52`, `data.json:105–112`).

### Conditional: `system_name_ato`

Required when `development_stage` is `Pilot` or `Deployed` AND `have_ato` is `"Yes"`
(`fed_inventory.rego:61`, `data.json:113–116`).

### Conditional: `HI_justification`

Required when `is_high_impact` is exactly `"Presumed High-Impact, but Not High-impact"`
(`fed_inventory.rego:70`).

### Conditional tier C — high-impact fields (9 `hi_*` fields)

Required when `is_high_impact` is `"High-impact"` AND `development_stage` is `"Deployed"`
(`fed_inventory.rego:77`, `data.json:117–131`).
The policy checks presence only for all tier C fields (see Limitations).

| Field |
|-------|
| `hi_testing_conducted` |
| `hi_assessment_completed` |
| `hi_potential_impacts` |
| `hi_independent_review` |
| `hi_ongoing_monitoring` |
| `hi_training_established` |
| `hi_failsafe_presence` |
| `hi_appeal_process` |
| `hi_public_consultation` |

### Optional (3 fields)

These fields are never required and carry no enum validation (`data.json:30–34`).

| Field | Notes |
|-------|-------|
| `link_to_data` | URL (no format validation) |
| `pia_url` | Privacy Impact Assessment URL (no format validation) |
| `code_url` | Source-code URL (no format validation) |

---

## Enum sets

The policy emits a `warning`-severity finding when a present field carries a value outside
its allowed set (`fed_inventory.rego:87–129`).
Enum strings must match exactly, including en-dashes.

| Field | Allowed values |
|-------|----------------|
| `is_withheld` | `No` · `Yes – Disclosure Risk` · `Yes – Prohibited by Law` · `Other` |
| `development_stage` | `Pre-deployment` · `Pilot` · `Deployed` · `Retired` |
| `is_high_impact` | `High-impact` · `Presumed High-Impact, but Not High-impact` · `Not High-impact` |
| `topic_area` | `Admin Functions` · `Cybersecurity` · `Emergency Mgmt` · `Energy and Environment` · `Benefits Processing` · `Health and Medical` · `HR` · `IT` · `International Affairs` · `Law Enforcement` · `Other` · `Procurement and Finance Mgmt` · `Science` · `Service Delivery` · `Transportation` |
| `classification` | `Agentic AI` · `Classical ML` · `Computer Vision` · `Generative AI` · `NLP` · `Reinforcement Learning` |
| `contracting_usage` | `Vendor Purchased` · `In-house Development` · `Contracting and In House` |
| `have_ato` | `Yes` · `No` |
| `has_pii` | `Yes` · `No` |
| `has_custom_code` | `Yes` · `No` |

Source for all enum values: `data.json:35–94` (loaded by OPA as `data.schema.enums`).

---

## Output format

The policy emits findings in the standard `deny` shape used across all pillars
(`fed_inventory.rego:28`):

```json
{"msg": "string", "severity": "error|warning", "field": "string", "rule": "string"}
```

**Severity convention:**

- `error` — a required or conditionally required field is missing.
- `warning` — a present field carries a value outside its allowed enum set,
  or a basic format check fails (e.g. `contact_email` missing `@`).

Example findings:

```json
{"msg": "missing required field: agency", "severity": "error", "field": "agency", "rule": "required"}
{"msg": "missing tier B field: have_ato (required when is_withheld=No and stage in {Pilot, Deployed})", "severity": "error", "field": "have_ato", "rule": "tier_b"}
{"msg": "invalid classification value: 'Deep Learning' (allowed: [...])", "severity": "warning", "field": "classification", "rule": "enum"}
{"msg": "contact_email format invalid (missing @)", "severity": "warning", "field": "contact_email", "rule": "format"}
```

---

## Public entrypoint rules

All rules below are exported by the `fed.inventory` package.

| Rule | Type | Returns |
|------|------|---------|
| `deny` | partial set | Every finding. Each entry carries `msg`, `severity`, `field`, and `rule`. |
| `valid` | boolean | `true` only when `deny` is empty; `false` by default (`fed_inventory.rego:146`). |
| `errors` | set | The subset of `deny` whose `severity == "error"` (`fed_inventory.rego:150`). |
| `warnings` | set | The subset of `deny` whose `severity == "warning"` (`fed_inventory.rego:152`). |
| `summary` | object | Bundles `valid`, `deny`, `error_count`, and `warning_count` (`fed_inventory.rego:154`). |

`summary` is the recommended single-call entrypoint for callers.

---

## Run it

From the repository root, evaluate a record against the policy.
Pass one JSON record as the input document.

```sh
# Full summary (valid, deny set, error/warning counts)
opa eval -d fed-inventory/ -i <record>.json 'data.fed.inventory.summary'

# Violations only
opa eval -d fed-inventory/ -i <record>.json 'data.fed.inventory.deny'

# Errors only (missing required fields)
opa eval -d fed-inventory/ -i <record>.json 'data.fed.inventory.errors'

# Boolean pass/fail
opa eval -d fed-inventory/ -i <record>.json 'data.fed.inventory.valid'
```

Replace `<record>.json` with the path to a single-record JSON file.
For CSV-sourced data, convert first — see [`docs/ingestion-field-map.md`](docs/ingestion-field-map.md).

Run the test suite:

```sh
opa test fed-inventory/ -v
```

---

## Known limitations

1. **Advisory output only.**
   This policy checks field completeness and field validity.
   It does not assess whether the substantive content of any field is accurate, adequate, or
   sufficient for any regulatory or statutory purpose.
   The caller is responsible for enforcement decisions.

2. **`demographic_features` and `hi_*` fields — presence only.**
   These fields carry complex or multi-select values whose enum sets are not fully enumerated
   in machine-readable form in the OMB data dictionary.
   The policy checks that these fields are present (non-empty) when required but does not
   validate individual values against an enum.
   Passing an out-of-vocabulary value will not produce a `warning` for these fields.
   This is documented at `fed_inventory.rego:133` and is intentional to avoid false positives.

3. **No format validation beyond `contact_email`.**
   The `operational_date`, `link_to_data`, `pia_url`, and `code_url` fields are not validated
   for date format or URL structure.

4. **Single-record evaluation.**
   OPA evaluates one record at a time.
   Cross-record checks (duplicate IDs, agency-level counts) are out of scope.

5. **No trusted clock.**
   The policy does not use a trusted clock.
   Fields such as `operational_date` are not compared against the current date.

6. **No input provenance.**
   The policy trusts the input document completely.
   A caller that can write the input document can pass any field check.

---

> The policies are advisory only: they emit structured `deny` decisions, and
> the *caller* is responsible for enforcing them.
