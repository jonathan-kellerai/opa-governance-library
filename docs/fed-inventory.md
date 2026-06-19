# Federal AI Use-Case Inventory Policy (OMB 2025)

- **Title:** `fed-inventory` — Pillar 4 of the `jonathan-kellerai/opa-governance-library`
- **Audience:** Engineers, policy practitioners, and data teams ingesting OMB 2025 Federal AI Use-Case Inventory disclosures
- **Schema version:** `fed-inventory@2025`, sourced from the OMB data dictionary, retrieved 2026-06-18
- **Last updated:** 2026-06-18

---

> The policies are **advisory only**: they emit structured `deny` decisions, and
> the *caller* is responsible for enforcing them (an admission webhook, a CI
> gate, a deployment script).

---

## Overview

`fed-inventory` is an [Open Policy Agent](https://www.openpolicyagent.org/) Rego policy that
validates OMB 2025 Federal Agency AI Use-Case Inventory disclosure records.
Given a single JSON record — one row from the OMB inventory CSV — the policy reports every way
that record fails the schema's field-presence and field-validity rules.

The policy checks two things and only two things:

1. **Field presence.** Every always-required field is present and non-empty. Conditionally
   required fields are present when their conditionality conditions are met (disclosure status,
   lifecycle stage, high-impact designation).
2. **Field validity.** Enumerated fields carry a recognized value from the OMB-defined allowed set.

The policy does **not** assess whether the substantive content of any field is accurate or
adequate, and it makes no compliance or regulatory determination.

## What the policy checks

The OMB schema organises its 35 fields into conditionality tiers. The policy evaluates each tier
independently for every input record.

### Always-required fields (9)

These fields must be present on every record regardless of any other field value
(`fed_inventory.rego:28`; field list at `data.json:3-13`).

| Field | Notes |
|-------|-------|
| `agency` | Agency code |
| `agency_name` | Agency full name |
| `id` | Record identifier; must not be whitespace-only |
| `use_case_name` | Human-readable use-case name |
| `agency_bureau` | Bureau or sub-agency |
| `contact_email` | Contact address; basic `@` format check applied |
| `is_withheld` | Disclosure status — enum-validated |
| `development_stage` | Lifecycle stage — enum-validated |
| `is_high_impact` | High-impact designation — enum-validated |

### Conditional tier A (5 fields)

Required when `is_withheld` does not start with `"Yes"` **AND** `development_stage` is
`Pre-deployment`, `Pilot`, or `Deployed` (`fed_inventory.rego:34`).

Fields: `topic_area`, `classification`, `problem_solved`, `benefits`, `system_outputs`.

### Conditional tier B (7 fields)

Required when `is_withheld` does not start with `"Yes"` **AND** `development_stage` is
`Pilot` or `Deployed` (`fed_inventory.rego:43`).

Fields: `operational_date`, `contracting_usage`, `have_ato`, `data_description`,
`has_pii`, `demographic_features`, `has_custom_code`.

### Point conditionals

- **`vendor_name`** — required when `development_stage` is `Pilot` or `Deployed` AND
  `contracting_usage` is `"Vendor Purchased"` or `"Contracting and In House"` (`fed_inventory.rego:52`).
- **`system_name_ato`** — required when `development_stage` is `Pilot` or `Deployed` AND
  `have_ato` is `"Yes"` (`fed_inventory.rego:61`).
- **`HI_justification`** — required when `is_high_impact` is exactly
  `"Presumed High-Impact, but Not High-impact"` (`fed_inventory.rego:70`).

### Conditional tier C — high-impact fields (9)

Required when `is_high_impact` is `"High-impact"` AND `development_stage` is `"Deployed"`
(`fed_inventory.rego:77`). All nine `hi_*` fields are presence-only checks.

### Optional fields (3)

`link_to_data`, `pia_url`, `code_url` — never required; no format validation.

### Enum validation

When a present field carries a value outside its allowed set, the policy emits a
`warning`-severity finding (`fed_inventory.rego:87-129`). Enum strings are case-sensitive and
must use en-dashes where the OMB schema does.

| Field | Allowed values |
|-------|----------------|
| `is_withheld` | `No` · `Yes – Disclosure Risk` · `Yes – Prohibited by Law` · `Other` |
| `development_stage` | `Pre-deployment` · `Pilot` · `Deployed` · `Retired` |
| `is_high_impact` | `High-impact` · `Presumed High-Impact, but Not High-impact` · `Not High-impact` |
| `classification` | `Agentic AI` · `Classical ML` · `Computer Vision` · `Generative AI` · `NLP` · `Reinforcement Learning` |
| `contracting_usage` | `Vendor Purchased` · `In-house Development` · `Contracting and In House` |
| `have_ato` | `Yes` · `No` |
| `has_pii` | `Yes` · `No` |
| `has_custom_code` | `Yes` · `No` |

Source for all enum values: `data.json:35-94` (loaded by OPA as `data.schema.enums`).

## Output format

Every finding is a structured object in the standard `deny` shape used across all pillars:

```json
{"msg": "string", "severity": "error|warning", "field": "string", "rule": "string"}
```

Severity convention:

- `error` — a required or conditionally required field is missing.
- `warning` — a present field carries an unrecognized enum value, or a basic format check fails.

The policy also exports `valid` (boolean), `errors` (severity-filtered set), `warnings`
(severity-filtered set), and `summary` (an object bundling all four). `summary` is the
recommended single-call entrypoint (`fed_inventory.rego:154`).

## Evaluate a record

```sh
# Full summary (valid flag + deny set + error/warning counts)
opa eval -d fed-inventory/ -i <record>.json 'data.fed.inventory.summary'

# Violations only
opa eval -d fed-inventory/ -i <record>.json 'data.fed.inventory.deny'

# Boolean pass/fail
opa eval -d fed-inventory/ -i <record>.json 'data.fed.inventory.valid'
```

Replace `<record>.json` with the path to a single-record JSON file converted from CSV.
See the [ingestion field map](../fed-inventory/docs/ingestion-field-map.md) for the
full CSV-to-JSON conversion procedure.

## Run the test suite

```sh
opa test fed-inventory/ -v
```

## Source attribution

This policy encodes the schema published by the U.S. Office of Management and Budget for the
2025 Federal AI Use-Case Inventory.

- **OMB 2025 Federal Agency AI Use-Case Inventory:**
  <https://github.com/ombegov/2025-Federal-Agency-AI-Use-Case-Inventory>
  — the authoritative schema is at `Validation/data_dictionary.md` and
  `Validation/data_dictionary.json`.
- **Federal Reserve AI Use-Case Inventory (2025):**
  <https://www.federalreserve.gov/AI-use-case-inventory-2025.htm>
  — the Federal Reserve reports approximately 39 AI use cases on its own disclosure page.
  Note: the Federal Reserve is **not** part of the OMB 56-agency government-wide dataset;
  it reports independently. Federal Reserve records are valid inputs to this policy when
  mapped onto the OMB schema fields.

The "56" figure is the OMB agency count, not a use-case count.

## Known limitations

1. **Advisory output only.** The policy reports structural findings; the caller decides what
   to do with them.
2. **`demographic_features` and `hi_*` fields — presence only.** These fields carry complex
   or multi-select values. The policy checks presence when required but does not enum-validate
   individual sub-values (`fed_inventory.rego:133`).
3. **No date or URL format validation** beyond the basic `@` check on `contact_email`.
4. **Single-record evaluation.** One JSON object per `opa eval` invocation;
   cross-record checks are out of scope.
5. **No trusted clock.** Fields such as `operational_date` are not compared against the
   current date.

---

> The policies are **advisory only**: they emit structured `deny` decisions, and
> the *caller* is responsible for enforcing them (an admission webhook, a CI
> gate, a deployment script).
