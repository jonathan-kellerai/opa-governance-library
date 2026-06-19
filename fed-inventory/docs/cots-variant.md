# Federal AI Use-Case Inventory — COTS Variant

## Overview

The OMB 2025 Federal AI Use-Case Inventory includes **two distinct data formats**:

1. **Individually Reported Use Cases** (`2025_individually_reported_AI_use_cases.csv`) — 35-field schema with tiered disclosure requirements
2. **Consolidated COTS Use Cases** (`2025_consolidated_COTS_AI_use_cases.csv`) — 5-field simplified schema for commercial off-the-shelf AI products

This document describes the COTS variant schema, its differences from the individual schema, and how the `fed-inventory` policy validates COTS records.

---

## COTS Data Source

- **File**: `2025_consolidated_COTS_AI_use_cases.csv`
- **URL**: https://github.com/ombegov/2025-Federal-Agency-AI-Use-Case-Inventory/blob/main/Data/2025_consolidated_COTS_AI_use_cases.csv
- **Record count**: 446 commercial products (as of 2025 inventory)
- **Purpose**: Agencies report AI capabilities embedded in widely-used commercial software (Microsoft 365 Copilot, Google Workspace AI, etc.)

---

## COTS Schema (5 Fields)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| **Agency** | text | Always | Federal agency abbreviation (e.g., "DOD", "DHS") |
| **AI Use Case** | text | Always | Description of the AI capability (e.g., "Transcribing, summarizing, or other efforts that improve the accessibility of a virtual meeting") |
| **Agency Use (Y/N)?** | enum | Always | Whether the agency uses this AI capability. Valid values: `Y`, `N` |
| **Name of Commercial Product or Service Used** | text | If `Agency Use = Y` | Vendor product name (e.g., "Microsoft 365 Copilot GCC") |
| **Estimated # of Licenses/Users** | text | If `Agency Use = Y` | Estimated scale (e.g., "1-100", "101-500", "500+") |

**Key difference from individual schema**: COTS records do NOT include:
- Contact email
- Development stage (Pre-deployment, Pilot, Deployed, Retired)
- High-impact designation or tier C fields
- PII/ATO/demographic fields
- Custom code or data description fields

---

## Individual vs COTS Field Comparison

| Individual Schema (35 fields) | COTS Schema (5 fields) | Delta |
|-------------------------------|------------------------|-------|
| `agency`, `agency_name`, `id`, `use_case_name`, `agency_bureau`, `contact_email`, `is_withheld`, `development_stage`, `is_high_impact`, ... (26 more fields) | `Agency`, `AI Use Case`, `Agency Use (Y/N)?`, `Name of Commercial Product or Service Used`, `Estimated # of Licenses/Users` | **-30 fields** |

### Field Name Mapping

| Individual Schema | COTS Schema | Notes |
|-------------------|-------------|-------|
| `agency` | `Agency` | Case difference; COTS capitalizes |
| `use_case_name` | `AI Use Case` | Different field name |
| `vendor_name` | `Name of Commercial Product or Service Used` | More verbose in COTS |
| (none) | `Agency Use (Y/N)?` | COTS-specific discriminator |
| (none) | `Estimated # of Licenses/Users` | COTS-specific scale indicator |

**No direct equivalents**: The remaining 32 individual-schema fields (`id`, `contact_email`, `is_withheld`, `development_stage`, `is_high_impact`, `topic_area`, `classification`, `problem_solved`, `benefits`, `system_outputs`, `operational_date`, `contracting_usage`, `have_ato`, `system_name_ato`, `data_description`, `link_to_data`, `has_pii`, `pia_url`, `demographic_features`, `has_custom_code`, `code_url`, plus all 9 `hi_*` tier-C fields) are **absent** from COTS records.

---

## Policy Validation for COTS Records

The `fed-inventory` policy detects COTS records by the presence of the `Agency Use (Y/N)?` field.

### Detection Logic

```rego
_is_cots if input["Agency Use (Y/N)?"]
```

If `input["Agency Use (Y/N)?"]` exists, the record is validated as COTS; otherwise, the individual-schema rules apply.

### COTS Validation Rules

All COTS validations produce **warnings** (not errors) — advisory conformance only.

| Rule | Severity | Condition |
|------|----------|-----------|
| `cots_required` | warning | Any of `Agency`, `AI Use Case`, `Agency Use (Y/N)?` is missing or empty |
| `cots_required_if_used` | warning | `Agency Use (Y/N)? = Y` but `Name of Commercial Product or Service Used` or `Estimated # of Licenses/Users` is missing |
| `cots_enum` | warning | `Agency Use (Y/N)?` is not `Y` or `N` |

### Entrypoints

- **Standard deny set** (`inventory.deny`): Validates individual-schema records; COTS records do NOT trigger these rules
- **COTS deny set** (`inventory.cots_deny`): Validates COTS records only
- **COTS summary** (`inventory.cots_summary`): Returns `{valid: bool, deny: [...], warning_count: int}` for COTS records

**Usage**:

```bash
# Validate a COTS record
opa eval -d fed-inventory/ -i cots-record.json 'data.fed.inventory.cots_summary'

# Validate an individual record (standard path)
opa eval -d fed-inventory/ -i individual-record.json 'data.fed.inventory.summary'
```

---

## Example COTS Records

### Conformant Record (Agency Use = Y)

```json
{
  "Agency": "Committee for Purchase From People Who Are Blind or Significantly Disabled",
  "AI Use Case": "Transcribing, summarizing, or other efforts that improve the accessibility of a virtual meeting or interview using AI.",
  "Agency Use (Y/N)?": "Y",
  "Name of Commercial Product or Service Used": "Microsoft 365 Copilot GCC",
  "Estimated # of Licenses/Users": "1-100"
}
```

**Validation result**: `cots_summary.valid = true` (0 warnings)

### Conformant Record (Agency Use = N)

```json
{
  "Agency": "Committee for Purchase From People Who Are Blind or Significantly Disabled",
  "AI Use Case": "Scheduling internal-to-government meetings or appointments or set reminders using AI.",
  "Agency Use (Y/N)?": "N",
  "Name of Commercial Product or Service Used": "",
  "Estimated # of Licenses/Users": ""
}
```

**Validation result**: `cots_summary.valid = true` (0 warnings) — product fields optional when `Agency Use = N`

### Non-Conformant Record (Missing Product Fields)

```json
{
  "Agency": "Department of Defense",
  "AI Use Case": "AI-powered threat detection",
  "Agency Use (Y/N)?": "Y",
  "Name of Commercial Product or Service Used": "",
  "Estimated # of Licenses/Users": ""
}
```

**Validation result**: `cots_summary.valid = false` (2 warnings) — `Name of Commercial Product or Service Used` and `Estimated # of Licenses/Users` required when `Agency Use = Y`

---

## Test Coverage

The `fed_inventory_test.rego` suite includes **5 COTS-specific tests** (tests 16-20):

| Test | Fixture | Expected Result |
|------|---------|-----------------|
| `test_cots_conformant_with_usage` | COTS record with `Agency Use = Y` and complete product fields | 0 warnings, valid |
| `test_cots_conformant_without_usage` | COTS record with `Agency Use = N` and empty product fields | 0 warnings, valid |
| `test_cots_missing_required` | COTS record with missing `Agency` and `Agency Use (Y/N)?` | 3 warnings (2 required + 1 enum) |
| `test_cots_missing_product_fields` | COTS record with `Agency Use = Y` but missing product fields | 2 warnings (`cots_required_if_used`) |
| `test_cots_invalid_enum` | COTS record with `Agency Use (Y/N)? = "Maybe"` | 1 warning (`cots_enum`) |

Run tests:

```bash
opa test fed-inventory/ -v
```

**Expected**: 20 tests pass (15 individual-schema tests + 5 COTS tests)

---

## Advisory Disclaimer

This policy performs **advisory conformance checks only**. It validates:

- Field presence (required vs optional)
- Field validity (enum membership, basic format)

It does **NOT**:

- Assess substantive compliance (whether an agency's disclosure is adequate or accurate)
- Enforce usage of COTS products
- Make recommendations about which products agencies should use
- Validate license counts or product names against vendor catalogs

Callers are responsible for all enforcement decisions.

---

## Version Note

This COTS variant encoding is based on the **2025 Federal AI Use-Case Inventory** (`fed-inventory@2025`).

Schema sources:
- Individual: https://github.com/ombegov/2025-Federal-Agency-AI-Use-Case-Inventory/blob/main/Data/2025_individually_reported_AI_use_cases.csv
- COTS: https://github.com/ombegov/2025-Federal-Agency-AI-Use-Case-Inventory/blob/main/Data/2025_consolidated_COTS_AI_use_cases.csv
- Data dictionary: https://github.com/ombegov/2025-Federal-Agency-AI-Use-Case-Inventory/blob/main/Validation/data_dictionary.json

If OMB publishes a 2026 or later inventory with schema changes, this policy will require updates.
