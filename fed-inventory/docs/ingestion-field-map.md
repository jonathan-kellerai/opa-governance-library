# Ingestion Field Map — OMB 2025 Federal AI Use-Case Inventory

> **Advisory only.** The policies are advisory only: they emit structured `deny` decisions, and
> the *caller* is responsible for enforcing them.

This document describes how to convert the OMB 2025 Federal AI Use-Case Inventory source file
into the JSON format expected by `fed_inventory.rego`.
OPA cannot evaluate CSV or XLSX directly; a conversion step is mandatory before policy evaluation.

- **Schema version:** `fed-inventory@2025`, sourced from the OMB data dictionary, retrieved 2026-06-18
- **Source attribution:**
  OMB 2025 Federal Agency AI Use-Case Inventory: <https://github.com/ombegov/2025-Federal-Agency-AI-Use-Case-Inventory>
  — authoritative schema at `Validation/data_dictionary.md` and `Validation/data_dictionary.json`.
  Federal Reserve AI Use-Case Inventory: <https://www.federalreserve.gov/AI-use-case-inventory-2025.htm>

---

## Source file

The OMB inventory distributes individual agency submissions as:

```text
Data/2025_individually_reported_AI_use_cases.csv
```

inside the repository at <https://github.com/ombegov/2025-Federal-Agency-AI-Use-Case-Inventory>.

The Federal Reserve publishes its own inventory separately at
<https://www.federalreserve.gov/AI-use-case-inventory-2025.htm>.
Note: the Federal Reserve is not part of the OMB 56-agency dataset.
The "56" figure is the OMB agency count, not a use-case count.
Federal Reserve records can be ingested by this policy when each row is mapped onto the OMB
schema fields below.

---

## Column-to-key mapping

The CSV column headers map 1:1 to JSON keys: the JSON key name is identical to the CSV column
header string.
No renaming, lowercasing, or camelCase conversion is applied.

The table below lists all 35 fields with their CSV column header, JSON key, conditionality tier,
and allowed enum values where applicable.

| CSV Column Header | JSON Key | Tier | Allowed values / notes |
|-------------------|----------|------|------------------------|
| `agency` | `agency` | Always required | Free text (agency code) |
| `agency_name` | `agency_name` | Always required | Free text |
| `id` | `id` | Always required | Non-empty string; must not be whitespace-only |
| `use_case_name` | `use_case_name` | Always required | Free text |
| `agency_bureau` | `agency_bureau` | Always required | Free text |
| `contact_email` | `contact_email` | Always required | Must contain `@` |
| `is_withheld` | `is_withheld` | Always required | `No` · `Yes – Disclosure Risk` · `Yes – Prohibited by Law` · `Other` |
| `development_stage` | `development_stage` | Always required | `Pre-deployment` · `Pilot` · `Deployed` · `Retired` |
| `is_high_impact` | `is_high_impact` | Always required | `High-impact` · `Presumed High-Impact, but Not High-impact` · `Not High-impact` |
| `topic_area` | `topic_area` | Tier A | `Admin Functions` · `Cybersecurity` · `Emergency Mgmt` · `Energy and Environment` · `Benefits Processing` · `Health and Medical` · `HR` · `IT` · `International Affairs` · `Law Enforcement` · `Other` · `Procurement and Finance Mgmt` · `Science` · `Service Delivery` · `Transportation` |
| `classification` | `classification` | Tier A | `Agentic AI` · `Classical ML` · `Computer Vision` · `Generative AI` · `NLP` · `Reinforcement Learning` |
| `problem_solved` | `problem_solved` | Tier A | Free text |
| `benefits` | `benefits` | Tier A | Free text |
| `system_outputs` | `system_outputs` | Tier A | Free text |
| `operational_date` | `operational_date` | Tier B | Free text (no format validation) |
| `contracting_usage` | `contracting_usage` | Tier B | `Vendor Purchased` · `In-house Development` · `Contracting and In House` |
| `have_ato` | `have_ato` | Tier B | `Yes` · `No` |
| `data_description` | `data_description` | Tier B | Free text |
| `has_pii` | `has_pii` | Tier B | `Yes` · `No` |
| `demographic_features` | `demographic_features` | Tier B | Complex/multi-select; presence-only check — see note below |
| `has_custom_code` | `has_custom_code` | Tier B | `Yes` · `No` |
| `vendor_name` | `vendor_name` | Conditional (vendor) | Required when stage in {Pilot, Deployed} AND contracting_usage in {Vendor Purchased, Contracting and In House} |
| `system_name_ato` | `system_name_ato` | Conditional (ATO) | Required when stage in {Pilot, Deployed} AND have_ato = Yes |
| `HI_justification` | `HI_justification` | Conditional (HI) | Required when is_high_impact = "Presumed High-Impact, but Not High-impact" |
| `hi_testing_conducted` | `hi_testing_conducted` | Tier C | Presence-only check |
| `hi_assessment_completed` | `hi_assessment_completed` | Tier C | Presence-only check |
| `hi_potential_impacts` | `hi_potential_impacts` | Tier C | Presence-only check |
| `hi_independent_review` | `hi_independent_review` | Tier C | Presence-only check |
| `hi_ongoing_monitoring` | `hi_ongoing_monitoring` | Tier C | Presence-only check |
| `hi_training_established` | `hi_training_established` | Tier C | Presence-only check |
| `hi_failsafe_presence` | `hi_failsafe_presence` | Tier C | Presence-only check |
| `hi_appeal_process` | `hi_appeal_process` | Tier C | Presence-only check |
| `hi_public_consultation` | `hi_public_consultation` | Tier C | Presence-only check |
| `link_to_data` | `link_to_data` | Optional | URL (no format validation) |
| `pia_url` | `pia_url` | Optional | URL (no format validation) |
| `code_url` | `code_url` | Optional | URL (no format validation) |

**Tier A** fields are required when `is_withheld` does not start with `"Yes"` AND `development_stage`
is `Pre-deployment`, `Pilot`, or `Deployed`.

**Tier B** fields are required when `is_withheld` does not start with `"Yes"` AND `development_stage`
is `Pilot` or `Deployed`.

**Tier C** fields are required when `is_high_impact` is `"High-impact"` AND `development_stage` is `"Deployed"`.

---

## Enum normalization notes

- **Exact string match is required.** Enum values are case-sensitive.
  `"no"`, `"NO"`, and `"No"` are three distinct values; only `"No"` is valid.
- **Preserve en-dashes.** The values `"Yes – Disclosure Risk"` and `"Yes – Prohibited by Law"`
  use an en-dash (`–`, U+2013), not a hyphen-minus (`-`, U+002D).
  Tools that export CSV with smart punctuation may substitute the correct character automatically;
  verify by inspecting the raw bytes if the `is_withheld` enum check fires unexpectedly.
- **Empty vs. absent.** The policy's `_has` helper (`fed_inventory.rego:19`) treats a field as
  absent when it is missing from the JSON object OR when its string value trims to `""`.
  A CSV cell that is blank or contains only spaces produces an absent field after conversion.
- **One record per JSON object.** The policy evaluates one record at a time.
  Each CSV row becomes one independent JSON object.
  Do not wrap rows in an array at the top level; pass each object as the `--input` document.

---

## Conversion procedure

Use the Python standard library — no third-party packages required.
The script below reads the CSV and writes one JSON file per row.

```python
import csv
import json
import pathlib
import sys

source_csv = pathlib.Path(sys.argv[1])   # e.g. Data/2025_individually_reported_AI_use_cases.csv
output_dir = pathlib.Path(sys.argv[2])   # directory to write per-record JSON files
output_dir.mkdir(parents=True, exist_ok=True)

with source_csv.open(newline="", encoding="utf-8-sig") as fh:
    reader = csv.DictReader(fh)
    for i, row in enumerate(reader):
        # Strip leading/trailing whitespace from every value.
        record = {k: v.strip() for k, v in row.items()}
        # Use the record's id field as the filename when available.
        record_id = record.get("id") or str(i)
        out_path = output_dir / f"{record_id}.json"
        with out_path.open("w", encoding="utf-8") as out:
            json.dump(record, out, ensure_ascii=False, indent=2)

print(f"Wrote {i + 1} records to {output_dir}/")
```

Run as:

```sh
python3 convert.py Data/2025_individually_reported_AI_use_cases.csv records/
```

Each row in the CSV becomes one file in `records/`.
Evaluate a single record:

```sh
opa eval -d fed-inventory/ -i records/<id>.json 'data.fed.inventory.summary'
```

To batch-evaluate all records, loop over the output directory:

```sh
for f in records/*.json; do
  echo "=== $f ===" && opa eval -d fed-inventory/ -i "$f" 'data.fed.inventory.summary'
done
```

---

## Notes on `demographic_features` and `hi_*` fields

These fields carry complex or multi-select values (e.g. comma-separated sub-values within a
single CSV cell).
The policy checks only that these fields are present and non-empty when required.
It does not split or validate individual sub-values.
The conversion script above passes the full cell value as a single string, which is sufficient
for the presence check to pass.
If your pipeline needs sub-value validation, apply that logic in the conversion layer before
OPA evaluation.

---

> The policies are advisory only: they emit structured `deny` decisions, and
> the *caller* is responsible for enforcing them.
