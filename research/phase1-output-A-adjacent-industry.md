# Research Output A: Adjacent Industry Validation Patterns

- **Researcher:** XD-1 (Adjacent Industry)
- **Date:** 2026-03-25
- **Scope:** How six adjacent industries solve structured report validation -- patterns applicable to SoFA and SoFREP Rego policies

---

## Executive Summary

SoFA and SoFREP already implement strong structural validation (required fields, enums, date formats) and some cross-field checks (fund reconciliation, dependency resolution). However, adjacent industries reveal **six validation pattern families** that neither policy fully exploits: (1) algebraic invariant enforcement, (2) conditional mandatory fields driven by report context, (3) cross-schedule/cross-template reconciliation, (4) severity-gated field escalation, (5) structured acknowledgment/feedback loops, and (6) temporal coherence guards. Each recommendation below extracts a reusable pattern and maps it to a concrete Rego implementation opportunity.

---

## 1. XBRL Calculation Linkbase -- Algebraic Invariant Enforcement

**Source:** [XBRL Formula Rules Tutorial](https://www.xbrl.org/guidance/xbrl-formula-rules-tutorial/), [XBRL Calculation Linkbase](https://www.openriskmanual.org/wiki/XBRL_Calculation_Linkbase), [Implementing Business Validation Rules](https://www.xbrl.org/guidance/implementingrules/)

**Confidence:** High

**Pattern:** XBRL defines *calculation linkbases* -- directed acyclic graphs where parent concepts must equal the weighted sum of child concepts. The canonical example: `Assets = Liabilities + Equity`. These are not ad-hoc checks; they are *declared as taxonomy relationships* and automatically enforced on every filing. The Formula Specification extends this to arbitrary XPath expressions across any two or more reported concepts (e.g., "depreciation cannot be negative", "revenue recognized cannot exceed contract value").

**Rego implementation opportunity:** SoFA already checks `net_movement == income - expenditure` and fund reconciliation (`opening + net = closing`). What is missing is a **generalized invariant declaration system** in `data.json`. Instead of hard-coding each reconciliation rule, define an array of algebraic invariants:

```json
{
  "invariants": [
    {"name": "balance_sheet", "expr": "opening + net_movement == closing", "scope": "fund_balances.*"},
    {"name": "transfer_netting", "expr": "sum(transfers.amount) == 0", "scope": "transfers"},
    {"name": "total_income", "expr": "sum(incoming_resources.amount) == incoming_resources_total", "scope": "root"}
  ]
}
```

A single Rego rule could iterate over `data.invariants` and evaluate each, eliminating the current pattern of one hand-written rule per mathematical relationship. This mirrors how XBRL separates *invariant declaration* (taxonomy) from *invariant enforcement* (processor).

**What SoFA is missing:** The current policy hard-codes five separate reconciliation rules. Adding a sixth requires writing new Rego. An invariant-driven approach would make it data-driven, matching XBRL's extensibility model.

---

## 2. CCAR FR Y-14A -- Cross-Schedule Reconciliation

**Source:** [FR Y-14A Federal Reserve](https://www.federalreserve.gov/apps/reportingforms/Report/Index/FR_Y-14A), [Automated Validation Frameworks for CCAR Reporting Pipelines](https://www.researchgate.net/publication/398420157_AUTOMATED_VALIDATION_FRAMEWORKS_FOR_CCAR_REPORTING_PIPELINES_FRY-14MQ)

**Confidence:** High

**Pattern:** The FR Y-14A report comprises multiple schedules (Summary, Scenario, Regulatory Capital Instruments, Operational Risk, Business Plan Changes). The Federal Reserve requires **cross-schedule reconciliation**: values reported in the Summary schedule must match aggregates from detail schedules. Files must pass all validation checks before submission (status: VALIDATING -> VALID -> INVALID). Capital instrument repurchases must reconcile between FR Y-14A Schedule C and FR Y-14Q Schedule C. Data errors directly impact projected losses and capital ratios, so the Fed issues MRAs (Matters Requiring Attention) for reconciliation failures.

**Rego implementation opportunity:** SoFREP has four quadrants but performs no cross-quadrant *numerical* consistency checks. A CCAR-inspired pattern would verify that aggregate counts or metrics computed from quadrant contents match any reported summary fields. More powerfully, if SoFREP ever adds a "summary" section, Rego rules should enforce that summary statistics are *derived* from quadrant data, not independently asserted.

For SoFA, the pattern suggests adding a **cross-section reconciliation rule**: the sum of all `fund_balances[*].net_movement` should equal `net_movement` at the top level. This is partially covered but could be generalized.

**What SoFA/SoFREP are missing:** Neither policy validates that summary-level aggregates are consistent with detail-level line items across different sections of the same report. CCAR treats this as a blocking validation error.

---

## 3. Solvency II QRT -- Cross-Template Validation with Data Point Model

**Source:** [EIOPA Supervisory Reporting DPM and XBRL](https://www.eiopa.europa.eu/tools-and-data/supervisory-reporting-dpm-and-xbrl_en), [Solvency II QRTs EIOPA Taxonomy Updates](https://www.milliman.com/en/insight/solvency-ii-qrts-eiopa-taxonomy-updates)

**Confidence:** Medium

**Pattern:** EIOPA's Solvency II framework uses a Data Point Model (DPM) where every cell in every Quantitative Reporting Template (QRT) is identified by a set of dimensional coordinates (template, row, column, currency, entity). Validation rules are expressed as relationships between data points *across* templates -- e.g., the total technical provisions in template S.02.01 must equal the sum of provisions by line of business in template S.17.01. EIOPA publishes an exclusion list for rules that are temporarily suspended, and the taxonomy version controls which rules are active.

**Rego implementation opportunity:** SoFA and SoFREP are currently single-document validators. The DPM pattern suggests designing for **multi-document validation** -- e.g., validating that a SoFREP's "at_risk" items are consistent with a SoFA's going-concern warnings, or that an organization's quarterly SoFA reports show temporal continuity. This would require Rego policies that accept multiple inputs (or a composite input with prior-period data, which SoFA's `prior_period` field partially enables).

**What SoFA/SoFREP are missing:** No mechanism for cross-report validation. An organization filing both SoFA and SoFREP has no policy ensuring consistency between them.

---

## 4. Aviation PIREP/METAR -- Severity-Gated Conditional Mandatory Fields

**Source:** [PIREP Submission Information](https://aviationweather.gov/help/pirep/), [FAA Handbook Chapter 3](https://www.faasafety.gov/files/events/SO/SO15/2024/SO15129448/FAA-H-8083-28Chpt3.pdf), [Federal Coordinator for Meteorological Services FMH-12](https://www.icams-portal.gov/resources/ofcm/fmh/FMH12/fmh12.pdf)

**Confidence:** High

**Pattern:** PIREPs use a two-tier urgency system: UA (routine) and UUA (urgent). The report type determines which fields become mandatory. All PIREPs require location (/OV), time (/TM), flight level (/FL), aircraft type (/TP), plus at least one weather element. But UUA reports have *additional* mandatory content: the hazardous condition must be explicitly described with intensity classification. Weather phenomena must be reported in priority order (tornado first, then thunderstorm, then other phenomena by predominance). Intensity qualifiers are constrained by phenomenon type -- e.g., only moderate or heavy intensity may be ascribed to dust/sand storms.

**Rego implementation opportunity:** SoFREP already has priority enums (P0-P4) and urgency enums for needed items, but it does **not** enforce conditional mandatory fields based on severity. The PIREP pattern suggests:

```rego
# If priority is P0 or P1, mitigation plan is mandatory
deny contains {...} if {
    some item in items_in("at_risk")
    item.priority in {"P0", "P1"}
    not item.mitigation
}
```

Similarly, SoFA could require variance explanations to be mandatory (not just warned) when variance exceeds a critical threshold, and could require going-concern disclosures when liquidity ratio drops below a critical level.

**What SoFREP is missing:** Priority and urgency are validated as enum values but do not *gate* additional field requirements. A P0 at_risk item with no mitigation plan is currently valid. In aviation, a UUA report without the hazardous condition detail is rejected.

---

## 5. AHRQ Common Formats -- Conditional Logic Trees and Harm-Severity Coupling

**Source:** [About Common Formats](https://pso.ahrq.gov/common-formats/about), [Common Formats Overview PSOPPC](https://www.psoppc.org/psoppc_web/publicpages/commonFormatsOverview), [Reliability of AHRQ Common Format Harm Scales](https://pubmed.ncbi.nlm.nih.gov/24080718/)

**Confidence:** Medium

**Pattern:** AHRQ Common Formats define a structured decision tree for patient safety events. Technical specifications include **conditional and go-to logic**: the answer to one question determines which subsequent questions are mandatory. The Harm Scale (6 levels: death, severe, moderate, mild, no harm, unknown) must be consistent with the event description. Research found that >30% of reports had discrepancies between free-text descriptions and structured harm classifications -- the text described a death but "no harm" was checked. This drove AHRQ to add **cross-field consistency validation**: the harm level must be plausible given the event type and outcome fields.

**Rego implementation opportunity:** SoFREP's risk matrix computes `impact * likelihood` to derive risk level, but does not validate that the *qualitative description* (title, description) is consistent with the *quantitative assessment*. The AHRQ pattern suggests:

- If `risk_level == "critical"`, require a non-empty `mitigation` field with minimum length
- If harm classification is "death" equivalent (critical risk + high impact), require escalation metadata (escalation contact, timeline)
- Validate that `urgency` and `priority` are not contradictory (e.g., `urgency: "low"` + `priority: "P0"` should trigger a warning)

For SoFA, the pattern suggests validating that `accounting_basis` is consistent with the *types* of line items present -- currently checked for accrual items under cash basis, but could be extended to verify that investment income categories are only used when the entity type supports them.

**What SoFREP is missing:** No validation that qualitative assessments (urgency, priority, impact) are mutually consistent. Contradictory severity signals pass validation silently.

---

## 6. EDI X12 997 -- Structured Acknowledgment and Layered Error Taxonomy

**Source:** [X12 997 Acknowledgments and Error Codes (Microsoft)](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-enterprise-integration-x12-997-acknowledgment), [X12 997 Functional Acknowledgment (Stedi)](https://www.stedi.com/edi/x12/transaction-set/997), [X12 997 Error Codes (EdiFabric)](https://support.edifabric.com/hc/en-us/articles/360000380131-X12-997-Acknowledgment-Error-Codes)

**Confidence:** High

**Pattern:** The X12 997 Functional Acknowledgment is a *response document* that validates a received transaction set at four hierarchical levels: (1) functional group (AK1), (2) transaction set (AK2), (3) segment (AK3), (4) element (AK4). Each level has its own error code taxonomy. The AK5 segment provides a transaction-level accept/reject/partially-accepted verdict. Critically, segments within the acknowledgment are **conditionally mandatory**: AK5 is mandatory only if AK2 is present; AK3/AK4 appear only when errors exist. This creates a **sparse error report** -- only violations are enumerated, not confirmations.

**Rego implementation opportunity:** Both SoFA and SoFREP already use a `deny` set pattern that is naturally sparse (only violations). However, they lack the **hierarchical error taxonomy** of X12. Current errors are flat: `{"msg", "severity", "field", "rule"}`. The X12 pattern suggests adding a `"layer"` or `"level"` field to each denial:

```json
{
  "msg": "...",
  "severity": "error",
  "field": "fund_balances",
  "rule": "fund_reconciliation",
  "layer": "mathematical_integrity",
  "error_code": "SoFA-0501"
}
```

This enables consumers to filter by validation layer (structural -> type/enum -> cross-field -> operational intelligence), matching X12's four-level hierarchy. It also enables stable error codes for automated processing, audit trails, and trend analysis across reporting periods.

**What SoFA/SoFREP are missing:** Denial messages are human-readable strings with no stable error codes. Automated consumers cannot reliably parse or categorize errors. Adding a layer taxonomy and stable codes would make the validation output machine-actionable, matching EDI industry practice.

---

## Summary of Recommendations

| # | Pattern | Source Industry | Applicable To | Confidence | Priority |
|---|---------|----------------|---------------|------------|----------|
| 1 | Declarative algebraic invariants in data.json | XBRL (financial reporting) | SoFA | High | High -- reduces rule sprawl |
| 2 | Cross-schedule reconciliation (summary vs. detail) | CCAR/Fed banking | SoFA, SoFREP | High | Medium -- requires schema evolution |
| 3 | Cross-report/multi-document validation | Solvency II/EIOPA insurance | SoFA + SoFREP together | Medium | Low -- architectural change |
| 4 | Severity-gated conditional mandatory fields | Aviation PIREP/METAR | SoFREP (primary), SoFA | High | High -- immediate gap |
| 5 | Cross-field qualitative consistency (contradictory signals) | AHRQ patient safety | SoFREP | Medium | Medium -- reduces false confidence |
| 6 | Hierarchical error taxonomy with stable codes | EDI X12 997 | Both | High | High -- enables machine consumption |

---

## Sources

- [XBRL Formula Rules Tutorial](https://www.xbrl.org/guidance/xbrl-formula-rules-tutorial/)
- [XBRL Calculation Linkbase](https://www.openriskmanual.org/wiki/XBRL_Calculation_Linkbase)
- [Implementing Business Validation Rules (XBRL)](https://www.xbrl.org/guidance/implementingrules/)
- [Approved Validation Rules (XBRL US)](https://xbrl.us/home/priorities/data-quality/rules-guidance/)
- [FR Y-14A Reporting Forms (Federal Reserve)](https://www.federalreserve.gov/apps/reportingforms/Report/Index/FR_Y-14A)
- [Automated Validation Frameworks for CCAR Reporting Pipelines](https://www.researchgate.net/publication/398420157_AUTOMATED_VALIDATION_FRAMEWORKS_FOR_CCAR_REPORTING_PIPELINES_FRY-14MQ)
- [EIOPA Supervisory Reporting DPM and XBRL](https://www.eiopa.europa.eu/tools-and-data/supervisory-reporting-dpm-and-xbrl_en)
- [Solvency II QRTs EIOPA Taxonomy Updates (Milliman)](https://www.milliman.com/en/insight/solvency-ii-qrts-eiopa-taxonomy-updates)
- [PIREP Submission Information (Aviation Weather)](https://aviationweather.gov/help/pirep/)
- [FAA Handbook Chapter 3](https://www.faasafety.gov/files/events/SO/SO15/2024/SO15129448/FAA-H-8083-28Chpt3.pdf)
- [FMH-12 Federal Coordinator for Meteorological Services](https://www.icams-portal.gov/resources/ofcm/fmh/FMH12/fmh12.pdf)
- [About AHRQ Common Formats](https://pso.ahrq.gov/common-formats/about)
- [Common Formats Overview (PSOPPC)](https://www.psoppc.org/psoppc_web/publicpages/commonFormatsOverview)
- [Reliability of AHRQ Common Format Harm Scales](https://pubmed.ncbi.nlm.nih.gov/24080718/)
- [X12 997 Acknowledgments and Error Codes (Microsoft)](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-enterprise-integration-x12-997-acknowledgment)
- [X12 997 Functional Acknowledgment (Stedi)](https://www.stedi.com/edi/x12/transaction-set/997)
- [X12 997 Error Codes (EdiFabric)](https://support.edifabric.com/hc/en-us/articles/360000380131-X12-997-Acknowledgment-Error-Codes)
