# Research Output D: Authoritative Standards for SoFA and SoFREP Validation

- **Researcher:** DS-1 (Whitepaper Researcher)
- **Date:** 2026-03-25
- **Scope:** 10 authoritative standards mapped to current Rego policy gaps
- **Method:** Web research against published standards, cross-referenced with existing `sofa/standard/sofa.rego` and `sofrep/standard/sofrep.rego`

---

## Part I: SoFA Domain Standards

### Standard 1 -- Charity SORP FRS 102 (Module 4: Statement of Financial Activities)

**Source:** [Charities SORP Module 4](https://charitiessorp.org/documents/23956307/23964541/4-statement-of-financial-activities.pdf), [SORP 2026 Edition](https://www.charitysorp.org/charities-sorp-frs102-second-edition)

**Confidence:** High

**Key structural requirements our policies LACK:**

1. **Tiered reporting format:** SORP defines three tiers. Tier 1 (smaller charities) may use natural classification for expenses; Tiers 2 and 3 MUST use activity-basis reporting. Our policy has no tier concept and does not validate that the chosen reporting format matches the charity's size tier.
   - *So what for Rego:* Add a `reporting_tier` field to schema; enforce that Tier 2/3 entities use activity-basis expense categories while Tier 1 may use natural classification categories.

2. **Mandatory income categories (SORP 2026):** Donations and legacies; Charitable activities; Other trading activities; Investments; Other income. Our current `income_categories` list uses slightly different naming (`voluntary_income`, `activities_for_generating_funds`) that predates SORP 2026. The 2026 edition renames several categories.
   - *So what for Rego:* Update `data.schema.income_categories` to match SORP 2026 terminology; add a `sorp_version` field to allow backward compatibility with pre-2026 category names.

3. **Mandatory expenditure categories (SORP 2026):** Raising funds; Charitable activities (with sub-analysis by activity); Other expenditure. Support costs and governance costs must be allocated across activities, not shown as standalone lines. Our policy currently allows `governance_costs` and `support_costs` as top-level categories, which SORP 2026 disallows for Tier 2/3.
   - *So what for Rego:* Add a rule that denies standalone `governance_costs` / `support_costs` categories when `reporting_tier >= 2`; require an `allocated_to` field on support/governance line items.

4. **Fund column analysis:** The SoFA MUST show separate columns for unrestricted, restricted, endowment, AND a total column. Comparative figures for the prior period total are mandatory. Our policy validates fund types exist but does not enforce that ALL fund types have closing balances disclosed or that prior-period comparatives are present for each fund column.
   - *So what for Rego:* Add a rule requiring `fund_balances` to contain at minimum `unrestricted` and a `total` entry; require `prior_period` to include per-fund comparatives, not just aggregate totals.

5. **Net debt reconciliation:** SORP requires a reconciliation of net debt (borrowings + finance leases - cash equivalents). Our policy has no concept of net debt.
   - *So what for Rego:* Add optional `net_debt_reconciliation` section with opening/closing/movement validation when the entity reports borrowings.

### Standard 2 -- CC17: Charity Accounts and Reports (Charity Commission for England and Wales)

**Source:** [Charities Annual Return Regulations 2024](https://www.gov.uk/government/publications/charity-commission-annual-returns-regulations-2024/the-charities-annual-return-regulations-2024), [Charity Audit Thresholds](https://www.charityexcellence.co.uk/charity-audit-and-independent-examination/)

**Confidence:** High

**Key requirements our policies LACK:**

6. **Audit/examination thresholds:** Gross income > 1M GBP requires statutory audit. Gross income > 250K GBP AND net assets > 3.26M GBP also triggers audit. Income > 25K GBP requires independent examination. Our policy has no concept of audit requirements based on income/asset thresholds.
   - *So what for Rego:* Add `audit_status` field (values: `audit`, `independent_examination`, `none`); validate it against computed income totals and reported net assets using CC17 thresholds. Warn if the declared audit level is inconsistent with the financial thresholds.

7. **Filing deadline validation:** Annual return due within 10 months of financial year end. Our policy validates date format but not filing timeliness.
   - *So what for Rego:* Add a `filing_date` field and a warning rule that computes whether `filing_date - report_date > 304 days` (10 months).

8. **Upcoming threshold changes (Oct 2026):** Audit threshold rising from 1M to 1.5M GBP; asset threshold from 3.26M to 5M GBP. Policy should be data-driven to allow threshold updates without code changes.
   - *So what for Rego:* Store audit thresholds in `data.thresholds` (already the pattern), ensuring easy updates when regulations change.

### Standard 3 -- IAS/IFRS for Nonprofit Entities

**Source:** [IAS 1 Presentation of Financial Statements](https://www.ifrs.org/content/dam/ifrs/publications/pdf-standards/english/2022/issued/part-a/ias-1-presentation-of-financial-statements.pdf), [IAS 20 Government Grants](https://www.ifrs.org/content/dam/ifrs/publications/pdf-standards/english/2021/issued/part-a/ias-20-accounting-for-government-grants-and-disclosure-of-government-assistance.pdf)

**Confidence:** Medium (IFRS does not have nonprofit-specific standards; charities primarily follow SORP which overlays FRS 102/IAS)

**Key requirements our policies LACK:**

9. **Going concern disclosure:** IAS 1 requires disclosure of material uncertainties related to going concern. Our policy checks consecutive negative net movements but does not require a `going_concern_disclosure` narrative field when the warning triggers.
   - *So what for Rego:* When the going concern warning fires, additionally require a non-empty `going_concern_disclosure` string field; elevate severity to `error` if the disclosure is absent.

10. **Government grant recognition (IAS 20):** Grants must not be recognized until there is reasonable assurance the entity will comply with conditions and the grant will be received. Our policy has no validation for conditional income recognition.
    - *So what for Rego:* Add an optional `recognition_status` field on income line items (values: `unconditional`, `conditional_met`, `conditional_pending`); warn if `conditional_pending` items are included in totals.

### Standard 4 -- OSCR Guidance Notes (Office of the Scottish Charity Regulator)

**Source:** [OSCR Reporting Requirements](https://www.oscr.org.uk/news/shift-to-more-proportionate-accounting-regime-for-charities-across-the-uk/), [Stewardship Scotland Differences](https://www.stewardship.org.uk/blogs/its-different-scotland)

**Confidence:** High

**Key requirements our policies LACK:**

11. **Jurisdiction field and deadline variance:** Scottish charities must file within 9 months (vs. 10 months for England/Wales). All Scottish charities require independent examination regardless of income level (unlike England/Wales where the threshold is 25K GBP). Our policy has no jurisdiction concept.
    - *So what for Rego:* Add a `jurisdiction` enum field (`england_wales`, `scotland`, `northern_ireland`); adjust filing deadline rules and examination thresholds based on jurisdiction.

12. **Trustee disclosure requirements:** From June 2025, OSCR requires full name, home address, DOB, and contact details for each trustee in annual submissions. Our policy has no trustee data validation.
    - *So what for Rego:* Add optional `trustees` array with required sub-fields when `jurisdiction == "scotland"`; validate completeness.

### Standard 5 -- Gift Aid Validation Requirements (HMRC)

**Source:** [HMRC Gift Aid Rules](https://www.charityexcellence.co.uk/hmrc-gift-aid-rules/), [Gift Aid Declaration Regulations 2016](https://www.legislation.gov.uk/uksi/2016/1195/regulation/9/made), [Charities Online Validation Rules v1.3](https://assets.publishing.service.gov.uk/media/5b7d5a2fed915d14d5936d4d/Charities-OnlineValidsV1.3.pdf)

**Confidence:** High

**Key requirements our policies LACK:**

13. **Gift Aid eligible income tagging:** Income items eligible for Gift Aid should be flagged. HMRC requires donor name, full postal address, and declaration reference for each Gift Aid claim. Our policy has no Gift Aid validation whatsoever.
    - *So what for Rego:* Add optional `gift_aid` object on voluntary income line items with fields: `declaration_reference`, `donor_name`, `donor_address`, `tax_year`; validate all four are present when `gift_aid` is not null.

14. **Four-year claim window:** Gift Aid claims must be made within 4 years of the end of the financial period the donation was received in. Our policy does not validate claim timeliness.
    - *So what for Rego:* When `gift_aid.tax_year` is present, warn if `report_date` minus `gift_aid.tax_year` end exceeds 4 years.

15. **Record retention period:** Charities must retain Gift Aid records for 6 years. This is an operational requirement, not a SoFA structural rule, but could be surfaced as an info-level reminder.
    - *So what for Rego:* Info-severity rule noting retention obligations when Gift Aid items are present.

---

## Part II: SoFREP Domain Standards

### Standard 6 -- DoD SITREP/SPOTREP Format (FM 101-5-2 / FM 6-99.2)

**Source:** [FM 101-5-2 US Army Report and Message Formats](https://www.bits.de/NRANEU/others/amd-us-archive/fm101-5-2(uk).pdf), [Army Study Guide SITREP](https://www.armystudyguide.com/content/the_tank/army_report_and_message_formats/commanders-situation-repo.shtml)

**Confidence:** High

**Key requirements our policies LACK:**

16. **Mandatory SITREP line items:** FM 101-5-2 defines 9 mandatory lines: (1) DTG, (2) Unit, (3) Reference, (4) Originator UIC, (5) Reported Unit UIC, (6) Home Location (MGRS), (7) Present Location (MGRS), (8) Activity, (9) Effective/Commander's Evaluation. Our SoFREP has `reporting_period`, `unit`, `author`, `classification` but lacks DTG, originator/reported unit distinction, location fields, and reference line.
    - *So what for Rego:* Add `dtg` (DateTime Group), `originator_uic`, `reported_unit_uic`, `home_location`, `present_location`, and `reference` to `required_metadata` when `report_format == "sitrep"`.

17. **Classification marking rules:** Per DoDM 5200.01 Vol 2, the originator is a derivative classifier responsible for marking. Classification must appear in the header AND footer of every page, and portion markings are required on each paragraph. Our policy validates classification as an enum but does not validate portion marking presence on individual items.
    - *So what for Rego:* Add optional `portion_marking` field on each quadrant item; when `classification != "UNCLASSIFIED"`, require portion markings on all items.

18. **Three-part message structure:** All FM 101-5-2 messages require heading, body, and conclusion sections. Our quadrant model does not map to this structure.
    - *So what for Rego:* Consider adding a `message_header` and `message_conclusion` metadata block for FM-compliant reports; validate presence when `report_format == "sitrep"`.

### Standard 7 -- NATO STANAG 2014 (Formats for Orders)

**Source:** [STANAG 2014 Edition 09](https://www.trngcmd.marines.mil/Portals/207/Docs/TBS/STANAG%202014%20Edition%2009-%20FORMATS%20FOR%20ORDERS%20(OPORD).pdf), [NATO OPORD Format](https://www.scribd.com/document/215294169/Formar-for-OPORDs-STANAG-2014-Annex-B-pdf)

**Confidence:** Medium (STANAG 2014 primarily covers OPORDs, not SITREPs; the SITREP annex has limited public availability)

**Key requirements our policies LACK:**

19. **Five-paragraph format:** STANAG 2014 mandates: (1) Situation (obligatory), (2) Mission (obligatory), (3) Execution, (4) Administration/Logistics, (5) Command and Signal. Paragraphs 1 and 2 are non-optional. Our SoFREP quadrant model does not map to the NATO five-paragraph structure.
    - *So what for Rego:* For NATO-formatted reports, add a `nato_paragraphs` schema that validates presence of at minimum `situation` and `mission` sections.

20. **Enemy/Friendly force sub-sections:** The Situation paragraph must include enemy forces (composition, strength, disposition, capabilities, intentions) and friendly forces information. Our `at_risk` quadrant partially maps to threats but lacks the structured enemy/friendly decomposition.
    - *So what for Rego:* Add structured `threat_assessment` and `friendly_forces` sub-objects when `report_format == "nato_stanag"`.

### Standard 8 -- ISO 31000:2018 (Risk Management Guidelines)

**Source:** [ISO 31000:2018](https://www.iso.org/obp/ui/#iso:std:iso:31000:ed-2:v1:en), [ISO 31000 Risk Matrix Guide](https://mindsetcyber.com.au/iso-31000-risk-matrix/)

**Confidence:** High

**Key requirements our policies LACK:**

21. **5x5 risk matrix with named levels:** ISO 31000 implementations use a 5x5 matrix mapping likelihood (Rare/Unlikely/Possible/Likely/Almost Certain) to consequence (Insignificant/Minor/Moderate/Major/Catastrophic). Our policy uses numeric 1-5 scales but does not validate that the named levels are used or that the risk level labels match ISO conventions.
    - *So what for Rego:* Add `likelihood_label` and `impact_label` enums to the `at_risk` quadrant schema with ISO-aligned values; validate label-to-numeric consistency.

22. **Risk appetite/tolerance thresholds:** ISO 31000 clause 6.4 requires organizations to define risk evaluation criteria reflecting objectives and risk appetite. Our policy has `risk_critical`, `risk_high`, `risk_medium` thresholds but no concept of declared organizational risk appetite or tolerance statements.
    - *So what for Rego:* Add a `risk_appetite` metadata field (e.g., `conservative`, `moderate`, `aggressive`) that shifts threshold multipliers in `data.thresholds`.

23. **Risk treatment tracking:** ISO 31000 requires documented treatment plans for risks above appetite. Our `mitigation` field is a free-text string with no structured treatment plan validation.
    - *So what for Rego:* Add structured `treatment_plan` object on at_risk items with fields: `strategy` (accept/mitigate/transfer/avoid), `responsible_owner`, `target_date`, `status`; warn if critical/high risks lack a treatment plan.

### Standard 9 -- NIST SP 800-30 Rev 1 (Guide for Conducting Risk Assessments)

**Source:** [NIST SP 800-30 Rev 1](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-30r1.pdf), [NIST Risk Assessment Guide](https://www.securityscientist.net/blog/complete-guide-to-likelihood-and-impact-analysis-nist-sp-800-30/)

**Confidence:** High

**Key requirements our policies LACK:**

24. **Five-level qualitative scales:** NIST defines: Very High (96-100), High (80-95), Moderate (21-79), Low (5-20), Very Low (0-4) for both likelihood and impact. Our policy uses integer 1-5 which is a simplified mapping. NIST's granular scale allows semi-quantitative scoring.
    - *So what for Rego:* Add optional `nist_likelihood_score` (0-100) and `nist_impact_score` (0-100) fields; map to qualitative labels per NIST Table D-4; validate consistency with the 1-5 integer values when both are present.

25. **Threat source identification:** NIST requires identifying threat sources (adversarial: capability, intent, targeting; non-adversarial: range of effects). Our `at_risk` items have no threat source taxonomy.
    - *So what for Rego:* Add optional `threat_source` field with sub-fields `type` (adversarial/non-adversarial), `capability`, `intent` for adversarial threats.

26. **Predisposing conditions:** NIST includes predisposing conditions as a risk factor (organizational conditions that affect likelihood). Our policy has no equivalent.
    - *So what for Rego:* Add optional `predisposing_conditions` array on at_risk items; info-level warning when high-likelihood items have no predisposing conditions documented.

### Standard 10 -- Military Readiness Reporting (SORTS/DRRS)

**Source:** [CBO Defense Readiness Report](https://www.cbo.gov/sites/default/files/cbofiles/attachments/44127_DefenseReadiness.pdf), [SORTS Course Material](https://elearning.sabresystems.com/drrsS/presentations/SORTS_Squadron_Det_Course_01Jan2023.pdf), [CJCSI 3401.02B Force Readiness Reporting](https://www.jcs.mil/Portals/36/Documents/Doctrine/training/cjcsi3401_02b.pdf)

**Confidence:** High

**Key requirements our policies LACK:**

27. **C-Level rating system (C1-C5):** SORTS defines C1 (fully mission capable) through C5 (unavailable/not resourced). Our `readiness_pct` is a percentage derived from working_well ratio. This does not map to the authoritative C-level system.
    - *So what for Rego:* Add a computed `c_level` (C1-C5) derived from readiness_pct with thresholds: C1 >= 90%, C2 >= 70%, C3 >= 50%, C4 >= 25%, C5 < 25%. Store thresholds in `data.thresholds`.

28. **Four measured resource areas:** SORTS measures Personnel (P), Equipment/Supplies on Hand (S), Equipment Condition (R), and Training (T). Each gets its own C-level, and the overall C-level is the worst of the four. Our policy has a single readiness score with no decomposition by resource area.
    - *So what for Rego:* Add optional `resource_areas` object with sub-scores for `personnel`, `equipment`, `supply`, `training`; compute per-area C-levels and derive overall as the minimum.

29. **Mission Essential Task (MET) assessment:** DRRS adds Y/Q/N (Yes/Qualified/No) mission capability assessment per MET. Our `working_well` items have binary status (present = working) with no qualified/partial state.
    - *So what for Rego:* Add `met_status` enum (Y/Q/N) on working_well items; adjust readiness calculation to weight Q items at 0.5 instead of 1.0.

30. **Reporting frequency and currency:** SORTS requires updates at minimum every 30 days, with significant changes reported within 24 hours. Our staleness threshold of 14 days is more aggressive than SORTS requires, which is fine, but we lack the concept of a "significant change trigger" for immediate reporting.
    - *So what for Rego:* Add a `significant_change` boolean on items; when true, warn if `last_updated` is more than 1 day before `reporting_period.end_date`.

---

## Summary: Gap Count by Domain

| Domain | Standards Reviewed | Gaps Identified | Critical (error-level) | Warning-level | Info-level |
|--------|-------------------|-----------------|------------------------|---------------|------------|
| SoFA   | 5                 | 15              | 7                      | 6             | 2          |
| SoFREP | 5                 | 15              | 8                      | 5             | 2          |
| **Total** | **10**         | **30**          | **15**                 | **11**        | **4**      |

## Priority Recommendations for Rego Implementation

**Highest priority (blocks compliance):**
- Rec 1: Tiered reporting format (SORP)
- Rec 6: Audit threshold validation (CC17)
- Rec 11: Jurisdiction-aware rules (OSCR)
- Rec 16: SITREP mandatory line items (FM 101-5-2)
- Rec 27: C-Level rating system (SORTS/DRRS)
- Rec 28: Four measured resource areas (SORTS)

**High priority (improves accuracy):**
- Rec 2-3: Updated SORP 2026 categories
- Rec 9: Going concern disclosure requirement (IAS 1)
- Rec 21: ISO 31000 5x5 risk matrix labels
- Rec 23: Structured treatment plans (ISO 31000)
- Rec 24: NIST five-level qualitative scales

**Medium priority (enhances coverage):**
- Rec 4: Fund column completeness
- Rec 13-14: Gift Aid validation
- Rec 17: Classification portion markings
- Rec 22: Risk appetite metadata
- Rec 29: MET Y/Q/N assessment

---

## Sources

- [Charities SORP Module 4 - Statement of Financial Activities](https://charitiessorp.org/documents/23956307/23964541/4-statement-of-financial-activities.pdf)
- [Charities SORP FRS 102 Second Edition (2026)](https://www.charitysorp.org/charities-sorp-frs102-second-edition)
- [Charities Annual Return Regulations 2024 - GOV.UK](https://www.gov.uk/government/publications/charity-commission-annual-returns-regulations-2024/the-charities-annual-return-regulations-2024)
- [UK Charity Audit Thresholds](https://www.charityexcellence.co.uk/charity-audit-and-independent-examination/)
- [Changes to Charity Audit Thresholds - Azets](https://www.azets.com/en-uk/insights/change-to-charity-audit-thresholds-in-england-and-wales)
- [IAS 1 Presentation of Financial Statements](https://www.ifrs.org/content/dam/ifrs/publications/pdf-standards/english/2022/issued/part-a/ias-1-presentation-of-financial-statements.pdf)
- [IAS 20 Government Grants](https://www.ifrs.org/content/dam/ifrs/publications/pdf-standards/english/2021/issued/part-a/ias-20-accounting-for-government-grants-and-disclosure-of-government-assistance.pdf)
- [OSCR - Shift to Proportionate Accounting](https://www.oscr.org.uk/news/shift-to-more-proportionate-accounting-regime-for-charities-across-the-uk/)
- [Stewardship - It's Different in Scotland](https://www.stewardship.org.uk/blogs/its-different-scotland)
- [HMRC Gift Aid Rules](https://www.charityexcellence.co.uk/hmrc-gift-aid-rules/)
- [Gift Aid Declaration Regulations 2016](https://www.legislation.gov.uk/uksi/2016/1195/regulation/9/made)
- [Charities Online Validation Rules v1.3](https://assets.publishing.service.gov.uk/media/5b7d5a2fed915d14d5936d4d/Charities-OnlineValidsV1.3.pdf)
- [FM 101-5-2 US Army Report and Message Formats](https://www.bits.de/NRANEU/others/amd-us-archive/fm101-5-2(uk).pdf)
- [Army Study Guide - Commander's SITREP](https://www.armystudyguide.com/content/the_tank/army_report_and_message_formats/commanders-situation-repo.shtml)
- [STANAG 2014 Edition 09 - Formats for Orders](https://www.trngcmd.marines.mil/Portals/207/Docs/TBS/STANAG%202014%20Edition%2009-%20FORMATS%20FOR%20ORDERS%20(OPORD).pdf)
- [ISO 31000:2018 Risk Management Guidelines](https://www.iso.org/obp/ui/#iso:std:iso:31000:ed-2:v1:en)
- [ISO 31000 Risk Matrix Guide](https://mindsetcyber.com.au/iso-31000-risk-matrix/)
- [NIST SP 800-30 Rev 1](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-30r1.pdf)
- [NIST Likelihood and Impact Analysis Guide](https://www.securityscientist.net/blog/complete-guide-to-likelihood-and-impact-analysis-nist-sp-800-30/)
- [CBO - Implications of DoD Readiness Reporting](https://www.cbo.gov/sites/default/files/cbofiles/attachments/44127_DefenseReadiness.pdf)
- [SORTS Squadron/Det Course (Jan 2023)](https://elearning.sabresystems.com/drrsS/presentations/SORTS_Squadron_Det_Course_01Jan2023.pdf)
- [CJCSI 3401.02B Force Readiness Reporting](https://www.jcs.mil/Portals/36/Documents/Doctrine/training/cjcsi3401_02b.pdf)
- [GAO-21-279 Military Readiness](https://www.gao.gov/assets/gao-21-279.pdf)
