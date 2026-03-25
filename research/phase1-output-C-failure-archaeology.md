# Research Output C: Failure Archaeology

- **Agent:** XD-3
- **Date:** 2026-03-25
- **Scope:** Real-world incidents, CVEs, and post-mortems where policy validation gaps caused damage
- **Word count:** ~1900

---

## 1. OPA/Rego CVEs and Security Advisories

### Finding 1.1: Rego Code Injection via HTTP Path (CVE-2025-46569)

OPA versions prior to 1.4.0 allowed attackers to inject Rego policy code through crafted HTTP Data API request paths. OPA constructs a Rego query reference (e.g., `data.path.to.resource`) from the HTTP request path (`/v1/data/path/to/resource`). Malicious path elements were misinterpreted as executable Rego code, enabling oracle attacks (making queries succeed or fail at will) and denial-of-service via computationally expensive injected expressions.

- **Source:** [Styra CVE-2025-46569 Advisory](https://www.styra.com/blog/cve-2025-46569-opa-rest-api-path-injection-vulnerability/), [GitHub Advisory GHSA-6m8w-jc87-6cr7](https://github.com/open-policy-agent/opa/security/advisories/GHSA-6m8w-jc87-6cr7)
- **Confidence:** HIGH
- **So what for Rego policy design:** If SoFA/SoFREP policies are ever evaluated via OPA's REST API with user-controlled path segments, an attacker could force `valid` to return `true` on an invalid report. Pin OPA >= 1.4.0 and never expose Data API paths to untrusted input.

### Finding 1.2: WithUnsafeBuiltins Bypass via `with` Keyword (CVE-2022-36085)

The `with` keyword (introduced in OPA v0.40.0) could mock unsafe built-in functions, bypassing the `WithUnsafeBuiltins` compiler protection. A policy could replace `is_object` with `http.send` at evaluation time, executing network calls that were supposed to be blocked. The fix arrived in OPA v0.43.1.

- **Source:** [GitHub Advisory GHSA-f524-rf33-2jjr](https://github.com/open-policy-agent/opa/security/advisories/GHSA-f524-rf33-2jjr), [Styra CVE-2022-36085](https://www.styra.com/blog/cve-2022-36085-opa-and-styra-das/)
- **Confidence:** HIGH
- **So what for Rego policy design:** If policies use `with` for testing mocks (which SoFA/SoFREP test files may do), ensure OPA >= 0.43.1. More importantly, use the `capabilities` feature instead of `WithUnsafeBuiltins` to restrict available built-ins.

### Finding 1.3: SMB Credential Leakage via Bundle Path (CVE-2024-8260)

All OPA for Windows versions before v0.68.0 accepted UNC paths where Rego file or bundle paths were expected. An attacker who controlled file-path arguments could force OPA to authenticate against a malicious SMB server, leaking NTLM credentials. The `loader.go` package performed no path sanitization.

- **Source:** [Tenable CVE-2024-8260](https://www.tenable.com/blog/cve-2024-8260-smb-force-authentication-vulnerability-in-opa-could-lead-to-credential-leakage)
- **Confidence:** HIGH
- **So what for Rego policy design:** Bundle loading paths for `data.schema` and `data.thresholds` must be validated. Never accept user-supplied bundle paths. This is an infrastructure concern, but our CI/CD bundle-loading scripts should hardcode paths.

---

## 2. Policy Bypass Patterns

### Finding 2.1: Gatekeeper k8sallowedrepos Trailing-Slash Bypass

Aqua Security demonstrated that the `k8sallowedrepos` Gatekeeper policy could be bypassed by omitting trailing slashes in allowed registry prefixes. The policy used `strings.any_prefix_match(container.image, input.parameters.repos)` -- without a trailing slash on `docker.io/myorg`, an attacker could pull from `docker.io/myorg-evil` and pass validation.

- **Source:** [Aqua Security: OPA Gatekeeper Bypass](https://www.aquasec.com/blog/risks-misconfigured-kubernetes-policy-engines-opa-gatekeeper/)
- **Confidence:** HIGH
- **So what for Rego policy design:** String prefix matching is dangerous for category and enum validation. Our SoFA policy uses set membership (`not item.category in income_cats`) which is safe. However, any future regex-based validation (e.g., `regex.match(schema.date_pattern, ...)`) must be anchored with `^...$` to prevent partial-match bypasses. **Current status: `date_pattern` and `currency_pattern` in `data.schema` need audit for anchoring.**

### Finding 2.2: Type Confusion -- String vs. Number Comparison

In Rego, `"a" > 7` evaluates to `true` because strings sort after numbers in Rego's type ordering. A policy checking `input.value > threshold` where `threshold` is numeric will pass if `input.value` is a string, because any string is "greater than" any number.

- **Source:** [OPA Discussion #50: Comparing String and Number](https://github.com/orgs/open-policy-agent/discussions/50)
- **Confidence:** HIGH
- **So what for Rego policy design:** Our SoFA policy uses `is_number(item.amount)` guards before arithmetic (lines 103-106 of `sofa/standard/sofa.rego`), which is correct. But SoFREP's `_in_range(v, lo, hi)` helper (line 111-114 of `sofrep/standard/sofrep.rego`) does NOT guard against string input for `likelihood`. A string `"5"` would bypass the range check entirely -- the comparison would succeed for wrong reasons. **Recommendation 5 addresses this gap.**

### Finding 2.3: `undefined` vs. `false` -- The Silent Pass

OPA rules that are `undefined` (no matching conditions) are NOT the same as `false`. A missing `default` keyword means the rule simply produces no value, which in many integration contexts is treated as "no objection" rather than "denied." Gatekeeper's empty matcher (undefined match field) is "inclusive" -- it matches everything.

- **Source:** [OPA FAQ](https://www.openpolicyagent.org/docs/faq), [Aqua Security Gatekeeper analysis](https://www.aquasec.com/blog/risks-misconfigured-kubernetes-policy-engines-opa-gatekeeper/)
- **Confidence:** HIGH
- **So what for Rego policy design:** SoFA has `default valid := false` (line 238), which is correct. SoFREP does NOT use `default valid` -- it uses `valid := count(errors) == 0` (line 321). If `errors` is undefined (e.g., because `deny` produced no results due to missing `data.schema`), `count(errors)` would fail or return 0, making `valid` true. **This is a critical gap -- Recommendation 3.**

---

## 3. Financial Reporting Fraud -- Validation Gaps

### Finding 3.1: Wirecard -- All Five Lines of Defence Failed

Wirecard fabricated EUR 1.9 billion in cash balances across third-party partner accounts in Asia. All five control lines failed: internal controls, supervisory board, external audit (EY), financial reporting oversight (FREP/DPR), and market supervisor (BaFin). AI-based anomaly detection (Transparently.AI) retroactively gave Wirecard the worst possible risk scores across asset quality, growth signals, and smoothing activity -- patterns that existed in the data for years.

- **Source:** [European Parliament Study IPOL_STU(2020)651383](https://www.europarl.europa.eu/RegData/etudes/STUD/2020/651383/IPOL_STU(2020)651383_EN.pdf), [Transparently.AI Wirecard Case Study](https://www.transparently.ai/blog/how-the-wirecard-scandal-happened)
- **Confidence:** HIGH
- **So what for Rego policy design:** Wirecard's fraud succeeded because no validation checked field *relationships* -- revenue growth vs. cash flow, reported balances vs. third-party confirmations, expense ratios vs. industry norms. Our SoFA variance analysis (rule 9, lines 170-178) checks year-over-year changes but requires explanations only as free text. **Recommendation 7: Add cross-field ratio checks and require structured variance explanations with verifiable references.**

### Finding 3.2: Enron -- SPE Consolidation Rules Ignored

Enron used Special Purpose Entities (SPEs) to move debt off-balance-sheet. Automated controls should have flagged that related-party transactions violated consolidation thresholds. The core gap: no validation enforced that transactions between related entities were eliminated in consolidated reporting.

- **Source:** [PlanetCompliance: Enron Compliance Failures](https://www.planetcompliance.com/regulatory-compliance/enron-compliance-failures/)
- **Confidence:** MEDIUM
- **So what for Rego policy design:** SoFA's transfer netting rule (rule 8, lines 159-164) catches inter-fund transfers that don't net to zero, which is the charity-domain analog. This defense exists. However, there is no rule validating that fund_balances entries reference only declared fund_types. **Recommendation 8.**

---

## 4. Operational Reporting Failures

### Finding 4.1: Boeing 737 MAX MCAS -- Single-Sensor Validation

MCAS relied on a single Angle of Attack (AoA) sensor. When the sensor transmitted electrically valid but factually incorrect data, MCAS activated repeatedly. The data was "valid" in format (correct voltage, correct signal protocol) but wrong in substance. No cross-validation against the second AoA sensor was performed.

- **Source:** [FAA 737 RTS Summary](https://www.faa.gov/sites/faa.gov/files/2022-08/737_RTS_Summary.pdf), [Boeing 737 MAX Groundings - Wikipedia](https://en.wikipedia.org/wiki/Boeing_737_MAX_groundings)
- **Confidence:** HIGH
- **So what for Rego policy design:** This is the "structurally valid but substantively wrong" problem. Our policies validate format and internal consistency but not external plausibility. A SoFA report claiming GBP 100M income for a small charity would pass all current rules. **Recommendation 9: Add plausibility bounds in `data.thresholds` for income/expenditure ranges.**

### Finding 4.2: Friendly Fire from GPS Battery Reset (Afghanistan, 2001)

A US Air Force Combat Controller called in an airstrike, then changed his GPS batteries. The unit reset to its own coordinates. The coordinates transmitted to the aircraft were structurally valid (correct format, correct datum) but pointed at the caller's position. The bomb killed three US soldiers and five Afghan allies.

- **Source:** [Texas Monthly: Fatal Error](https://www.texasmonthly.com/news-politics/fatal-error-inspired-plan-to-reduce-friendly-fire/)
- **Confidence:** HIGH
- **So what for Rego policy design:** Structurally valid data that contradicts other fields in the same report. SoFREP's conflict detection (rule 13, lines 166-170) catches items appearing in both `working_well` and `at_risk`, but does not catch semantic contradictions within fields (e.g., a "needed" item with priority "P0" and status "resolved"). **Recommendation 10.**

---

## 5. Data Document Poisoning

### Finding 5.1: External Data Manipulation Without Policy Changes

Both SoFA and SoFREP load validation parameters from `data.schema` and `data.thresholds`. If an attacker modifies these data documents (e.g., setting `reconciliation_tolerance` to `999999999` or emptying `required_fields`), all validation is effectively disabled without touching any `.rego` file. OPA bundles that include data documents are the attack surface.

- **Source:** Architectural analysis of current SoFA/SoFREP policies, informed by [CNCF OPA Best Practices (2025)](https://www.cncf.io/blog/2025/03/18/open-policy-agent-best-practices-for-a-secure-deployment/)
- **Confidence:** HIGH
- **So what for Rego policy design:** **Recommendation 6: Add meta-validation rules that assert `data.schema` and `data.thresholds` themselves are valid** -- e.g., `count(schema.required_fields) > 0`, `tolerance > 0`, `tolerance < 100`. A poisoned data document should trigger deny rules, not silently disable them.

---

## Numbered Recommendations

| # | Title | Failure Pattern | Rego Defense | Current Coverage | Priority |
|---|-------|----------------|-------------|-----------------|----------|
| 1 | Pin OPA >= 1.4.0 | CVE-2025-46569 path injection can force `valid = true` | Version constraint in CI, not Rego | NOT COVERED | High |
| 2 | Use `capabilities` not `WithUnsafeBuiltins` | CVE-2022-36085 `with` keyword mock bypass | OPA configuration, not Rego | NOT COVERED | Medium |
| 3 | Add `default valid := false` to SoFREP | `undefined` vs. `false` silent pass when `data.schema` is missing | `default valid := false` | SoFA: covered. SoFREP: **NOT COVERED** | Critical |
| 4 | Anchor all regex patterns with `^...$` | Trailing-slash / partial-match prefix bypass | Audit `data.schema.date_pattern`, `currency_pattern` | NEEDS AUDIT | High |
| 5 | Add `is_number` guard to SoFREP `_in_range` | Type confusion: string > number is always true in Rego | `_in_range(v, lo, hi) if { is_number(v); ... }` | **NOT COVERED** | High |
| 6 | Meta-validate `data.schema` and `data.thresholds` | Data document poisoning disables all rules silently | Deny rules asserting data doc invariants (non-empty fields, bounded tolerances) | **NOT COVERED** | Critical |
| 7 | Add cross-field ratio checks to SoFA | Wirecard-style fabrication passes per-field validation | Ratio rules: income/expenditure vs. prior period, expense-to-income bounds | **NOT COVERED** | High |
| 8 | Validate fund_balances keys against declared fund_types | Undeclared fund entries bypass fund-type validation | `deny if { some ft, _ in input.fund_balances; not ft in fund_types }` | **NOT COVERED** | Medium |
| 9 | Add plausibility bounds in thresholds | Boeing MCAS: valid format, implausible value | `deny if { computed_income > thresholds.max_plausible_income }` | **NOT COVERED** | Medium |
| 10 | Add semantic contradiction checks to SoFREP | GPS reset / friendly fire: valid format, contradictory content | Deny needed items with resolved status, at_risk items with zero impact, etc. | **NOT COVERED** | Medium |

---

## Summary of Gaps

Of 10 recommendations, the current SoFA/SoFREP standard policies cover **0 fully** and **1 partially** (SoFA has `default valid := false` but SoFREP does not). The two critical gaps are:

1. **Recommendation 3** -- SoFREP lacks `default valid := false`, meaning a missing or corrupted `data.schema` could cause the entire policy to silently pass.
2. **Recommendation 6** -- Neither policy validates its own data documents, making `data.schema`/`data.thresholds` poisoning a single point of failure that disables all validation without modifying any `.rego` file.

Sources:
- [Styra CVE-2025-46569](https://www.styra.com/blog/cve-2025-46569-opa-rest-api-path-injection-vulnerability/)
- [GitHub GHSA-f524-rf33-2jjr (CVE-2022-36085)](https://github.com/open-policy-agent/opa/security/advisories/GHSA-f524-rf33-2jjr)
- [Tenable CVE-2024-8260](https://www.tenable.com/blog/cve-2024-8260-smb-force-authentication-vulnerability-in-opa-could-lead-to-credential-leakage)
- [Aqua Security Gatekeeper Bypass](https://www.aquasec.com/blog/risks-misconfigured-kubernetes-policy-engines-opa-gatekeeper/)
- [OPA Discussion #50: Type Confusion](https://github.com/orgs/open-policy-agent/discussions/50)
- [European Parliament Wirecard Study](https://www.europarl.europa.eu/RegData/etudes/STUD/2020/651383/IPOL_STU(2020)651383_EN.pdf)
- [Transparently.AI Wirecard Analysis](https://www.transparently.ai/blog/how-the-wirecard-scandal-happened)
- [PlanetCompliance: Enron Failures](https://www.planetcompliance.com/regulatory-compliance/enron-compliance-failures/)
- [FAA 737 MAX Summary](https://www.faa.gov/sites/faa.gov/files/2022-08/737_RTS_Summary.pdf)
- [Texas Monthly: Friendly Fire](https://www.texasmonthly.com/news-politics/fatal-error-inspired-plan-to-reduce-friendly-fire/)
- [CNCF OPA Best Practices 2025](https://www.cncf.io/blog/2025/03/18/open-policy-agent-best-practices-for-a-secure-deployment/)
- [OPA FAQ: undefined vs false](https://www.openpolicyagent.org/docs/faq)
