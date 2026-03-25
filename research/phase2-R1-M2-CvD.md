# R1-M2: C (Failure Archaeology) vs D (Whitepaper Standards)

- **Judge:** Strategic Reasoner Agent
- **Date:** 2026-03-25
- **Match:** Round 1, Match 2

---

## Score Table

| Dimension | C | D |
|---|---|---|
| Novelty | 8 | 7 |
| Divergence | 7 | 5 |
| Evidence | 9 | 8 |
| Actionability | 9 | 7 |
| Cross-pollination | 8 | 7 |
| **TOTAL** | **41** | **34** |

---

## Winner: C by 7 points

Output C (Failure Archaeology) wins on the strength of its **immediately actionable critical fixes**, **primary-source CVE evidence**, and **high divergence** in the analogical reasoning (GPS friendly fire, Boeing MCAS).
The gap is not a rout — D contributes irreplaceable domain-authoritative standards content that C cannot generate.
The decisive margin comes from C's two critical one-session fixes (Rec 3, Rec 6) that block silent validation bypass, both of which are impossible to derive from standards documents alone.

---

## Top Insights from C

### C-1: Data Document Poisoning Disables All Rules Without Touching `.rego` Files

Both SoFA and SoFREP delegate their validation parameters to `data.schema` and `data.thresholds`.
An attacker who modifies those data documents (setting `reconciliation_tolerance` to `999999999`
or emptying `required_fields`) silently disables all validation with zero changes to policy code.
The fix is meta-validation deny rules that assert the data documents themselves are valid:
`count(schema.required_fields) > 0`, `tolerance > 0`, `tolerance < 100`.
This is the highest-priority single gap in the current architecture.

- **Source:** CNCF OPA Best Practices 2025, architectural analysis of current policies
- **Rego target:** New `deny` rules asserting invariants over `data.schema` and `data.thresholds`
- **Priority:** Critical

### C-2: `undefined` vs `false` — SoFREP's Silent Pass on Missing Schema

SoFREP uses `valid := count(errors) == 0` (line 321) with no `default valid := false`.
If `errors` is undefined because `data.schema` is absent or corrupted, `count(errors)`
either fails or returns 0 — making `valid` true.
SoFA has `default valid := false` (line 238) and is protected; SoFREP is not.
This is a one-line fix with critical security impact.

- **Source:** OPA official FAQ; Aqua Security Gatekeeper analysis
- **Rego target:** Add `default valid := false` to `sofrep/standard/sofrep.rego`
- **Priority:** Critical (one-line fix)

### C-3: "Structurally Valid, Substantively Wrong" — Analogy from Boeing MCAS and GPS Battery Reset

Boeing's MCAS accepted sensor readings that were electrically valid but physically incorrect.
A US GPS unit transmitted structurally correct coordinates that pointed at the wrong location after a battery reset.
Both map to a class of SoFA/SoFREP inputs that pass format checks but fail plausibility or semantic-contradiction checks.
C translates this into two concrete gaps: (a) SoFA needs plausibility bounds in `data.thresholds`
for income/expenditure ranges; (b) SoFREP needs semantic contradiction checks (a "needed" item
with status "resolved", an `at_risk` item with priority P0 and zero impact).

- **Source:** FAA 737 RTS Summary; Texas Monthly (GPS incident)
- **Rego target:** `deny` rules in SoFA for implausible income values; SoFREP contradiction rules on item state combinations
- **Priority:** Medium

---

## Top Insights from D

### D-1: SORTS C-Level Rating System — Authoritative Replacement for `readiness_pct`

SORTS (Status of Resources and Training System) defines C1 (fully mission capable, >=90%)
through C5 (<25%) with the critical rule that the overall C-level is the **worst** of four
resource area sub-scores: Personnel (P), Equipment on Hand (S), Equipment Condition (R), Training (T).
SoFREP's current `readiness_pct` is a homogeneous average with no resource decomposition.
A unit with 100% personnel but 20% equipment would show ~60% readiness (C3-ish) but should
report C4 under SORTS because the worst area governs.

- **Source:** CJCSI 3401.02B Force Readiness Reporting; SORTS Squadron/Det Course (Jan 2023)
- **Rego target:** Add `resource_areas` object with per-area C-level computation; derive overall as `min` of four; store thresholds in `data.thresholds`
- **Priority:** High (blocks SORTS compliance)

### D-2: CC17 Audit Threshold Validation — Enforceable Compliance Rule with Oct 2026 Change

UK Charity Commission requires: gross income >£1M → statutory audit; income >£250K AND assets >£3.26M → audit;
income >£25K → independent examination. These thresholds rise in October 2026 (£1M→£1.5M, £3.26M→£5M).
SoFA has no `audit_status` field and no rule comparing declared audit level against computed income totals.
Because D stores thresholds in `data.thresholds` (already the policy pattern), the Oct 2026 change
requires only a data document update — no Rego code change.

- **Source:** Charities Annual Return Regulations 2024 (gov.uk); Azets charity audit threshold changes
- **Rego target:** Add `audit_status` enum field; `warn` rule comparing declared status to computed income against CC17 thresholds in `data.thresholds`
- **Priority:** High

### D-3: ISO 31000 Structured Treatment Plans — Replace Free-Text `mitigation` Strings

ISO 31000 clause 6.4 requires documented treatment plans for risks above appetite.
SoFREP's current `mitigation` field is an unvalidated free-text string — an at-risk item
with critical risk score can satisfy the field with `"tbd"` or an empty string.
The fix is a structured `treatment_plan` object requiring `strategy`
(accept/mitigate/transfer/avoid), `responsible_owner`, `target_date`, `status`,
with a warn rule that fires when critical/high-scored items have no treatment plan present.

- **Source:** ISO 31000:2018 (ISO official OBP)
- **Rego target:** New structured sub-object on `at_risk` items; warn rule gated on risk score threshold
- **Priority:** Medium-High

---

## Cross-Pollination Opportunities

### XP-1: Data Poisoning Attacks the Very Thresholds D Defines

C (Finding 5.1) shows that `data.thresholds` can be modified to disable validation.
D (Standards 6, 10) provides the concrete threshold values that will now live in `data.thresholds`:
CC17 audit thresholds, SORTS C-level cutoffs, ISO 31000 risk appetite multipliers.
Combined insight: the meta-validation rules from C's Rec 6 must specifically bound these
domain-authoritative values. A poisoned threshold setting audit income to £999M or C1>=101%
is a targeted compliance bypass that neither output identified independently.

**Synthesized rule pattern:**
```rego
deny contains "data.thresholds misconfigured: audit_threshold_major out of plausible range" if {
    not data.thresholds.audit_threshold_major >= 500000
    not data.thresholds.audit_threshold_major <= 5000000
}
deny contains "data.thresholds misconfigured: c1_threshold impossible" if {
    data.thresholds.c1_threshold > 100
}
```

### XP-2: `undefined`-Pass Vulnerability Threatens Every D-Defined Warning Rule

C (Finding 2.3) shows that rules computed from `errors` sets are silently disabled when `data.schema` is absent.
D defines multiple new warning rules (going-concern disclosure, audit threshold warn, Gift Aid tagging warn)
that will all be computed from `errors` sets or analogous accumulators.
Combined: D's rules are structurally vulnerable to C's failure mode until SoFREP gets `default valid := false`
and C's meta-validation guards are in place.
The cross-pollination priority is: **implement C's Rec 3 and Rec 6 before implementing any D rules**,
otherwise D's compliance additions can all be silently bypassed.

### XP-3: Type Confusion Threatens Every Numeric Rule D Introduces

C (Finding 2.2) shows that Rego's type ordering (`"a" > 7 == true`) bypasses numeric comparisons when
input values are strings. D introduces a substantial number of new numeric comparisons: SORTS C-level
thresholds (readiness_pct >= 90), NIST 0-100 scores, ISO 31000 likelihood/impact numeric values,
CC17 income comparisons, Gift Aid four-year date arithmetic.
Combined: every numeric comparison in D's new rules needs an `is_number(v)` guard that C demonstrated
is currently missing from SoFREP's `_in_range` helper.
A single shared helper — e.g., `_numeric_check(v, lo, hi)` with built-in type guard — could satisfy
both the existing gap C identified and all numeric comparisons D will introduce.

### XP-4: OSCR Jurisdiction + Wirecard Cross-Field Ratio Checks

D (Standard 4) introduces `jurisdiction` as an enum that modulates validation rules for Scottish charities.
C (Finding 3.1, Rec 7) proposes cross-field ratio checks (income/expenditure vs. prior period).
Combined: Scottish charities under OSCR have different acceptable income recognition rules
(e.g., treatment of legacies and grants differs). Wirecard-style ratio anomalies in Scottish
charity reports would need jurisdiction-adjusted plausibility bounds, not a single global threshold.
A `jurisdiction`-parameterized plausibility check would be more accurate and harder to spoof.
