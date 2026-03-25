## R2-M3: D (Whitepaper Standards) vs F (Attack Surface)

- **Judge:** Strategic Reasoner Agent
- **Date:** 2026-03-25
- **Match:** Output D (DS-1, Whitepaper Standards Researcher) vs Output F (DS-3, Attack Surface Mapper)
- **Scope:** SoFA (`sofa/standard/sofa.rego`) and SoFREP (`sofrep/standard/sofrep.rego`) standard policies

---

### Score Table

| Dimension | D | F |
|---|---|---|
| Novelty | 8 | 9 |
| Divergence | 7 | 9 |
| Evidence | 10 | 9 |
| Actionability | 8 | 10 |
| Cross-pollination | 8 | 9 |
| **TOTAL** | **41** | **46** |

### Winner: F by 5 points

---

### Scoring Rationale

**Novelty — D: 8, F: 9**

The two outputs occupy entirely non-overlapping domains: D maps compliance gaps against
authoritative external standards; F maps mechanical bypass vectors inside the existing
Rego implementation.
Neither could have produced the other's findings.
F earns the edge because its discoveries are novel relative to D AND novel relative to
the expected output of any standards-survey brief.
The skeleton JSON (`{"incoming_resources": [], "net_movement": 0, ...}`) that games the
entire SoFA validator by exploiting empty-array short-circuiting is not a finding any
standards document would surface.
D's novelty is genuine but bounded: it is the expected output of "look up authoritative
standards and map gaps."

**Divergence — D: 7, F: 9**

D follows the natural research path — find the relevant standard, read it, enumerate
gaps — and executes it well.
The SORP 2026 category rename, the OSCR June 2025 trustee disclosure deadline, and the
C-level SORTS/DRRS mapping to `readiness_pct` are time-sensitive and specific, but the
method is conventional.
F applies an adversarial + type-theoretic lens to a compliance validator, which is
genuinely non-obvious.
The discovery that `data.schema.fund_types = []` is NOT a bypass but a DoS vector
(because `not item.fund_type in {}` is always true, rejecting all fund types) requires
OPA set semantics reasoning that is orthogonal to any compliance research brief.
The `not input[f]` false positive on `net_movement: 0` is an implementation bug hiding
inside a compliance tool — only visible when you read the code as an adversary.

**Evidence — D: 10, F: 9**

D cites named, linked, versioned authoritative sources for every gap: SORP FRS 102
second edition (2026), CJCSI 3401.02B, NIST SP 800-30 Rev 1, Charities Online
Validation Rules v1.3, GOV.UK Annual Return Regulations 2024.
Every claim is traceable to a primary source URL.
F's evidence is the source code itself, cited with file path and line number
(`sofa.rego:45`, `sofrep.rego:322`), with confidence ratings and rationale for each.
F loses one point because the downstream consumer impact of undefined evaluation
(`sofrep.rego:322` valid being undefined vs false) depends on OPA host integration
context that is not fully characterized.

**Actionability — D: 8, F: 10**

Every F recommendation maps to a specific file, line, and fix:
"Add `default valid := false` to SoFREP at `sofrep.rego:322`" is a 2-minute change.
"Replace `not input[f]` with `f in input` at `sofa.rego:45`" is equally immediate.
The sentinel rule for missing data documents is approximately 5 lines of Rego.
All 12 F recommendations have exact locations and are independently executable.
D's 30 gaps each have "So what for Rego" prescriptions that are implementable, but
many require schema additions (new data documents, new fields, new enums) and the
volume requires prioritization across multiple sessions.
D helpfully tiers its recommendations but the single-session criterion slightly penalizes
breadth.

**Cross-pollination — D: 8, F: 9**

This dimension reveals the deepest interaction between the outputs:

- D's SORP tier concept requires a `reporting_tier` schema field.
F shows any schema field is a kill switch if the data document can be manipulated.
Combined: the tier field must be added AND the data document must be guarded by F's
sentinel rule or the entire tier-validation logic is bypassable with one JSON edit.

- D's OSCR jurisdiction field requires adding to `required_metadata`.
F shows `data.schema.required_metadata = []` silences all required-metadata checks.
Combined: the jurisdiction field addition and the metadata list sentinel must land
in the same commit or the new requirement is immediately defeatable.

- D's Gift Aid `declaration_reference` field addition + F's finding that omitting
`category` or `fund_type` silently bypasses enum validation via undefined guard:
every new field D adds will carry the same silent non-firing vulnerability unless
F's guard pattern fix (`f in input` instead of `not input[f]`) is applied first.

- D's going concern disclosure requirement (require a narrative string when warning
fires) + F's `not input[f]` false positive on zero/empty values: a disclosure field
legitimately set to `""` would be flagged as missing under the current guard pattern,
producing false positives that break D's intended rule.

- D's NIST 0-100 impact scoring addition + F's finding that `impact` defaults to `0`
with no range check: adding NIST fields without fixing the impact range guard would
silently produce `risk_score = 0` for any item that omits the new NIST field.

F scores higher on cross-pollination because F's fixes are prerequisites for D's
additions — every new field D introduces is a future bypass surface unless F's
structural fixes are applied first.

---

### Strongest Insights from D

**D-1: SORP 2026 category rename breaks current policy correctness today.**
The existing `income_categories` list uses pre-2026 terminology (`voluntary_income`,
`activities_for_generating_funds`).
The SORP 2026 second edition (live now) renames these.
Any charity filing under the 2026 edition against the current policy receives false
positives on income category validation.
This is a live compliance regression, not a future gap.
Source: `charitiessorp.org` second edition, Standard 1, Gap 2.

**D-2: The C-level / readiness_pct mismatch invalidates the SoFREP readiness metric.**
The current `readiness_pct` (working_well ratio as percentage) has no authoritative
anchoring.
SORTS/DRRS defines C1-C5 with specific thresholds (C1 ≥ 90%, C2 ≥ 70%, etc.) and
requires four separate resource-area scores (Personnel, Equipment, Supply, Training)
where the overall rating is the worst of the four.
A single percentage average is not equivalent and will produce incorrect C-level
classifications.
Source: CJCSI 3401.02B, Standard 10, Gaps 27-28.

**D-3: OSCR jurisdiction-awareness is a mandatory, time-bounded gap.**
Scottish charities must file within 9 months (not 10), require independent examination
regardless of income level, and from June 2025 must submit full trustee personal details.
The current policy has no `jurisdiction` field.
This is not a theoretical gap — it is a live miscategorization for any Scottish charity
processed by the current policy.
Source: OSCR reporting requirements, Standard 4, Gaps 11-12.

---

### Strongest Insights from F

**F-1: Removing the data document is a silent total bypass.**
Neither policy guards against absent `data.schema` or `data.thresholds`.
An OPA deployment that loads the policy without its companion data document gets
`valid = true` for any input, because every rule that references `schema.*` or
`thresholds.*` evaluates to undefined, producing an empty `deny` set.
This is not a theoretical risk — a misconfigured CI pipeline, a staging environment
without data documents, or a deliberate attacker omitting the data file passes
everything silently.
File: `sofa.rego:21-37`, `sofrep.rego:7-18`.

**F-2: SoFREP `valid` is undefined (not false) when the data document is absent.**
SoFA has `default valid := false`.
SoFREP has `valid := count(errors) == 0` without a `default` declaration.
When `deny` is undefined, `errors` is undefined, and `valid` is undefined — not
`true`, not `false`.
Depending on the consumer, this may be treated as falsy (safe) or cause a crash /
unexpected behavior in a policy bundle.
The asymmetry between SoFA and SoFREP on this point means defenses applied to SoFA
are not automatically applied to SoFREP.
File: `sofrep.rego:322`.

**F-3: `data.schema.fund_types = []` is a DoS vector, not a bypass.**
The intuitive expectation is that emptying a schema list disables validation.
For `fund_types` and `income_categories`, the opposite is true: the rule fires
`deny` when `not item.fund_type in data.schema.fund_types`, and if `fund_types`
is the empty set `{}`, then `not item.fund_type in {}` is always true, so every
line item with a `fund_type` produces a denial.
An attacker (or misconfigured deployment) setting these lists to `[]` does not
bypass validation — it breaks all valid inputs.
Correctly understanding this distinction matters for the kill-switch mitigations:
threshold inflation (set to huge number) and list emptying have opposite effects
and require different defenses.
File: `sofa.rego:86-91`, Section C.

---

### Cross-pollination Opportunities

**XP-1: Apply F's sentinel rule before implementing any D addition.**
Every schema field D adds (tier, jurisdiction, gift_aid, C-level thresholds, NIST
scores) becomes a new kill-switch surface unless F's sentinel that guards against
absent/empty data documents is in place first.
Implementation order: sentinel rule → schema additions.
If the order is reversed, a day-one deployment without the data document silently
passes all new compliance checks.

**XP-2: Fix `not input[f]` before implementing D's disclosure requirement rules.**
D's going concern disclosure rule requires a non-empty `going_concern_disclosure`
string field when the going concern warning fires.
F's Finding D-2 shows `not input[f]` false-positives on any falsy value including
`""`.
A disclosure field set to `""` (no concern) would trigger a false positive under
the current guard pattern.
The correct guard is `not "going_concern_disclosure" in input`.
This fix must precede D's disclosure requirement or the new rule will immediately
misflag valid inputs.

**XP-3: The NIST impact field gap (D) + the impact range non-validation gap (F) must close together.**
D recommends adding `nist_impact_score` (0-100) with validation.
F finds that the existing `impact` field on at_risk items defaults to `0` via
`object.get` with no range check, silently producing `risk_score = 0`.
If NIST impact scoring is added before the range guard fix, the new field inherits
the same defect: a missing `nist_impact_score` defaults to `0`, the computation
proceeds, and the result is a plausible-looking score of zero rather than an error.
The range guard fix and the NIST field addition should be implemented atomically.
File: `sofrep.rego:179` (impact default), Standard 9 Gap 24 (NIST scoring).

**XP-4: Jurisdiction-aware rules (D) require metadata sentinel (F) to be enforceable.**
D's jurisdiction field must be added to `required_metadata` for Scotland.
F shows `data.schema.required_metadata = []` silences all required-metadata checks
(SoFREP rule 14, `sofrep.rego:23-27`).
Combined recommendation: when implementing jurisdiction-aware filing deadlines and
examination thresholds, simultaneously add a sentinel that rejects evaluations where
`count(data.schema.required_metadata) == 0`, preventing the jurisdiction requirement
from being silently defeatable.

**XP-5: The Gift Aid guard pattern must use F's corrected check.**
D recommends adding a `gift_aid` object to voluntary income line items with four
required sub-fields.
F's Finding D-1 shows that `not object.get(item, f, "") != ""` is falsy-value-blind:
sub-fields set to `0`, `false`, or `null` pass as "present and valid."
For Gift Aid, `donor_address` set to `null` would be silently accepted.
D's Gift Aid implementation must use `f in item` (explicit key presence check) rather
than the existing guard pattern inherited from the current base field validation.
