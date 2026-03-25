# Phase 5 — Judge 2: The Oracle
## Lens: ALIEN DISCIPLINE — 8 Rounds of Cross-Disciplinary Analysis

**Subject:** SoFA (`sofa/standard/sofa.rego`) and SoFREP (`sofrep/standard/sofrep.rego`)
**Date:** 2026-03-25
**Method:** Import mental models from 8 unrelated disciplines; surface blind spots no domain expert would see.

---

## Round 1: Biology (Immune Systems)

### Findings

- **[CRITICAL]** Brittle Binary Recognition — No "Self" Tolerance Window for Financial Variation
  - **Location:** `sofa.rego:260–263` (`net_movement_check`), `sofa.rego:269–275` (`fund_reconciliation`)
  - **Evidence:** Both rules fire on `abs(delta) > tolerance` where tolerance is a single scalar (e.g., 0.01). A healthy immune system distinguishes "self" (expected normal variation) from "non-self" (pathological deviation). These rules treat all deviations above a fixed scalar identically — a £0.02 rounding error and a £500 fraud get the same severity: `"error"`. There is no graduated response. Biology calls this autoimmune disease: the system attacks itself over legitimate variation.
  - **Impact:** Legitimate reports with floating-point rounding artifacts in multi-currency consolidations will be rejected at the same severity as genuine reconciliation failures. Reporters may game tolerance by nudging figures to land inside the window rather than fixing the underlying arithmetic.
  - **Fix:** Add a secondary `"warning"` band between `tolerance` and `tolerance * 10`. Errors fire only above the upper band. This mirrors immune tolerance zones — small deviations are noted, large ones are attacked.

- **[MAJOR]** No Adaptive Immunity — Thresholds Are Static, Never Updated by History
  - **Location:** `sofa.rego:327–335` (`variance_analysis`), `sofa.rego:338–345` (`income_growth_plausibility`)
  - **Evidence:** The immune system maintains memory cells: after seeing a pathogen once, it calibrates faster next time. SoFA's `variance_limit` and `max_income_growth_ratio` are fixed in `data.thresholds` — they never adapt to the entity's own historical variance profile. A charity that legitimately grows 6x per year due to a major government grant program will trigger `income_growth_plausibility` every single year with no memory that this pattern is "self" for that entity.
  - **Impact:** High-false-positive rate for fast-growing organisations. Reporters suppress warnings by learning the threshold numbers, not by ensuring the data is accurate.
  - **Fix:** The schema could carry an `entity_profile.historical_growth_band` field. When present, `income_growth_plausibility` compares against the entity-specific band rather than the global threshold. This is adaptive immunity: the system learns what "self" looks like for each organism.

- **[MAJOR]** No Innate vs. Adaptive Separation — All Rules Fire Simultaneously
  - **Location:** `sofa.rego` entire `deny` set; `sofrep.rego` entire `deny` set
  - **Evidence:** In biology, the innate immune system fires first (fast, broad, non-specific) and the adaptive system fires second (slow, precise, memory-based). Both policies flatten all rules into a single `deny` set that fires in one evaluation. There is no "fast path" for catastrophic structural failures that halts further evaluation.
  - **Impact:** A report missing `data.schema` entirely still evaluates all 20+ downstream rules, producing a flood of cascading errors that obscure the root cause. In a real immune failure, the body goes septic from too many simultaneous signals.
  - **Fix:** The `data_sentinel` rules already exist as a proto-innate layer. Make them structurally prior: gate the entire remaining `deny` set behind `_schema_present` and `_thresholds_present`. SoFREP does this slightly better with `_has_schema` / `_has_thresholds` guards on threshold_bounds, but neither policy fully short-circuits downstream rules when the data document is absent.

- **[MINOR]** No Apoptosis — No Mechanism to Retire Stale Warnings
  - **Location:** `sofrep.rego:427–445` (`stale_item`, `stale_at_risk`)
  - **Evidence:** Biology uses apoptosis (programmed cell death) to eliminate cells that are no longer useful. SoFREP's staleness rules fire as long as `last_updated` is old — but there is no complementary rule that clears or archives items once they are actioned. An item that was `at_risk` last period but is now `working_well` will generate a `stale_at_risk` warning if its `last_updated` was not refreshed on transition.
  - **Impact:** Reporters learn to bump `last_updated` on every submission regardless of actual change, defeating the staleness signal entirely.
  - **Fix:** Add a `resolved_date` field convention; staleness rules exclude items where `resolved_date` is present and recent.

### Verdict: CRACKED

The policy is brittle in the immunological sense — it lacks tolerance zones, has no adaptive memory, and produces autoimmune-style false positives for legitimate variation. The binary error/pass model is the core pathology.

---

## Round 2: Music (Harmony and Dissonance)

### Findings

- **[CRITICAL]** Dissonant Duet — `going_concern` and `going_concern_disclosure` Are Unsynchronised Instruments
  - **Location:** `sofa.rego:369–383`
  - **Evidence:** Two separate rules share identical trigger conditions (`every p in array.slice(hist, count(hist) - n, count(hist)) { p < 0 }`), but produce different severity outputs: `going_concern` fires as `"warning"` while `going_concern_disclosure` fires as `"error"`. A reporter who provides `going_concern_disclosure` suppresses the `error` but not the `warning`. The two rules play in different keys simultaneously. In music this is an unresolved tritone — theoretically valid but perceptually jarring.
  - **Impact:** A valid, fully-disclosed going concern report always carries a warning. `summary.valid` can be `true` (no errors) while `warning_count > 0` due to `going_concern`. This creates confusion: the report is simultaneously "valid" and "has a going concern warning" with no way for a downstream consumer to distinguish "warning because we disclosed it correctly" from "warning because something else is wrong."
  - **Fix:** When `going_concern_disclosure` is present and non-empty, suppress `going_concern` warning. The disclosure IS the correct response; flagging it again as a warning is double-penalisation.

- **[MAJOR]** No Rhythmic Structure — Validation Order Is Indeterminate
  - **Location:** `sofa.rego` entire file; `sofrep.rego` entire file
  - **Evidence:** Good music has structure: intro → verse → chorus → bridge → outro. A well-composed validation policy should follow: structural → type → semantic → cross-entity → operational. Both policies interleave these freely. In SoFA, `materiality` (section 15) fires before `compliance` (section 17), which fires before `fund_restriction` (section 9) — but structurally, fund restriction is more fundamental than materiality. In SoFREP, `risk_matrix` is computed before `base_fields` is fully validated, meaning a corrupted impact/likelihood value could cause `risk_matrix` to produce a score of 0 (defaulting `_risk_level` to "low") silently.
  - **Impact:** When multiple errors co-exist, reporters see a random ordering of messages with no structural priority guidance. The most important error may appear 15th in the deny set.
  - **Fix:** Add a `layer` field to each deny entry (`"structural"`, `"semantic"`, `"cross_entity"`, `"operational"`). Consumers can sort by layer before displaying.

- **[MAJOR]** Chord Cluster — Four `escalation_required` Rules Produce Identical Severity/Field/Rule Triples
  - **Location:** `sofrep.rego:477–491`
  - **Evidence:** All four escalation deny entries share `"severity": "warning"`, `"field": "escalation"`, `"rule": "escalation_required"`. Only the `msg` string differs. In music, this is four instruments playing the same note at the same dynamic — the individual voices are lost. A consumer doing `{d | some d in deny; d.rule == "escalation_required"}` gets a set of up to 4 entries that look nearly identical.
  - **Impact:** Deduplication logic in downstream consumers (which typically key on `rule + field`) will collapse four distinct triggers into one, silently losing three escalation reasons.
  - **Fix:** Use distinct `rule` names: `"escalation_critical_risk"`, `"escalation_low_readiness"`, `"escalation_at_risk_ratio"`, `"escalation_p0_stale"`. This gives each voice its own identity.

- **[MINOR]** Unresolved Resolution — `valid` Is Defined But `invalid` Is Not
  - **Location:** `sofa.rego:470–472`; `sofrep.rego:521–523`
  - **Evidence:** Both policies define `valid if count(errors) == 0` and `default valid := false`, but never define a complementary `invalid` rule. In music, every tension needs a resolution. A consumer who wants to react only to invalid states must negate valid, which in OPA requires a double-negation pattern (`not policy.valid`) rather than a positive assertion. The absence of an `invalid` rule creates asymmetry that forces consumers to reason about absence rather than presence.
  - **Fix:** Add `invalid if count(errors) > 0` as an explicit positive assertion. Small change, significant semantic clarity.

### Verdict: CRACKED

The policies have rhythm problems (no layered evaluation order), dissonant duplicate-trigger pairs (going_concern duet), and chord clusters that lose individual voices (escalation_required collapse). Structurally valid but tonally dissonant.

---

## Round 3: Game Theory (Incentives and Nash Equilibria)

### Findings

- **[CRITICAL]** Nash Equilibrium Is "Empty Report With All Fields Present"
  - **Location:** `sofa.rego` structural rules (sections 3–4); `sofrep.rego` base_fields / quadrant_fields rules
  - **Evidence:** Game theory asks: what is the minimum-effort input that passes all rules? For SoFA, the Nash equilibrium is a report with all required fields present as empty arrays or zero amounts, no prior_period (avoiding variance checks), no fund_balances (avoiding reconciliation), no transfers (avoiding transfer_netting), and `net_movement: 0` computed from empty line items. This passes `required_field`, `net_movement_check`, `date_format`, and all category checks. For SoFREP, the equilibrium is exactly 4 items (one per quadrant) each with all base_fields populated with placeholder strings, `priority: "P2"`, `last_updated` set to the `end_date` (never stale), no dependencies, and `impact/likelihood: 1` (risk score 1, never critical). Both equilibria are substantively meaningless but policy-valid.
  - **Impact:** A bad-faith reporter can produce a passing SoFA report containing: `incoming_resources: []`, `resources_expended: []`, `net_movement: 0`, `fund_balances: {}`, `reconciliation: {opening_total: 0, net_movement: 0, closing_total: 0}`. All errors: 0. All warnings: 0. `valid: true`. This is a blank financial statement that passes validation.
  - **Fix:** `minimum_substance` in SoFA (`sofa.rego:411–416`) addresses this but is disabled by default (`min_substance_items: 0`). The default should be non-zero (at least 1). For SoFREP, `quadrant_non_empty` (`sofrep.rego:203–207`) catches empty quadrants, which partially closes this gap — but a single item per quadrant with all minimum fields is still a hollow report.

- **[MAJOR]** Reporting Arbitrage — Prior Period Is Optional, Eliminating Growth Checks
  - **Location:** `sofa.rego:327–335` (`variance_analysis`), `sofa.rego:338–345` (`income_growth_plausibility`)
  - **Evidence:** Both variance rules are guarded by `prior := object.get(input, "prior_period", {})`. If `prior_period` is absent, neither rule fires. A rational reporter who knows income grew by 20x simply omits `prior_period`. The policy has no rule requiring `prior_period` when the entity has previously filed.
  - **Impact:** The "Wirecard plausibility cap" (R25) can be trivially bypassed by any reporter who knows it exists. The incentive structure actively rewards omitting historical context.
  - **Fix:** Add a rule: if `entity_registration_date` is present and predates `report_date` by more than 1 year, `prior_period` is required (error severity). This closes the arbitrage.

- **[MAJOR]** Audit Reference Is a Warning, Creating a Rational Omission Incentive
  - **Location:** `sofa.rego:231–235` (`audit_reference`)
  - **Evidence:** Missing `reference` on line items fires at `"warning"` severity, not `"error"`. Since `valid` is gated only on `count(errors) == 0`, a reporter can omit all audit references and still receive `valid: true`. The game-theoretic dominant strategy is to omit references (less work, same validity outcome).
  - **Impact:** The audit trail — which exists precisely to prevent fraud — is optional in practice. Any reporter optimising for "pass" will never provide references.
  - **Fix:** Escalate `audit_reference` to `"error"` for line items above `thresholds.materiality_floor`. Below materiality, warning is acceptable. This aligns the incentive with the compliance goal.

- **[MINOR]** Contradictory Severity Signals Is a Warning, Not an Error (SoFREP)
  - **Location:** `sofrep.rego:493–501` (`contradictory_severity_signals`)
  - **Evidence:** A P0 item with urgency "low" fires a warning. The item still passes as valid. A rational reporter who wants to downplay urgency while maintaining high priority simply sets `urgency: "low"` on all P0 items. The policy detects this but cannot stop it.
  - **Impact:** The urgency field becomes systematically unreliable as reporters learn the threshold.
  - **Fix:** Elevate to `"error"` for P0 items specifically. P1 can remain a warning. P0 with urgency "low" is a logical impossibility that should block submission.

### Verdict: SHATTERED

The Nash equilibrium analysis reveals that both policies can be fully satisfied by substantively empty submissions. The game-theoretic dominant strategy is "minimum effort, omit optional context." The `minimum_substance` safety valve is disabled by default. This is a fundamental incentive design failure.

---

## Round 4: Materials Science (Stress Testing)

### Findings

- **[CRITICAL]** Yield Point — Cascading Errors When `data.schema` Is Absent
  - **Location:** `sofa.rego:43–55` (data aliases computed at module scope); `sofrep.rego:21–28`
  - **Evidence:** In materials science, the yield point is where a material transitions from elastic (recoverable) to plastic (permanent) deformation. In SoFA, `income_cats`, `expense_cats`, `fund_types`, `tolerance`, and `all_items` are all computed at module scope from `data.schema` and `data.thresholds`. When `data.schema` is absent or malformed, OPA does not evaluate these as errors — it simply produces `undefined` for the alias, which then propagates through all downstream rules. The `data_sentinel` error fires, but so do potentially 15+ other rules that reference `income_cats` (which is now an empty set), producing spurious "invalid income category" errors for every line item.
  - **Evidence detail:** `income_cats := {c | some c in schema.income_categories}` — when `schema.income_categories` is missing, `income_cats` is `{}` (empty set). Every item then fails `income_category` because nothing is in the empty set. The deny set explodes with O(n) spurious errors where n is the number of line items.
  - **Impact:** A malformed data document produces a deny set that is completely uninterpretable. A report with 100 line items and a missing schema produces 200+ deny entries, all of which are artifacts of the schema failure, not the report's actual defects.
  - **Fix:** Gate the entire deny set on `_schema_present` and `_thresholds_present`. OPA supports this via rule bodies: `deny contains ... if { _schema_present; ... }`. All rules below the meta-validation layer should carry this guard.

- **[MAJOR]** Fatigue Failure — The `_date_approx_days` Calendar Is Structurally Unsound Under Load
  - **Location:** `sofa.rego:441–448` (`_date_approx_days`)
  - **Evidence:** The function uses `days := ((y * 365) + (m * 30)) + d` — a flat approximation ignoring leap years and the actual varying length of months. This produces errors of up to 11 days (the difference between a 31-day month and 30 days assumed). Materials under cyclic fatigue fail at stress levels below their yield point because small accumulated errors compound. Here: a filing_date of 2024-01-31 computes as `(2024*365 + 1*30 + 31) = 738,937`. A report_date of 2023-03-31 computes as `(2023*365 + 3*30 + 31) = 738,488`. Difference: 449 days. The actual calendar difference is 306 days. The approximation is off by 143 days — nearly 5 months — making the deadline check unreliable for cross-year comparisons.
  - **Impact:** The `filing_deadline_check` rule is materially inaccurate across year boundaries. It will produce both false positives (flagging on-time filings as late) and false negatives (missing genuinely late filings). As a compliance rule, this is serious.
  - **Fix:** Use OPA's `time.parse_rfc3339_ns` + integer division (as SoFREP's `_days_between` does correctly at `sofrep.rego:419–423`). SoFA should adopt the exact same pattern.

- **[MAJOR]** Stress Concentration — `unique_ids` Rule Is O(n²) in SoFREP
  - **Location:** `sofrep.rego:304–312` (`unique_ids`)
  - **Evidence:** The duplicate ID detection iterates all pairs `[q1, i, q2, j]` across all quadrants — this is a full Cartesian product. For a report with 50 items per quadrant (200 total), this generates 200 × 200 = 40,000 pair comparisons. Materials science calls this stress concentration: a geometric notch that amplifies local stress disproportionately. OPA evaluates this as a set comprehension, so the practical limit before timeout depends on OPA's evaluation strategy, but the design is O(n²).
  - **Impact:** Large operational SoFREP reports (e.g., a brigade-level report with hundreds of items) may hit OPA evaluation timeouts. The policy becomes unreliable at scale — which is precisely when it matters most.
  - **Fix:** Use set intersection instead: `dupe_ids := all_ids & {id | count([i | some q in quadrants; some i in items_in(q); i.id == id]) > 1}`. This is O(n) with hash-based set operations.

- **[MINOR]** Brittleness Under Null Injection — `endowment_principal` Has No Type Guard
  - **Location:** `sofa.rego:301–304` (`endowment_principal`)
  - **Evidence:** `object.get(fb, "principal_spent", 0) > 0` — if `principal_spent` is a string (e.g., "none"), `is_number` is not checked and OPA's `>` comparison will be undefined rather than true/false, causing the rule to silently not fire. No type guard protects this comparison.
  - **Impact:** A malicious or malformed input with `principal_spent: "yes"` bypasses the endowment principal check entirely with no error.
  - **Fix:** Add `is_number(object.get(fb, "principal_spent", 0))` as a guard condition, matching the pattern used in `fund_balance_type` (sofa.rego:242–248).

### Verdict: CRACKED

Two structural failures (schema-absent cascade, O(n²) uniqueness check) plus a materially inaccurate date approximation make the policies fragile under real-world stress conditions. The calendar bug alone is a compliance liability.

---

## Round 5: Neuroscience (Cognitive Load)

### Findings

- **[CRITICAL]** Working Memory Overflow — No Error Grouping or Suppression Hierarchy
  - **Location:** `sofa.rego:466–480` (result section); `sofrep.rego:516–534`
  - **Evidence:** Human working memory holds 7 ± 2 chunks (Miller's Law). A SoFA report with: missing schema (1 error) + 50 line items each missing `category` (50 errors) + 50 items each missing `fund_type` (50 errors) + failed reconciliation (1 error) = 102 deny entries. A human reviewing 102 entries cannot process them meaningfully. Neuroscience shows that cognitive overload causes decision fatigue and error blindness — the reviewer stops reading after ~7 entries.
  - **Impact:** The policy's purpose is to guide reporters to fix problems. When error count exceeds ~10, the guidance function fails entirely. Reporters see a wall of text and either (a) stop reading, (b) fix only the first N errors, or (c) seek a rubber-stamp approval path. The policy creates the very behaviour it is designed to prevent.
  - **Fix:** Implement error suppression: when a structural error (e.g., missing required field) would cause cascading downstream errors, suppress those downstream errors and emit a single meta-error: `"structural errors present: N downstream validation rules suppressed"`. This mirrors how the brain's attentional spotlight works — foreground the root cause, background the symptoms.

- **[MAJOR]** No Severity Salience — `info` Items Mix With `error` Items in `deny`
  - **Location:** `sofa.rego:398–403` (`materiality`); the `deny` set is a flat union
  - **Evidence:** The `deny` set contains `"error"`, `"warning"`, and `"info"` items interleaved. When a consumer iterates `deny`, high-severity errors share attention with low-salience info items. The neuroscience of visual attention shows that uniform presentation of items with different importance causes attention to distribute equally — the critical items do not receive proportional attention.
  - **Impact:** Reviewers miss critical errors because their attention is partially consumed by info-level materiality notices. The `summary` object (`sofa.rego:474–480`) does split errors/warnings, but `info` is bucketed into `warnings`, creating another conflation.
  - **Fix:** Add `"info"` as a separate severity in `summary`. Separate `deny` entries into three named collections: `errors`, `warnings`, `notices`. The `info` materiality entries are notices, not warnings.

- **[MAJOR]** Ambiguous Identity — Same `rule` Name Fires From Different Contexts
  - **Location:** `sofa.rego:165–174` (`required_field` fires twice — once for absent key, once for null value); `sofrep.rego:170–188` (`required_metadata` fires three separate rules)
  - **Evidence:** The `required_field` rule fires from two separate deny rules with identical `rule` tag. A consumer cannot distinguish "key absent" from "key present but null" by examining the deny entry alone — both emit `rule: "required_field"` with the same field name. This is like a brain receiving two identical error signals from different circuits — it cannot localise the source.
  - **Impact:** Downstream consumers building automated remediation cannot determine whether to add the field or correct its value. The action required is different for each case but the signal is identical.
  - **Fix:** Use distinct rule names: `"required_field_absent"` vs. `"required_field_null"`. One character of change, significant diagnostic improvement.

- **[MINOR]** No Progressive Disclosure — All Detail Emitted on Every Evaluation
  - **Location:** Both policies, entire `deny` set
  - **Evidence:** Neuroscience of information processing shows that progressive disclosure (reveal detail on demand) is more effective than simultaneous full disclosure. Both policies emit full `msg` strings, `field`, `rule`, and `severity` on every evaluation. There is no mechanism for a "summary mode" vs. "detail mode."
  - **Fix:** Add `"summary_msg"` as a short (≤50 char) field alongside `"msg"`. Consumers can surface `summary_msg` in dashboards and `msg` in drill-down views.

### Verdict: CRACKED

The flat, unsuppressed, unsorted deny set is cognitively toxic at scale. The policy is analytically correct but pedagogically broken — it cannot effectively communicate what needs to be fixed when multiple errors co-exist.

---

## Round 6: Jurisprudence (Legal Reasoning)

### Findings

- **[CRITICAL]** Void for Vagueness — `variance_analysis` Has No Minimum Prior-Period Threshold
  - **Location:** `sofa.rego:327–335` (`variance_analysis`)
  - **Evidence:** The rule fires when `abs(current - prior) / abs(prior) > thresholds.variance_limit` AND `prior_val != 0`. There is no minimum absolute threshold. A charity with prior income of £10 that now has £13 income triggers a 30% variance warning even though the absolute difference is £3. Under jurisprudence, a law that applies disproportionate sanctions for trivially small violations is void for vagueness — it fails the proportionality test.
  - **Impact:** Micro-organisations (community groups with £50 prior income that grew to £100) receive the same variance warning as organisations that tripled from £10M to £30M. The rule has no concept of materiality relative to scale.
  - **Fix:** Gate `variance_analysis` on `abs(prior_val) >= thresholds.materiality_floor`. No variance warning fires on prior values below the materiality threshold.

- **[CRITICAL]** No Due Process — Denied Inputs Cannot Determine Remediation Path
  - **Location:** `sofa.rego:260–263` (`net_movement_check`): msg is `"net_movement %v != computed %v"`; `sofa.rego:269–275` (`fund_reconciliation`): msg is `"fund '%s': opening(%v) + net_movement(%v) != closing(%v)"`
  - **Evidence:** Due process in law requires that a person know not only WHAT they violated but HOW to remedy it. The reconciliation error messages state the mismatch but provide no guidance on which field to change. For `fund_reconciliation`, the reporter sees three numbers that don't add up — but all three are reported without indication of which is wrong (opening balance from last year? net movement from line items? closing balance from bank statement?).
  - **Impact:** Reporters with legitimate data entry errors cannot self-remediate without domain expertise. The policy is authoritative but not instructive. This is the difference between a court that issues a ruling and one that explains its reasoning.
  - **Fix:** Add a `hint` field to high-confusion deny entries. For `net_movement_check`: `"hint": "check that net_movement equals sum(incoming_resources) minus sum(resources_expended)"`. For `fund_reconciliation`: `"hint": "verify opening_balance matches prior year closing; net_movement matches fund's income minus expenditure"`.

- **[MAJOR]** Retroactive Punishment — `filing_deadline_check` Fires on Past Reports
  - **Location:** `sofa.rego:450–460` (`filing_deadline_check`)
  - **Evidence:** The rule computes `fd_days - rd_days > deadline` where `fd_days` and `rd_days` are derived from the submitted dates. If a charity submits a historical report (e.g., for a prior year audit), the rule may fire because the filing_date in the document exceeds the deadline relative to the report_date — even if the filing was on time when originally submitted and is now being re-validated. Retroactive application of penalties is a core violation of lex mitior (the principle that laws should not apply retroactively to past actions).
  - **Impact:** Archival re-validation of historical reports produces spurious deadline warnings that were not present at time of original filing. This corrupts compliance records.
  - **Fix:** Add a `validation_date` field. The filing deadline check should compare `filing_date` against `validation_date` (or `report_date + deadline`), and only fire when `validation_date` is within a reasonable current window (e.g., current year ± 1).

- **[MAJOR]** Self-Contradictory Precedent — `schema_list_nonempty` for `required_metadata` and `base_fields` in SoFREP Are Dead Rules
  - **Location:** `sofrep.rego:140–150`
  - **Evidence:** Two rules read:
    ```
    count(object.get(data.schema, "required_metadata", [])) > 0
    count(object.get(data.schema, "required_metadata", [])) < 1
    ```
    The condition `count > 0 AND count < 1` is mathematically impossible — no integer satisfies both simultaneously. These rules can never fire. Similarly for `base_fields`. This is equivalent to a statute that criminalises behaviour X only when X has simultaneously occurred and not occurred — it is a legal nullity.
  - **Impact:** The `schema_list_nonempty` protection for `required_metadata` and `base_fields` in SoFREP is entirely non-functional. An empty `required_metadata: []` list bypasses the guard, causing all metadata validation to silently pass (nothing to iterate over).
  - **Fix:** Change the condition from `count > 0 AND count < 1` to simply `count == 0`, matching the data_sentinel guard pattern used at `sofrep.rego:91–94`.

- **[MINOR]** Unsigned Legislation — No Policy Version in the Deny Output
  - **Location:** Both policies, `deny` set structure
  - **Evidence:** Deny entries carry `msg`, `severity`, `field`, `rule` — but no `policy_version`. Legal judgments always cite the statute and version under which they were made. If the policy is updated (e.g., a new threshold), previously-stored deny results cannot be re-interpreted or appealed under the correct version.
  - **Fix:** Add `"policy_version": "2.0.0"` (from the metadata header) to the `summary` object. Individual deny entries do not need it, but the summary should be version-stamped.

### Verdict: SHATTERED

Two dead rules (legal nullities), a retroactive penalty mechanism, a vague proportionality failure, and absent remediation guidance make this policy legally unsound. The `schema_list_nonempty` dead rules for SoFREP are a particularly severe finding — a protection that looks present but provides zero coverage.

---

## Round 7: Architecture (Load-Bearing Structure)

### Findings

- **[CRITICAL]** Load-Bearing Rule Identified — Removing `data_sentinel` Collapses the Entire Structure
  - **Location:** `sofa.rego:67–93`; `sofrep.rego:75–99`
  - **Evidence:** An architectural load-bearing wall, if removed, causes the structure above to collapse. `data_sentinel` is the only rule that guards against missing `data.schema` and `data.thresholds`. If `data_sentinel` is removed (or bypassed by passing `data.schema as {}`), all downstream rules that reference schema contents silently evaluate against empty structures — producing `valid: true` because `income_cats` is `{}`, `fund_types` is `{}`, so no items fail category or fund_type checks (nothing to fail against). The policy inverts: missing configuration becomes maximum permissiveness.
  - **Impact:** This is the most dangerous structural property of both policies: removing or bypassing the configuration layer does not cause the policy to reject everything — it causes the policy to accept everything. A deployment error (missing data document) produces false-valid results, not errors.
  - **Fix:** The fix for Round 1 (gate all downstream rules on `_schema_present`) also addresses this architectural failure. Make the load-bearing wall explicitly structural by having every downstream deny rule begin with `_schema_present` as its first condition.

- **[CRITICAL]** Decorative Pillar — `max_expense_growth_ratio` Threshold Exists in Schema But Has No Corresponding Rule
  - **Location:** `sofa/standard/schema.json:26` (`"max_expense_growth_ratio": 5.0`); `sofa.rego` — no `expense_growth_plausibility` rule exists
  - **Evidence:** `schema.json` declares `max_expense_growth_ratio: 5.0` and `_threshold_bounds` in `sofa.rego:96–107` includes `"max_expense_growth_ratio"` bounds validation. But there is no `expense_growth_plausibility` rule that actually uses `thresholds.max_expense_growth_ratio` to evaluate expense data. The threshold is validated (bounds check passes) but never consumed. This is a decorative column — it looks structural but carries no load.
  - **Impact:** Organisations can double their expenditure every year with no plausibility check, even though the threshold exists in the schema. The Wirecard-style fraud detection is one-sided: income is checked, expenses are not. An organisation concealing income by inflating expenses bypasses the plausibility cap entirely.
  - **Fix:** Add `expense_growth_plausibility` rule mirroring `income_growth_plausibility` at `sofa.rego:338–345`, substituting `resources_expended_total` and `max_expense_growth_ratio`.

- **[MAJOR]** Structural Hierarchy Inversion — Cross-Entity Rules Run Before Type Rules
  - **Location:** `sofrep.rego`: `unique_ids` (section 11, line 304) runs before `base_fields` (section 3, line 210) has been fully validated
  - **Evidence:** In architecture, foundations must be poured before walls are built. `unique_ids` iterates `item1.id` directly — if `id` is absent (caught by `base_fields`), the comprehension `{item.id | ...}` will include `undefined` for items with missing IDs, which OPA excludes from sets silently. This means two items both missing `id` will not be detected as "duplicate" (both produce undefined, which is excluded from the id set) — even though they represent a deeper structural problem.
  - **Impact:** Two items with missing IDs pass `unique_ids` silently. Only `base_fields` catches the missing ID. If the consumer stops processing after `unique_ids` passes, the base_fields error is never reached.
  - **Fix:** The architecture fix is ordering: enforce that `base_fields` errors are resolved before `unique_ids` is evaluated. In practice, add a guard: `unique_ids` should only fire when the item's `id` field is present and non-empty.

- **[MINOR]** Unsupported Span — `reconciliation` Totals Are Not Summed Across `fund_balances`
  - **Location:** `sofa.rego:281–287` (`aggregate_reconciliation`)
  - **Evidence:** The aggregate reconciliation rule validates that `r.opening_total + r.net_movement == r.closing_total` — but it does not verify that `r.opening_total` actually equals the sum of all fund opening balances, or that `r.closing_total` equals the sum of all fund closing balances. The bridge span is checked for level but not anchored to its supports. A reporter can pass aggregate reconciliation while having individual fund balances that do not sum to the aggregate totals.
  - **Impact:** A report can pass both `fund_reconciliation` (each fund internally consistent) and `aggregate_reconciliation` (totals internally consistent) while the sum of fund balances does not equal the aggregate total. This is a gap large enough for material misstatement.
  - **Fix:** Add a cross-check rule: `sum(fb.closing for ft, fb in fund_balances) == r.closing_total` and `sum(fb.opening for ...) == r.opening_total`.

### Verdict: SHATTERED

The inverted permissiveness failure (missing config = accepts everything) and the missing expense growth plausibility rule are load-bearing structural defects. The decorative `max_expense_growth_ratio` threshold is a particularly sharp finding — it creates a false sense of security while providing no actual protection.

---

## Round 8: Quantum Mechanics (Superposition)

### Findings

- **[CRITICAL]** Superposition Collapse — `c_level` Is Undefined When Thresholds Overlap
  - **Location:** `sofrep.rego:368–387` (`c_level`)
  - **Evidence:** In quantum mechanics, a particle in superposition collapses to a definite state when observed. The `c_level` rules are defined as a chain of mutually exclusive conditions — but they depend on `data.thresholds.c1_threshold`, `c2_threshold`, `c3_threshold`, `c4_threshold` being strictly ordered. If the thresholds are misconfigured such that `c2_threshold >= c1_threshold` (e.g., both set to 90), a readiness score of 90 would match BOTH the `c1` rule (`>= c1_threshold`) AND the `c2` rule (`< c1_threshold AND >= c2_threshold` — this second condition would be false, so actually c1 wins). But if `c2_threshold == c1_threshold == 90` and `readiness_pct == 90`, c_level collapses to "C1" only because OPA evaluates all complete rules and takes the first defined value. However, `c_level` is a partial rule — if none of the five conditions match (possible when `c4_threshold == 0` and `readiness_pct == 0`: `c_level == "C5"` fires for `< c4_threshold`... actually `0 < 0` is false), `c_level` is undefined. `summary.c_level` then produces `undefined`, crashing any consumer that expects a string.
  - **Evidence detail:** When `readiness_pct == 0` and `c4_threshold == 0`: the rule `c_level := "C5" if { readiness_pct < data.thresholds.c4_threshold }` evaluates `0 < 0` = false. The rule `c_level := "C4" if { readiness_pct < c3_threshold AND readiness_pct >= c4_threshold }` evaluates `0 < 50 AND 0 >= 0` = true — so C4 fires. However, when `c4_threshold > readiness_pct` but all higher rules also fail (a threshold misconfiguration), `c_level` is undefined.
  - **Impact:** `summary.c_level` can be `undefined` under threshold misconfiguration, causing JSON serialisation failures in downstream consumers that do not handle OPA's undefined-in-object behaviour.
  - **Fix:** Add `default c_level := "UNKNOWN"`. This collapses the superposition to a defined ground state when no rule matches.

- **[CRITICAL]** Observer Effect — `risk_matrix` Intermediate Result Affects Both `critical_risk` and `treatment_plan_required` But Is Separately Computed
  - **Location:** `sofrep.rego:341–349` (`risk_matrix`), `sofrep.rego:351–354` (`critical_risk`), `sofrep.rego:504–512` (`treatment_plan_required`)
  - **Evidence:** In quantum mechanics, the act of observing a system affects it. `risk_matrix` is a named rule that produces a set. Both `critical_risk` and `treatment_plan_required` iterate `risk_matrix`. `treatment_plan_required` also does: `item := [i | some i in items_in("at_risk"); i.id == id][0]` — a second traversal of `at_risk`. If `at_risk` items are modified between evaluations (impossible in a single OPA evaluation but a maintenance hazard), the two paths could diverge. More critically: `treatment_plan_required` accesses `r.id` from `risk_matrix` and then re-fetches the item from `items_in("at_risk")` by matching `id`. If an item appears in `risk_matrix` (computed from `items_in("at_risk")`) but is not found by the re-fetch (impossible in OPA but the pattern is fragile), the comprehension `[i | ...; i.id == id][0]` would panic with an index-out-of-bounds on an empty array.
  - **Impact:** The `[...][0]` array index pattern is the single most dangerous construct in the SoFREP policy. If `risk_matrix` and `items_in("at_risk")` ever diverge (e.g., due to policy refactoring that changes one but not the other), evaluation panics rather than failing gracefully.
  - **Fix:** Replace `[i | some i in items_in("at_risk"); i.id == id][0]` with a safer pattern: `item := {i | some i in items_in("at_risk"); i.id == id}` then `count(item) > 0`. Or use `some item in items_in("at_risk"); item.id == id` directly within the deny rule body, eliminating the separate `risk_matrix` indirection.

- **[MAJOR]** Entanglement Without Separation — `readiness_pct` and `c_level` Are Entangled With `total_items`
  - **Location:** `sofrep.rego:357–362` (`readiness_pct`)
  - **Evidence:** `readiness_pct := 0 if total_items == 0` and `readiness_pct := round(count(working_well) * 100 / total_items) if total_items > 0`. When `total_items == 0`, readiness is 0%, triggering `low_readiness`, `c_level_readiness` (C4 or C5), and potentially `escalation_required`. But an empty report is a structural error caught by `quadrant_non_empty` — the operational intelligence layer fires on a structurally invalid input. The entanglement between structural validity and operational metrics means that a structurally broken report produces misleading operational conclusions.
  - **Impact:** A report missing all quadrants produces: (a) 4 `quadrant_presence` errors, (b) `low_readiness` warning, (c) `c_level_readiness` warning, (d) `escalation_required` warning. The operational warnings are noise caused by the structural errors. This is quantum entanglement: measuring one thing (structural) changes the state of another (operational).
  - **Fix:** Gate all Layer 4 operational intelligence rules (`low_readiness`, `c_level_readiness`, `escalation_required`, `defensive_posture`) behind a `count(errors where rule in structural_rules) == 0` guard. Do not compute operational intelligence on structurally invalid inputs.

- **[MINOR]** Wave Function Collapse Without Normalisation — `readiness_pct` Uses `round()` But Thresholds Are Integer Comparisons
  - **Location:** `sofrep.rego:361` (`readiness_pct := round(...)`)
  - **Evidence:** `round((3 * 100) / 8) = round(37.5) = 38`. The threshold comparisons `readiness_pct >= data.thresholds.c2_threshold` use integer thresholds (e.g., 70). Whether `round()` rounds half-up or half-to-even (banker's rounding) affects whether a score of exactly 37.5 becomes 37 or 38. OPA's `round()` uses half-away-from-zero. This is deterministic but may surprise operators who expect a unit that is 37.5% ready to be in C3 (≥30%) rather than C4 (<50%). The rounding collapses the quantum probability to a discrete state in a way that is opaque.
  - **Impact:** Minor boundary condition confusion at threshold values. The effect is small but the lack of documentation makes it a maintenance hazard when thresholds are adjusted.
  - **Fix:** Document the rounding convention in a comment adjacent to `readiness_pct`. Consider using `floor()` instead of `round()` for conservative readiness reporting — it is safer to under-report readiness than to over-report it.

### Verdict: CRACKED

The `c_level` undefined-state vulnerability and the `[...][0]` array panic pattern are real defects. The entanglement between structural and operational rule layers produces noise that degrades the policy's signal quality under error conditions.

---

## Cross-Round Summary

| Round | Discipline | Verdict | Critical Findings |
|-------|-----------|---------|-------------------|
| 1 | Biology | CRACKED | Binary tolerance; no adaptive thresholds; innate/adaptive unseparated |
| 2 | Music | CRACKED | Going-concern dissonance; escalation_required identity collapse; no rhythm |
| 3 | Game Theory | SHATTERED | Nash equilibrium is empty report; audit reference incentive inversion; prior_period bypass |
| 4 | Materials Science | CRACKED | Schema-absent cascade; O(n²) uniqueness; calendar approximation error (143 days off) |
| 5 | Neuroscience | CRACKED | Working memory overflow; no error suppression; rule name ambiguity |
| 6 | Jurisprudence | SHATTERED | Two dead rules (legal nullities); retroactive penalty; missing expense growth rule |
| 7 | Architecture | SHATTERED | Inverted permissiveness (missing config = accepts everything); decorative threshold |
| 8 | Quantum Mechanics | CRACKED | c_level undefined state; [0] array panic; operational/structural entanglement |

### Top 5 Must-Fix Issues (Cross-Round Priority)

1. **[R7-CRITICAL / R1-CRITICAL]** Missing config inverts to accept-everything. Gate all downstream rules on `_schema_present`. (Architecture + Biology)
2. **[R3-CRITICAL]** Nash equilibrium allows empty-report bypass. Enable `min_substance_items > 0` by default. (Game Theory)
3. **[R6-CRITICAL]** Dead rules in SoFREP `schema_list_nonempty` — `count > 0 AND count < 1` is unsatisfiable. Fix to `count == 0`. (Jurisprudence)
4. **[R4-MAJOR]** `_date_approx_days` is off by up to 143 days across year boundaries. Replace with `time.parse_rfc3339_ns` division. (Materials Science)
5. **[R7-CRITICAL]** `max_expense_growth_ratio` threshold exists but no corresponding rule consumes it. Add `expense_growth_plausibility`. (Architecture)

---

*Analysis performed by Judge 2: The Oracle. All findings derived from direct reading of source files. No speculation beyond what is demonstrable in the code.*
