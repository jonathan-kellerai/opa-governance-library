# SICA Tournament — Phase 2, Round 3, Match 3: Output C vs Output E

- **Judge:** Strategic Reasoner Agent
- **Date:** 2026-03-25
- **Output C:** Failure Archaeology (Agent XD-3) — CVEs, real-world incidents, policy bypass patterns
- **Output E:** Rego Pattern Library (Agent DS-2) — style guide violations, anti-patterns, tooling

---

## Scoring Rubric

Each dimension scored 0–10. Higher = better.

| Dimension | Definition |
|---|---|
| **Novelty** | Does this insight appear in the other output? Lower overlap = higher score. |
| **Divergence** | How far from obvious/expected given the domain? |
| **Evidence** | Backed by a real, citable source? |
| **Actionability** | Can this become a Rego rule/test/data change in one session? |
| **Cross-pollination** | Combines with the OTHER output to create something neither produced alone? |

---

## Dimension-by-Dimension Scoring

### Dimension 1: Novelty (does each output avoid the other's territory?)

**Output C** ranges across CVE advisories, Kubernetes Gatekeeper bypass post-mortems, financial fraud cases (Wirecard, Enron), aerospace failures (Boeing MCAS), and GPS coordinate disasters. None of these source categories appear in Output E, which stays entirely within the OPA/Rego ecosystem documents. The only content overlap is the `default valid := false` gap — both outputs independently identify it (C as Finding 2.3, E as R-E04). That single convergence on a known gap is expected; it validates both outputs rather than penalizing novelty. Everything else in C is absent from E.

**Output E** covers style guide violations, idiomatic Rego patterns, linting toolchain gaps (Regal, pre-commit-opa), test isolation failures, and a double-negation anti-pattern. None of this appears in C. The R-E12 finding — that identical escalation messages in SoFREP's four triggers will deduplicate inside the deny set, silently masking trigger count — is entirely absent from C and requires close reading of how Rego set semantics interact with partial rule definitions.

**Verdict:** Both outputs are highly novel relative to each other. C's domain excursions are wider; E's are deeper inside the codebase. Score difference is marginal.

- **Output C Novelty: 8**
- **Output E Novelty: 8**

---

### Dimension 2: Divergence (how far from the obvious?)

**Output C** draws on aerospace telemetry failures and friendly-fire incidents to argue that SoFA/SoFREP share the same structural problem as Boeing MCAS: data that is format-valid but substantively implausible passes without challenge. The GPS battery-reset analogy (finding 4.2) for semantic contradictions within a single report is distinctly non-obvious. The data document poisoning finding (5.1) — that attacking `data.schema` is equivalent to attacking policy without touching any `.rego` file — is a threat-model inversion most practitioners miss. These insights require active imagination to connect to policy design.

**Output E** identifies genuine problems but they are the kinds of problems a style-guide checklist produces: missing metadata blocks, line-length violations, raw string preferences. Most are what any Regal linter run would surface. The R-E12 set-deduplication finding is the strongest divergent insight — recognizing that four syntactically correct partial rule definitions can produce only one deny entry is non-obvious and demands understanding of OPA's set evaluation semantics. R-E10 (pass `input` as argument rather than referencing it directly inside helpers) is mildly divergent; the rest are routine.

**Verdict:** C diverges significantly more. The worst-case failure scenarios it imports from external domains require genuine lateral thinking. E's divergence peaks at R-E12 and then drops to style-guide transcription.

- **Output C Divergence: 8**
- **Output E Divergence: 5**

---

### Dimension 3: Evidence (real, citable sources?)

**Output C** cites 11 distinct sources with full URLs: three CVE advisories from Styra/GitHub/Tenable, an Aqua Security Gatekeeper analysis, an OPA GitHub discussion thread, a European Parliament study, Transparently.AI case study, a PlanetCompliance regulatory analysis, FAA 737 RTS Summary, Texas Monthly investigative piece, and CNCF OPA Best Practices 2025. Every finding has a live URL. Confidence ratings are assigned per finding. This is the strongest evidence profile in the tournament so far.

**Output E** cites local file paths with line numbers throughout (e.g., `rego-style-guide/style-guide.md` lines 82–139, `sofrep.rego` line 322). This is internally verifiable but not externally citable — a reader outside the repo cannot follow these references. External sources are limited to GitHub repo URLs mentioned in passing for tools (Regal, rego-test-assertions, pre-commit-opa). The sourcing is precise for local claims but thin for external validation.

**Verdict:** C's evidence is clearly superior — multiple independent authoritative external sources per finding. E's internal file citations are valuable for implementation but weaker as research evidence.

- **Output C Evidence: 10**
- **Output E Evidence: 7**

---

### Dimension 4: Actionability (one-session Rego implementation?)

**Output C** recommendations split into two groups. Infrastructure/configuration items (pin OPA >= 1.4.0, use capabilities API, harden bundle paths) are not Rego changes — they live in CI configuration. The directly actionable Rego changes are strong: add `default valid := false` to SoFREP, add `is_number` guard to `_in_range`, add meta-validation deny rules for `data.schema` invariants, add cross-field fund_balances key validation. The data document poisoning defense (Rec 6) and the `_in_range` type guard (Rec 5) are each single-function changes. The ratio checks (Rec 7) and plausibility bounds (Rec 9) require new threshold data and new deny rules — achievable in one session but not trivial. Roughly 6 of 10 recommendations are direct Rego changes.

**Output E** recommendations are almost entirely one-session Rego or config changes. Every improvement section includes a before/after code snippet. The Regal config YAML is ready to copy in. The SoFREP test isolation improvement is a self-contained data injection block. The `default valid := false` fix is two lines. The inline set extraction is a named-rule refactor. The double-negation fix is a helper function. The metadata block is a copy-paste. The main exception is R-E19 (JSON schema for input/data type checking), which requires schema authoring.

**Verdict:** E is more immediately actionable — nearly every recommendation ships with exact before/after code. C's actionable items are fewer and some (plausibility bounds, cross-field ratios) require design decisions about threshold values before code can be written.

- **Output C Actionability: 6**
- **Output E Actionability: 9**

---

### Dimension 5: Cross-pollination (do the outputs combine to create something neither produced alone?)

This is the synthesis dimension — does the pairing unlock new insight?

**C's data document poisoning threat (Finding 5.1) + E's inline test data pattern (R-E14):**
C identifies that `data.schema` and `data.thresholds` are a single-point-of-failure attack surface — if they are empty or corrupted, all validation silently passes. E identifies that SoFREP tests depend on external data files rather than inline data, meaning tests cannot exercise the "missing data document" failure mode. Together: the fix for both problems is the same — inline the schema in tests AND add meta-validation deny rules that fire when the data documents fail invariant checks. Neither output connected these two problems to the same root cause (dependency on external data at evaluation time).

**C's type confusion gap (Finding 2.2) + E's `_in_range` function signature (R-E10):**
C identifies that SoFREP's `_in_range(v, lo, hi)` has no `is_number(v)` guard — a string input passes the range check for wrong reasons due to Rego's cross-type ordering. E identifies that `_in_range` references `input` implicitly and should accept arguments instead. Together: the full fix is `_in_range(v, lo, hi) if { is_number(v); v >= lo; v <= hi }` where `v` is passed explicitly rather than read from `input`. Neither output stated the complete two-part fix; C had the type guard requirement, E had the argument-passing requirement.

**C's cross-field ratio checks (Rec 7, Wirecard) + E's inline enum set extraction (R-E03/R-E11):**
C proposes ratio checks (income-to-expenditure, revenue-to-cash-flow) as new deny rules. E's pattern shows how to pre-compute named sets for repeated enum lookups. The same pattern applies to ratio check thresholds — instead of hardcoding `0.8` inside a deny rule, extract `_income_ratio_bounds := { ... }` as a named rule drawing from `data.thresholds`. C supplied the what; E supplied the how.

**C's undefined-vs-false gap (Finding 2.3) + E's test isolation gap (R-E14):**
C explains why `valid` can be `undefined` when `data.schema` is missing. E shows that SoFREP tests load schema from external files. The combined observation: no test currently exercises the `data.schema`-absent scenario, which is the exact scenario where the `default valid := false` fix matters most. A test that calls `standard.valid` with `with data.schema as {}` (empty schema) should return `false`, not `undefined`. This specific test case is implied by the union of both outputs but appears in neither.

**Verdict:** The cross-pollination score reflects how much the pairing generates. C+E produce at least four distinct synthesis targets that neither output identified on its own. This is high cross-pollination yield.

- **Output C Cross-pollination: 9** (its external-domain insights become actionable when combined with E's code-level precision)
- **Output E Cross-pollination: 9** (its code-level patterns solve C's identified gaps precisely)

---

## Score Summary

| Dimension | Output C | Output E |
|---|---|---|
| Novelty | 8 | 8 |
| Divergence | 8 | 5 |
| Evidence | 10 | 7 |
| Actionability | 6 | 9 |
| Cross-pollination | 9 | 9 |
| **Total** | **41** | **38** |

---

## Winner: Output C

Output C wins 41–38. The margin is driven by two dimensions: divergence and evidence. C's failure archaeology imports insight from five distinct external domains (CVE advisories, Kubernetes policy engines, financial fraud, aerospace telemetry, military operations) and backs every finding with a live authoritative URL. These are not findings a practitioner would generate by reading the Rego style guide — they require active search across unrelated fields and the imagination to map their failure patterns onto a charity reporting policy engine.

Output E is the better implementation guide. It is more immediately executable and its before/after code snippets are ready to paste. But it is bounded by what a thorough reading of the OPA style guide and the two policy files would produce. A competent Regal run would surface most of E's findings automatically.

The decisive gap: C's two critical findings — data document poisoning (Rec 6) and the SoFREP `undefined` vs `false` gap under missing schema (Rec 3) — are the highest-severity items in either output, and they are grounded in CVE history and real-world exploit patterns, not just style conventions. When combined with E's code-level precision, they become a complete remediation plan.

---

## Top Insights Extracted

### From Output C

**C-1: Data Document Poisoning as a Policy Bypass Vector (Finding 5.1, Rec 6)**
An attacker who modifies `data.schema` (e.g., emptying `required_fields` or setting `reconciliation_tolerance` to 999999999) disables all validation without touching any `.rego` file. This is a threat model inversion — the data layer is as critical as the policy layer. Defense: add deny rules that assert data document invariants (`count(schema.required_fields) > 0`, `tolerance < 100`). Currently not covered in either policy.

**C-2: Type Confusion in `_in_range` — String Bypasses Range Check (Finding 2.2, Rec 5)**
Rego's cross-type ordering means any string is "greater than" any number. SoFREP's `_in_range(v, lo, hi)` lacks `is_number(v)` guard. A report submitting `"5"` (string) for a likelihood field bypasses the 1–5 range check entirely — the comparison evaluates to `true` for wrong reasons. One-line fix: add `is_number(v)` as first body predicate in `_in_range`.

**C-3: Plausibility Bounds — The Boeing MCAS Problem in Policy Form (Finding 4.1, Rec 9)**
Format-valid but substantively implausible data (a small charity reporting GBP 100M income) passes all current rules. MCAS accepted a sensor signal that was electrically valid but factually impossible. Both failed for the same structural reason: no cross-validation against expected magnitude. Fix: add `data.thresholds.max_plausible_income` and a deny rule that fires when `computed_income > threshold`.

### From Output E

**E-1: Identical Escalation Messages Silently Mask Trigger Count via Set Deduplication (R-E12)**
SoFREP's four escalation triggers (lines 299–313) all produce the same deny object with identical message strings. Because OPA deny sets deduplicate identical objects, all four triggers can fire simultaneously and still produce only one entry in the deny set. A caller inspecting the errors array sees one error and concludes only one trigger fired. Fix: include the trigger name or condition in the message string to make each object distinct.

**E-2: SoFREP Tests Depend on External Data Files — Cannot Test Missing-Schema Scenarios (R-E14)**
SoFA tests inject `data.schema` and `data.thresholds` inline via `with` keyword. SoFREP tests load them from external files, making the test suite non-portable and — critically — unable to test the exact scenario where `default valid := false` matters: a missing or empty schema document. Fix: inject schema inline using the `_schema` and `_thresholds` blocks shown in Improvement 5. Same pattern SoFA already uses.

**E-3: Double-Negation Anti-Pattern in SoFREP Metadata Check (R-E20)**
`not object.get(input, f, "") != ""` is a double negative that is hard to audit and reason about during security review. It appears in three separate metadata-check rules. Fix: extract to `_field_empty_or_missing(obj, field)` helper with `object.get(obj, field, "") == ""`. The helper is then independently queryable, testable in isolation, and reusable across all three callers.

---

## Cross-Pollination Opportunities

### XP-1: The Complete `_in_range` Fix (C-2 + E-10)

C identified the missing `is_number(v)` guard. E identified that helper functions should accept arguments rather than reading `input` directly. Neither stated the full fix. Combined:

```rego
_in_range(v, lo, hi) if {
    is_number(v)
    v >= lo
    v <= hi
}
```

This is a two-part repair: type safety (from C) and argument isolation for testability (from E). The current implementation fails both.

### XP-2: The Missing "Empty Schema" Test Case (C-3 + E-2)

C explains that when `data.schema` is absent, `count(errors)` may return 0, making `valid` true despite no validation having run. E shows that SoFREP tests never inject `data.schema` inline. Combined implication: no test currently verifies that `valid` returns `false` when called with a minimal or empty schema. This test case must be added:

```rego
test_valid_is_false_when_schema_missing if {
    not standard.valid
        with input as valid_input
        with data.schema as {}
        with data.thresholds as {}
}
```

This test would fail today (valid returns undefined, not false) and only passes after the `default valid := false` fix from Rec 3.

### XP-3: Meta-Validation Deny Rules Using Named-Set Pattern (C-1 + E-3/E-11)

C proposes meta-validation deny rules that assert `data.schema` invariants. E shows the pattern of extracting repeated inline constructions into named rules. Combined: the meta-validation rules should follow the same named-set pattern for their invariant checks, and the `data.thresholds` values they reference should be pre-computed named rules rather than inline literals:

```rego
# Meta-validation: assert the data documents themselves are valid
_schema_required_fields_present if {
    count(data.schema.required_fields) > 0
}

deny contains {"msg": "data.schema.required_fields is empty — all field validation disabled", "rule": "meta_schema", "severity": "critical"} if {
    not _schema_required_fields_present
}

deny contains {"msg": sprintf("data.schema reconciliation_tolerance out of bounds: %v", [data.schema.reconciliation_tolerance]), "rule": "meta_schema", "severity": "critical"} if {
    t := data.schema.reconciliation_tolerance
    is_number(t)
    t >= 100
}
```

This combines C's threat model (data document poisoning) with E's structural patterns (named rules, type guards, descriptive messages).

### XP-4: Escalation Trigger Deduplication Fix Enables Downstream Risk Scoring (C-3 + E-1)

C proposes plausibility bounds as deny rules. E identifies that escalation trigger deduplication masks trigger count. If multiple plausibility violations fire simultaneously but produce identical deny objects, the severity signal is lost — a report with 5 implausibility violations looks the same as a report with 1. The fix for E-1 (unique trigger messages) is also the prerequisite for any future severity-scoring logic that counts the number of fired rules.

---

## Recommended Immediate Implementation Order

Based on combined analysis, priority order for a single implementation session:

1. **`default valid := false` in SoFREP** — two lines, highest severity, prerequisite for XP-2 test
2. **`is_number(v)` guard in `_in_range`** — one line, closes confirmed type confusion bypass
3. **XP-2 empty-schema test** — verifies fix #1 actually closes the gap
4. **Escalation message differentiation** — fixes silent deduplication, enables future severity counting
5. **Meta-validation deny rules for `data.schema`** — closes data document poisoning vector
6. **SoFREP test data inline injection** — decouples tests from external files, enables portable CI

Items 7–10 from C's table (ratio checks, plausibility bounds) require threshold design decisions before code can be written and belong in a separate design session.
