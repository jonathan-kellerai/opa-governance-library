# R1-M3: E (Rego Patterns) vs F (Attack Surface)

- **Judge:** Strategic Reasoner Agent
- **Date:** 2026-03-25
- **Inputs:** phase1-output-E-rego-patterns.md, phase1-output-F-attack-surface.md

---

## Score Table

| Dimension | E | F |
|-----------|---|---|
| Novelty | 9 | 8 |
| Divergence | 5 | 8 |
| Evidence | 9 | 8 |
| Actionability | 9 | 7 |
| Cross-pollination | 7 | 8 |
| **TOTAL** | **39** | **39** |

---

## Winner: F by divergence tiebreak

Raw totals are tied at 39–39.
The tiebreak criterion is Divergence, the dimension hardest to manufacture and most valuable for surfacing non-obvious work.
F scored 8 vs E's 5 on Divergence.
F wins R1-M3.

**Rationale for the gap:** E is an expert-level application of a known discipline — OPA style guide compliance — to an existing codebase.
Every finding is well-grounded and immediately usable, but all findings were in-scope for any senior Rego reviewer.
F frames the same policies as an adversarial surface and asks a different question: "how would a motivated actor or misconfigured deployment bypass every rule?"
That reframing produces findings that would not appear in any style guide: the data-document kill switch table, the DoS inversion vector, and the minimum viable valid input skeleton.

---

## Top Insights from E

### E-1: Identical escalation messages cause silent trigger-count masking (R-E12)

SoFREP's four escalation trigger rules (lines 299–313) all produce the identical deny object.
Because `deny` is a set, all four collapse to one entry regardless of how many triggers are active.
A report with all four escalation conditions simultaneously active is indistinguishable from one with a single trigger.
Fix: differentiate the `msg` field per trigger (e.g., include the trigger condition name), restoring the full count to consumers.
This is a non-obvious consequence of OPA set semantics that a normal code review would miss.

### E-2: `default valid := false` absence leaves SoFREP's entrypoint undefined on data-document failure (R-E04)

SoFREP's `valid := count(errors) == 0` (line 322) has no `default` declaration.
If `data.schema` is absent, `errors` is undefined, and `valid` is undefined — not `true`, not `false`.
Consumers checking `data.sofrep.standard.valid` receive no value.
SoFA already uses `default valid := false` (line 238), providing a safe-closed baseline.
This is a one-line fix with a material behavioral difference in failure modes.

### E-3: SoFREP tests couple to external data files, breaking portability (R-E14)

SoFREP's test file relies on `data.schema` and `data.thresholds` being loaded from companion files rather than injected inline via `with data.schema as ...`.
SoFA's tests already inject both inline (sofa_test.rego lines 8–25).
The consequence: SoFREP tests break if the schema files are renamed, moved, or evolved, and cannot be run in isolation.
The fix is a direct port of SoFA's pattern, with a complete before/after snippet provided in the output.
Also demonstrates the backtick raw-string fix for date regex patterns (R-E08).

---

## Top Insights from F

### F-1: Data-document kill switches — threshold manipulation disables rules without a trace (Section C)

Every threshold value in `data.thresholds` is an unconstrained number.
Setting `reconciliation_tolerance` to `999999999` silently passes all reconciliation checks.
Setting `materiality_floor` to `0` disables all materiality warnings.
Setting `going_concern_periods` to `999` means going-concern never fires.
These are not edge cases: any deployment that loads a wrong or tampered `data.thresholds` document gets a policy that produces no findings.
No finding in Output E addresses this; it requires a separate validation layer on the data document itself.

### F-2: Empty enum arrays invert from kill switch to denial-of-service (Section C)

Setting `data.schema.fund_types = []` does not disable the fund-type check — it inverts it.
`not item.fund_type in {}` is always true, so every item with any `fund_type` value fires an error.
An attacker or misconfiguration that zeroes out enum arrays causes the policy to reject all valid input rather than accepting all invalid input.
This is a qualitatively different failure mode (service disruption vs. bypass) that falls out of the same data-document attack surface.
Output E has no corresponding finding.

### F-3: Minimum viable valid input — empty arrays game SoFA's structural completeness (Section G)

The smallest JSON blob that passes all SoFA validation is a 9-field document with empty arrays for `incoming_resources` and `resources_expended` and empty objects for `fund_balances` and `reconciliation`.
Because every line-item rule guards on iteration over the array, an empty array means zero deny entries.
A charity reporting zero income, zero expenditure, no funds, and no reconciliation passes the validator as a "valid" SoFA report.
This is a minimum-substance gap, not a style issue, and requires new rule logic to close.

---

## Cross-Pollination Opportunities

### CP-1: Fail-closed hardening session (F-A1 + F-E2 + E-E04)

F's sentinel rule finding (Section A: missing `data.schema` causes all rules to silently skip) combined with E's `default valid := false` fix (R-E04) and E's per-rule metadata blocks (R-E02) form a single coherent "fail-closed hardening" session.
The three changes are independent but together ensure: (1) the policy detects its own data-document absence, (2) `valid` returns `false` rather than undefined when data is missing, and (3) structured error codes in metadata blocks allow consumers to distinguish "missing data" errors from "invalid input" errors.
Neither output proposes this trio as a combined deliverable.

### CP-2: `data.thresholds` validation policy (F-Section C + E-R-E19)

F identifies that unconstrained threshold values are a kill-switch attack surface.
E identifies that OPA supports JSON schema annotations for strict type checking (R-E19).
Combined: write a companion `data_validation.rego` policy that applies range guards to every threshold value (e.g., `reconciliation_tolerance` must be between 0 and 1000; `going_concern_periods` must be between 1 and 24).
This is a new artifact that neither output proposes: a policy that validates the data document rather than the input document.
It closes F's kill-switch class without modifying the primary policy rules.

### CP-3: Falsy-value-safe `_field_present` helper (F-D1/D2 + E-R-E06/R-E10)

F identifies two complementary type confusion bugs: SoFREP's double-negation treats `0`, `false`, and `null` as "present" (D-1), while SoFA's `not input[f]` treats `0` and `false` as "missing" (D-2).
E's helper-function extraction pattern (R-E06) and the recommendation to pass `input` as an argument (R-E10) provide the implementation scaffold.
Combined, these generate a single reusable helper:

```rego
# Returns true if the field is present and semantically non-empty.
# Handles OPA falsy-value edge cases: 0, false, null, "", [], {}.
_field_present(obj, field) if {
    val := object.get(obj, field, _sentinel)
    val != _sentinel
    not val == null
    not val == ""
    not val == 0
    not val == false
    not val == []
    not val == {}
}
_sentinel := "__MISSING__"
```

Neither output writes this helper or identifies that both policies need it for different reasons.

### CP-4: Anti-fixture test pattern (F-Section G + E-R-E14)

F's minimum viable valid input analysis (Section G) proves that certain structurally empty inputs currently pass validation when they should fail.
E's test isolation pattern (R-E14) provides the mechanism: inline data injection via `with input as ...`.
Combined, these motivate a new test category: "anti-fixtures" — test cases that are expected to fail but currently pass, committed before the fix to prove the gap exists.
This is the TDD inversion of normal test writing and would give the policy a regression baseline for the minimum-substance rules that F recommends adding.
Neither output proposes this as a test strategy.
