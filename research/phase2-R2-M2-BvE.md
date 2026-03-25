# Phase 2 — Round 2, Match 2: B (Formal Methods) vs E (Rego Patterns)

- **Output B Agent:** XD-2 (Academic/Formal Methods)
- **Output E Agent:** DS-2 (Rego Pattern Library)
- **Judge:** Strategic Reasoner
- **Date:** 2026-03-25

---

## R2-M2: B (Formal Methods) vs E (Rego Patterns)

### Score Table

| Dimension | B | E |
|---|---|---|
| Novelty | 9 | 7 |
| Divergence | 9 | 5 |
| Evidence | 9 | 8 |
| Actionability | 6 | 9 |
| Cross-pollination | 8 | 8 |
| **TOTAL** | **41** | **37** |

---

### Winner: B by 4 points

---

### Scoring Rationale

#### Novelty (B: 9, E: 7)

B introduces six techniques with zero overlap with E: property-based testing (PBT via
Hypothesis), mutation testing (XACMUT operators translated to Rego), MC/DC coverage,
decidability/PSPACE-completeness analysis, SMT-based verification via Z3, and differential
testing.
None of these concepts appear anywhere in E.

E introduces 20 numbered findings, but several converge on the same root theme: "style
guide violations in the existing codebase."
Findings R-E01 through R-E20 are distinct line-level issues, but they cluster around
two ideas (add metadata, fix repeated inline set construction) that are variations on
the same practice gap.
The R-E12 finding (identical escalation messages collapsing in a set) and R-E04
(`default valid := false`) are genuinely novel relative to B.
Score docked to 7 because the majority of findings are style-guide audits rather than
novel concepts.

#### Divergence (B: 9, E: 5)

B departs furthest from the obvious.
Applying MC/DC (a NASA avionics standard) to Rego validation, translating XACML
mutation operators into a Rego AST mutation tool, and encoding allow/deny logic as Z3
constraints are all non-obvious moves.
The connection between Cedar's Lean 4 proof assistant and what is missing in OPA is a
genuine conceptual leap.

E stays close to the ground.
Its recommendations are derivable by anyone who reads the Rego style guide and diffs
SoFA vs SoFREP.
The pre-computed enum sets and `default valid := false` insights are practical but
expected for anyone with OPA experience.
R-E12 (set deduplication masking escalation trigger count) is the one genuinely
non-obvious finding.

#### Evidence (B: 9, E: 8)

B cites 24 sources with specific URLs: IEEE papers (XACMUT 2013, WWW 2007 fault model,
IEEE 2013 regression selection), NASA DO-178C documentation, CNCF TAG Security formal
verification overview, arXiv Cedar paper, Amazon Science blog posts, and a Springer
chapter on policy coverage.
Every recommendation is backed by a named published source.

E cites real file paths with line numbers for every finding (e.g., "sofrep.rego lines
78-101", "sofa_test.rego line 10"), which is strong for the codebase-audit claims.
External tool citations (Regal, rego-test-assertions, pre-commit-opa) are real GitHub
repositories.
Score is 8 rather than 9 because the style-guide citations are all to a local file
path rather than a canonical URL, making them slightly harder to independently verify.

#### Actionability (B: 6, E: 9)

E wins this dimension clearly.
Every recommendation maps to a specific file, specific line number, and a before/after
code snippet.
Improvement 3 (add `default valid := false`) is a two-line change.
Improvement 4 (fix double-negation) is a five-line refactor.
Improvement 5 (inline test data) includes the complete replacement block.
A developer could implement all five improvements in a single two-hour session.

B's recommendations require building new tools: a Hypothesis harness, a Python AST
mutation engine, a differential testing shell script, a Z3 encoder.
The differential testing harness (Rec 6) is the most actionable and could be written in
one session.
The mutation tool and Z3 encoder are multi-session research efforts.
Score is 6 because two of the six recommendations (diff testing, invalidity taxonomy)
are genuinely one-session deliverables, but the highest-impact ones (mutation testing,
Z3 encoding) are not.

#### Cross-pollination (B: 8, E: 8)

Both outputs score equally on cross-pollination potential because the two research
streams are maximally complementary — E provides the exact symptom map that B's
techniques need as targets.

The combination creates several synthesis opportunities neither output produces alone
(see section below).
Both receive 8 rather than 10 because neither output explicitly anticipates the other
or points toward the synthesis.

---

### Top Insights from B

1. **MC/DC coverage gap in OPA tooling.**
   `opa test --coverage` measures only statement coverage (level 1 of 4).
   For a rule with four conjuncts — such as the SoFA deny rule requiring missing amount
   AND invalid currency AND missing date AND wrong format — MC/DC requires at least five
   test cases demonstrating each conjunct independently affects the outcome.
   OPA cannot tell you whether you have them.
   This is the single most underappreciated gap in the current test suite.
   Source: NASA DO-178C; Springer 2006 policy coverage paper.

2. **Differential testing as a low-effort regression guard for policy evolution.**
   A single shell script running `opa eval -d v3/ -i corpus/` against
   `opa eval -d v4/ -i corpus/` and diffing the output catches unintended behavioral
   changes across every policy version transition.
   Estimated effort: one session.
   Source: Cedar differential testing methodology (Amazon Science); IEEE 2013 regression
   selection paper.

---

### Top Insights from E

1. **Identical escalation trigger messages collapse to one entry in the deny set.**
   SoFREP's four escalation triggers (sofrep.rego lines 299-313) all emit the same
   message string.
   Because Rego sets deduplicate identical objects, a report hitting all four triggers
   still shows only one deny entry, silently masking that multiple escalation conditions
   are simultaneously active.
   This is a silent correctness bug, not a style issue.
   One-session fix: add the trigger type as a field in each deny object.
   Source: sofrep.rego lines 299-313; rego-cheat-sheet OR pattern.

2. **`default valid := false` missing from SoFREP is a fail-open vulnerability.**
   SoFREP's `valid := count(errors) == 0` (line 322) produces `undefined` — not `false`
   — if `data.schema` is absent or `errors` is undefined.
   An undefined `valid` can be interpreted as passing by some callers.
   SoFA already uses `default valid := false` (line 238) as a fail-closed guard.
   Source: sofrep.rego line 322 vs sofa.rego line 238; style-guide lines 286-331.

---

### Cross-Pollination Opportunities

1. **Mutation score as a target metric for E's style improvements.**
   E identifies that SoFREP's inline enum set construction appears at lines 81, 91, and
   100.
   If those three deny rules share structurally identical conditions, a "conjunct removal"
   mutation operator (B, Rec 2) applied to them would fail to be caught by the current
   test suite precisely because SoFREP tests depend on external data files (E, R-E14)
   rather than inline injection.
   The synthesis: fix E's R-E14 (inline test data) first, then run B's mutation tool to
   measure how many of E's refactored rules are independently tested.

2. **Differential testing corpus seeded from E's policy-violation inventory.**
   B's differential testing harness (Rec 6) requires a shared input corpus.
   E's policy-specific violation tables (Section 4) enumerate the exact categories of
   invalid input for SoFA and SoFREP: missing metadata fields, wrong enum values,
   identical escalation triggers, double-negation conditions.
   These are the seed corpus for the diff harness.
   Neither output makes this connection: E provides the corpus taxonomy, B provides the
   evaluation engine.

3. **MC/DC test generation guided by E's helper-rule refactoring.**
   B's Rec 3 requires identifying rules with multiple conjuncts for MC/DC analysis.
   E's R-E06 recommends extracting complex deny rule heads into named helper rules.
   If E's refactoring is applied first, each conjunct becomes a named, independently
   queryable rule — exactly the structure needed to generate MC/DC test cases
   systematically.
   The synthesis sequence: apply E's helper-rule extraction, then use B's MC/DC
   analysis to generate the required n+1 test cases per rule.

4. **Z3 verification of R-E12 (escalation deduplication bug).**
   E identifies that identical escalation messages deduplicate in the deny set.
   B's Z3 approach (Rec 5) could formally verify the property: "for inputs triggering k
   distinct escalation conditions, the deny set contains exactly k entries."
   This is a bounded, encodable property — more tractable than full policy verification.
   The synthesis turns E's observed bug into a formal specification that Z3 can check
   for all possible escalation input combinations.

5. **PBT harness parameterized by E's enum constraint discoveries.**
   B's Hypothesis-based fuzzer (Rec 1) needs to know the input schema to generate
   valid-but-boundary inputs.
   E's R-E03 and R-E11 document the exact enum sets used in SoFREP
   (`classification`, `priority`, `urgency`).
   The PBT harness should treat these as constrained domains — generating inputs that
   are structurally valid but contain out-of-range enum values — precisely the category
   of invalid input that E's inline set construction anti-pattern is most likely to
   mishandle.
