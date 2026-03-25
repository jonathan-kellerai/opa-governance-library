# Phase 2 Judgment: Round 3, Match 2 — Output B vs Output F

- **Match:** R3-M2
- **Output B:** XD-2 (Academic / Formal Methods) — "Formal Methods for Policy Validation Completeness"
- **Output F:** DS-3 (Attack Surface Mapper) — "Attack Surface Analysis"
- **Judge:** Strategic Reasoner (claude-sonnet-4-6)
- **Date:** 2026-03-25

---

## Scoring Rubric

Each dimension scored 0–10. Higher = better.

| Dimension | Definition |
|-----------|------------|
| **Novelty** | Does this insight appear in the other output? Lower overlap = higher score. |
| **Divergence** | How far from obvious/expected for this domain? |
| **Evidence** | Backed by real, cited sources? |
| **Actionability** | Can this become a Rego rule/test/data change in one session? |
| **Cross-pollination** | Combines with the OTHER output to create something neither produced alone? |

---

## Output B — Formal Methods (XD-2)

### Dimension Scores

| Dimension | Score | Reasoning |
|-----------|-------|-----------|
| **Novelty** | 8/10 | None of B's six techniques — PBT, mutation testing, MC/DC coverage, invalidity taxonomy, SMT/Z3 encoding, differential testing — appear in F. F is entirely runtime/structural; B is entirely verification-theoretic. Near-zero overlap. |
| **Divergence** | 9/10 | Applying NASA DO-178C avionics coverage standards (MC/DC) to OPA policy testing is a genuinely non-obvious cross-domain transfer. Porting XACML mutation operators to Rego, and referencing Cedar's Lean 4 proof assistant as a model for Rego verification, are both far outside the expected "write more unit tests" advice. |
| **Evidence** | 9/10 | Every recommendation cites peer-reviewed or production sources: XACMUT (IEEE 2013), Fault Model paper (WWW 2007, Purdue), MC/DC (NASA NTRS), Zelkova (FMCAD 2018), Cedar arXiv paper, Teleport RBAC linter (open source, verifiable). No invented citations detected. |
| **Actionability** | 5/10 | Mixed. Differential testing (`diff_test.sh`) is genuinely one-session implementable. MC/DC coverage analysis as a script against `opa test --coverage` output is achievable in a session. But mutation testing requires AST manipulation of `.rego` files, and Z3 encoding of Rego rules is multi-session research work. Scores lower because the most novel recommendations (SMT, mutation) are multi-session. |
| **Cross-pollination** | 9/10 | B's techniques directly amplify F's findings in ways neither output reaches alone (see Cross-Pollination section below). B gives F the measurement apparatus; F gives B the specific attack targets. |

**Output B Total: 40/50**

### Strongest Insights from B

**B-1: MC/DC Coverage as the Missing Standard**
OPA's `opa test --coverage` measures statement coverage only — the weakest meaningful metric. NASA's DO-178C Level A requires MC/DC: each condition in a multi-conjunct rule must be shown to independently affect the outcome, requiring n+1 test cases for n conditions. A SoFA deny rule with 4 conjuncts needs 5 test cases minimum. The current tooling cannot detect whether this bar is met. This is the highest-value measurement gap in the entire ecosystem, and it is backed by a NASA standard rather than opinion.

**B-2: Mutation Testing via XACML Operator Taxonomy**
The XACML mutation literature defines six operator classes (comparison swap, conjunct removal, negation insertion, default value change, rule deletion, quantifier swap) that map directly onto Rego syntax. The "conjunct removal" operator is especially potent: if removing a condition from a deny rule does not cause any existing test to fail, that condition has no independent test coverage. This is a structural gap detector, not just a coverage reporter. The technique is proven for policy languages; only Rego-specific tooling is absent.

**B-3: Differential Testing for Version Transitions**
The v1-to-v4 progression of SoFA/SoFREP creates exactly the scenario differential testing was designed for. A single script comparing `opa eval -d v3/ -i corpus/` against `opa eval -d v4/ -i corpus/` surfaces decision regressions and unintended behavioral changes. Cedar's production use of this technique (Rust implementation vs. Lean formal model) provides existence proof. This is the lowest-effort, highest-return recommendation in B — one session, no new dependencies.

---

## Output F — Attack Surface Analysis (DS-3)

### Dimension Scores

| Dimension | Score | Reasoning |
|-----------|-------|-----------|
| **Novelty** | 9/10 | F's findings are almost entirely absent from B. B does not touch data-document kill switches, the `not input[f]` false-positive on zero values, the `default valid` asymmetry between SoFA and SoFREP, the double-negation falsy-value blindness, or the minimum-viable-valid-input bypass. These are original structural findings about this specific codebase. |
| **Divergence** | 8/10 | The data-document kill switch analysis (Section C) is non-obvious: F identifies that `fund_types = []` is not a permissiveness kill switch but a DoS vector — every item fires an error because `not item.fund_type in {}` is always true. This is a counter-intuitive inversion of the expected threat direction and distinguishes F from generic "missing field" analysis. The minimum-viable-valid-input skeleton (Section G) demonstrating a financially meaningless document passes all checks is also a divergent framing. |
| **Evidence** | 7/10 | F cites specific file paths and line numbers throughout, making every finding verifiable against the actual `.rego` source. This is high-quality empirical evidence, though it lacks external academic or specification citations. The confidence ratings are calibrated (High/Medium) and the one finding marked as "actually correct" (D-3 likelihood default) demonstrates intellectual honesty. Docked 3 points for no external sources. |
| **Actionability** | 10/10 | Every one of F's 12 recommendations maps to a specific file and line number and can be implemented in a single session. Recommendation 2 (add `default valid := false` to SoFREP) is one line. Recommendation 1 (sentinel rules for missing data documents) is 3–4 lines of Rego. Recommendation 3 (replace `not input[f]` with explicit key check) is a targeted Edit. This is the highest-actionability output in the tournament to date. |
| **Cross-pollination** | 8/10 | F's attack surface catalog is the ideal input corpus for B's verification techniques. F identifies 13 SoFA silent-non-firing vectors and 9 SoFREP vectors — these are exactly the invariant classes B's PBT harness and invalidity taxonomy should enumerate. Neither output alone bridges this; together they form a closed loop. |

**Output F Total: 42/50**

### Strongest Insights from F

**F-1: Data-Document Kill Switches — Two Distinct Threat Classes**
F distinguishes two fundamentally different kill-switch threat classes: (a) setting a list to `[]` which disables iteration-based rules entirely (e.g., `required_fields = []` silently disables all required-field checks), and (b) setting a list to `[]` which inverts to a DoS vector (e.g., `fund_types = []` causes `not item.fund_type in {}` to always be true, rejecting every item). The second class is counter-intuitive and dangerous: an attacker or misconfigured deployment does not get a bypass — it gets a complete validation failure for all inputs. These require different mitigations: class (a) needs sentinel guards; class (b) needs minimum-length guards on schema arrays.

**F-2: The `default valid` Asymmetry**
SoFA has `default valid := false` (safe-fail) but SoFREP has `valid := count(errors) == 0` with no default. When `deny` is undefined — which happens whenever `data.schema` is missing and no rules fire — `errors` is undefined, `count(errors)` is undefined, and `valid` is undefined. Not false. Not true. Undefined. Consumers get no value. SoFA's `default` prevents this; SoFREP's absence of one creates a third state that neither validates nor rejects. This is a one-line fix with high severity.

**F-3: The `not input[f]` False-Positive on Zero**
`sofa.rego:45` uses `not input[f]` to test required-field presence. In Rego, `not input[f]` evaluates to true when `input[f]` is any falsy value: `0`, `false`, `""`, `[]`, `{}`, `null`. If `net_movement` is legitimately `0` — a valid financial state for a break-even period — the required_field rule fires an error claiming the field is missing. This is a false positive that will produce spurious validation failures on real data. The fix requires replacing `not input[f]` with `not _key_present(input, f)` using an explicit key-presence check (`f in input` or `object.get(input, f, "__MISSING__") == "__MISSING__"`).

---

## Winner

**Output F wins: 42/50 vs. 40/50**

### Margin Analysis

The margin is narrow (2 points). The decisive difference is Actionability: F scores 10/10 against B's 5/10. F's findings are all implementation-ready with specific file and line coordinates; B's most novel recommendations (Z3 encoding, mutation testing) require multi-session investment. On all other dimensions the outputs are competitive: B leads on Divergence (9 vs. 8) and Evidence (9 vs. 7); F leads on Novelty (9 vs. 8) and Actionability (10 vs. 5); Cross-pollination is near-tied (8 vs. 9 favoring B).

The judgment is not "F is better research than B." B's formal methods framing is more academically rigorous and more divergent from conventional OPA advice. The judgment is "F delivers more deployable value per insight in a single session" — which is the scoring criterion.

---

## Cross-Pollination Opportunities

These are synthesis opportunities that neither output produced alone.

### XP-1: Mutation Testing Targets F's 22 Silent Non-Firing Vectors

F identified 22 specific rules across SoFA and SoFREP that can be silenced by omitting or manipulating input fields or data documents. B identified the conjunct-removal mutation operator as the highest-value mutation operator: if removing a condition does not cause any test to fail, that condition has no independent test.

**Synthesis:** Use F's 22 silent-non-firing findings as the seed list for B's mutation testing harness. Each entry in F's tables is a specific "this condition can be silenced" observation — exactly the class of defect conjunct-removal mutation testing is designed to catch. Running B's `mutate_rego.py` against the rules in F's tables would produce a prioritized mutation score: rules that F identified as vulnerable AND that have low mutation scores are the highest-priority fixes.

**Artifact:** `mutation_targets.json` — a machine-readable list of rule names, file:line coordinates, and the specific missing-field bypass vector, derived from F's tables and structured as input to B's mutation harness.

### XP-2: F's Kill-Switch Catalog Defines B's Invalidity Taxonomy

B recommended building an "invalidity taxonomy" — a finite enumeration of invalid input categories — as a bounded completeness metric. B proposed 5 categories: missing fields, wrong types, out-of-range values, invalid cross-field combinations, format violations. F produced 34 specific invalidity vectors across 12 recommendation entries.

**Synthesis:** F's Section B tables (22 silent non-firing vectors) and Section C table (12 kill-switch configurations) directly populate B's invalidity taxonomy. The taxonomy becomes concrete and codebase-specific rather than abstract. Each entry in F's tables maps to one or more of B's five categories, plus adds a sixth: data-document manipulation. A single `invalidity_matrix.md` combining both outputs would be the most complete policy test specification this codebase has ever had.

**Artifact:** `invalidity_matrix.md` — rows from F's findings, columns from B's taxonomy categories, with traceability to deny rules and test cases.

### XP-3: Differential Testing Catches F's `default valid` Regression Class

F found that SoFREP lacks `default valid := false`, meaning a missing data document produces `valid = undefined` instead of `valid = false`. If this is ever fixed (or ever broken by a refactor), no existing test will catch the regression — because the scenario requires running the policy without its data document, which is not in any standard test fixture.

**Synthesis:** B's differential testing harness (`diff_test.sh`) can be extended to run policies against a corpus that includes a "no data document" input — a JSON input evaluated without any `data.*` bindings. Comparing the output of `opa eval -d policy/ -i corpus/no_data_test.json` against `opa eval -d policy/ -d data/ -i corpus/no_data_test.json` would immediately surface any `valid = undefined` vs `valid = false` divergence. This turns F's structural finding into a regression test that runs on every policy version transition.

**Artifact:** `corpus/no_data_doc.json` (empty input with no data bindings) + one test case in `diff_test.sh` that asserts `valid` is defined and false when data documents are absent.

### XP-4: PBT Harness Boundary Cases Target F's Numeric False-Positive

F found that `not input[f]` false-positives on `net_movement: 0`. B's property-based testing harness is designed to generate random JSON inputs including boundary values (`0`, empty arrays, null fields). The specific invariant "a document with `net_movement: 0` must not produce a required-field error for `net_movement`" is exactly the kind of invariant a PBT harness can assert and randomly verify across all numeric fields.

**Synthesis:** Add a monotonicity invariant to B's PBT harness: "Adding a valid zero-value numeric field to a document that currently fails required-field validation must not cause a new required-field error for that field." This directly tests for the class of false positives F identified at `sofa.rego:45`, and generalizes it across all numeric required fields in the schema.

**Artifact:** One Hypothesis strategy in `fuzz_inputs.py` that generates inputs where any numeric required field is set to exactly `0`, asserting the required_field rule does not fire for that field.

---

## Summary Table

| Dimension | Output B Score | Output F Score |
|-----------|---------------|---------------|
| Novelty | 8/10 | 9/10 |
| Divergence | 9/10 | 8/10 |
| Evidence | 9/10 | 7/10 |
| Actionability | 5/10 | 10/10 |
| Cross-pollination | 9/10 | 8/10 |
| **Total** | **40/50** | **42/50** |

**Winner: Output F (42/50)**
**Runner-up: Output B (40/50)**
**Match verdict: F advances. B eliminated.**

---

## Extracted Learnings

1. **Actionability is the swing dimension in close matches.** When two outputs are comparable in quality, the one with specific file:line coordinates and one-session implementability wins because it generates immediate value. Abstract correctness (B's SMT encoding) loses to concrete deployability (F's `default valid := false`) on the actionability axis.

2. **The highest-value cross-pollination is measurement apparatus meeting attack surface.** B provides the tools to measure; F provides the targets to measure against. Neither is complete alone. The synthesis artifacts (mutation_targets.json, invalidity_matrix.md) are more valuable than either output individually.

3. **Counter-intuitive threat inversions deserve top marks.** F's finding that `fund_types = []` is a DoS vector rather than a bypass — the opposite of the expected threat direction — is the kind of divergent insight that separates attack-surface analysis from a checklist review. Findings that invert the expected threat model should be flagged as high-priority for inclusion in test corpora.

4. **Absence of external citations does not disqualify empirical findings.** F's evidence base is file:line citations against real source code. This is sufficient for high-confidence findings when the sources are verifiable in the repository. The Evidence dimension should weight empirical verifiability, not just academic citation density.
