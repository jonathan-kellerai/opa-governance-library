# Research Output B: Formal Methods for Policy Validation Completeness

- **Agent:** XD-2 (Academic/Formal Methods)
- **Date:** 2026-03-25
- **Scope:** Property-based testing, mutation testing, coverage metrics, decidability, model checking, and differential testing as applied to OPA/Rego policy validation

---

## 1. Property-Based Testing for Policies

### Finding

Property-based testing (PBT) --- exemplified by Haskell's QuickCheck and Python's Hypothesis --- generates random inputs and checks that stated invariants (properties) hold across all of them. PBT is essentially the same practice as fuzzing at a certain level of abstraction, but with structured input generation and automatic shrinking of counterexamples. Coverage-guided property-based testing (CGPT), as described in the FuzzChick paper from UPenn/UMD, combines PBT with AFL-style coverage instrumentation to bias input generation toward uncovered code paths.

No published work applies PBT directly to OPA/Rego policies. However, the technique maps cleanly: Rego policies are pure functions from `input` (JSON) to decisions (allow/deny plus structured output). A PBT harness would generate random JSON `input` documents conforming to a schema and verify that invariants hold, such as:

- **Monotonicity:** Adding a valid field never causes a previously-passing document to fail.
- **Completeness of denial:** Every document missing a required field is denied.
- **Idempotency:** Evaluating the same input twice produces the same result.
- **No vacuous truth:** At least one generated input triggers each deny rule.

For financial validation policies, key invariants include: amounts are never negative when approved, currency codes conform to ISO 4217, and approval thresholds are strictly enforced (not off-by-one).

### Maturity Level

Mature for general software (QuickCheck: 25+ years). **Unapplied** to Rego specifically. Implementation would require a custom harness using `opa eval` or the Go/Wasm SDK.

### Recommendation 1

**Technique:** Build a PBT harness that generates random `input` JSON from the policy's expected schema and asserts invariants against `opa eval` output.

- **Source:** [FuzzChick: Coverage-Guided Property-Based Testing (UPenn)](https://lemonidas.github.io/pdf/FuzzChick.pdf); [Hypothesis: What is PBT?](https://hypothesis.works/articles/what-is-property-based-testing/)
- **Confidence:** Medium --- no Rego-specific tooling exists, but the technique is well-understood and the mapping is direct.
- **So what for Rego:** A Hypothesis-based harness generating random SoFA/SoFREP input documents would catch edge cases (empty arrays, null fields, boundary amounts) that hand-written tests miss.

---

## 2. Mutation Testing for OPA Policies

### Finding

Mutation testing measures test suite adequacy by injecting small faults (mutants) into the code under test and checking whether tests detect them. The XACMUT framework (IEEE, 2013) defines mutation operators specific to access control policies: changing `permit` to `deny`, altering comparison operators (`>` to `>=`), removing conjuncts from conditions, and swapping attribute references. The paper "A Fault Model and Mutation Testing of Access Control Policies" (WWW 2007, Purdue) established that mutation analysis is an effective approach for measuring the adequacy of policy test suites. A later NSF-funded project on "Automated Strong Mutation Testing of XACML Policies" demonstrated that test suites generated from all mutants of a policy can achieve a perfect mutation score.

No mutation testing framework exists for Rego specifically. The OPA ecosystem search for "mutation" returns results about Kubernetes admission controller mutations (Gatekeeper Assign/AssignMeta), which is a different concept entirely.

### Applicable Mutation Operators for Rego

Adapting from the XACML mutation literature, Rego-specific operators would include:

| Operator | Example Mutation | What It Tests |
|----------|-----------------|---------------|
| Comparison swap | `amount > 10000` becomes `amount >= 10000` | Boundary condition tests |
| Conjunct removal | Remove one condition from a rule body | Tests for necessary conditions |
| Negation insertion | `not valid_currency` becomes `valid_currency` | Tests for correct polarity |
| Default value change | `default allow := false` becomes `default allow := true` | Tests for fail-closed behavior |
| Rule deletion | Remove an entire deny rule | Tests for rule coverage |
| Quantifier swap | `every` becomes `some` | Tests for universal vs. existential |

### Maturity Level

Mature for XACML (10+ years of academic work). **Nonexistent** for Rego. Building a Rego mutation tool would require AST manipulation of `.rego` files, which OPA's `ast` package in Go supports.

### Recommendation 2

**Technique:** Implement a Rego mutation testing tool that applies the six operators above and runs the existing test suite against each mutant. Track the mutation score (killed mutants / total mutants).

- **Source:** [XACMUT: XACML 2.0 Mutants Generator (IEEE)](https://ieeexplore.ieee.org/document/6571605/); [A Fault Model and Mutation Testing of Access Control Policies (WWW 2007)](https://archives.iw3c2.org/www2007/papers/paper447.pdf); [Automated Strong Mutation Testing of XACML Policies (NSF)](https://par.nsf.gov/biblio/10376452-automated-strong-mutation-testing-xacml-policies)
- **Confidence:** High --- the technique is proven for policy languages; only the Rego-specific tooling is missing.
- **So what for Rego:** A mutation score below 80% on SoFA/SoFREP test suites would reveal undertested rules. The "conjunct removal" operator is especially valuable: if removing a condition from a deny rule does not cause any test to fail, that condition is not independently tested.

---

## 3. Policy Coverage Metrics

### Finding

OPA's built-in `opa test --coverage` provides **line coverage**: it reports which lines (rule heads and expressions) were evaluated during testing. When a line is not covered, it indicates either that the rule body was never true (for rule heads) or that the expression was never evaluated (for body expressions). This is the weakest meaningful coverage metric.

The formal testing literature defines a hierarchy of coverage criteria, codified in NASA's DO-178C standard for safety-critical avionics software:

1. **Statement coverage** --- every statement executed at least once (equivalent to OPA's line coverage).
2. **Decision coverage** --- every decision (rule head) evaluates to both true and false.
3. **Condition coverage** --- every individual condition within a decision evaluates to both true and false.
4. **MC/DC (Modified Condition/Decision Coverage)** --- each condition is shown to independently affect the decision's outcome. Requires n+1 test cases for n conditions. Required by DO-178C Level A.

OPA's coverage is at level 1 (statement). It does not measure whether each condition in a rule body has been independently shown to affect the rule's outcome. The paper "Defining and Measuring Policy Coverage in Testing Access Control Policies" (Springer, 2006) specifically addresses this gap for policy systems, defining policy-specific coverage criteria that go beyond line coverage.

### Recommendation 3

**Technique:** Implement MC/DC-aware coverage analysis for Rego policies. For each rule with multiple conjuncts, verify that the test suite demonstrates each conjunct independently affecting the rule's outcome.

- **Source:** [MC/DC: A Practical Approach (NASA)](https://ntrs.nasa.gov/api/citations/20040086014/downloads/20040086014.pdf); [Defining and Measuring Policy Coverage in Testing Access Control Policies (Springer)](https://link.springer.com/chapter/10.1007/11935308_11); [OPA Policy Testing Docs](https://www.openpolicyagent.org/docs/policy-testing)
- **Confidence:** High --- MC/DC is a well-established standard; the gap in OPA tooling is clear and measurable.
- **So what for Rego:** A SoFA deny rule with 4 conjuncts (e.g., missing amount AND invalid currency AND missing date AND wrong format) needs at least 5 test cases for MC/DC. Current `opa test --coverage` cannot tell you if you have them. This is the single highest-value improvement to add.

---

## 4. Decidability and Completeness

### Finding

Rego is based on Datalog and inherits its decidability guarantees: policy evaluation always terminates and produces a result. OPA restricts recursion to prevent non-termination (using `graph.reachable` as the escape hatch for transitive closure). This means for any finite input, the policy engine will always return a decision.

However, **decidability of evaluation is not the same as completeness of the policy**. The question "does this policy correctly deny ALL possible invalid inputs?" is a different problem. The CNCF TAG Security formal verification overview identifies two categories:

- **Bounded analysis:** Checking policy properties against a finite set of input shapes. Tractable but incomplete.
- **Unbounded analysis:** Checking policy properties against ALL possible inputs. NP-complete to PSPACE-complete depending on the policy language features used.

The theoretical limit is this: for a policy with string matching, regular expressions, or unbounded data structures, proving that it rejects ALL invalid inputs is PSPACE-complete. This is the same complexity class as AWS Zelkova's problem, which AWS solved pragmatically by processing a billion SMT queries daily.

A practical "policy completeness" metric does not exist as a formal standard. The closest concept is **policy coverage relative to a threat model**: given a defined set of invalid input categories, what percentage does the policy cover?

### Recommendation 4

**Technique:** Define a finite "invalidity taxonomy" for each policy domain (e.g., 15 categories of invalid SoFA input) and measure what percentage of categories have at least one deny rule and one test. This is a bounded completeness metric.

- **Source:** [CNCF TAG Security: Policy Formal Verification Overview](https://tag-security.cncf.io/community/working-groups/archive/policy/overview-policy-formal-verification/); [Rego Decidability (Snyk)](https://snyk.io/articles/getting-started-with-practical-rego/); [Zelkova: Semantic-based Automated Reasoning for AWS Policies (FMCAD 2018)](https://www.cs.utexas.edu/~hunt/FMCAD/FMCAD18/papers/paper3.pdf)
- **Confidence:** Medium --- the invalidity taxonomy is a practical approximation, not a formal proof of completeness.
- **So what for Rego:** Without this, there is no way to answer "what invalid inputs can slip through?" For SoFA/SoFREP, the taxonomy should cover: missing fields, wrong types, out-of-range values, invalid cross-field combinations, and format violations.

---

## 5. Model Checking and SMT-Based Verification

### Finding

Three production systems demonstrate that SMT-based policy verification works at scale:

**AWS Zelkova/IAM Access Analyzer:** Encodes IAM policies as SMT formulas and uses Z3 (plus Z3Automata for regex) to check properties for ALL possible requests. Grew from 1,000 to 1 billion SMT calls daily over five years. Solves a PSPACE-complete problem. Open-sourced as part of IAM Access Analyzer.

**Teleport RBAC Linter:** Uses Z3 from Python to analyze RBAC role templates. Can verify that one role is a subset of another, detect duplicate roles, and check that specific security policies are enforced --- all without enumerating users or nodes. Open source at `github.com/gravitational/rbac-linter`.

**Amazon Cedar:** A purpose-built authorization language with formal verification baked in from the start. Cedar's verification-guided development process uses Lean 4 as a proof assistant to model the authorization engine and prove safety properties (explicit-permit, forbid-overrides-permit). The Cedar Symbolic Compiler in Lean enables mathematical proofs of correctness. Cedar Analysis uses SMT solvers to verify that policies satisfy properties like "no unauthorized access" with guarantees that hold for ALL possible scenarios. Cedar joined CNCF as a sandbox project.

For Rego specifically, no SMT-based verification tool exists. However, since Rego is Datalog-based and decidable, it is theoretically possible to translate Rego rules into SMT constraints. The CNCF TAG Security overview explicitly identifies this as a research direction.

### Recommendation 5

**Technique:** For critical policy rules (e.g., the final allow/deny decision), encode the rule logic as Z3 constraints and verify properties like "no input simultaneously satisfies allow AND triggers a deny rule" (consistency) and "every input that lacks a required field triggers at least one deny rule" (completeness for known categories).

- **Source:** [AWS Zelkova (Amazon Science)](https://aws.amazon.com/blogs/security/protect-sensitive-data-in-the-cloud-with-automated-reasoning-zelkova/); [Teleport RBAC Linter](https://goteleport.com/blog/z3-rbac/); [Cedar Verification-Guided Development (arXiv)](https://arxiv.org/html/2407.01688v1); [Cedar Analysis (AWS Blog)](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/)
- **Confidence:** Medium --- Z3 encoding of individual Rego rules is feasible; full policy translation is a research project.
- **So what for Rego:** Even a partial Z3 encoding of the top-level allow/deny logic would catch logical contradictions and gaps that no amount of example-based testing can find.

---

## 6. Differential Testing

### Finding

Differential testing compares two implementations on the same inputs to find behavioral differences. Amazon's Cedar team uses this as a core methodology: production Rust code is tested against Lean formal models using randomly generated inputs, ensuring the implementation matches the specification.

The academic literature shows differential testing discovers 21-34% more behavioral changes than regression testing alone (Savoia, ESEC/FSE 2007). Microsoft applied differential regression testing across 17 versions of Azure networking APIs and found 5 specification regressions and 9 service regressions.

For policy evolution (v1 -> v2 -> v3 -> v4 -> standard), differential testing maps directly: run both the old and new policy against the same corpus of inputs and flag any decision changes. The IEEE paper "Selection of Regression System Tests for Security Policy Evolution" (2013) establishes that regression-test-selection for policy changes can efficiently reduce the test corpus while still catching policy regressions.

### Recommendation 6

**Technique:** Build a differential testing harness that evaluates two policy versions against a shared input corpus and reports: (a) inputs where the decision changed, (b) inputs where the structured output (violation messages, metadata) changed, and (c) inputs where both agree. Use this for every policy version transition.

- **Source:** [Cedar Differential Testing (Amazon Science)](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing); [Differential Testing (Savoia, ESEC/FSE)](http://www.albertosavoia.com/uploads/1/4/0/9/14099067/differentialtesting.pdf); [Regression Test Selection for Security Policies (IEEE)](https://ieeexplore.ieee.org/document/6494932/)
- **Confidence:** High --- the technique is straightforward to implement with `opa eval` and a shared test corpus.
- **So what for Rego:** The v1-to-v4 progression of SoFA/SoFREP policies creates exactly the scenario where differential testing catches unintended behavioral changes. A single script comparing `opa eval -d v3/ -i corpus/` against `opa eval -d v4/ -i corpus/` would immediately surface regressions.

---

## Summary: Prioritized Recommendations for SoFA/SoFREP

| Priority | Recommendation | Effort | Impact | Confidence |
|----------|---------------|--------|--------|------------|
| **1** | MC/DC coverage analysis (Rec 3) | Medium | High | High |
| **2** | Differential testing harness (Rec 6) | Low | High | High |
| **3** | Mutation testing tool (Rec 2) | High | High | High |
| **4** | Property-based test harness (Rec 1) | Medium | Medium | Medium |
| **5** | Invalidity taxonomy metric (Rec 4) | Low | Medium | Medium |
| **6** | Z3 encoding of critical rules (Rec 5) | Very High | Medium | Medium |

### Concrete Tools/Tests to Add

1. **`test_coverage_mcdc.sh`** --- Script that analyzes `opa test --coverage` output and cross-references with rule conjunct counts to flag under-tested rules.
2. **`diff_test.sh`** --- Runs two policy versions against a shared corpus directory and reports decision deltas.
3. **`mutate_rego.py`** --- Python script using AST manipulation to generate mutants (comparison swap, conjunct removal, negation insertion) and measure mutation score.
4. **`fuzz_inputs.py`** --- Hypothesis-based generator producing random JSON inputs conforming to the SoFA/SoFREP input schema.
5. **`invalidity_matrix.md`** --- Enumeration of invalid input categories with traceability to deny rules and test cases.
6. **`z3_verify.py`** (future) --- Z3 encoding of top-level allow/deny logic for consistency checking.

---

## Sources

- [Hypothesis: What is Property-Based Testing?](https://hypothesis.works/articles/what-is-property-based-testing/)
- [FuzzChick: Coverage-Guided Property-Based Testing](https://lemonidas.github.io/pdf/FuzzChick.pdf)
- [OPA Policy Testing Documentation](https://www.openpolicyagent.org/docs/latest/policy-testing/)
- [XACMUT: XACML 2.0 Mutants Generator (IEEE 2013)](https://ieeexplore.ieee.org/document/6571605/)
- [A Fault Model and Mutation Testing of Access Control Policies (WWW 2007)](https://archives.iw3c2.org/www2007/papers/paper447.pdf)
- [Automated Strong Mutation Testing of XACML Policies (NSF)](https://par.nsf.gov/biblio/10376452-automated-strong-mutation-testing-xacml-policies)
- [Defining and Measuring Policy Coverage (Springer 2006)](https://link.springer.com/chapter/10.1007/11935308_11)
- [MC/DC: A Practical Approach (NASA)](https://ntrs.nasa.gov/api/citations/20040086014/downloads/20040086014.pdf)
- [CNCF TAG Security: Policy Formal Verification Overview](https://tag-security.cncf.io/community/working-groups/archive/policy/overview-policy-formal-verification/)
- [Zelkova: Semantic-based Automated Reasoning for AWS Policies (FMCAD 2018)](https://www.cs.utexas.edu/~hunt/FMCAD/FMCAD18/papers/paper3.pdf)
- [AWS Zelkova Blog Post](https://aws.amazon.com/blogs/security/protect-sensitive-data-in-the-cloud-with-automated-reasoning-zelkova/)
- [A Billion SMT Queries a Day (Springer)](https://link.springer.com/chapter/10.1007/978-3-031-13185-1_1)
- [Teleport RBAC Analysis with Z3](https://goteleport.com/blog/z3-rbac/)
- [Teleport RBAC Linter (GitHub)](https://github.com/gravitational/rbac-linter)
- [Cedar: Expressive, Fast, Safe, and Analyzable Authorization (Amazon Science)](https://assets.amazon.science/96/a8/1b427993481cbdf0ef2c8ca6db85/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization.pdf)
- [How We Built Cedar with Automated Reasoning and Differential Testing](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing)
- [Cedar Analysis: Open Source Tools (AWS Blog)](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/)
- [Cedar Verification-Guided Development (arXiv)](https://arxiv.org/html/2407.01688v1)
- [Lean Powers Cedar (Lean Lang)](https://lean-lang.org/use-cases/cedar/)
- [Differential Testing (Savoia, ESEC/FSE 2007)](http://www.albertosavoia.com/uploads/1/4/0/9/14099067/differentialtesting.pdf)
- [Differential Regression Testing for REST APIs (Microsoft Research)](https://dl.acm.org/doi/10.1145/3395363.3397374)
- [Regression Test Selection for Security Policy Evolution (IEEE 2013)](https://ieeexplore.ieee.org/document/6494932/)
- [Rego Decidability and Datalog Foundations (Snyk)](https://snyk.io/articles/getting-started-with-practical-rego/)
- [Conftest: Tests for Structured Configuration Data](https://www.conftest.dev/)
