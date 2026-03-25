# R1-M1: A (Adjacent Industry) vs B (Formal Methods)

- **Judge:** Strategic Reasoner (SICA Tournament, Round 1, Match 1)
- **Date:** 2026-03-25
- **Inputs:**
  - Output A: `phase1-output-A-adjacent-industry.md`
  - Output B: `phase1-output-B-formal-methods.md`

---

## Score Table

| Dimension | A | B |
|-----------|---|---|
| Novelty | 9 | 8 |
| Divergence | 8 | 7 |
| Evidence | 8 | 9 |
| Actionability | 8 | 9 |
| Cross-pollination | 8 | 8 |
| **TOTAL** | **41** | **41** |

---

## Winner: B (Formal Methods) on tiebreak

The total scores are identical at 41.
Tiebreak criterion: **near-term implementability**.
Output B's top two recommendations (differential testing harness, MC/DC coverage analysis)
are single-session implementations with no schema changes required and no dependency on
evolving the `data.json` contract.
Output A's top recommendations either require schema evolution (invariant declarations,
cross-report validation) or touch Rego logic that does not yet exist (severity-gated
mandatory fields).
B wins the tiebreak by a narrow margin.

---

## Scoring Rationale

### Novelty

**A: 9.**
Every pattern comes from a domain entirely outside the OPA/policy-language literature.
XBRL calculation linkbases, CCAR cross-schedule reconciliation, EIOPA DPM multi-document
validation, FAA PIREP severity gating, AHRQ harm-severity coupling, EDI X12 hierarchical
error taxonomy --- none of these appear in Output B, and none are obvious extrapolations
from Rego documentation.

**B: 8.**
Mutation testing (XACML literature), MC/DC (NASA DO-178C), property-based testing
(QuickCheck/Hypothesis), and differential testing (Cedar, Microsoft Azure) are all
genuinely non-obvious for a Rego practitioner.
One point deducted because PBT and differential testing are reasonably discoverable
from the OPA testing docs if you follow upstream references, whereas A's sources
require genuine cross-domain knowledge.

### Divergence

**A: 8.**
Importing FAA PIREP urgency logic into a charity financial report validator is
cognitively distant.
Importing AHRQ patient safety harm-severity coupling to catch contradictory
`urgency: low` + `priority: P0` combinations in SoFREP is non-obvious and valuable.
The XBRL declarative invariant pattern reframes Rego rule authoring as taxonomy design,
which is a genuine shift in mental model.
One point deducted: the "cross-schedule reconciliation" and "cross-report validation"
patterns are extensions of ideas already present in the existing policies (reconciliation
rules exist; extending them is incremental).

**B: 7.**
MC/DC is a rigorous upgrade from line coverage and non-obvious for policy developers.
Mutation testing operators (conjunct removal, quantifier swap) are divergent for a
Rego context.
However, property-based testing and differential testing are patterns a senior engineer
might reach for independently.
The Z3/SMT idea is high-divergence but also flagged as "very high effort / future work,"
limiting its practical impact on this round's score.

### Evidence

**A: 8.**
Every recommendation cites a specific, named standard, published paper, or regulatory
requirement (XBRL Formula Specification, FR Y-14A Federal Reserve report, EIOPA XBRL
taxonomy, FMH-12, PubMed 24080718, EDI X12 997 error codes).
One point deducted: the Solvency II recommendation is marked "Medium" confidence
and the cross-report validation idea is speculative (no SoFA+SoFREP combined filing
requirement currently exists).

**B: 9.**
Sources are exceptionally strong: NASA DO-178C (safety-critical avionics standard),
peer-reviewed IEEE/WWW/Springer papers for mutation testing, production-deployed systems
(AWS Zelkova at 1 billion SMT queries/day, Amazon Cedar with Lean 4 proof assistant,
Teleport RBAC linter on GitHub).
The differential testing recommendation cites Amazon's own methodology paper.
One point deducted only because the Rego-specific application of Z3 is explicitly
described as a research direction with no existing tooling.

### Actionability

**A: 8.**
Four of the six recommendations are direct Rego/data.json changes:
- Invariant array in `data.json` + single iterator rule (one session)
- Severity-gated mandatory field rule (one session, specific Rego snippet provided)
- Contradictory-signal warning rule for `urgency` + `priority` (one session)
- Hierarchical error taxonomy via `layer` and `error_code` fields (one data document change)

Two recommendations require schema evolution or architectural changes (cross-schedule
reconciliation requires a summary field; cross-report validation requires multi-document
input).

**B: 9.**
Five of the six recommendations produce runnable artifacts in one session:
- `diff_test.sh` --- two `opa eval` calls and a diff (one hour)
- `invalidity_matrix.md` --- enumeration document, no code
- `fuzz_inputs.py` --- Hypothesis harness, no Rego changes needed
- `mutate_rego.py` --- Python AST script, standalone tool
- `test_coverage_mcdc.sh` --- shell script analyzing existing `opa test --coverage` output

The one high-effort item (Z3) is honestly flagged as future work.
B provides working tool names and file names, not just patterns.

### Cross-pollination

**A: 8.**
The XBRL declarative invariant pattern, combined with B's mutation testing,
creates a high-value pairing: declare invariants as data, then generate mutants
that violate those invariants programmatically rather than manually.
The EDI X12 hierarchical error taxonomy (`layer` + `error_code`) combines
naturally with B's invalidity taxonomy (`invalidity_matrix.md`): the taxonomy
becomes the source of truth for both the error codes and the test coverage matrix.
The AHRQ contradictory-signal check combines with B's PBT monotonicity property:
"adding a priority field never decreases the required fields" is a testable invariant.

**B: 8.**
The MC/DC coverage analysis is most valuable when applied to rules that A identifies
as under-tested: the severity-gated rules (if they exist) have multiple conjuncts
that line coverage cannot distinguish.
Differential testing is specifically valuable for validating that adding A's new
invariant rules does not regress the existing passing corpus.
Mutation testing's "conjunct removal" operator directly tests whether A's new
conditional-mandatory-field rules are independently necessary.

---

## Top Insights from A

**1. Severity-gated conditional mandatory fields (PIREP/METAR pattern)**

A P0 or P1 SoFREP item with no `mitigation` field currently passes validation.
Aviation rejects a UUA report missing a hazard description.
The Rego pattern for this is a one-session change (snippet provided in the output).
This is the most immediate gap: enum validation is present, but the enum value
does not gate downstream field requirements.

**2. Hierarchical error taxonomy with stable machine-readable codes (EDI X12 997 pattern)**

Current denial objects are flat structs with human-readable `msg` strings.
No stable `error_code` field exists, making automated consumers unable to
classify or trend errors.
Adding `layer` (structural / type-enum / cross-field / operational) and
`error_code` (e.g., `SoFA-0501`) is a pure data-document change that
makes the policy output machine-actionable.
This is foundational for any downstream tooling built on the policies.

**3. Declarative algebraic invariants in `data.json` (XBRL calculation linkbase pattern)**

The current policy hard-codes each reconciliation relationship as a separate Rego rule.
Adding a sixth mathematical invariant requires writing new Rego.
Moving invariant declarations into a `data.invariants` array and writing a single
iterator rule separates policy logic from policy configuration, matching XBRL's
taxonomy/processor architecture.
This is the highest-leverage structural change for long-term maintainability.

---

## Top Insights from B

**1. MC/DC coverage as the correct metric for multi-conjunct deny rules**

OPA's `opa test --coverage` reports line coverage only.
A SoFA deny rule with 4 conjuncts needs at minimum 5 test cases to demonstrate
that each condition independently affects the outcome.
The current test suite cannot prove this.
MC/DC is the NASA DO-178C Level A standard for safety-critical software,
and the gap in OPA tooling is explicit and measurable.
A `test_coverage_mcdc.sh` script analyzing `opa test --coverage` JSON output
against conjunct counts is implementable in one session.

**2. Differential testing harness for policy version transitions**

The v1-to-v4 progression of SoFA/SoFREP creates exactly the scenario where
unintended behavioral changes slip through.
A `diff_test.sh` script running two policy versions against a shared corpus
directory and reporting decision deltas is the lowest-effort, highest-confidence
regression guard available.
No schema changes, no new dependencies --- two `opa eval` calls and a `diff`.
This should exist before any further policy evolution.

**3. Mutation testing operators for Rego (conjunct removal is most critical)**

The XACML mutation literature (IEEE 2013, WWW 2007) establishes that removing
a conjunct from a deny rule is the most revealing operator: if no test fails,
that condition is not independently tested.
No Rego mutation tool exists.
A `mutate_rego.py` script using OPA's Go AST package (or Python string manipulation
on `.rego` files) to generate and score mutants would quantify the test suite's
actual adequacy for the first time.
This is the highest-effort item in B but also the most diagnostic.

---

## Cross-Pollination Opportunities

**1. Invariant-driven mutation generation (A-1 x B-2)**

A's declarative `data.invariants` array defines exactly what relationships must hold.
B's mutation testing framework should generate test inputs that violate each
declared invariant, not hand-crafted violations.
Concretely: for each entry in `data.invariants`, a PBT harness (B's `fuzz_inputs.py`)
could generate documents where the invariant is violated (e.g., `opening + net != closing`
by a random delta) and assert that the policy denies them.
This closes the loop: invariants are both enforcement rules and test oracle sources.

**2. Error taxonomy as invalidity matrix (A-6 x B-4)**

A's hierarchical error taxonomy (layer + error_code) and B's invalidity taxonomy
(`invalidity_matrix.md`) are the same artifact from two directions.
A approaches it from the output side (what codes do denial messages carry).
B approaches it from the input side (what categories of invalid input exist).
Merging them produces a single traceability matrix: `error_code → deny rule → test case → input category`.
This matrix is the foundation for both machine-readable error reporting and
bounded completeness measurement.
Neither output produced this artifact alone; together they describe it completely.

**3. Differential testing as regression guard for new invariant/conditional rules (A-1,A-4 x B-6)**

Before adding A's severity-gated mandatory fields or new algebraic invariants,
run B's differential test harness against the existing corpus to establish a baseline.
After adding the new rules, re-run to surface any previously-passing documents
that are now denied.
This is the professional workflow for policy evolution: establish baseline,
change policy, diff, triage new denials as intentional vs. regression.
Currently no such baseline corpus exists and no diff harness exists.
Both need to be built together, not independently.
