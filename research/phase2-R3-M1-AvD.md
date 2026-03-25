# Phase 2 — Round 3, Match 1: Output A vs Output D

- **Judge:** Strategic Reasoner (claude-sonnet-4-6)
- **Date:** 2026-03-25
- **Inputs:** `phase1-output-A-adjacent-industry.md`, `phase1-output-D-whitepaper-standards.md`
- **Scoring dimensions:** Novelty, Divergence, Evidence, Actionability, Cross-pollination (0-10 each)

---

## Scoring Rubric Applied

| Dimension | Definition |
|-----------|------------|
| Novelty | Insight absent from the other output; low overlap = higher score |
| Divergence | Distance from the obvious/expected approach |
| Evidence | Backed by a cited, real source — not reasoning from first principles |
| Actionability | Becomes a concrete Rego rule, test, or data change in one session |
| Cross-pollination | Combining this with the other output unlocks something neither produced alone |

---

## Output A: Adjacent Industry Validation Patterns

### Top 3 Insights

**A1 — Declarative algebraic invariants in `data.json` (XBRL Calculation Linkbase)**

Instead of one hard-coded Rego rule per mathematical relationship, declare an
`invariants` array in `data.json` and iterate over it with a single generic rule.
This mirrors XBRL's separation of invariant declaration (taxonomy) from invariant
enforcement (processor).

**A2 — Severity-gated conditional mandatory fields (Aviation PIREP UUA)**

Priority enum values (P0-P4) should gate additional required fields, not merely be
validated as valid enum values.
A P0 at-risk item with no mitigation plan currently passes.
In PIREP, a UUA report without its hazardous-condition detail is structurally
rejected — not warned.

**A3 — Hierarchical error taxonomy with stable codes (EDI X12 997)**

Current denial objects carry human-readable strings; automated consumers cannot
reliably parse or categorize them.
X12 997 uses four validation layers (functional group, transaction set, segment,
element) each with its own stable error code.
Adding a `layer` and `error_code` field to every denial makes the output
machine-actionable and enables trend analysis across reporting periods.

### Dimension Scores

| Insight | Novelty | Divergence | Evidence | Actionability | Cross-pollination | Total |
|---------|---------|------------|----------|---------------|-------------------|-------|
| A1 — Declarative invariants | 9 | 8 | 9 | 9 | 8 | 43 |
| A2 — Severity-gated fields | 7 | 7 | 9 | 10 | 9 | 42 |
| A3 — Hierarchical error codes | 9 | 8 | 9 | 8 | 7 | 41 |

**Rationale:**

- **Novelty:** None of Output D's 30 recommendations mention data-driven invariant
  declaration, layered error codes, or aviation-derived mandatory-field gating.
  Overlap is near zero on all three insights.
- **Divergence:** Pulling validation patterns from aviation weather reports and EDI
  transaction acknowledgment is non-obvious for a charity finance / military readiness
  policy domain.
  The declarative invariant idea inverts the normal Rego authoring model (rules as
  code → rules as data).
- **Evidence:** All three cite real, reachable primary sources (XBRL.org formula spec,
  FAA handbook, X12 spec on Stedi/Microsoft).
- **Actionability:** A1 requires a `data.json` schema change and one new Rego iterator;
  achievable in one session.
  A2 is a single new `deny` block with a priority guard; implementable immediately.
  A3 requires adding two fields (`layer`, `error_code`) to every existing denial
  object — more mechanical but tractable in one session with a shared helper rule.
- **Cross-pollination:** A2 (severity gating) combines explosively with D's ISO 31000
  structured treatment plan (D's Rec 23) — the treatment plan fields become
  conditionally mandatory precisely when priority gates trigger.
  A3's error taxonomy can classify D's 30 identified gaps into consistent layers,
  giving every new gap a machine-readable home.

**Output A weighted score: 42 / 50 average across top 3 insights.**

---

## Output D: Authoritative Standards for SoFA and SoFREP Validation

### Top 3 Insights

**D1 — Jurisdiction-aware filing rules (OSCR vs. CC17)**

Scottish charities operate under a materially different regulatory regime:
9-month filing deadline (vs. 10 months for England/Wales), mandatory independent
examination regardless of income level (vs. 25K GBP threshold), and from June 2025
full trustee disclosure requirements.
A single `jurisdiction` enum field unlocks an entire family of conditionally active
rules that currently do not exist at all.

**D2 — SORTS/DRRS C-Level readiness rating (FM 101-5-2 / CJCSI 3401.02B)**

The SoFREP `readiness_pct` is a derived percentage with no authoritative mapping.
SORTS defines C1–C5 with published thresholds per resource area (Personnel, Supply,
Equipment Condition, Training), where overall C-level is the worst of the four.
This closes a direct compliance gap for any user who submits SoFREP in a DoD context
and is grounded in CJCSI 3401.02B, a public authoritative source.

**D3 — Going concern disclosure requirement (IAS 1)**

The existing going-concern warning fires when consecutive negative net movements are
detected but does not require a disclosure narrative field.
IAS 1 requires material uncertainty disclosure; the gap is that the policy warns but
does not block when the disclosure text is absent.
Elevating to `error` severity when `going_concern_disclosure` is null converts a
passive advisory into a structural validation gate.

### Dimension Scores

| Insight | Novelty | Divergence | Evidence | Actionability | Cross-pollination | Total |
|---------|---------|------------|----------|---------------|-------------------|-------|
| D1 — Jurisdiction rules | 9 | 6 | 9 | 9 | 7 | 40 |
| D2 — C-Level rating | 9 | 5 | 9 | 8 | 7 | 38 |
| D3 — Going concern gate | 7 | 5 | 9 | 10 | 8 | 39 |

**Rationale:**

- **Novelty:** All three are absent from Output A, which never touches charity
  regulatory thresholds, military readiness standards, or IFRS going-concern rules.
  High novelty relative to A.
- **Divergence:** D's insights are mostly *within*-domain (the expected place to look
  for charity finance rules is charity finance standards; for military readiness, the
  military readiness framework).
  The approach is rigorous but not conceptually surprising; hence lower divergence
  scores than A's cross-domain jumps.
- **Evidence:** Every insight cites publicly accessible primary sources (OSCR.org,
  CJCSI 3401.02B, IAS 1 PDF).
  Evidence quality is equally strong to A.
- **Actionability:** D1 and D3 are single-session changes.
  D2 requires adding a computed derived field plus resource-area sub-schema —
  slightly more structural but still achievable.
- **Cross-pollination:** D1's `jurisdiction` field could carry A's error-code taxonomy
  prefix (e.g., `SOFA-GB-SCT-*` vs. `SOFA-GB-EW-*`), enabling jurisdiction-namespaced
  error codes.
  D3's going-concern gate pairs with A's AHRQ cross-field consistency pattern (if
  the narrative says "going concern risk" but no disclosure field is populated, that
  is the same contradictory-signal problem).

**Output D weighted score: 39 / 50 average across top 3 insights.**

---

## Head-to-Head Summary

| Dimension | Output A | Output D |
|-----------|----------|----------|
| Novelty (relative to other) | 8.3 | 8.3 |
| Divergence | 7.7 | 5.3 |
| Evidence | 9.0 | 9.0 |
| Actionability | 9.0 | 9.0 |
| Cross-pollination | 8.0 | 7.3 |
| **Average** | **8.4** | **7.8** |

---

## Winner: Output A

Output A wins on Divergence and Cross-pollination.
Both outputs are equally strong on Evidence and Actionability.
On Novelty they are symmetric (neither overlaps the other).

The deciding factor is that Output A's pattern sourcing — XBRL formula linkbases,
aviation PIREP urgency tiers, EDI X12 acknowledgment layers — is genuinely
non-obvious for a policy domain covering charity finance and military readiness.
Output D is rigorous and deeply authoritative within its domain but stays inside
the expected search space (the governing standards for the exact domains in scope).

Output A also contributes structural ideas (data-driven invariants, error taxonomy)
that can *contain* Output D's 30 gap recommendations, making A architecturally
upstream of D.

---

## Cross-Pollination Opportunities

### CP1: Severity Gating + Structured Treatment Plans

**Source:** A2 (Aviation PIREP urgency gates) + D's Rec 23 (ISO 31000 treatment plans)

When a SoFREP `at_risk` item's `priority` is P0 or P1, a `deny` rule currently does
not fire on the absence of a mitigation.
Combining A2 with D's structured `treatment_plan` object (fields: `strategy`,
`responsible_owner`, `target_date`, `status`) would make the treatment plan
*conditionally mandatory* precisely at P0/P1 — matching both the PIREP urgency model
and ISO 31000's requirement to document treatment for risks above appetite.

Implementation path (one session):

1. Add `treatment_plan` sub-object to `sofrep/standard/sofrep.rego` schema
2. Add severity-gated `deny` rule: P0/P1 item without `treatment_plan` → error
3. Add test fixtures: P1 item with and without `treatment_plan`

### CP2: Error Taxonomy as a Compliance Layer Map

**Source:** A3 (X12 997 hierarchical error codes) + D's 30 gap recommendations

Output D identified 30 distinct compliance gaps across 10 standards.
Output A proposed adding `layer` and `error_code` fields to every denial.
Combining them: assign each of D's 30 gaps to a layer (`structural`,
`type_enum`, `cross_field`, `regulatory_compliance`) and mint stable error codes.

Example mapping:

| Gap | Layer | Error Code |
|-----|-------|------------|
| Missing `jurisdiction` field | `structural` | SOFA-0101 |
| `audit_status` inconsistent with income | `cross_field` | SOFA-0501 |
| `going_concern_disclosure` absent | `regulatory_compliance` | SOFA-0701 |
| P0 item without treatment plan | `cross_field` | SFRP-0301 |
| C-Level not computed | `regulatory_compliance` | SFRP-0801 |

This makes the validation output stable enough for machine consumption, CI integration,
and external audit trails — something neither output proposed on its own.

### CP3: Going Concern Narrative + Cross-Field Consistency Gate

**Source:** A's AHRQ pattern (contradictory qualitative signals) + D3 (IAS 1 going concern gate)

Output A observed that qualitative assessments (urgency, priority, impact) can
contradict each other silently.
Output D noted that the going-concern warning fires but does not block on absent
disclosure.
Combined: a cross-field consistency rule that checks whether going-concern risk
language appears in any `notes` or `description` field *without* a corresponding
`going_concern_disclosure` field.
This mirrors the AHRQ finding that >30% of reports had free-text "death" with a
"no harm" structured field checked — the same mismatch pattern.

---

## Implementation Priority Order

| Priority | Insight | Source | Effort |
|----------|---------|--------|--------|
| 1 | Severity-gated P0/P1 mandatory mitigation (A2) | PIREP UUA | Low |
| 2 | Going concern disclosure gate (D3) | IAS 1 | Low |
| 3 | Jurisdiction-aware rules skeleton (D1) | OSCR/CC17 | Medium |
| 4 | Declarative `data.json` invariants (A1) | XBRL | Medium |
| 5 | C-Level rating derived field (D2) | SORTS/DRRS | Medium |
| 6 | Hierarchical error codes on denial objects (A3) | X12 997 | Medium |
| 7 | CP1: Treatment plan + severity gate combined | A2 + D Rec 23 | Medium |
| 8 | CP2: Error taxonomy map for all 30 D gaps | A3 + D full set | High |
