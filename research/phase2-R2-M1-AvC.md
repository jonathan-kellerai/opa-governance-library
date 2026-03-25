## R2-M1: A (Adjacent Industry) vs C (Failure Archaeology)

### Score Table

| Dimension | A | C |
|---|---|---|
| Novelty | 8 | 9 |
| Divergence | 9 | 8 |
| Evidence | 8 | 9 |
| Actionability | 7 | 10 |
| Cross-pollination | 8 | 8 |
| **TOTAL** | **40** | **44** |

### Winner: C by 4 points

---

### Scoring Rationale

**Novelty** — A: 8, C: 9.
Zero overlap between the two outputs; both score high.
C earns the edge because its domain focus (OPA-specific failure modes at the Rego engine level) is more directly bounded to the codebase under analysis, making its novel findings higher-signal.
A's novelty is broad and lateral; C's novelty is narrow and deep.

**Divergence** — A: 9, C: 8.
A draws from aviation PIREPs, patient safety decision trees, and EDI acknowledgment protocols to illuminate a charity reporting policy — genuinely non-obvious domain hops.
C's OPA CVEs and Wirecard/Enron fraud patterns are somewhat expected for their respective research briefs.
However, C's GPS-battery-reset / friendly-fire finding and the data-document-poisoning vector are genuinely surprising.
A wins on breadth of divergence; the gap is small.

**Evidence** — A: 8, C: 9.
Both use primary sources exclusively.
A cites 16 URLs including XBRL.org, Federal Reserve, EIOPA, FAA, AHRQ, and PubMed.
C cites 11 URLs but CVE advisories from Styra/GitHub/Tenable are the highest-quality citation class available for security findings — they are version-pinned, auditable, and machine-parseable.
Official CVE citations give C a marginal edge.

**Actionability** — A: 7, C: 10.
This is C's decisive advantage.
C provides exact file paths with line numbers (`sofrep.rego` line 111-114, `sofa.rego` line 238), a 10-row table with "Current Coverage" status per recommendation, and complete Rego snippets for each fix.
The highest-priority items (Rec 3: one-line `default valid := false`; Rec 5: two-line type guard on `_in_range`) are implementable in under five minutes.
A's recommendations are well-specified but require schema evolution (`data.json` invariant arrays) or new rule patterns before code can be written.
A scores 7 because the Rego snippets are real and usable; the gap reflects that C's recommendations require no design work before implementation begins.

**Cross-pollination** — A: 8, C: 8.
Both outputs generate strong cross-pollination opportunities with each other (see below).
Scored equal because each produces approximately the same number of high-value synthesis opportunities, and the most valuable ones require both outputs simultaneously.

---

### Top Insights from A

1. **Severity-gated conditional mandatory fields (PIREP pattern)** — SoFREP validates priority enums (P0-P4) as enum values but does not use them to gate additional field requirements.
   A P0 `at_risk` item with no `mitigation` field currently passes validation.
   Aviation rejects a UUA report without the hazardous condition detail.
   Directly implementable as a Rego deny rule.

2. **Declarative algebraic invariants in `data.json` (XBRL pattern)** — Instead of one hand-written Rego rule per mathematical relationship, define an array of invariants in `data.json` and use a single iterator rule to enforce them all.
   SoFA currently hard-codes five separate reconciliation rules; adding a sixth requires new Rego.
   The XBRL separation of invariant declaration (taxonomy) from enforcement (processor) makes the policy extensible without code changes.

---

### Top Insights from C

1. **`default valid := false` missing from SoFREP (undefined vs. false silent pass)** — SoFREP uses `valid := count(errors) == 0`.
   If `errors` is undefined because `data.schema` is absent or corrupt, `count(errors)` produces 0, making `valid` silently true.
   SoFA correctly uses `default valid := false`.
   This is a one-line fix with critical-severity impact.

2. **Data document poisoning disables all validation without touching `.rego` files** — An attacker who modifies `data.schema` or `data.thresholds` (setting `reconciliation_tolerance` to `999999999` or emptying `required_fields`) disables all validation silently.
   Neither policy currently validates its own data documents.
   Adding meta-validation rules (`count(schema.required_fields) > 0`, `tolerance < 100`) closes this single point of failure.

---

### Cross-Pollination Opportunities

1. **Severity-gated rules that are themselves undefined when data.schema is poisoned.**
   A's PIREP/AHRQ pattern adds conditional-mandatory rules keyed to severity levels read from `data.schema`.
   C's data-document-poisoning finding means those conditional rules silently disappear if `data.schema` is tampered with.
   The synthesis: any severity-gated rule must also be protected by C's meta-validation layer.
   Neither output identifies this compound vulnerability alone.

2. **A data-driven ratio invariant system that catches Wirecard-style fabrication.**
   A's XBRL declarative invariant pattern (define invariants in `data.json`, enforce with a generic iterator) combined with C's Wirecard recommendation (Rec 7: cross-field ratio checks) produces a single implementation: declare ratio bounds as invariants in `data.json` (e.g., `{"name": "income_growth_plausibility", "expr": "income / prior_income < thresholds.max_growth_ratio"}`) and enforce them through A's iterator.
   A proposes the mechanism; C identifies the ratios that matter.
   Together they define a complete implementation.

3. **EDI error taxonomy extended with a `meta_validation` layer for data-document failures.**
   A's X12 hierarchical error taxonomy proposes a `"layer"` field on denial objects with values like `structural`, `type_enum`, `cross_field`, `operational_intelligence`.
   C's data-document-poisoning gap creates a distinct failure class that belongs at a layer below structural — it disables the validator itself rather than rejecting a report.
   The synthesis: add a `"layer": "meta_validation"` tier to the taxonomy so consumers can distinguish "this report field is wrong" from "the policy data documents are corrupted."
   Neither output proposes this combined taxonomy extension.
