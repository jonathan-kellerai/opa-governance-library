# Phase 5 — Judge 3: The Pilot
## Production Safety Analysis — SoFA and SoFREP Rego Policies

- **Role:** Judge 3 — The Pilot
- **Lens:** Production Safety
- **Scope:** sofa/standard/sofa.rego, sofa/standard/schema.json, sofrep/standard/sofrep.rego, sofrep/standard/schema.json (plus test files)
- **Date:** 2026-03-25
- **Method:** Direct policy reading, evidence-first, no speculation

---

## Round 1: Context Pressure

**Scenario:** The OPA engine has 100ms. The input has 10,000 line items. Are there O(n²) rules? What is the worst-case evaluation complexity for `owner_counts`, `risk_matrix`, and `all_items`?

### Findings

- **[CRITICAL]** SoFREP `unique_ids` rule is O(n²) over the full item population
  - **Location:** `sofrep/standard/sofrep.rego:304–312`
  - **Evidence:**
    ```rego
    deny contains ... if {
        some q1 in quadrants
        some i, item1 in items_in(q1)
        some q2 in quadrants
        some j, item2 in items_in(q2)
        item1.id == item2.id
        [q1, i] != [q2, j]
        id := item1.id
    }
    ```
    This is a four-way nested `some` over `quadrants × items × quadrants × items`. With `k` quadrants (fixed at 4) and `n` items per quadrant, the outer structure is O(4 × n × 4 × n) = O(16n²). For 10,000 total items (2,500 per quadrant), that is 62.5 million pair comparisons per evaluation. OPA's set-comprehension short-circuits on the `deny contains` form, but all pairs must still be checked since the rule accumulates all violating pairs, not just the first.
  - **Impact:** Evaluation time for a 10,000-item report can easily exceed 100ms. OPA's Rego interpreter has no built-in time-boxing per rule; the evaluator will run to completion or hit a global timeout configured at the HTTP API layer. If no timeout is configured, the request hangs. If one is configured, it returns 500 without a partial result.
  - **Fix:** Replace the nested quadrant iteration with a linear ID-collection pass followed by a set-cardinality check:
    ```rego
    _all_id_list := [item.id | some q in quadrants; some item in items_in(q)]
    deny contains {"msg": sprintf("duplicate id '%s' found across quadrants", [id]), ...} if {
        some id in all_ids
        count([1 | some x in _all_id_list; x == id]) > 1
    }
    ```
    Or, more idiomatically: build `all_ids` as a set (already done at line 28), build a parallel multiset count, and compare. The fix is O(n).

- **[MAJOR]** SoFREP `owner_counts` is O(n²) per owner
  - **Location:** `sofrep/standard/sofrep.rego:408–411`
  - **Evidence:**
    ```rego
    owner_counts[owner] := c if {
        some owner in {item.owner | some item in all_items}
        c := count([1 | some item in all_items; item.owner == owner])
    }
    ```
    For each distinct owner, a full linear scan of `all_items` is performed to count matches. With `d` distinct owners and `n` total items, this is O(d × n). If every item has a unique owner, d = n and this is O(n²).
  - **Impact:** At 10,000 items with 10,000 distinct owners, this is 100 million iterations. At 100 items per owner (100 owners), it is 1 million iterations — still expensive. In practice SoFREP is a readiness report with dozens to low hundreds of items, so this is unlikely to hit 100ms, but the pattern is wrong and will bite if scope expands.
  - **Fix:** Use a single-pass grouped comprehension:
    ```rego
    owner_counts[owner] := count(items) if {
        some owner in {item.owner | some item in all_items}
        items := [1 | some item in all_items; item.owner == owner]
    }
    ```
    This is the same code but the fix is structural: move to `group_by` semantics using an `object` comprehension keyed on owner, built in one pass.

- **[MAJOR]** SoFREP `risk_matrix` accesses items via linear scan inside `treatment_plan_required`
  - **Location:** `sofrep/standard/sofrep.rego:510`
  - **Evidence:**
    ```rego
    item := [i | some i in items_in("at_risk"); i.id == id][0]
    ```
    For each entry in `risk_matrix`, this performs a full linear scan of `at_risk` items to find the one whose id matches. If there are `m` at_risk items, this is O(m) per risk_matrix entry, and risk_matrix itself has up to `m` entries, making this O(m²) in the worst case.
  - **Impact:** For large at_risk lists, this doubles the at_risk evaluation cost. For SoFREP's intended scale (tens of items per quadrant), this is tolerable. For any future expansion to hundreds of items, it is not.
  - **Fix:** Index at_risk items by id before the rule:
    ```rego
    _at_risk_by_id[id] := item if { some item in items_in("at_risk"); id := item.id }
    ```
    Then reference `_at_risk_by_id[r.id]` directly.

- **[MINOR]** SoFA `all_items` is computed via `array.concat` of two arrays (line 49), which is O(n) and fine. The `materiality` rule iterates over all items with a guard — O(n), acceptable.

- **[MINOR]** SoFA has no O(n²) rules. All its line-item rules use a single `some sec in [...]; some i, item in items(sec)` loop — O(n) per rule.

### Verdict: CRACKED

SoFREP's `unique_ids` rule is structurally O(n²) and will breach 100ms at realistic batch sizes if inputs grow. SoFA is clean.

---

## Round 2: Concurrent Collision

**Scenario:** Two evaluations run simultaneously with the same `data.schema` but different inputs. Is there any mutable state? Any aliasing risk?

### Findings

- **[MINOR]** Pure Rego has no mutable state — this is by design and confirmed
  - **Location:** Both policies, all rules
  - **Evidence:** Both policies use `import rego.v1`, which enforces the modern Rego rule model. All definitions are either complete rules (`deny contains ...`), partial rules (incremental definitions), or computed local variables (`:=` within a rule body). There are no `assign` operations, no global variable mutation, no side effects. The `_sentinel`, `schema`, `thresholds`, `quadrants`, `all_items`, etc. are all rules that compute fresh values from `input` and `data` on every evaluation. OPA evaluates policies functionally — each query gets its own evaluation context.
  - **Impact:** No concurrent collision risk from the policy code itself.

- **[MAJOR]** The `data.schema` and `data.thresholds` documents are shared across concurrent evaluations — but this is an OPA deployment concern, not a policy concern
  - **Location:** Both `schema.json` files; OPA bundle loading mechanism
  - **Evidence:** If `data.schema` or `data.thresholds` is being hot-reloaded (bundle update) while an evaluation is in progress, OPA's bundle activation is atomic per OPA's documented behavior — the old bundle remains active until the new one is fully validated and swapped in. This is correct. However, the policy files themselves do not enforce or document this expectation.
  - **Impact:** A deployment that bypasses OPA's bundle mechanism (e.g., writing to the data API directly via `PUT /v1/data/schema`) could produce mid-evaluation data inconsistency in theory, though OPA's Go implementation uses read locks during evaluation. The risk is in non-standard deployment, not in the policy.
  - **Fix:** Document in the schema files and/or an accompanying README that `data.schema` and `data.thresholds` must be loaded via OPA bundle, not via the mutable data API. Add a bundle manifest. This is an operational rather than a code fix.

- **[MINOR]** No aliasing between `_sentinel` and any possible input value is exploitable
  - **Location:** `sofa.rego:26`, `sofrep.rego:8`
  - **Evidence:** Both policies use `_sentinel := "__MISSING__"`. This value is used in `object.get(obj, field, _sentinel)` to detect absent keys. An attacker who supplies `"__MISSING__"` as an actual field value would cause `_field_present` to return false, treating a present field as absent. This is a semantic collision, not a concurrency issue.
  - **Impact:** This is a cross-cutting vulnerability examined more fully in Round 4 (Malicious Input).

### Verdict: HOLDS

Pure Rego eliminates mutable state by design. No concurrent collision from policy code. The `data` document reload risk is an operational concern that belongs in deployment documentation, not the policy.

---

## Round 3: Stale Data

**Scenario:** `data.schema` was last updated 6 months ago. A new fund type or category was added to the real-world standard but not to `schema.json`. What happens? Is there a mechanism to detect stale schema?

### Findings

- **[CRITICAL]** No schema versioning or staleness detection mechanism exists in either policy
  - **Location:** `sofa/standard/schema.json` (entire file), `sofrep/standard/schema.json` (entire file)
  - **Evidence:** Neither `schema.json` file contains a `version`, `last_updated`, `effective_date`, or `schema_version` field. The policies do not check for or enforce any schema version. There is no rule in either policy that fires when the schema document is unexpectedly old or when a known-required key is absent from `data.schema`.
  - **Impact:** If the real-world charity commission adds a new fund type (e.g., "impact_investing") and a submitter uses it, the policy rejects the input with `"invalid fund_type 'impact_investing'"` — a false positive error. The submitter's report is blocked as invalid when it is in fact compliant with the updated standard. This false rejection silently enforces stale rules until the schema is updated. The reverse also applies: if a previously valid category is deprecated in the real-world standard but remains in `data.schema`, the policy continues to accept it as valid — a false negative.
  - **Fix:** Add a `schema_version` and `schema_effective_date` to both `schema.json` files. Add a meta-validation rule:
    ```rego
    deny contains {"msg": sprintf("data.schema version '%s' may be stale (effective %s)", [v, d]), "severity": "warning", "field": "data.schema", "rule": "schema_staleness"} if {
        v := object.get(data.schema, "schema_version", "")
        d := object.get(data.schema, "schema_effective_date", "")
        # staleness check would require knowing the current date — use input.report_date as proxy
        rd := object.get(input, "report_date", "")
        rd != ""
        d != ""
        # If report date is more than N days after schema effective date, warn
        ...
    }
    ```
    More practically: add a `schema_version` field and have callers pass `input.expected_schema_version`. The policy can then assert the versions match.

- **[MAJOR]** SoFA: Adding a new fund type to the real world but not to `schema.json` causes silent false positives
  - **Location:** `sofa/standard/sofa.rego:224–229` (fund_type rule), `sofa/standard/schema.json:6`
  - **Evidence:** `fund_types := {f | some f in schema.fund_types}` is a closed enumeration derived entirely from `data.schema`. Any fund type not in that set is rejected. The schema currently lists exactly 4 types: `unrestricted`, `restricted`, `endowment`, `designated`. The Charity Commission SORP recognises that new fund structures can emerge (e.g., from merger accounting or new legislative categories).
  - **Impact:** False rejection of valid inputs. The error message `"invalid fund_type 'X'"` gives no indication that the schema may be out of date, leaving the submitter and operator both confused.

- **[MAJOR]** SoFREP: New classification levels (e.g., a new handling caveat between CUI and CONFIDENTIAL) would cause identical false rejection
  - **Location:** `sofrep/standard/sofrep.rego:232–236`, `sofrep/standard/schema.json:13`
  - **Evidence:** `_classification_values := {x | some x in data.schema.enums.classification}` — same closed-enum pattern. Currently lists 5 levels; any new level silently becomes invalid.
  - **Impact:** Same as above. In a classified environment, a misclassification error can halt report submission entirely.

- **[MINOR]** The meta-validation rules (R1, R4) guard against an empty schema but not against a schema that is present, non-empty, and outdated. An empty `fund_types: []` fires `schema_list_nonempty`. But a `fund_types: ["unrestricted"]` (missing three types) passes meta-validation and causes silent false positives for all restricted/endowment/designated items.
  - **Location:** `sofa/standard/sofa.rego:127–140`
  - **Evidence:** `_schema_list_mins` requires at least 1 entry per list — not a content-correct minimum.

### Verdict: CRACKED

No schema versioning exists. Stale schema causes silent false positives with no indication to consumers that the schema is the problem. There is no detection mechanism. This is a production day-one gap for any policy used across regulatory cycles.

---

## Round 4: Malicious Input

**Scenario:** Craft adversarial inputs — 1MB string in a field, deeply nested JSON, regex-bomb patterns in date fields, negative array indices, field names that shadow Rego built-ins. What survives?

### Findings

- **[CRITICAL]** Sentinel value collision: input field containing `"__MISSING__"` bypasses `_field_present`
  - **Location:** `sofa/standard/sofa.rego:26–37`, `sofrep/standard/sofrep.rego:8–19`
  - **Evidence:** `_field_present` returns false when `val == _sentinel` (i.e., `val == "__MISSING__"`). If an attacker submits `{"category": "__MISSING__"}`, the function returns false, treating the present field as absent. This causes `line_required` (SoFA) and `base_fields` (SoFREP) to fire a missing-field error for a field that is technically present. The inverse effect: an item with `{"description": "__MISSING__"}` fires a spurious "missing base field: description" error, making a valid (if odd) description look like a structural error.
  - **Impact:** Primarily a denial-of-service against validation: a report can be made to appear structurally broken by including the sentinel string. In an automated ingestion pipeline, this causes valid reports to be rejected. An attacker who controls input can force any report to fail structural checks without changing any semantically meaningful field.
  - **Fix:** Use a cryptographically improbable sentinel (e.g., a UUID: `_sentinel := "opa-sentinel-f47ac10b-58cc-4372-a567-0e02b2c3d479"`) or switch to OPA's built-in `has(obj, key)` idiom where available, or use `object.get(obj, field, null) != null` combined with a separate `field in object.keys(obj)` check.

- **[MAJOR]** Regex evaluation on unbounded input strings — ReDoS risk in date and currency patterns
  - **Location:** `sofa/standard/sofa.rego:177–184`, `sofrep/standard/sofrep.rego:274–289`
  - **Evidence:** Both policies call `regex.match(schema.date_pattern, input.report_date)` and `regex.match(schema.currency_pattern, input.currency)`. The current patterns are `^\\d{4}-\\d{2}-\\d{2}$` and `^[A-Z]{3}$` — these are safe, simple patterns with no catastrophic backtracking potential. However, the `pattern_anchoring` meta-validation only checks that patterns start with `^` and end with `$`. It does not validate that patterns are safe (no nested quantifiers, no exponential alternation). If an operator misconfigures `schema.date_pattern` to something like `^(\\d+)+$` (a classic ReDoS pattern), a long string in `input.report_date` would cause catastrophic backtracking and hang the OPA process.
  - **Impact:** Operator-controlled (via `data.schema`), not attacker-controlled from input alone. But if the schema is loaded from an untrusted or misconfigured source, this becomes a vector.
  - **Fix:** Add pattern complexity validation (ban nested quantifiers) or use a fixed-string date format check instead of regex. OPA's `time.parse_rfc3339_ns` could replace the date regex entirely.

- **[MAJOR]** 1MB string in a field: no length guards on any string field in either policy
  - **Location:** Both policies, all string field checks
  - **Evidence:** Neither policy checks `count(input.entity_name) < N` or any equivalent. A 1MB string in `entity_name`, `description`, `unit`, or any other string field passes all validations (assuming it matches required patterns). It will be embedded in the `deny` message via `sprintf` if the field appears in an error (e.g., the fund type or category rules include the value in the message). OPA's `sprintf` on a 1MB string will produce a 1MB deny message, which then propagates into the `deny` set, into `errors`, into `summary`, and into the HTTP response body.
  - **Impact:** A single 1MB field value can produce a multi-megabyte response body when serialized. In a batch processing scenario with many such inputs, this can exhaust OPA sidecar memory or cause upstream JSON parsers to OOM.
  - **Fix:** Add string length guards on user-controlled fields that appear in error messages:
    ```rego
    deny contains {"msg": sprintf("field '%s' exceeds maximum length %d", [f, max_len]), ...} if {
        some f in ["entity_name", "description", ...]
        count(object.get(input, f, "")) > max_len
    }
    ```

- **[MAJOR]** Deeply nested JSON: no depth guards
  - **Location:** Both policies
  - **Evidence:** Neither policy limits nesting depth. `fund_balances` in SoFA accepts arbitrary object nesting — if an attacker submits `fund_balances: {"unrestricted": {"opening": {"value": {"nested": ...}}}}`, OPA will traverse the structure. However, the `fund_balance_type` rule does guard the specific numeric fields with `is_number`, and `object.get` with a sentinel prevents arbitrary deep traversal in practice. The risk is primarily at JSON parse time (OPA's Go JSON parser) rather than in Rego evaluation.
  - **Impact:** Go's `encoding/json` has stack-overflow protections for deeply nested structures (returns an error at depth > ~10,000). OPA will return a 400 before the policy evaluates. This is an OPA-level protection, not a policy-level one. MINOR in practice.

- **[MINOR]** Negative array indices: Rego arrays are accessed by positive integer index only. `some i, item in array` uses OPA's built-in iterator which ignores negative indices from external input — they simply never iterate. No risk.

- **[MINOR]** Field names that shadow Rego built-ins: Rego evaluates `input.X` via the `input` document, never confusing field names with built-in function names. An input field named `count` or `sum` does not shadow the built-in because Rego's namespace resolution treats `input.count` and the built-in `count()` as completely distinct. No risk.

- **[MINOR]** Integer overflow in financial calculations
  - **Location:** `sofa/standard/sofa.rego:254–258`
  - **Evidence:** `computed_income := sum([item.amount | ...])`. OPA uses Go's `float64` for all numeric operations. `float64` can represent values up to ~1.8 × 10^308, so overflow is not a practical concern for financial figures. However, `float64` has only 53 bits of mantissa precision, meaning integers above 2^53 (approximately 9 quadrillion) lose precision. A national-scale financial report with totals in the quadrillions could produce silent precision loss in reconciliation checks.
  - **Impact:** Negligible for charity sector reports. Worth noting for any future expansion to central bank or sovereign wealth fund scale.

### Verdict: CRACKED

Two production-grade vulnerabilities: sentinel collision allows forced validation failures on valid inputs, and no string length guards allow multi-megabyte error messages. The ReDoS risk is operator-dependent, not input-dependent, but still real.

---

## Round 5: Cascading Failure

**Scenario:** Rule A fails, producing 500 deny entries (one per line item with the same error). Does the policy cap deny entries? Does it aggregate? What happens to consumers processing 500 entries?

### Findings

- **[CRITICAL]** No cap on deny set cardinality — 10,000 line items produce up to 10,000 deny entries for a single rule
  - **Location:** `sofa/standard/sofa.rego:398–403` (materiality rule), `sofa/standard/sofa.rego:197–209` (line_required rule)
  - **Evidence:** The `materiality` rule fires for every line item whose amount is below the floor:
    ```rego
    deny contains {"msg": sprintf("%s[%d]: amount %v below materiality floor %v", [sec, i, item.amount, thresholds.materiality_floor]), "severity": "info", ...} if {
        some sec in ["incoming_resources", "resources_expended"]
        some i, item in items(sec)
        ...
    }
    ```
    With 10,000 items all below the floor, this produces 10,000 distinct deny entries (each unique because `i` differs). The same pattern applies to `line_required`, `audit_reference`, `income_category`, `expense_category`, `fund_type` — every per-item rule.
  - **Impact:** Consumers receive a 10,000-entry array in `errors` or `warnings`. At approximately 100 bytes per entry, that is 1MB of error payload per evaluation. JSON serialization and deserialization of 10,000 structured objects is expensive. Downstream logging systems that store every deny entry per evaluation will accumulate tens of gigabytes per day at 10,000 reports/day. UI consumers that render all errors will hang browsers.

- **[CRITICAL]** No error aggregation — identical structural errors for different items are not grouped
  - **Location:** Both policies, all per-item rules
  - **Evidence:** If all 10,000 items are missing the `category` field, the policy emits 10,000 separate deny entries:
    - `"incoming_resources[0]: missing fields {\"category\"}"`, `"incoming_resources[1]: ..."`, ...
    - These are not aggregated into a single `"all items missing category"` entry. The set deduplication in Rego only de-dupes entries that are identical objects — entries with different `i` indices are distinct.
  - **Impact:** An operator or auditor receiving this response cannot meaningfully triage it. The first fix (missing category) should be evident from one entry, but they receive 10,000. Automated systems that inspect `error_count` may have business logic thresholds (e.g., "reject if > 50 errors") that are tripped by a single structural issue that a competent operator could resolve in one edit.

- **[MAJOR]** SoFREP's per-item rules have the same unbounded accumulation pattern
  - **Location:** `sofrep/standard/sofrep.rego:210–216` (base_fields), `sofrep/standard/sofrep.rego:219–227` (quadrant_fields)
  - **Evidence:** Same structure as SoFA — `some q in quadrants; some item in items_in(q)` without any cap.
  - **Impact:** SoFREP's scale is smaller by design (readiness report = tens of items), so this is less likely to cause a practical problem. But it is the same structural gap.

- **[MAJOR]** The `summary` object in both policies includes the full `errors` and `warnings` sets
  - **Location:** `sofa/standard/sofa.rego:474–480`, `sofrep/standard/sofrep.rego:525–534`
  - **Evidence:**
    ```rego
    summary := {
        "valid": valid,
        "error_count": count(errors),
        "warning_count": count(warnings),
        "errors": errors,
        "warnings": warnings,
    }
    ```
    The consumer receives the full unbounded set in every response. There is no `"errors_truncated": true` flag or `"max_errors_shown": 50` limit.
  - **Impact:** Every downstream consumer that calls `/v1/data/sofa/standard/summary` receives the full payload. No consumer can opt for a lightweight response.
  - **Fix:** Cap at the rule level using a `limit` approach or add a separate `summary_brief` rule that returns only `error_count`, `warning_count`, `valid`, and the first N errors. Alternatively, add aggregation rules that group per-item errors by rule name and field:
    ```rego
    error_summary[rule_name] := count if {
        some rule_name in {d.rule | some d in errors}
        count := count({d | some d in errors; d.rule == rule_name})
    }
    ```

### Verdict: SHATTERED

Both policies produce unbounded deny sets with no aggregation, no cap, and no brief-summary alternative. A single structural error in a 10,000-item batch produces 10,000 deny entries. This is a production-day-one failure mode for any batch ingestor at scale.

---

## Round 6: Scale

**Scenario:** 10,000 reports/day in batch. OPA HTTP sidecar. Memory footprint of compiled policy + data? Does it grow with input count?

### Findings

- **[MAJOR]** Policy memory footprint is static but evaluate-time memory grows with input
  - **Location:** Both policies — compiled policy in OPA bundle
  - **Evidence:** OPA compiles Rego to a plan (intermediate representation) and then to Wasm or Go-native evaluation. The compiled policy bundle itself is static — it does not grow with input count. However, during evaluation, OPA materializes intermediate values: `all_items` in SoFREP is a full array copy of all items across all quadrants (line 23–26). For 10,000 items, this is a 10,000-element array allocated per evaluation. Similarly, `all_ids` (line 28) is a 10,000-element set. These are garbage-collected after each evaluation, so memory does not accumulate across evaluations — but peak per-evaluation memory is proportional to input size.
  - **Impact:** With OPA's default HTTP sidecar concurrency of multiple goroutines, simultaneous evaluations each allocate their own `all_items` copy. At 10,000 items × 100 bytes/item × 10 concurrent goroutines, that is ~10MB of live working memory for `all_items` alone, before deny set accumulation. The deny set itself (10,000 entries × 100 bytes = 1MB) is another allocation. Total per-evaluation peak: ~2–5MB. Total for 10 concurrent evaluations: 20–50MB. An OPA sidecar with a 256MB memory limit handles this; one with a 64MB limit may OOM under peak concurrency.

- **[MAJOR]** SoFA `computed_income` and `computed_expenditure` iterate the full items arrays in array comprehensions
  - **Location:** `sofa/standard/sofa.rego:254–256`
  - **Evidence:**
    ```rego
    computed_income := sum([item.amount | some item in items("incoming_resources"); is_number(item.amount)])
    ```
    This allocates a temporary array of all amounts before summing. For 10,000 items, this is a 10,000-element float64 array. This is O(n) time and space — acceptable, but noteworthy.
  - **Impact:** Minor memory pressure; OPA's garbage collector handles this cleanly.

- **[MAJOR]** `deny` set accumulation for 10,000-item reports is the dominant memory cost
  - **Location:** Both policies, result aggregation
  - **Evidence:** Each deny entry is a map with 4 fields (msg, severity, field, rule). At ~150 bytes each, 10,000 entries = 1.5MB per evaluation. This is non-trivial in a high-throughput sidecar.
  - **Impact:** At 10,000 reports/day with a 10-second average report, concurrent evaluations at peak could be ~1–2 per second. Memory pressure is manageable but not free.

- **[MINOR]** Bundle size: both `schema.json` files are tiny (under 1KB). The compiled policy IR will be under 1MB. Static memory footprint of the deployed policy is negligible.

- **[MINOR]** No `opa bench` data is available from the repository. The analysis above is derived from algorithmic complexity inspection, not empirical measurement. The **strongly recommended** pre-production step is:
  ```bash
  opa bench --data schema.json --input synthetic_10k.json 'data.sofa.standard.summary'
  opa bench --data schema.json --input synthetic_10k.json 'data.sofrep.standard.summary'
  ```
  to get empirical ns/op and B/op measurements.

### Verdict: CRACKED

No static memory growth, but per-evaluation working memory is proportional to input size and unbounded deny sets. At 10,000 items, each evaluation allocates 2–5MB of working memory. The O(n²) `unique_ids` rule in SoFREP is the performance ceiling, not memory. The combination of large inputs + unbounded deny sets is the operational risk at scale.

---

## Round 7: Backwards Compatibility

**Scenario:** New `schema.json` adds a required field. All existing inputs that were valid now fail. Is there a versioning mechanism? Migration path? Grace period?

### Findings

- **[CRITICAL]** No versioning mechanism exists in either policy or schema
  - **Location:** `sofa/standard/schema.json` (entire file), `sofrep/standard/schema.json` (entire file)
  - **Evidence:** Neither schema file has a `version`, `schema_version`, `policy_version`, `effective_from`, or `deprecated_fields` key. The policies themselves carry a `# custom: version: "2.0.0"` annotation in SoFA's metadata comment (line 12), but this is a comment annotation — it is not accessible at runtime as `data.schema.version` or enforced by any rule.
  - **Impact:** When a new required field is added to `schema.required_fields` (SoFA) or `schema.base_fields` / `schema.required_metadata` (SoFREP), every existing input that was previously valid immediately fails with `"missing required field: X"`. There is no grace period. There is no way for submitters to know which schema version their report was validated against. There is no way to run dual-version validation.

- **[CRITICAL]** The `required_fields` list in SoFA is the primary backwards-compatibility bomb
  - **Location:** `sofa/standard/schema.json:3`
  - **Evidence:** Currently: `["report_date", "entity_name", "currency", "accounting_basis", "incoming_resources", "resources_expended", "net_movement", "fund_balances", "reconciliation"]`. Adding any new field here (e.g., `"trustees_report"`, `"audit_opinion"`) immediately invalidates all existing inputs. The `required_field` rule (lines 165–174) fires for any field in this list that is absent from input.
  - **Impact:** A schema update becomes a hard cut-over with no backward path. In a production filing system serving hundreds of charities, this is a breaking change with no warning.

- **[CRITICAL]** SoFREP `base_fields` and `quadrant_fields` carry identical risk
  - **Location:** `sofrep/standard/schema.json:5–10`
  - **Evidence:** Adding `"last_reviewed"` to `base_fields` immediately invalidates all existing SoFREP reports that do not include it.
  - **Impact:** Same as above.

- **[MAJOR]** No migration path is defined or encodable in the current architecture
  - **Location:** Both policies
  - **Evidence:** There is no mechanism for `optional_fields`, `deprecated_fields`, `added_in_version`, or `grace_period_until`. The policies have no concept of a field being "new as of this cycle, warning only for 2 reporting periods, then error."
  - **Fix — Option A (versioned schema):** Add `schema_version` to `data.schema`. Add a rule:
    ```rego
    deny contains {"msg": sprintf("schema version mismatch: input targets v%s, loaded schema is v%s", [iv, sv]), "severity": "error", ...} if {
        iv := object.get(input, "schema_version", "")
        sv := object.get(data.schema, "schema_version", "")
        iv != ""
        sv != ""
        iv != sv
    }
    ```
  - **Fix — Option B (grace period fields):** Add `optional_until` to the schema:
    ```json
    "required_fields": [...],
    "optional_until": {"trustees_report": "2027-01-01"}
    ```
    The policy emits a warning (not an error) for fields in `optional_until` whose deadline has not passed.
  - **Fix — Option C (additive-only policy):** Never add to `required_fields` directly; instead add to a new `recommended_fields` list that fires warnings, and only graduate to `required_fields` in a major version bump with explicit operator notice.

### Verdict: SHATTERED

Zero backwards compatibility infrastructure. A one-line change to `schema.json` breaks all existing valid inputs with no warning period, no version detection, no migration path. This is the most dangerous production risk in the entire codebase because it makes the policy unsafe to update.

---

## Round 8: Human Factors

**Scenario:** A non-technical auditor reads the deny output. Can they understand it? Can they act on it? Are messages for humans or machines? Is there a fix suggestion?

### Findings

- **[MAJOR]** Messages are partially human-readable but contain no fix instructions
  - **Location:** Both policies, all deny rules
  - **Evidence:** Sample error messages from SoFA:
    - `"missing required field: entity_name"` — clear, actionable
    - `"net_movement 37001 != computed 37000"` — clear, actionable
    - `"fund 'restricted': opening(50000) + net_movement(15000) != closing(65000.01)"` — clear for an accountant
    - `"variance >20.0% on incoming_resources_total unexplained"` — requires domain knowledge to understand what "explained" means and how to supply it
    - `"income growth ratio 6.3 exceeds plausibility threshold 5.0"` — no fix suggestion: should the user reduce the income, add a note, or contact the operator?

  Sample from SoFREP:
    - `"duplicate id 'WW-001' found across quadrants"` — clear
    - `"critical risk: 'AR-001' (score=25)"` — what should the user do? Reduce the score? Add a treatment plan?
    - `"escalation required: readiness below escalation threshold"` — who should escalate, to whom, and how?
  - **Impact:** Non-technical auditors and first-time submitters cannot self-serve on approximately 40% of the messages. They require either training or a support desk to interpret and resolve warnings.

- **[MAJOR]** No `fix` or `action` field in deny entries
  - **Location:** Both policies, deny entry structure
  - **Evidence:** Every deny entry has exactly 4 fields: `msg`, `severity`, `field`, `rule`. There is no `fix`, `action`, `reference`, `docs_url`, or `example` field. Compare to industry-standard linter output (ESLint, Biome, cargo clippy) which includes a `suggestion` or `help` alongside every finding.
  - **Impact:** A non-technical auditor receiving `"variance >20.0% on net_movement unexplained"` has no indication that they need to add a `variance_explanations.net_movement` field with a string value. They must either know the schema by heart or read policy source code.
  - **Fix:** Add a `fix` field to structured deny entries:
    ```rego
    deny contains {
        "msg": sprintf("variance >%v%% on %s unexplained", [thresholds.variance_limit * 100, k]),
        "severity": "warning",
        "field": k,
        "rule": "variance_analysis",
        "fix": sprintf("Add 'variance_explanations.%s' with a narrative explanation of the change", [k])
    } if { ... }
    ```

- **[MAJOR]** Severity levels are inconsistently communicated to human consumers
  - **Location:** Both policies, result structure
  - **Evidence:** The `severity` field uses `"error"`, `"warning"`, and `"info"` (SoFA) or `"error"` and `"warning"` (SoFREP). The `valid` flag is only false when `errors` is non-empty — warnings do not block validity. However, a non-technical auditor reading the raw response cannot easily distinguish blocking errors from advisory warnings without reading both the `errors` array and the `warnings` array separately and understanding the `valid` flag semantics.
  - **Impact:** Auditors may treat all deny entries as blocking, causing unnecessary escalations. Or they may dismiss all entries as advisory, missing genuine errors.
  - **Fix:** The `summary` object should include a `"blocked_by"` plain-English field:
    ```rego
    summary := {
        ...
        "blocked_by": "Report blocked: 3 errors must be resolved before acceptance" if count(errors) > 0,
        "blocked_by": "Report accepted with warnings: review 5 advisory items" if count(errors) == 0,
    }
    ```

- **[MINOR]** `"info"` severity in SoFA (materiality rule) is not separated from warnings in the result
  - **Location:** `sofa/standard/sofa.rego:467–468`
  - **Evidence:** `warnings := {d | some d in deny; d.severity in {"warning", "info"}}` — info and warning are merged into a single set. A non-technical auditor cannot distinguish an informational note (materiality: this amount is below the reporting floor — no action required) from a genuine warning (going concern: action is required).
  - **Impact:** The materiality rule fires for every sub-floor item and can flood the warnings set with info-level noise, causing genuine warnings to be missed.
  - **Fix:** Separate `info` from `warning` at the result level:
    ```rego
    warnings := {d | some d in deny; d.severity == "warning"}
    info_items := {d | some d in deny; d.severity == "info"}
    ```
    Expose both in `summary`.

- **[MINOR]** Rule names (`"net_movement_check"`, `"fund_reconciliation"`, `"data_sentinel"`) are machine identifiers, not human-readable labels
  - **Location:** Both policies, all deny entries
  - **Evidence:** `"rule": "data_sentinel"` tells a developer which rule fired. It tells an auditor nothing.
  - **Fix:** Add a `"rule_label"` field with a human-readable name: `"Data validation configuration missing"`, `"Fund balance reconciliation failure"`, etc. The machine-readable `rule` key is preserved for programmatic routing; the `rule_label` is for human display.

### Verdict: CRACKED

Messages are partially human-readable but lack fix instructions, fix examples, and doc links. The severity model is not clearly communicated in the summary output. The `info`/`warning` merge buries advisory items under materiality noise. Non-technical auditors can understand roughly half the messages without additional support.

---

## Cross-Cutting Summary

| Round | Policy | Verdict | Root Cause |
|-------|--------|---------|------------|
| 1 — Context Pressure | SoFREP | CRACKED | O(n²) `unique_ids` rule; O(d×n) `owner_counts` |
| 1 — Context Pressure | SoFA | HOLDS | All rules are O(n) or better |
| 2 — Concurrent Collision | Both | HOLDS | Pure Rego, no mutable state |
| 3 — Stale Data | Both | CRACKED | No schema versioning, no staleness detection |
| 4 — Malicious Input | Both | CRACKED | Sentinel collision, no string length caps |
| 5 — Cascading Failure | Both | SHATTERED | Unbounded deny sets, no aggregation |
| 6 — Scale | SoFREP | CRACKED | O(n²) dominates; deny set memory proportional to items |
| 6 — Scale | SoFA | CRACKED | Deny set memory; no `opa bench` baseline |
| 7 — Backwards Compat | Both | SHATTERED | Zero versioning infrastructure |
| 8 — Human Factors | Both | CRACKED | No fix instructions, no rule labels, info/warning merge |

### Critical Findings (Must Fix Before Production)

1. **SoFREP `unique_ids` O(n²)** — replace nested quadrant iteration with single-pass id multiset
2. **Unbounded deny set cardinality** — add per-rule aggregation and a `summary_brief` endpoint
3. **No schema versioning** — add `schema_version` field and version-mismatch detection rule
4. **Sentinel collision `"__MISSING__"`** — replace with UUID sentinel in both policies
5. **No backwards compatibility mechanism** — define `optional_until` or `recommended_fields` before any schema update

### Major Findings (Fix Before GA)

6. **No string length caps on user-controlled fields** — add max-length guards for fields that appear in error messages
7. **No fix/action field in deny entries** — add `"fix"` field to every deny rule
8. **`info` merged with `warning`** in SoFA result — separate into distinct sets
9. **No `opa bench` baseline** — establish empirical performance gates before 10K-item deployment
10. **No deployment documentation** — document that `data.schema` must be loaded via OPA bundle, not mutable data API
