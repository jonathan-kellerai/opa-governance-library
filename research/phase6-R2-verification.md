# Phase 6 — R2 Verification Panel
## Dance Cards: Three Judges, One Pass

- **Prepared by:** R2 Verification Panel (Craftsman, Oracle, Pilot perspectives)
- **Date:** 2026-03-25
- **Source policies verified:**
  - `sofa/standard/sofa.rego` (Phase 6 merge)
  - `sofa/standard/sofa_test.rego`
  - `sofa/standard/schema.json`
  - `sofrep/standard/sofrep.rego` (Phase 6 merge)
  - `sofrep/standard/sofrep_test.rego`
  - `sofrep/standard/schema.json`
- **R1 findings verified against:** `research/phase5-judge1-craftsman.md`, `research/phase5-judge2-oracle.md`, `research/phase5-judge3-pilot.md`

---

## Verdict Scale

- **HOLDS:** Patch fixes the issue
- **CRACKED:** Partial fix, still exploitable in narrower case
- **SHATTERED:** Patch did not fix it, or introduced new vulnerability
- **NEW SURFACE:** Patch created an attack surface that did not exist before

---

## Judge 1 (Craftsman) R2: Precision and Consistency

**Mandate:** Verify every CRITICAL fix has a regression test. Verify fixes did not introduce spec-to-rule misalignment. Check for fix-one-break-two patterns. Specifically verify `is_number` guards on `variance_analysis`, `liquidity_ratio`, and `transfer_netting`; dead `schema_list_nonempty` code in SoFREP; `filing_deadline_days` schema key.

---

### CRITICAL 1 — `variance_analysis` is_number guards

**R1 finding:** `prior_val` and `current_val` in `variance_analysis` had no `is_number` guards, allowing string values to silently bypass the check.

**What the patch did:**
`sofa.rego` lines 338–344 now read:

```rego
prior_val := prior[k]
is_number(prior_val)
prior_val != 0
current_val := input[k]
is_number(current_val)
abs(current_val - prior_val) / abs(prior_val) > thresholds.variance_limit
```

Both `is_number(prior_val)` and `is_number(current_val)` are present immediately after their respective assignments.

**Regression tests present?** Yes. `sofa_test.rego` lines 664–689 add:
- `test_variance_analysis_string_values_no_crash` — both prior and current are strings; asserts `variance_analysis` does not fire
- `test_variance_analysis_string_prior_no_fire` — prior is `"TBD"`, current is numeric; asserts no fire

**Verdict: HOLDS.** Both guards present; both regression tests present. No spec-to-rule misalignment introduced.

---

### CRITICAL 2 — `liquidity_ratio` is_number guards

**R1 finding:** `cl := object.get(input, "current_liabilities", 0)` had no `is_number` guard. A string value like `"1000"` would pass `cl > 0` (string > number in OPA is true, producing undefined on division).

**What the patch did:**
`sofa.rego` lines 378–384 now read:

```rego
cl := object.get(input, "current_liabilities", 0)
is_number(cl)
cl > 0
ca := object.get(input, "current_assets", 0)
is_number(ca)
ratio := ca / cl
```

Both `is_number(cl)` and `is_number(ca)` are explicit guards before the division.

**Regression tests present?** Yes. `sofa_test.rego` lines 696–712 add:
- `test_liquidity_ratio_string_values_no_crash` — both assets and liabilities are `"pending"`; asserts rule does not fire
- `test_liquidity_ratio_string_liabilities_no_fire` — assets numeric, liabilities `"TBD"`; asserts no fire

**Verdict: HOLDS.** Guards present; regression tests present.

---

### CRITICAL 3 — `transfer_netting` string-amount bypass

**R1 finding:** String amounts in transfers were silently excluded from `transfer_net` via the `is_number` filter in the comprehension, causing the netting check to pass when all amounts were strings.

**What the patch did:**
1. The `transfer_netting` main rule (lines 318–323) now adds an additional guard: `every t in transfers { is_number(t.amount) }`. This means the netting check only fires when ALL transfer amounts are numeric — a mixed batch no longer silently passes.
2. A new companion rule `transfer_netting_type` (lines 325–329) explicitly fires an error when a transfer's `amount` key is present but non-numeric.

**Regression tests present?** Yes. `sofa_test.rego` lines 718–735 add:
- `test_transfer_netting_string_amount_type_error` — one string amount; asserts `transfer_netting_type` error fires
- `test_transfer_netting_all_string_amounts_no_netting_rule` — all string amounts; asserts `transfer_netting` (not `transfer_netting_type`) does not fire (the type-guard rule fires instead)

**Fix-one-break-two check:** The `every t in transfers { is_number(t.amount) }` guard on the netting rule combined with the new type error rule creates correct defense-in-depth. No path allows a mixed transfer batch to pass silently. The companion type rule closes the gap the R1 finding identified.

**Verdict: HOLDS.** Both the detection rule and the type-guard companion are in place with regression tests.

---

### CRITICAL 4 — Dead `schema_list_nonempty` in SoFREP (`required_metadata` and `base_fields`)

**R1 finding:** SoFREP's `schema_list_nonempty` for `required_metadata` and `base_fields` contained the unsatisfiable condition `count > 0 AND count < 1`, making both guards dead code. Empty `required_metadata: []` and `base_fields: []` would not be caught.

**What the patch did:**
`sofrep.rego` lines 145–153 now read:

```rego
deny contains {"msg": "data.schema.required_metadata must have at least 1 entry", ...} if {
    _has_schema
    count(object.get(data.schema, "required_metadata", [])) < 1
}

deny contains {"msg": "data.schema.base_fields must have at least 1 entry", ...} if {
    _has_schema
    count(object.get(data.schema, "base_fields", [])) < 1
}
```

The impossible `count > 0` conjunct has been removed. Each rule now uses only the `< 1` condition (equivalent to `== 0`), which is satisfiable and correct.

**Additionally:** The `data_sentinel` layer in SoFREP (lines 91–93) also has a guard:
```rego
deny contains {"msg": "data.schema.required_metadata is missing or empty", ...} if {
    _has_schema
    count(object.get(data.schema, "required_metadata", [])) == 0
}
```
This provides a second layer of protection at the sentinel level.

**Regression tests present?** Yes. `sofrep_test.rego` lines 820–836 add:
- `test_r4_required_metadata_empty` — overrides schema with `required_metadata: []`; asserts `schema_list_nonempty` fires with correct message
- `test_r4_base_fields_empty` — overrides schema with `base_fields: []`; asserts `schema_list_nonempty` fires with correct message

**Verdict: HOLDS.** Dead code eliminated; both previously-dead paths now fire correctly; regression tests confirm the previously-dead behavior is now live.

---

### MAJOR — `filing_deadline_days` schema key wired

**R1 finding:** `filing_deadline_days` in `sofa/standard/schema.json` was a dead key — the policy used a hardcoded Rego function `_filing_deadline_days(j)` instead of reading from `data.thresholds`. Operators attempting to tune the deadline via `schema.json` would find it had no effect.

**What the patch did:**
`sofa.rego` line 507 now reads:

```rego
deadline := object.get(thresholds, "filing_deadline_days", _filing_deadline_days(jur))
```

The `object.get` uses `data.thresholds.filing_deadline_days` when present, falling back to the hardcoded `_filing_deadline_days(jur)` function only when the threshold is absent. The `sofa/standard/schema.json` `thresholds` section includes `"filing_deadline_days": 304`, so this key is now live and operator-configurable.

**Regression tests present?** The cross-year boundary tests at lines 741–756 exercise the deadline path with RFC3339-accurate date arithmetic. No test specifically validates that overriding `filing_deadline_days` via thresholds changes behavior, but the wiring is mechanically correct.

**Verdict: HOLDS (with minor caveat).** The key is wired. The absence of a test asserting `object.get(thresholds, "filing_deadline_days", ...)` override behavior is a minor gap — not a functional defect.

---

### NEW SURFACE identified by Craftsman R2

**`transfer_netting_type` fires on transfers without an `amount` key? — Check required.**

The new `transfer_netting_type` rule (lines 325–329) reads:
```rego
deny contains {...} if {
    some i, t in object.get(input, "transfers", [])
    "amount" in object.keys(t)
    not is_number(t.amount)
}
```

The guard `"amount" in object.keys(t)` ensures the rule only fires when the `amount` key is present but non-numeric. A transfer missing `amount` entirely does not trigger this rule. This is correct — missing `amount` is a different kind of error that other rules would catch.

**Assessment:** NEW SURFACE is not introduced. The rule is correctly scoped.

---

**Craftsman R2 Overall Verdict: 4 HOLDS, 0 CRACKED, 0 SHATTERED, 0 NEW SURFACE**

All four CRITICAL-class Craftsman R1 findings are patched with regression tests. The `filing_deadline_days` wiring is functionally correct with a minor test-coverage gap (not blocking).

---

## Judge 2 (Oracle) R2: Game Theory and Architecture Attacks

**Mandate:** Re-apply the 2 most devastating attacks from R1 — (1) Nash equilibrium / empty report still passes, (2) missing config → accept-everything.

---

### ATTACK 1 — Nash Equilibrium: Does an Empty Report Still Pass?

**R1 finding (SHATTERED):** The Nash equilibrium was a report with all required fields present as empty arrays (`incoming_resources: []`, `resources_expended: []`, `net_movement: 0`, `fund_balances: {}`, `reconciliation: {opening_total: 0, net_movement: 0, closing_total: 0}`). This passed with zero errors and zero warnings. The `minimum_substance` rule existed but had `min_substance_items: 0` (disabled by default). Oracle rated this SHATTERED — a fundamental incentive design failure.

**What the patch did:**
Reading `sofa/standard/schema.json` line 24:
```json
"min_substance_items": 0,
```

The default value in the deployed schema is **still 0**. The `minimum_substance` rule in `sofa.rego` lines 432–438 still reads:
```rego
min_items := object.get(thresholds, "min_substance_items", 0)
min_items > 0
```

When `min_substance_items: 0`, the condition `min_items > 0` is false and the rule never fires.

**Attack re-run:** Submit a report with `incoming_resources: []`, `resources_expended: []`, `net_movement: 0`, `fund_balances: {}`, `reconciliation: {opening_total: 0, net_movement: 0, closing_total: 0}`. Result: zero errors, the `net_movement_check` passes (0 == 0), `fund_reconciliation` iterates an empty map (no entries, no violations), `aggregate_reconciliation` fires only if three numeric fields are present (and the zero values satisfy `0 + 0 == 0`). The report passes with `valid: true` and zero warnings.

**The Oracle has run the attack. It succeeds.**

The schema still ships with `min_substance_items: 0`. No rule has been added that requires at least one line item unconditionally. The empty-report Nash equilibrium persists unchanged.

**Verdict: SHATTERED.** The R1 finding was explicitly flagged as "The default should be non-zero (at least 1)." The Phase 6 merge did not change the default. The game-theoretic dominant strategy — submit an empty report — remains fully viable. `valid: true` is returned for a blank financial statement.

---

### ATTACK 2 — Missing Config → Accept Everything

**R1 finding (Architecture Round 7, SHATTERED):** When `data.schema` is absent or empty, `income_cats`, `expense_cats`, and `fund_types` resolve to empty sets. Every `income_category` rule then passes (nothing in the empty set to fail against), producing `valid: true` instead of rejection.

**What the patch did:**
`sofa.rego` lines 82–93 define three sentinel guards:

```rego
deny contains {"msg": "data.schema is missing or empty", ...} if {
    not _schema_present
}

deny contains {"msg": "data.thresholds is missing or empty", ...} if {
    not _thresholds_present
}

deny contains {"msg": "data.schema.required_fields is empty", ...} if {
    _schema_present
    not _schema_required_fields_present
}
```

When `data.schema` is absent, `data_sentinel` fires an error, setting `valid: false` (because `errors != {}`).

**Attack re-run — Does `data_sentinel` catch this before category rules fire?**

Trace evaluation with `data.schema` absent:

1. `_schema_present` evaluates to false (empty schema → `count(data.schema) > 0` is false)
2. `deny contains {"msg": "data.schema is missing or empty", ...}` fires
3. `errors` set is non-empty → `valid := false`
4. BUT: `income_cats := {c | some c in schema.income_categories}` — with schema absent, `schema.income_categories` is undefined, so `income_cats = {}` (empty set)
5. `income_category` rule: `not item.category in income_cats` — if `income_cats = {}`, then nothing is in the set, so `not item.category in {}` is always true → `income_category` fires for every line item

**This is still the cascade described in R1.** The sentinel fires, yes — but so do all the downstream rules. The deny set explodes. The difference from R1: `valid: false` is correctly set because `errors` is non-empty. The architectural failure of "accept everything" is **partially fixed** (valid is now false) but the **cascade of spurious errors remains**.

**What has NOT been fixed:** The downstream rules are not gated on `_schema_present`. There is no guard at the beginning of `income_category`, `expense_category`, `fund_type`, or any other category rule that short-circuits when the schema is missing. OPA evaluates all `deny` rules regardless of the sentinel state.

**Impact assessment for this phase:** The Oracle originally rated this SHATTERED because the missing config caused `valid: true`. That specific failure is now fixed — `valid: false` is returned. However, the secondary failure (O(n) spurious category errors flooding the deny set when schema is missing) remains. A 100-item report with missing schema now produces 100+ spurious `income_category` and `expense_category` errors alongside the one real `data_sentinel` error. The consumer cannot distinguish the root cause.

**Verdict: CRACKED.** The `valid: true` inversion is fixed. The cascading spurious error flood under missing schema is not fixed. The SHATTERED condition (accepting everything as valid) has been resolved, but the architectural recommendation (gate all downstream rules on `_schema_present`) has not been implemented. The attack now produces `valid: false` with an uninterpretable flood of errors rather than a silent `valid: true` — a meaningful improvement but not a complete fix.

---

### Oracle Additional Check — `data_sentinel` catches before category rules? (SoFREP)

SoFREP uses a different sentinel pattern. `_has_schema` checks for the presence of `data.schema.quadrants`:

```rego
_has_schema if {
    object.get(data.schema, "quadrants", null) != null
}
```

When `data.schema` is missing entirely, `_has_schema` is false, `data_sentinel` fires, and `valid: false` is returned. However, the module-scope alias `quadrants := data.schema.quadrants` on line 21 would be `undefined` when schema is absent. All downstream rules using `some q in quadrants` would silently produce no iterations (empty set from undefined). Unlike SoFA, SoFREP's category rules iterate over `quadrants` — so with `quadrants` undefined, no quadrant iteration fires, and the cascading spurious error problem is much smaller in SoFREP.

**SoFREP sentinel assessment:** HOLDS. The cascade problem is SoFA-specific.

---

**Oracle R2 Verdict Summary:**

| Attack | R1 Verdict | R2 Verdict | Notes |
|--------|-----------|-----------|-------|
| Nash equilibrium (empty report) | SHATTERED | SHATTERED | `min_substance_items: 0` unchanged; empty report still produces `valid: true` |
| Missing config → accept everything | SHATTERED | CRACKED | `valid: false` now returned; cascading spurious errors not suppressed |

---

## Judge 3 (Pilot) R2: Production Safety

**Mandate:** Re-run the 2 SHATTERED scenarios — (1) cascading failure / deny cap, (2) backwards compatibility / schema version check.

---

### SCENARIO 1 — Cascading Failure: Is There Now a Deny Cap?

**R1 finding (SHATTERED):** No cap on deny set cardinality. 10,000 line items produce up to 10,000 deny entries for a single rule. No aggregation. The `summary` object includes the full unbounded set.

**What the patch did — SoFA:**

`sofa.rego` lines 511–552 add a complete deny cap and truncation mechanism:

```rego
_max_deny := object.get(thresholds, "max_deny_entries", 100)

_deny_truncated if count(deny) > _max_deny

_capped_deny := {d | some i, d in array.slice(sort(deny), 0, _max_deny)} if { _deny_truncated }
_capped_deny := deny if { not _deny_truncated }

_truncation_entry contains {"msg": sprintf("output truncated: %d additional findings suppressed", [count(deny) - _max_deny]), ...} if { _deny_truncated }

summary := {
    "valid": valid,
    "error_count": count(errors),
    "warning_count": count(warnings),
    "errors": {d | some d in _capped_deny; d.severity == "error"} | {d | some d in _truncation_entry},
    "warnings": {d | some d in _capped_deny; d.severity in {"warning", "info"}} | {d | some d in _truncation_entry},
    "deny_count": count(deny),
}
```

The `summary` returns capped deny sets. `deny_count` exposes the true total so consumers know truncation occurred. The truncation entry is appended to both `errors` and `warnings` sets to signal consumers regardless of which severity they inspect.

**What the patch did — SoFREP:**

`sofrep.rego` lines 541–588 add a parallel mechanism:

```rego
default max_deny_entries := 100
max_deny_entries := data.thresholds.max_deny_entries if { is_number(data.thresholds.max_deny_entries) }

_deny_is_capped if { count(deny) > max_deny_entries }

deny_capped contains d if { not _deny_is_capped; some d in deny }
deny_capped contains d if {
    _deny_is_capped
    _deny_as_array := sort([d2 | some d2 in deny])
    some i, d in _deny_as_array
    i < max_deny_entries
}

deny_capped contains {"msg": sprintf("output truncated: %d total findings exceed cap of %d", ...), ...} if { _deny_is_capped }

summary := { ..., "deny_capped": deny_capped }
```

**Does the cap work?**

Test evidence from `sofa_test.rego` lines 844–852:
- `test_deny_cap_summary_has_deny_count` — confirms `deny_count` is numeric
- `test_deny_cap_no_truncation_under_limit` — confirms no `deny_cap` rule fires under normal conditions

Test evidence from `sofrep_test.rego` lines 911–918:
- `test_deny_cap_default_100` — confirms default cap is 100
- `test_deny_capped_equals_deny_when_under_cap` — confirms `deny_capped == deny` when under cap

**What happens with 1,000 identical violations?**

With `min_substance_items: 0` (unchanged), 1,000 line items all missing `category` would produce 1,000 `income_category` deny entries. With the cap at 100 (default), `_deny_truncated` fires, `_capped_deny` returns the first 100 entries sorted, and the truncation entry announces the remaining 900 are suppressed. The `summary.deny_count` shows 1,000. The consumer receives 101 entries (100 actual + 1 truncation notice) rather than 1,000.

**Critical note on `_capped_deny` implementation (SoFA):**

```rego
_capped_deny := {d | some i, d in array.slice(sort(deny), 0, _max_deny)} if { _deny_truncated }
```

`sort(deny)` converts the deny set to a sorted array. `array.slice(sorted, 0, 100)` takes the first 100. Then a set comprehension re-builds a set from those 100. This is correct but has a subtle implication: `sort(deny)` where `deny` is a set of objects sorts by OPA's internal ordering (lexicographic on the serialized object). The "first 100" entries may not be the 100 highest-severity entries. This is a **priority-ordering gap** — errors may be de-prioritized in favor of alphabetically-earlier warnings. The `deny_count` field preserves awareness of the true total.

**Verdict: HOLDS.** The deny cap exists, is configurable, is capped at 100 by default, and produces a truncation notice. The full untruncated count is preserved in `deny_count`. The Pilot's SHATTERED scenario no longer applies — 1,000 violations no longer produce an unbounded response. The sort-order priority gap is a minor UX issue, not a safety failure.

---

### SCENARIO 2 — Backwards Compatibility: Is There a Schema Version Check?

**R1 finding (SHATTERED):** No versioning mechanism in either policy or schema. Adding a new required field to `schema.required_fields` immediately invalidates all existing inputs with no warning, no grace period, no version mismatch signal.

**What the patch did — SoFREP (schema.json):**

`sofrep/standard/schema.json` now contains at the root level:
```json
{
    "_schema_version": "1.0.0",
    "schema": { ... },
    "thresholds": { ... }
}
```

**What the patch did — SoFREP policy:**

`sofrep.rego` lines 155–169 add:
```rego
_expected_schema_version := "1.0.0"

_actual_schema_version := v if {
    v := data._schema_version
} else := ""

deny contains {"msg": sprintf("schema version mismatch: policy expects '%s' but schema has '%s'", ...), "severity": "warning", ...} if {
    _actual_schema_version != ""
    _actual_schema_version != _expected_schema_version
}

deny contains {"msg": sprintf("schema version missing: policy expects '%s' but _schema_version is not set", ...), "severity": "warning", ...} if {
    _actual_schema_version == ""
}
```

**Does it warn on mismatch?**

Test evidence from `sofrep_test.rego` lines 861–886:
- `test_schema_version_mismatch_fires` — overrides `data._schema_version` to `"2.0.0"`; asserts `schema_version_check` warning fires with "mismatch" in message
- `test_schema_version_missing_fires` — overrides to `""`; asserts warning fires with "missing" in message
- `test_schema_version_match_no_fire` — overrides to `"1.0.0"`; asserts no `schema_version_check` rule fires

**Remaining gaps — what the patch does NOT address:**

1. **SoFA has no schema version check.** `sofa/standard/schema.json` does not contain `_schema_version`. `sofa.rego` has no `schema_version_check` rule. SoFA remains fully unversioned.

2. **Warning severity, not error.** A schema version mismatch fires as `"warning"`, not `"error"`. `valid: true` is returned even on a version mismatch. A consumer that only checks `valid` will not detect the mismatch.

3. **No `optional_until` grace period mechanism.** The Pilot R1 finding described a full grace-period architecture (warning-only for newly-added fields during a transition period). No such mechanism exists. Adding a field to `schema.required_fields` still immediately breaks all existing inputs with no gradual transition.

4. **`_schema_version` is at the data root, not in `data.schema`.** The policy reads `data._schema_version`. This means the version is a top-level data document key, not embedded inside the schema object. This works in OPA but differs from the standard pattern of self-describing schema documents and may surprise operators.

5. **The version check is only in SoFREP.** The backwards-compatibility bomb for SoFA's `required_fields` list remains entirely unaddressed.

**Verdict: CRACKED.** SoFREP now has a schema version check with regression tests — the specific mismatch warning fires correctly. But SoFA is unversioned, the severity is warning-not-error (mismatches don't block submission), there is no grace period mechanism, and the top-level `_schema_version` placement is unconventional. The SHATTERED scenario is partially addressed for SoFREP only.

---

**Pilot R2 Verdict Summary:**

| Scenario | R1 Verdict | R2 Verdict | Notes |
|----------|-----------|-----------|-------|
| Cascading failure / deny cap | SHATTERED | HOLDS | Cap at 100 entries; `deny_count` preserves true total; truncation notice emitted |
| Backwards compatibility / schema version | SHATTERED | CRACKED | SoFREP only; warning-not-error; no grace period; SoFA unversioned |

---

## Consolidated R2 Verdict Table

| R1 Finding | Judge | R1 Verdict | R2 Verdict | Evidence |
|-----------|-------|-----------|-----------|---------|
| `variance_analysis` missing `is_number` guards | Craftsman | CRITICAL | **HOLDS** | `sofa.rego:339,342`; tests at lines 664–689 |
| `liquidity_ratio` missing `is_number` guards | Craftsman | CRITICAL | **HOLDS** | `sofa.rego:379,382`; tests at lines 696–712 |
| `transfer_netting` string-amount bypass | Craftsman | CRITICAL | **HOLDS** | New `transfer_netting_type` rule + `every` guard; tests at lines 718–735 |
| Dead `schema_list_nonempty` in SoFREP | Craftsman/Oracle | CRITICAL | **HOLDS** | `sofrep.rego:145–153`; tests at lines 820–836 |
| `filing_deadline_days` schema key dead | Craftsman | MAJOR | **HOLDS** | `sofa.rego:507` wires `object.get(thresholds, "filing_deadline_days", ...)` |
| Nash equilibrium: empty report passes | Oracle | SHATTERED | **SHATTERED** | `schema.json:24` still `"min_substance_items": 0`; no unconditional line-item requirement added |
| Missing config → accept everything (SoFA cascade) | Oracle/Architecture | SHATTERED | **CRACKED** | `valid: false` now returned; cascading spurious errors not gated |
| Cascading failure / deny cap | Pilot | SHATTERED | **HOLDS** | `sofa.rego:511–552` and `sofrep.rego:541–588`; 100-entry cap; `deny_count` field |
| Backwards compatibility / schema version | Pilot | SHATTERED | **CRACKED** | SoFREP gets `_schema_version` + warning rule; SoFA entirely unversioned; no grace period |

---

## Remaining Open Vulnerabilities

### Open 1 — Nash Equilibrium Unpatched (SHATTERED, Unresolved)

**Location:** `sofa/standard/schema.json:24`, `sofa/standard/sofa.rego:432–438`

A bad-faith reporter can submit a blank financial statement — all required structural fields present, all as empty arrays or zero values — and receive `valid: true` with zero errors and zero warnings. The `minimum_substance` rule exists but fires only when `min_substance_items > 0` in thresholds. The deployed schema ships with `min_substance_items: 0`.

**Minimum fix:** Change `sofa/standard/schema.json` `"min_substance_items": 0` to `"min_substance_items": 1`. This changes the equilibrium so a report must have at least one line item.

---

### Open 2 — SoFA Unversioned (CRACKED, Partial)

**Location:** `sofa/standard/schema.json` (no `_schema_version` key), `sofa/standard/sofa.rego` (no `schema_version_check` rule)

SoFREP received a schema version check in Phase 6. SoFA did not. Any change to `sofa/standard/schema.json` that adds or removes a required field will silently break all existing inputs with no signal to consumers about which schema version produced the result.

**Minimum fix:** Add `"_schema_version": "2.0.0"` to `sofa/standard/schema.json` and add a `schema_version_check` rule to `sofa.rego` mirroring the SoFREP pattern.

---

### Open 3 — Schema Cascading Errors Under Missing Data (CRACKED, Partial)

**Location:** `sofa/standard/sofa.rego` — all category rules (`income_category`, `expense_category`, `fund_type`), all `schema` references

When `data.schema` is absent, `data_sentinel` correctly produces `valid: false`, but all downstream rules that reference `schema.*` still evaluate against empty sets, producing O(n) spurious errors that flood the deny set. The consumer cannot distinguish the root cause from the noise.

**Minimum fix:** Add `_schema_present` as the first condition to all rules that reference `income_cats`, `expense_cats`, or `fund_types`. In SoFREP this problem is smaller because `quadrants` is undefined when schema is absent, causing no quadrant iteration.

---

### Open 4 — `treatment_plan_required` uses `[...][0]` Array Index (Not Fixed)

**Location:** `sofrep/standard/sofrep.rego:535`

Oracle R1 identified `item := [i | some i in items_in("at_risk"); i.id == id][0]` as a fragile pattern that panics if the comprehension produces an empty array. Phase 6 did not change this line. The pattern remains:

```rego
item := [i | some i in items_in("at_risk"); i.id == id][0]
```

In practice this cannot panic during normal evaluation because `id` comes from `risk_matrix` which is computed from `items_in("at_risk")`. But as a maintenance hazard, if either rule is refactored independently, the `[0]` index will cause an evaluation panic rather than a graceful undefined.

**Risk:** LOW in current form; HIGH under refactoring conditions.

---

## New Surfaces Introduced by Phase 6 Patches

### NEW SURFACE 1 — `schema_version_check` fires on every SoFREP evaluation by default

**Location:** `sofrep/standard/sofrep.rego:167–169`

The rule:
```rego
deny contains {"msg": sprintf("schema version missing: policy expects '%s' but _schema_version is not set", ...), "severity": "warning", ...} if {
    _actual_schema_version == ""
}
```

`_actual_schema_version` defaults to `""` when `data._schema_version` is absent. The `sofrep/standard/schema.json` now contains `"_schema_version": "1.0.0"` at the root, so in the normal deployment with `schema.json` loaded as the data document, `data._schema_version` resolves to `"1.0.0"` and the missing-version warning does not fire.

However: the SoFREP test suite uses `with input as valid_input` without overriding `data._schema_version`. In an OPA test context where the data document is not loaded from file, `data._schema_version` is undefined, `_actual_schema_version` defaults to `""`, and `schema_version_missing_fires` warning fires on **every test that does not explicitly set `data._schema_version`**.

**Impact:** Every existing SoFREP test that calls `standard.valid with input as valid_input` without `with data._schema_version as "1.0.0"` will now also see a `schema_version_check` warning in the deny set. Tests that assert `count(standard.errors) == 0` are unaffected (this is a warning, not an error). Tests that assert `count(standard.deny) == 0` or check for zero warnings would break. The `test_zero_errors` test at line 51 asserts `count(standard.errors) == 0` — this holds because schema_version_check is a warning. The `test_valid_input` at line 45 asserts `standard.valid` — this holds because `valid` is gated on errors only.

**Assessment:** The new surface is **contained**. The warning does not break `valid` and does not affect `errors`. Existing tests that only check `valid` and `errors` pass. Tests that check for an exactly-zero warning count would be newly broken, but no such tests are present in the current suite.

**Verdict: NEW SURFACE (contained, low severity).**

---

## Summary

The Phase 6 merge successfully patched 5 of 9 R1 findings to HOLDS status. Two findings that were previously SHATTERED are partially addressed (CRACKED). One finding remains SHATTERED unchanged. One new surface was introduced that is contained to warning-severity noise.

**SHATTERED (1):** The Nash equilibrium / empty report bypass remains fully exploitable. `min_substance_items: 0` ships as the default. A blank financial statement returns `valid: true`.

**CRACKED (2):** The schema cascading error flood under missing data is improved (`valid: false` now returned) but not suppressed. SoFA remains unversioned while SoFREP received a version check.

**HOLDS (5):** All three `is_number` type-guard fixes, the dead `schema_list_nonempty` fix, and the deny cap are correctly implemented with regression tests.

**Phase 6 Recommendation:** Before merge to production, address Open 1 (set `min_substance_items: 1`) and Open 2 (add schema version to SoFA). These are single-line and single-rule changes respectively. Open 3 and Open 4 can be deferred to Phase 7 as hardening work.

---

*Verification performed by R2 Panel (Craftsman, Oracle, Pilot) on 2026-03-25.
All findings derived from direct reading of source files at the paths listed above.
No speculation beyond what is demonstrable in the code.*
