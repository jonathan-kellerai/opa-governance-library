# Research Output E: Rego Pattern Library

- **Agent:** DS-2 (Rego Pattern Library)
- **Date:** 2026-03-25
- **Scope:** OPA ecosystem best practices for multi-layer validation policies
- **Sources:** rego-style-guide, rego-cheat-sheet, awesome-opa, SoFA standard policy, SoFREP standard policy

---

## 1. Findings from the Rego Style Guide

### R-E01: Missing Package-Level Metadata Annotations on SoFREP

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-style-guide/style-guide.md` (lines 82-139)
- **Confidence:** High
- **So what:** The style guide mandates `# METADATA` blocks with `title`, `description`, `authors`, and `custom` fields at the package level; SoFA has this (sofa.rego lines 1-13) but SoFREP entirely lacks it, making the policy invisible to tooling that parses OPA metadata annotations.

### R-E02: No Per-Rule Metadata Annotations

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-style-guide/style-guide.md` (lines 82-139)
- **Confidence:** High
- **So what:** Neither SoFA nor SoFREP uses per-rule `# METADATA` blocks; the style guide recommends them for error codes, related resources, and documentation links, which would allow structured error responses via `rego.metadata.rule()` instead of hardcoded strings in every `deny` rule head.

### R-E03: Inline Set Construction Anti-Pattern

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-style-guide/style-guide.md` (lines 456-491)
- **Confidence:** High
- **So what:** Both policies repeatedly construct inline sets for membership checks (e.g., `not input.accounting_basis in {b | some b in schema.accounting_bases}` in sofa.rego line 61, and `not c in {x | some x in data.schema.enums.classification}` in sofrep.rego line 81); the style guide recommends pre-computing these as named partial rules or top-level set assignments for readability and reuse.

### R-E04: Missing `default valid := false` in SoFREP

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-style-guide/style-guide.md` (lines 286-331, on handling undefined)
- **Confidence:** High
- **So what:** SoFA declares `default valid := false` (sofa.rego line 238) but SoFREP does not (sofrep.rego line 322 uses `valid := count(errors) == 0` without a default); if `errors` evaluates to undefined due to upstream issues, `valid` becomes undefined rather than safely defaulting to false.

### R-E05: Use `every` for "FOR ALL" Validation Patterns

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-style-guide/style-guide.md` (lines 566-619)
- **Confidence:** Medium
- **So what:** The `every` keyword eliminates the need for count-comparison patterns and negated helper rules; SoFA's going-concern rule (sofa.rego line 206) correctly uses `every`, but several other rules in both policies use `count(x) > 0` or `count(x) == 0` checks where `every` would be clearer.

### R-E06: Prefer Helper Rules Over Complex Rule Heads

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-style-guide/style-guide.md` (lines 243-284)
- **Confidence:** High
- **So what:** Both policies embed long `sprintf` messages and complex object literals directly in `deny contains {...}` rule heads; extracting validation logic into named helper rules would improve readability, debugging (each helper is independently queryable), and reuse.

### R-E07: Prefer `some .. in` Over Indexed Iteration

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-style-guide/style-guide.md` (lines 493-564)
- **Confidence:** High
- **So what:** Both policies correctly use `some .. in` for most iteration, which is good; however, array comprehensions like `sum([item.amount | some item in items("incoming_resources"); is_number(item.amount)])` (sofa.rego line 103) use semicolons inside comprehensions instead of line breaks, reducing readability below the 120-character line length recommendation.

### R-E08: Use Raw Strings for Regex Patterns

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-style-guide/style-guide.md` (lines 866-890)
- **Confidence:** Medium
- **So what:** The test files define regex patterns with escaped backslashes in double-quoted strings (e.g., `"^\\d{4}-\\d{2}-\\d{2}$"` in sofa_test.rego line 10); raw strings using backticks (`` `^\d{4}-\d{2}-\d{2}$` ``) are recommended to avoid escaping errors.

### R-E09: No `.editorconfig` for Rego Formatting

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-style-guide/style-guide.md` (lines 56-65)
- **Confidence:** Medium
- **So what:** The style guide recommends an `.editorconfig` file for Rego projects to ensure tabs display consistently (especially on GitHub); the opa-rego repo lacks one.

### R-E10: Functions Should Prefer Arguments Over `input`/`data` References

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-style-guide/style-guide.md` (lines 805-835)
- **Confidence:** Medium
- **So what:** SoFA's `items(section)` function (sofa.rego line 25) and SoFREP's `items_in(q)` function (sofrep.rego line 16) both reference `input` directly; passing the input document as an argument would make them testable in isolation and reusable across packages.

## 2. Findings from the Rego Cheat Sheet

### R-E11: Set Comprehension for Deduplication

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-cheat-sheet/cheats/comprehensions/sets/cheat.rego`
- **Confidence:** High
- **So what:** The cheat sheet demonstrates `contains` partial rules for building named sets; both policies already use set comprehensions but could benefit from extracting repeated inline set constructions (e.g., `{x | some x in data.schema.enums.priority}` appears in multiple SoFREP rules) into named top-level sets.

### R-E12: OR Pattern via Multiple Rule Definitions

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-cheat-sheet/cheats/control_flow/or/cheat.rego`
- **Confidence:** High
- **So what:** SoFREP's escalation triggers (sofrep.rego lines 299-313) correctly use multiple `deny contains` rule definitions for OR semantics; however, the identical message string across all four triggers means they produce only one entry in the deny set (since sets deduplicate identical objects), which may mask the number of active triggers.

### R-E13: `every` Keyword for Universal Quantification

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-cheat-sheet/cheats/iteration/every/cheat.rego`
- **Confidence:** Medium
- **So what:** The cheat sheet shows `every` for path-prefix checking; SoFREP's conflict detection (sofrep.rego line 166) uses set intersection (`ww_ids & ar_ids`) which is already idiomatic, but several rules using `count(missing) > 0` patterns could be rewritten with `every` or `some` for clarity.

### R-E14: `with` Keyword for Test Isolation

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-cheat-sheet/cheats/testing/with/cheat.rego`
- **Confidence:** High
- **So what:** Both test files use `with input as ...` correctly; SoFA tests also properly use `with data.schema as _schema with data.thresholds as _thresholds` for full isolation; SoFREP tests rely on `data.schema` and `data.thresholds` being loaded from files rather than injected inline, which couples tests to external data files and reduces portability.

## 3. Findings from Awesome OPA

### R-E15: Regal Linter Not Configured for SoFA/SoFREP

- **Source:** `/Users/jonathans_macbook/opa-rego/awesome-opa/README.md` (line 317); Regal config found only in `rego-cheat-sheet/.regal/config.yaml`, `opa/.regal/config.yaml`, `regal/.regal/config.yaml`
- **Confidence:** High
- **So what:** Regal is the official OPA linter recommended by Styra; neither `sofa/` nor `sofrep/` directories have a `.regal/config.yaml`, meaning no automated style enforcement exists for the standard policies.

### R-E16: rego-test-assertions Library for Richer Test Assertions

- **Source:** `/Users/jonathans_macbook/opa-rego/awesome-opa/README.md` (line 304)
- **Confidence:** Medium
- **So what:** The `rego-test-assertions` library (github.com/anderseknert/rego-test-assertions) provides helper functions for assertions in Rego unit tests, which could replace the manual `some d in deny; d.rule == "..."; d.severity == "..."` pattern repeated in every test case across both test files.

### R-E17: OPA Pre-commit Hooks for CI Pipeline

- **Source:** `/Users/jonathans_macbook/opa-rego/awesome-opa/README.md` (line 320)
- **Confidence:** Medium
- **So what:** The `pre-commit-opa` hooks (github.com/anderseknert/pre-commit-opa) run `opa fmt`, `opa check`, and Regal as pre-commit checks, which would catch style violations before they enter the codebase.

### R-E18: Conftest for Structured Configuration Testing

- **Source:** `/Users/jonathans_macbook/opa-rego/awesome-opa/README.md` (line 60)
- **Confidence:** Low
- **So what:** Conftest allows writing OPA tests against structured configuration data (JSON, YAML); since both SoFA and SoFREP validate JSON input, Conftest could provide an alternative test harness with better CLI ergonomics for integration testing.

### R-E19: JSON Schema Type Checking

- **Source:** `/Users/jonathans_macbook/opa-rego/rego-style-guide/style-guide.md` (lines 156-159)
- **Confidence:** Medium
- **So what:** OPA supports strict type checking via JSON schemas for `input` and `data`; neither policy provides a JSON schema, which means typos in field references are caught only at runtime.

## 4. Policy-Specific Violations and Anti-Patterns

### SoFA (sofa.rego)

| Issue | Location | Style Guide Violation |
|---|---|---|
| Inline set construction for enum checks | Lines 60-61 | R-E03: Should be pre-computed named set |
| Long single-line comprehensions | Lines 103-105 | R-E07: Line length > 120 chars |
| No per-rule metadata | All deny rules | R-E02: Missing `# METADATA` blocks |
| Escaped regex in test data | sofa_test.rego line 10 | R-E08: Use backtick raw strings |

### SoFREP (sofrep.rego)

| Issue | Location | Style Guide Violation |
|---|---|---|
| No package-level metadata | Line 1 | R-E01: Missing `# METADATA` block |
| Repeated inline set construction | Lines 81, 91, 100 | R-E03: `{x \| some x in data.schema.enums.*}` repeated |
| No `default valid` | Line 322 | R-E04: `valid` undefined if `errors` is undefined |
| Identical escalation messages | Lines 299-313 | R-E12: Set deduplication masks trigger count |
| Double negation pattern | Lines 26-27 | Anti-pattern: `not object.get(...) != ""` is a double negative |
| No per-rule metadata | All deny rules | R-E02: Missing `# METADATA` blocks |

### SoFREP Tests (sofrep_test.rego)

| Issue | Location | Style Guide Violation |
|---|---|---|
| No inline data injection | All tests | R-E14: Tests depend on external `data.schema`/`data.thresholds` files |

### SoFA Tests (sofa_test.rego)

| Issue | Location | Note |
|---|---|---|
| Escaped regex patterns | Line 10 | R-E08: Use raw strings |
| No negative-case completeness | Throughout | Missing tests for valid input with zero warnings |

## 5. Missing Regal Configuration

No `.regal/config.yaml` exists in `/Users/jonathans_macbook/opa-rego/sofa/` or `/Users/jonathans_macbook/opa-rego/sofrep/` or at the opa-rego root level.

Recommended `.regal/config.yaml` for both policy directories:

```yaml
rules:
  style:
    opa-fmt:
      level: error
    prefer-snake-case:
      level: error
    line-length:
      level: warning
      max-line-length: 120
  idiomatic:
    use-in-operator:
      level: error
    use-some-for-output-vars:
      level: error
    no-defined-entrypoint:
      level: ignore
  imports:
    prefer-package-imports:
      level: warning
    avoid-importing-input:
      level: warning
  testing:
    file-missing-test-suffix:
      level: error
    test-outside-test-package:
      level: warning
```

## 6. Top 5 Improvements with Before/After Code Snippets

### Improvement 1: Add Package Metadata to SoFREP

**Before** (sofrep.rego line 1):

```rego
package sofrep.standard

import rego.v1
```

**After:**

```rego
# METADATA
# title: SoFREP Standard -- Definitive Validation Policy
# description: >
#   Four-layer validation for SoFREP reports: structural integrity,
#   type/enum validation, cross-quadrant integrity, and operational
#   intelligence. Data-driven via data.schema and data.thresholds.
# authors:
#   - name: SoFREP Policy Team
# custom:
#   version: "1.0.0"
# entrypoint: true
package sofrep.standard

import rego.v1
```

**Why:** Enables tooling (Regal, documentation generators, IDE plugins) to discover and describe the policy. Matches the pattern SoFA already uses.

---

### Improvement 2: Extract Repeated Inline Enum Sets into Named Rules

**Before** (sofrep.rego lines 78-101, repeated 3 times):

```rego
deny contains {...} if {
    ...
    not c in {x | some x in data.schema.enums.classification}
}

deny contains {...} if {
    ...
    not p in {x | some x in data.schema.enums.priority}
}

deny contains {...} if {
    ...
    not u in {x | some x in data.schema.enums.urgency}
}
```

**After:**

```rego
# Pre-computed enum sets (top of file, after helpers)
_classification_values := {x | some x in data.schema.enums.classification}

_priority_values := {x | some x in data.schema.enums.priority}

_urgency_values := {x | some x in data.schema.enums.urgency}

# Then in rules:
deny contains {...} if {
    ...
    not c in _classification_values
}

deny contains {...} if {
    ...
    not p in _priority_values
}

deny contains {...} if {
    ...
    not u in _urgency_values
}
```

**Why:** Eliminates redundant set construction on every evaluation. Named rules are independently queryable for debugging. Leading underscore signals internal-only per style guide convention.

---

### Improvement 3: Add `default valid := false` to SoFREP

**Before** (sofrep.rego line 322):

```rego
valid := count(errors) == 0
```

**After:**

```rego
default valid := false

valid if count(errors) == 0
```

**Why:** If `errors` evaluates to undefined (e.g., due to missing `data.schema`), `valid` becomes undefined rather than `false`. The `default` keyword ensures the policy fails closed, matching SoFA's existing pattern and the style guide's recommendation on handling undefined.

---

### Improvement 4: Fix Double-Negation Anti-Pattern in SoFREP Metadata Check

**Before** (sofrep.rego lines 23-27):

```rego
deny contains {"msg": sprintf("missing required metadata field: %s", [f]), "severity": "error", "field": f, "rule": "required_metadata"} if {
    some f in data.schema.required_metadata
    f != "reporting_period"
    not object.get(input, f, "") != ""
}
```

**After:**

```rego
deny contains {"msg": sprintf("missing required metadata field: %s", [f]), "severity": "error", "field": f, "rule": "required_metadata"} if {
    some f in data.schema.required_metadata
    f != "reporting_period"
    _field_empty_or_missing(input, f)
}

_field_empty_or_missing(obj, field) if {
    object.get(obj, field, "") == ""
}
```

**Why:** `not X != ""` is a double negation that is hard to read and reason about. Extracting it into a named helper (`_field_empty_or_missing`) makes the intent explicit and is reusable across the three metadata-check rules that all share this pattern.

---

### Improvement 5: Inject Test Data Inline in SoFREP Tests

**Before** (sofrep_test.rego line 46):

```rego
test_valid_input if {
    standard.valid with input as valid_input
}
```

**After:**

```rego
_schema := {
    "quadrants": ["working_well", "needed", "at_risk", "next"],
    "required_metadata": ["unit", "reporting_period", "classification", "author"],
    "date_pattern": `^\d{4}-\d{2}-\d{2}$`,
    "base_fields": ["id", "title", "description", "owner", "priority", "last_updated"],
    "quadrant_fields": {
        "working_well": ["evidence"],
        "needed": ["justification", "urgency"],
        "at_risk": ["impact", "likelihood", "mitigation"],
        "next": ["target_date", "dependencies", "assigned_to"],
    },
    "enums": {
        "classification": ["UNCLASSIFIED", "CUI", "SECRET", "TOP_SECRET"],
        "priority": ["P0", "P1", "P2", "P3"],
        "urgency": ["critical", "high", "medium", "low"],
    },
}

_thresholds := {
    "risk_critical": 20,
    "risk_high": 12,
    "risk_medium": 6,
    "min_readiness_pct": 30,
    "max_owner_items": 5,
    "staleness_days": 30,
    "escalation_readiness_pct": 20,
}

test_valid_input if {
    standard.valid with input as valid_input
        with data.schema as _schema
        with data.thresholds as _thresholds
}
```

**Why:** SoFA tests already inline schema and thresholds (sofa_test.rego lines 8-25) for full isolation. SoFREP tests depend on external data files, making them non-portable and fragile to schema changes. Also note the use of backtick raw string for the date regex pattern, per R-E08.

---

## 7. Recommended Tools for Policy Testing and Deployment

| Tool | Source | Benefit |
|---|---|---|
| **Regal** | github.com/open-policy-agent/regal | Linter enforcing 60+ style guide rules; should be integrated into CI |
| **rego-test-assertions** | github.com/anderseknert/rego-test-assertions | Assertion helpers to reduce boilerplate in test files |
| **pre-commit-opa** | github.com/anderseknert/pre-commit-opa | Pre-commit hooks for `opa fmt`, `opa check --strict`, and Regal |
| **Conftest** | github.com/open-policy-agent/conftest | CLI for testing structured config data; useful for integration tests |
| **setup-opa** | github.com/open-policy-agent/setup-opa | GitHub Action for OPA in CI/CD pipelines |
| **ocov** | github.com/C5T/ocov | Colorized coverage reports for `opa test --coverage` |
| **opa-codecov** | github.com/SVilgelm/opa-codecov | Convert OPA coverage to Codecov format for tracking |

## 8. Summary of Numbered Recommendations

| # | Recommendation | Confidence | Priority |
|---|---|---|---|
| R-E01 | Add package-level `# METADATA` to SoFREP | High | P0 |
| R-E02 | Add per-rule `# METADATA` blocks to both policies | High | P1 |
| R-E03 | Extract inline set constructions into named rules | High | P0 |
| R-E04 | Add `default valid := false` to SoFREP | High | P0 |
| R-E05 | Use `every` keyword where count-comparison patterns exist | Medium | P2 |
| R-E06 | Extract complex deny rule heads into helper rules | High | P1 |
| R-E07 | Break long comprehensions across multiple lines | High | P1 |
| R-E08 | Use raw strings (backticks) for regex patterns in test data | Medium | P2 |
| R-E09 | Add `.editorconfig` for Rego tab formatting | Medium | P2 |
| R-E10 | Pass `input` as argument to helper functions | Medium | P2 |
| R-E11 | Pre-compute named sets for repeated enum lookups | High | P0 |
| R-E12 | Differentiate escalation trigger messages to avoid set dedup | High | P1 |
| R-E13 | Replace `count(x) > 0` with `some`/`every` where applicable | Medium | P2 |
| R-E14 | Inline test data in SoFREP tests for full isolation | High | P0 |
| R-E15 | Create `.regal/config.yaml` for sofa/ and sofrep/ | High | P0 |
| R-E16 | Evaluate rego-test-assertions for test simplification | Medium | P2 |
| R-E17 | Add OPA pre-commit hooks to CI pipeline | Medium | P1 |
| R-E18 | Evaluate Conftest for integration testing | Low | P3 |
| R-E19 | Provide JSON schemas for `input` and `data` type checking | Medium | P1 |
| R-E20 | Fix double-negation anti-pattern in SoFREP metadata checks | High | P0 |
