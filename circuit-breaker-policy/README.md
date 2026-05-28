# Circuit Breaker Policy

A data-driven Open Policy Agent (OPA) policy that validates structured status
reports before they are allowed to circulate. The policy package is
`circuit_breaker` (`circuit_breaker.rego:8`).

This pillar grades a status report on a continuous readiness scale: a
structurally sound, low-risk report scores high and is cleared to circulate; a
report carrying non-blocking `warning`-severity findings is usable but flagged;
a report carrying blocking `error`- or `critical`-severity findings is
rejected. All thresholds and enumerations that drive these decisions live in
`data.json`, so the policy can be retuned without editing Rego.

---

## What this pillar is

The policy ingests a report organized into four **quadrants** —
`working_well`, `needed`, `at_risk`, and `next` (`data.json:3`) — and runs a
suite of validations:

- **Required metadata** — top-level fields must be present (`circuit_breaker.rego:17`).
- **Base field validation** — every item in every quadrant must carry the
  shared base fields (`circuit_breaker.rego:23`).
- **Quadrant-specific fields** — each quadrant requires its own additional
  fields (`circuit_breaker.rego:31`).
- **Enum validation** — the report classification and each item's `priority`,
  `urgency`, and `likelihood` must be drawn from the allowed sets
  (`circuit_breaker.rego:39`, `circuit_breaker.rego:45`).
- **Unique ID enforcement** — no item ID may repeat across quadrants
  (`circuit_breaker.rego:55`).
- **Dependency resolution** — every dependency declared by a `next` item must
  reference a known item ID (`circuit_breaker.rego:65`).
- **Conflict detection** — an item must not appear in both `working_well` and
  `at_risk` (`circuit_breaker.rego:72`).
- **Risk scoring** — an `at_risk` item with a sufficiently high `likelihood` is
  flagged critical (`circuit_breaker.rego:81`).
- **Staleness detection** — items not updated within the staleness window are
  flagged (`circuit_breaker.rego:87`).
- **Owner overload** — an owner assigned more than the allowed number of items
  raises an alarm (`circuit_breaker.rego:103`).
- **Readiness scoring** — a numeric readiness score is computed from the error
  ratio (`circuit_breaker.rego:110`).

---

## Interpreting the output

The policy does not store a state field. It produces several outputs that a
caller combines into a gating decision (`circuit_breaker.rego:116`):

| Output | Type | Meaning |
|--------|------|---------|
| `deny` | set of objects | Every finding. Empty means no violations. |
| `valid` | boolean | `true` only when `deny` is empty (`circuit_breaker.rego:115`). |
| `readiness` | number in `[0.0, 1.0]` | `1.0 - (error-severity findings / item count)`; `0.0` for an empty report. |
| `ready` | boolean | `true` when `readiness` meets `readiness_threshold` (`circuit_breaker.rego:112`). |

A caller typically circulates a report when `valid` is `true`; treats a report
whose only findings are `warning`-severity (for example `staleness`,
`conflict`, or `owner_overload`) as usable but flagged; and rejects a report
carrying any `error`- or `critical`-severity finding. The thresholds that
drive `ready` and `readiness` live in `data.json`, so a caller tunes the gate
without touching the policy.

Severity is set per finding inside each `deny` rule: `error`, `warning`, or
`critical` (for example `circuit_breaker.rego:17`, `circuit_breaker.rego:72`,
`circuit_breaker.rego:81`).

---

## Public entrypoint rules

All rules below are exported by the `circuit_breaker` package.

| Rule | Type | Returns |
|------|------|---------|
| `deny` | set of objects | Every violation found. Each entry carries `msg`, `severity`, `field`, and `rule` (`circuit_breaker.rego:17`). |
| `readiness` | number | A score in `[0.0, 1.0]` computed as `1.0 - (errors / item_count)`, or `0.0` when there are no items (`circuit_breaker.rego:110`, `circuit_breaker.rego:111`). |
| `ready` | boolean | `true` when `readiness` meets `readiness_threshold` (`circuit_breaker.rego:112`). |
| `valid` | boolean | `true` when `deny` is empty (`circuit_breaker.rego:115`). |
| `report` | object | A summary bundling `valid`, `deny`, `readiness`, `ready`, and `item_count` (`circuit_breaker.rego:116`). |

`report` is the recommended entrypoint for callers: it returns the full
decision in one object.

---

## Role-gating model

This pillar is designed to slot into a generic three-role authorization scheme
— `operator`, `reviewer`, and `admin` — applied by the caller around the
policy decision:

- **operator** — submits a report as `input` and reads back `report`. An
  operator may circulate a report only when it is `valid`.
- **reviewer** — inspects `warning`-severity findings in the `deny` set and
  decides whether the report may proceed despite non-blocking findings.
- **admin** — owns `data.json`. Only an admin adjusts thresholds and
  enumerations, which is the single lever that retunes gating behavior across
  every report.

This separation of duties keeps report authors (operators) from changing the
rules that judge their own reports (admins), while reviewers gate the
discretionary path of proceeding despite `warning`-severity findings.

---

## Configuration: `data.json`

All tunable behavior is data, not code. The keys below are read directly by
the policy.

### `schema`

| Key | Controls |
|-----|----------|
| `quadrants` | The four report sections iterated by every rule (`data.json:3`). |
| `required_metadata` | Top-level fields that must be present: `unit`, `reporting_period`, `classification`, `author` (`data.json:4`). |
| `base_fields` | Fields required on every item: `id`, `title`, `description`, `owner`, `priority`, `last_updated` (`data.json:5`). |
| `quadrant_fields` | Extra fields required per quadrant — e.g. `at_risk` requires `impact`, `likelihood`, `mitigation` (`data.json:6`). |
| `enums.classification` | Allowed report classifications (`data.json:13`). |
| `enums.priority` | Allowed item priorities `P0`–`P3` (`data.json:14`). |
| `enums.urgency` | Allowed urgency values (`data.json:15`). |
| `enums.likelihood` | Allowed likelihood values `1`–`5` (`data.json:16`). |

### `thresholds`

| Key | Default | Controls |
|-----|---------|----------|
| `staleness_days` | `14` | Age, in days, after which an item is flagged stale (`circuit_breaker.rego:92`). |
| `readiness_threshold` | `0.7` | Minimum `readiness` for `ready` to be `true` (`circuit_breaker.rego:112`). |
| `max_owner_items` | `5` | Item count above which an owner triggers an overload alarm (`circuit_breaker.rego:105`). |
| `risk_critical_threshold` | `4` | `likelihood` at or above which an `at_risk` item is flagged critical (`circuit_breaker.rego:83`). |

---

## Input shape: `input.example.json`

A caller passes a single JSON object containing the report metadata and the
four quadrant arrays:

- `unit`, `classification`, `author` — string metadata.
- `reporting_period` — an object with `start_date` and `end_date`.
- `working_well` — items, each adding an `evidence` field.
- `needed` — items, each adding `justification` and `urgency`.
- `at_risk` — items, each adding `impact`, `likelihood`, and `mitigation`.
- `next` — items, each adding `target_date` and `dependencies` (an array of
  item IDs).

Every item in every quadrant carries the base fields `id`, `title`,
`description`, `owner`, `priority`, and `last_updated`. See
`input.example.json` for a complete, valid example.

---

## Run it

From the repository root, evaluate the example input against the policy:

```sh
opa eval --data circuit-breaker-policy/ --input circuit-breaker-policy/input.example.json 'data.circuit_breaker.report'
```

To inspect only the violations:

```sh
opa eval --data circuit-breaker-policy/ --input circuit-breaker-policy/input.example.json 'data.circuit_breaker.deny'
```

Run the test suite for this pillar:

```sh
opa test circuit-breaker-policy/
```

---

## Tests

The suite in `circuit_breaker_test.rego` contains **10** `test_` rules, one per
behavior: valid input, missing metadata, missing base field, invalid enum,
duplicate ID, unresolved dependency, conflict detection, critical risk,
owner overload, and readiness above threshold
(`circuit_breaker_test.rego:11`–`circuit_breaker_test.rego:142`).

---

Part of [`jonathan-kellerai/opa-governance-library`](https://github.com/jonathan-kellerai/opa-governance-library).
