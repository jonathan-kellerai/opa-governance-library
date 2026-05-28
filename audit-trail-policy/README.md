# Audit Trail Policy

A minimal, data-driven [Open Policy Agent](https://www.openpolicyagent.org/) (Rego) policy
that validates the structural integrity of audit-trail and event-log records. Every
threshold and vocabulary used by the policy lives in external data, so the rules
themselves stay compact and need no edits to retune.

Part of [`jonathan-kellerai/opa-governance-library`](https://github.com/jonathan-kellerai/opa-governance-library).

- **Package:** `audit_trail`
- **Rego version:** `rego.v1` (`audit_trail.rego:11`)
- **Design goal:** maximum rules in minimum lines — data-driven, no helper rules, a single `deny` set (`audit_trail.rego:1-5`)

---

## What this pillar is

The policy ingests one audit-trail record and reports every way that record fails
structural and arithmetic integrity checks. It is deliberately dense: a single
`deny` partial set accumulates all violations, and the pass/fail verdict is derived
from the size of that set. There are no procedural helpers — each rule earns its
place.

Validation is **data-driven**. The accepted vocabularies (fund types, categories,
accounting bases), required-field lists, and numeric thresholds are supplied through
`data.schema` and `data.thresholds` (`audit_trail.rego:14-15`). Tuning the policy
means editing `data.json`, not the rules.

---

## Public entrypoints

The policy exposes four rules a caller can query:

| Rule | Type | Returns |
| --- | --- | --- |
| `deny` | partial set | A set of structured violation objects. Each object has `msg`, `severity` (`error`, `warning`, or `info`), and `field`. Defined across `audit_trail.rego:23-105`. |
| `valid` | boolean | `true` only when `deny` is empty; `false` otherwise. Default `false` (`audit_trail.rego:108-110`). |
| `errors` | set | The subset of `deny` whose `severity == "error"` (`audit_trail.rego:112`). |
| `warnings` | set | The subset of `deny` whose `severity` is `warning` or `info` (`audit_trail.rego:113`). |

`valid` is the headline verdict. `deny`, `errors`, and `warnings` let a caller
triage findings by severity — for example, blocking a submission on `errors` while
surfacing `warnings` as advisory notes to an operator, reviewer, or admin.

> Note: this policy has no separate `report` or `ready` aggregate rule. Query the
> rules above directly. The examples below use `data.audit_trail.deny` and
> `data.audit_trail.valid`.

---

## Validation logic

A record is **valid** when the `deny` set is empty (`audit_trail.rego:110`). The
following checks contribute to `deny`:

### Errors (block validity)

- **Missing required field** — any field listed in `schema.required_fields` that is
  absent from the input (`audit_trail.rego:23-26`).
- **Bad `report_date` format** — `report_date` present but not matching
  `schema.date_pattern` (`audit_trail.rego:28-31`).
- **Bad `currency`** — `currency` present but not matching `schema.currency_pattern`,
  i.e. not a 3-letter ISO code (`audit_trail.rego:33-36`).
- **Invalid `accounting_basis`** — a value not in `schema.accounting_bases`
  (`audit_trail.rego:38-41`).
- **Line item missing fields** — any item in `incoming_resources` or
  `resources_expended` missing a field from `schema.line_required`
  (`audit_trail.rego:43-48`).
- **Invalid line-item category** — an item `category` not in the combined set of
  `schema.income_categories` and `schema.expense_categories` (`audit_trail.rego:50-55`).
- **Invalid line-item fund type** — an item `fund_type` not in `schema.fund_types`
  (`audit_trail.rego:57-62`).
- **`net_movement` mismatch** — the declared `net_movement` differs from the computed
  total (sum of incoming amounts minus sum of expended amounts) by more than
  `thresholds.reconciliation_tolerance` (`audit_trail.rego:64-68`).
- **Reconciliation mismatch** — `opening_total + net_movement` does not equal
  `closing_total` within tolerance (`audit_trail.rego:70-73`).
- **Orphaned fund type** — a `fund_type` used in a line item that has no matching
  entry in `fund_balances` (`audit_trail.rego:75-79`).

### Warnings and info (do not block validity, but appear in `deny`)

- **Low unrestricted balance** (`warning`) — `fund_balances.unrestricted.closing` at
  or below `thresholds.min_unrestricted_balance` (`audit_trail.rego:81-84`).
- **Unexplained variance** (`warning`) — a period-over-period change exceeding
  `thresholds.variance_limit` with no matching entry in `variance_explanations`
  (`audit_trail.rego:86-91`).
- **Going-concern signal** (`warning`) — the last `thresholds.going_concern_periods`
  entries of `historical_net_movements` are all negative (`audit_trail.rego:93-98`).
- **Below materiality floor** (`info`) — a line-item amount whose absolute value is
  below `thresholds.materiality_floor` (`audit_trail.rego:100-105`).

Because `valid` keys only off the full `deny` set being empty
(`audit_trail.rego:110`), any warning or info finding also makes the record
invalid. Callers that want to tolerate non-error findings should evaluate
`count(data.audit_trail.errors) == 0` instead of `valid`.

---

## Configuration: `data.json`

`data.json` holds the schema vocabulary and the numeric thresholds. All keys are
tunable without touching `audit_trail.rego`.

### `schema`

| Key | Controls |
| --- | --- |
| `required_fields` | Top-level fields that must be present on the input. |
| `date_pattern` | Regex `report_date` must match (`^\d{4}-\d{2}-\d{2}$`). |
| `currency_pattern` | Regex `currency` must match (`^[A-Z]{3}$`). |
| `fund_types` | Allowed `fund_type` values for line items (`unrestricted`, `restricted`, `endowment`). |
| `income_categories` | Allowed categories for incoming-resource line items. |
| `expense_categories` | Allowed categories for expended-resource line items. |
| `line_required` | Fields every line item must carry (`description`, `amount`, `fund_type`, `category`). |
| `accounting_bases` | Allowed `accounting_basis` values (`accrual`, `cash`). |

### `thresholds`

| Key | Default | Controls |
| --- | --- | --- |
| `materiality_floor` | `100` | Amounts below this absolute value raise an `info` finding. |
| `variance_limit` | `0.20` | Fractional period-over-period change above which an unexplained variance is flagged. |
| `min_unrestricted_balance` | `0` | Closing unrestricted balance at or below this raises a `warning`. |
| `reconciliation_tolerance` | `0.01` | Allowed rounding slack for `net_movement` and reconciliation arithmetic. |
| `going_concern_periods` | `2` | Number of trailing negative periods that triggers the going-concern warning. |

---

## Input shape: `input.example.json`

A caller passes a single audit-trail record. The bundled example
(`input.example.json`) shows the full shape:

- **Top-level fields:** `report_date`, `entity_name`, `currency`, `accounting_basis`,
  `net_movement`.
- **`incoming_resources` / `resources_expended`:** arrays of line items, each with
  `description`, `amount`, `fund_type`, and `category`.
- **`fund_balances`:** an object keyed by fund type, each holding `opening` and
  `closing` balances.
- **`reconciliation`:** an object with `opening_total`, `net_movement`, and
  `closing_total`.
- **`prior_period`** (optional): comparison totals used by the variance check.
- **`historical_net_movements`** (optional): an ordered array of past period
  movements used by the going-concern check.
- **`variance_explanations`** (optional): per-field notes that suppress variance
  warnings.

The bundled example is a clean record that produces an empty `deny` set.

---

## Run it

From the repository root, evaluate the policy against the example input:

```sh
# Full verdict (the deny set of structured violations)
opa eval --data audit-trail-policy/ --input audit-trail-policy/input.example.json 'data.audit_trail.deny'

# Boolean pass/fail
opa eval --data audit-trail-policy/ --input audit-trail-policy/input.example.json 'data.audit_trail.valid'

# Errors only (severity == "error")
opa eval --data audit-trail-policy/ --input audit-trail-policy/input.example.json 'data.audit_trail.errors'
```

Run the test suite:

```sh
opa test audit-trail-policy/
```

---

## Tests

The suite in `audit_trail_test.rego` contains **8 test cases**
(`audit_trail_test.rego:51-111`):

1. `test_valid_input` — a clean record passes `valid`.
2. `test_missing_required_field` — a removed required field raises an `error`.
3. `test_invalid_category` — an out-of-vocabulary category is caught.
4. `test_net_movement_mismatch` — a wrong `net_movement` raises an `error`.
5. `test_reconciliation_mismatch` — broken reconciliation arithmetic is caught.
6. `test_going_concern` — consecutive negative movements raise the warning.
7. `test_materiality_info` — a sub-floor amount raises an `info` finding.
8. `test_fund_type_cross_ref` — a fund type absent from `fund_balances` is caught.

Each test injects fixture schema and thresholds via `with data.schema` and
`with data.thresholds`, so the suite runs independently of `data.json`.
