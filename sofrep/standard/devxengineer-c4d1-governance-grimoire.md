# DevXEngineer Review: Governance Grimoire Amendments

- **Reviewer role:** DevXEngineer — developer experience lens
- **Source document:** `/Users/jonathans_macbook/ArchangelMCP/docs/research/governance-grimoire-opa-rego.md`
- **Review date:** 2026-03-25
- **Scope:** Policy authoring friction, testing workflow, error message quality, debugging
  denied requests, policy discoverability, onboarding, and day-to-day usability

---

## Preamble: What the Grimoire Gets Right

The grimoire is well-structured research. The layering model (L0–L4), the T4 governance
concept, the deployment options comparison, and the shadow-mode rollout pattern are all
genuinely useful. The 15 example policies are concrete starting points.

What follows is not a rejection — it is the friction log of someone who would have to
**live with this system every day**: write policies, debug denials at 11pm, onboard a
new team member, add a policy without breaking an existing session, and explain to an
agent why it was blocked.

---

## Section 2: Rego Language Deep Dive

### ~ CHANGE: `semver.compare` is not a real Rego built-in

**Was (Policy 15, line ~621):**

```rego
semver.compare(actual, expected) < 0
```

**Should be:** Remove `semver.compare` — it does not exist in OPA's built-in function
set. The real OPA built-ins for version comparison are:

```rego
# Option A: Use semver.is_valid + string comparison for simple major.minor checks
# semver.is_valid(version) is a real built-in (OPA v0.44+)

# Option B: Split and compare numerically (reliable for semver)
deny contains msg if {
    not input.meta.governance_pack_version
    input.tool_name in data.governed_tools
    msg := "Governed tools require governance_pack_version in metadata"
}

deny contains msg if {
    actual   := input.meta.governance_pack_version
    expected := data.minimum_pack_version
    not _version_gte(actual, expected)
    msg := sprintf("Governance pack %s is below minimum %s", [actual, expected])
}

_version_gte(actual, expected) if {
    a_parts := split(actual,  ".")
    e_parts := split(expected, ".")
    to_number(a_parts[0]) > to_number(e_parts[0])
}

_version_gte(actual, expected) if {
    a_parts := split(actual,  ".")
    e_parts := split(expected, ".")
    to_number(a_parts[0]) == to_number(e_parts[0])
    to_number(a_parts[1]) >  to_number(e_parts[1])
}

_version_gte(actual, expected) if {
    a_parts := split(actual,  ".")
    e_parts := split(expected, ".")
    to_number(a_parts[0]) == to_number(e_parts[0])
    to_number(a_parts[1]) == to_number(e_parts[1])
    to_number(a_parts[2]) >= to_number(e_parts[2])
}
```

**Rationale:** `semver.compare` is not in the OPA built-in reference. Using it in
production will produce a `undefined built-in function` error at runtime. A policy
author who copies this example, runs `opa test`, and gets a cryptic failure will lose
trust in the entire document. The actual real built-ins for strings are:
`split`, `to_number`, `semver.is_valid`. Use them.

The complete OPA built-in reference: <https://www.openpolicyagent.org/docs/latest/policy-reference/>

---

### + ADDITION: Rego Built-ins Quick Reference Card for Policy Authors

Add a table of the built-ins that are actually used across the 15 example policies,
with their actual signatures. Policy authors should not have to hunt the full OPA
reference to know what is available.

```
| Built-in            | Signature                              | Used in Policy |
|---------------------|----------------------------------------|----------------|
| sprintf             | sprintf(fmt, [args]) -> string         | 1,4,8,9,10,11  |
| re_match            | re_match(pattern, value) -> bool       | 2,3,12,13      |
| startswith          | startswith(str, prefix) -> bool        | 3              |
| contains            | contains(str, search) -> bool          | 2,3,11,12,14   |
| endswith            | endswith(str, suffix) -> bool          | 2              |
| count               | count(collection) -> number            | 8,9,11         |
| split               | split(str, delim) -> [string]          | (version comp) |
| to_number           | to_number(str) -> number               | (version comp) |
| time.now_ns         | time.now_ns() -> number (nanoseconds)  | 5,10           |
| time.clock          | time.clock(ns) -> [h,m,s]              | 5              |
| time.weekday        | time.weekday(ns) -> string             | 5              |
| semver.is_valid     | semver.is_valid(str) -> bool           | (validation)   |
| object.get          | object.get(obj, key, default) -> any   | (safe access)  |
```

**Not in OPA:** `semver.compare`, `time.format`, `json.schema_validate` (last one is
available but experimental — test first).

---

## Section 5: 15 Example Policies

### + ADDITION: Show how to compose policies across packages

The 15 policies are presented in isolation. A policy author staring at 15 separate
`package` declarations will wonder: how do they talk to each other? How does
`tool_guard` call into `budget_guard`?

Add a composition example showing the intended entry-point pattern:

```rego
# governance-packs/kellerai/grc/decision.rego
# The single entry point queried by the gateway.
# Aggregates all guard packages into one decision document.

package kellerai.grc.decision

import rego.v1
import data.kellerai.grc.tool_guard
import data.kellerai.grc.budget_guard
import data.kellerai.grc.param_guard
import data.kellerai.grc.temporal_guard
import data.kellerai.grc.chain_guard
import data.kellerai.grc.audit_guard

default allow := false

# Collect all deny reasons across all guards
deny contains msg if { msg in tool_guard.deny    }
deny contains msg if { msg in budget_guard.deny  }
deny contains msg if { msg in param_guard.deny   }
deny contains msg if { msg in temporal_guard.deny }
deny contains msg if { msg in chain_guard.deny   }
deny contains msg if { msg in audit_guard.deny   }

# Collect all HIL requirements
require_hil contains msg if { msg in tool_guard.require_hil }

# Final allow: no denials, no pending HIL
allow if {
    count(deny)        == 0
    count(require_hil) == 0
}

allow if {
    count(deny)        == 0
    count(require_hil) > 0
    input.meta.hil_approved == true
}
```

Then the gateway queries exactly one path: `POST /v1/data/kellerai/grc/decision`

This also means adding a new guard package requires only one change to `decision.rego`
— a single line import — rather than rewiring the gateway.

---

### + ADDITION: Concrete example of Policy 8 test fixture for `data.recent_calls`

Policy 8 (rate limiting) depends on `data.recent_calls[agent][category]` but the
grimoire never explains how this data is structured for testing. A policy author
writing tests will hit this immediately.

```rego
# In test file: policies/kellerai/grc/tool_guard_test.rego

test_rate_limit_exceeded if {
    # Provide a fixture that simulates 5 recent calls in the window
    tool_guard.deny["Rate limit exceeded"] with input as {
        "tool_name": "tavily_tavily_search",
        "agent": {"name": "researcher-1"},
    }
    with data.rate_limited_tools as ["tavily_tavily_search"]
    with data.tool_categories as {"tavily_tavily_search": "search"}
    with data.rate_limits as {"search": {"max_calls": 5, "window_seconds": 60}}
    with data.recent_calls as {
        "researcher-1": {
            "search": [
                {"ts": 1711357200},
                {"ts": 1711357210},
                {"ts": 1711357220},
                {"ts": 1711357230},
                {"ts": 1711357240},
            ]
        }
    }
}

test_rate_limit_not_exceeded if {
    not tool_guard.deny["Rate limit exceeded"] with input as {
        "tool_name": "tavily_tavily_search",
        "agent": {"name": "researcher-1"},
    }
    with data.rate_limited_tools as ["tavily_tavily_search"]
    with data.tool_categories as {"tavily_tavily_search": "search"}
    with data.rate_limits as {"search": {"max_calls": 5, "window_seconds": 60}}
    with data.recent_calls as {
        "researcher-1": {"search": [{"ts": 1711357200}]}
    }
}
```

**Rationale:** The `with data.X as {...}` override is the standard Rego test fixture
mechanism. Without a concrete example of how to structure `recent_calls` fixtures,
every policy author will spend 20 minutes reading OPA docs to figure this out
themselves.

---

### - SUBTRACTION: Remove the temporal policy `time.weekday` example as-is

**Remove:** The `time.weekday` call in Policy 5 without timezone context.

**Rationale:** `time.now_ns()` returns UTC nanoseconds. A policy that blocks
"Saturday and Sunday" using this without timezone conversion will block at wrong
times for users in UTC+8 or UTC-5. The grimoire presents this as a straightforward
pattern, but it silently fails in production environments across timezones.

**Replace with:**

```rego
deny contains msg if {
    input.tool_name in data.deploy_tools
    # Use input.meta.local_weekday provided by gateway (TZ-aware)
    # rather than calling time.weekday(time.now_ns()) which is always UTC
    input.meta.local_weekday in {"Saturday", "Sunday"}
    not input.tool_name in data.weekend_exempt_tools
    msg := "Deployment tools blocked on weekends unless explicitly exempted."
}
```

The gateway should inject `meta.local_weekday` and `meta.local_hour` using the
configured server timezone, not let Rego guess from UTC nanoseconds.

---

## Section 7: Policy-as-Code Best Practices

### + ADDITION: Actual policy documentation template

Section 7 says "every policy should be documented with: Intent, Scope, Exceptions,
Escalation, Expiration" but provides no template. Here is one that can be copy-pasted:

```rego
# =============================================================================
# POLICY: <human-readable name>
# Package: kellerai.grc.<guard_name>
# Version: 1.0.0
# Added: 2026-MM-DD
# Review by: 2027-MM-DD
#
# INTENT
#   One or two sentences on why this policy exists.
#   Include the business or safety justification.
#   Bad example: "Blocks rm -rf"
#   Good example: "Prevents irreversible filesystem destruction in all agent
#     archetypes. rm -rf with -r or --recursive has caused data loss in three
#     separate sessions (incidents #12, #41, #89). The 'trash' command provides
#     recoverable deletion."
#
# SCOPE
#   - Applies to: tool_name == "Bash", command contains rm
#   - Agent archetypes: all
#   - Environments: all
#   - Exceptions: none
#
# ESCALATION
#   An agent that legitimately needs to delete files should:
#   1. Use 'trash <path>' instead (recoverable)
#   2. Or request HIL approval with: gateway_policy_request_hil_approval
#   3. Or contact admin archetype to add a project-specific exemption
#
# EXPIRATION
#   This policy has no expiration. Review if 'trash' becomes unavailable.
# =============================================================================

package kellerai.grc.tool_guard

import rego.v1

deny contains msg if {
    input.tool_name == "Bash"
    re_match(`rm\s+(-rf?|--recursive)`, input.arguments.command)
    msg := "rm -rf is permanently blocked. Use 'trash' instead."
}
```

**Rationale:** "Document your policies" is advice. A template with fill-in fields and
a worked example of good vs bad intent descriptions is a tool. A new policy author
will write the comment block once, copy it, and fill it in. Without this template they
write nothing.

---

### + ADDITION: CI integration recipe for `opa test`

The grimoire shows `opa test policies/ -v` but stops there. Anyone setting up a repo
from scratch needs the full CI recipe:

```yaml
# .github/workflows/governance-pack.yaml
name: Governance Pack CI

on:
  push:
    paths: ["governance-packs/**"]
  pull_request:
    paths: ["governance-packs/**"]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install OPA
        run: |
          curl -L -o /usr/local/bin/opa \
            https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
          chmod +x /usr/local/bin/opa

      - name: Install Regal
        run: |
          curl -L -o /usr/local/bin/regal \
            https://github.com/StyraInc/regal/releases/latest/download/regal_Linux_x86_64
          chmod +x /usr/local/bin/regal

      - name: Lint policies
        run: regal lint governance-packs/

      - name: Run tests
        run: opa test governance-packs/ -v --coverage

      - name: Build bundle
        run: |
          opa build -b governance-packs/ \
            -o dist/governance-pack-$(git describe --tags).tar.gz

      - name: Verify bundle
        run: opa inspect dist/governance-pack-*.tar.gz
```

**For the justfile (local development):**

```makefile
# Run all governance pack tests with coverage
opa-test:
    opa test governance-packs/ -v --coverage

# Run only tests matching a pattern (fast feedback during authoring)
opa-test-filter PATTERN:
    opa test governance-packs/ -v -r {{PATTERN}}

# Lint all policies with Regal
opa-lint:
    regal lint governance-packs/

# Lint a single file (fastest feedback loop)
opa-lint-file FILE:
    regal lint {{FILE}}

# Full pre-commit check
opa-check: opa-lint opa-test
    echo "All governance checks passed"
```

---

### + ADDITION: How to safely add a new policy without breaking existing sessions

Adding a policy to a live system is the most dangerous part of the authoring workflow.
The grimoire mentions shadow mode but never walks through the full sequence. This is
the decision a policy author has to make every single time.

**The rollout ladder:**

```
Step 1: Author policy in a feature branch
        Write tests. opa test must pass with 100% rule coverage.

Step 2: Merge to governance-packs with mode: shadow
        In governance-pack-config.yaml:
            - name: my-new-policy
              mode: shadow          # logs decisions, enforces nothing
              shadow_duration_days: 3

Step 3: Review shadow logs for 3 days
        Query: grep "would-deny" ~/.claude/archangel/opa-decisions.jsonl | jq .
        Look for:
          - False positives (legitimate calls that would be blocked)
          - Missing data documents (undefined references)
          - Performance (decision time > 10ms needs investigation)

Step 4: If false positives found → refine policy, restart shadow timer
        If clean → promote to enforce mode

Step 5: Promote
        Change mode: shadow → mode: enforce
        Hot-reload: PUT to OPA bundle endpoint (or launchctl kickstart)

Step 6: Monitor for 24h post-promotion
        Watch for unexpected denial spikes in opa-decisions.jsonl
```

**What to check before promoting:**

```bash
# Count shadow denials by rule
jq 'select(.result.advisory) | .result.advisory[]' ~/.claude/archangel/opa-decisions.jsonl \
  | sort | uniq -c | sort -rn

# Check for undefined (policy referenced data that didn't exist)
jq 'select(.result == null)' ~/.claude/archangel/opa-decisions.jsonl | wc -l
```

---

### + ADDITION: How to bump `governance_pack_version`

The `governance_pack_version` concept in Policy 15 is referenced but the workflow for
bumping it is never described. A policy author who wants to increment the version has
to reverse-engineer the intent.

**The versioning contract:**

```
governance-packs/
├── version.json          ← single source of truth
│     { "version": "1.3.2", "minimum_client_version": "1.2.0" }
├── CHANGELOG.md          ← required entry for every version bump
└── kellerai/grc/
    └── ...
```

**Bump workflow:**

```bash
# 1. Increment version.json
#    Use conventional bump: patch for new deny rules, minor for new rule files,
#    major for breaking changes to input schema

# 2. Update CHANGELOG.md with entry:
#    ## [1.3.2] - 2026-03-25
#    ### Added
#    - Policy 16: blocks X because Y (incident #102)
#    ### Changed
#    - Policy 4: raised token budget threshold from 100k to 200k (ops request)

# 3. Run: opa test governance-packs/ -v

# 4. Commit: feat(governance): bump pack version to 1.3.2

# 5. The gateway reads version.json on startup and pushes it to OPA as
#    data.minimum_pack_version. Agents declaring an older version in
#    input.meta.governance_pack_version will be denied on governed tools.
```

**When to NOT bump minimum_client_version:**
Adding a new deny rule is safe — existing compliant clients are unaffected.
Only bump `minimum_client_version` when the input schema changes (new required field).

---

## Section 8: Progressive Disclosure in Policy Systems

### ~ CHANGE: Clarify who writes T1/T2/T3 denial messages and how they are tested

**Was:** The T1/T2/T3 disclosure model is described purely as a concept. The grimoire
shows example messages but never addresses authorship or testing.

**Should be:** Add an explicit authorship and testing protocol.

**Authorship:** The policy author who writes the deny rule owns the T1 message (the
`msg` string in the deny rule). The T2 and T3 messages are authored in a separate
`denial_detail` document, keyed by a normalized version of the T1 string:

```rego
# In governance-packs/kellerai/grc/denial_messages.rego
package kellerai.grc.denial_messages

import rego.v1

# T2 — usage guide shown to calling agent
t2[key] := detail if {
    some key, detail in data.denial_details.t2
}

# T3 — full reference (shown on escalation request)
t3[key] := detail if {
    some key, detail in data.denial_details.t3
}
```

```json
// governance-packs/data/denial_details.json
{
  "t2": {
    "rm -rf is permanently blocked. Use 'trash' instead.": "Use 'trash <path>' for recoverable deletion. 'trash' moves files to macOS Trash, allowing recovery. Run: trash /path/to/target",
    "Token budget exceeded for scope": "Your session has consumed its allocated token budget. To continue: (1) request a budget increase via gateway_policy_request_budget_extension, or (2) start a new session with a higher-budget archetype."
  },
  "t3": {
    "rm -rf is permanently blocked. Use 'trash' instead.": "Rule: kellerai.grc.tool_guard (Policy 2). Pattern matched: rm -rf, rm -r, rm --recursive. Incidents that motivated this rule: #12 (2025-09-14 lost build artifacts), #41 (2025-11-02 git history deleted), #89 (2026-01-18 project wipe). Appeal: admin archetype only, requires written justification in HIL ticket."
  }
}
```

**Testing denial messages:** Add to the test suite:

```rego
test_t2_message_exists_for_every_deny_rule if {
    every msg in tool_guard.deny {
        denial_messages.t2[msg]
    }
    with input as test_input_that_triggers_all_denials
}
```

This test fails when a developer adds a deny rule without a corresponding T2 message —
enforcing the progressive disclosure contract at test time rather than at user-confusion
time.

---

## Section 10: ArchangelMCP Integration Architecture

### + ADDITION: Decision replay workflow for debugging denied requests

The grimoire shows the tool call lifecycle but has no answer to the most common
operational question: "why was this request denied 20 minutes ago?"

**The debug workflow every policy author needs:**

```bash
# 1. Find the decision in the decision log (OPA emits JSON per decision)
#    Assumes decision_logs.console=true in launchd plist (already configured)
jq 'select(.input.tool_name == "morph_edit_file") | {time: .timestamp, deny: .result.deny}' \
  ~/.claude/archangel/opa-decisions.jsonl | tail -20

# 2. Replay the exact decision locally with opa eval
#    Extract the input from the decision log:
jq 'select(.timestamp == "2026-03-25T10:34:22Z") | .input' \
  ~/.claude/archangel/opa-decisions.jsonl > /tmp/replay-input.json

#    Run the exact same evaluation:
opa eval \
  --data governance-packs/ \
  --input /tmp/replay-input.json \
  --format pretty \
  'data.kellerai.grc.decision'

# 3. Use opa eval --explain=full for trace-level debugging
opa eval \
  --data governance-packs/ \
  --input /tmp/replay-input.json \
  --format pretty \
  --explain full \
  'data.kellerai.grc.decision' 2>&1 | head -100
```

**Add to justfile:**

```makefile
# Replay a past OPA decision by timestamp
opa-replay TIMESTAMP:
    jq 'select(.timestamp == "{{TIMESTAMP}}") | .input' \
      ~/.claude/archangel/opa-decisions.jsonl > /tmp/replay-input.json
    opa eval --data governance-packs/ --input /tmp/replay-input.json \
      --format pretty 'data.kellerai.grc.decision'

# Explain why a specific tool call was denied (full trace)
opa-explain TIMESTAMP:
    jq 'select(.timestamp == "{{TIMESTAMP}}") | .input' \
      ~/.claude/archangel/opa-decisions.jsonl > /tmp/replay-input.json
    opa eval --data governance-packs/ --input /tmp/replay-input.json \
      --format pretty --explain full 'data.kellerai.grc.decision' 2>&1 | less
```

**Rationale:** Without a replay workflow, debugging a production denial means either
reconstructing the input from application logs (error-prone) or adding `print()`
statements to Rego (which requires a redeploy and is not available in WASM mode).
The OPA decision log already records the full input — the tooling just needs to
wire it to `opa eval --explain`.

---

### + ADDITION: Policy REPL / playground for iterating during authorship

The grimoire describes a complete deployment pipeline but nothing for the inner loop
of policy authoring — the tightest feedback cycle a developer has.

**Local REPL setup:**

```bash
# Interactive REPL: evaluate expressions against live data
opa run --watch governance-packs/

# Inside the REPL:
> data.kellerai.grc.tool_guard.deny with input as {"tool_name":"Bash","arguments":{"command":"rm -rf /"},"agent":{"archetype":"editor"}}
# → {"rm -rf is permanently blocked. Use 'trash' instead."}

> data.kellerai.grc.decision.allow with input as {...}
# → false

# Load a specific input file
> import input.json
> data.kellerai.grc.decision
```

**`--watch` mode** is the key flag: OPA reloads policy files on every save. The author
edits a `.rego` file, saves, and the REPL immediately reflects the change. No redeploy,
no restart.

**Add to justfile:**

```makefile
# Start OPA REPL watching all governance packs (hot-reload on save)
opa-repl:
    opa run --watch governance-packs/

# Start REPL with a pre-loaded input fixture
opa-repl-with INPUT_FILE:
    opa run --watch governance-packs/ --stdin-input < {{INPUT_FILE}}
```

**Web playground alternative (no install required for exploration):**
<https://play.openpolicyagent.org> — paste any policy and input, evaluate immediately.
Useful for sharing policy questions with teammates who don't have OPA installed.

---

### + ADDITION: Regal is already in this repository — wire it into the policy workflow

The `rego-cheat-sheet` submodule at `/Users/jonathans_macbook/opa-rego/rego-cheat-sheet/.regal/config.yaml`
shows Regal is already configured and in use in this repo. The grimoire does not mention
Regal at all.

**What Regal provides:**

- Linting for idiomatic Rego style violations
- Detection of common correctness mistakes (e.g., partial rule used as complete rule)
- Style enforcement (formatting, naming, function structure)
- IDE integration (Language Server Protocol support)
- Rules for test coverage, `print`/`trace` calls left in production, etc.

**Add to Section 7 (Policy-as-Code Best Practices):**

```bash
# Install Regal
brew install styrainc/packages/regal
# or:
curl -L -o /usr/local/bin/regal \
  https://github.com/StyraInc/regal/releases/latest/download/regal_Darwin_arm64
chmod +x /usr/local/bin/regal

# Lint all policies
regal lint governance-packs/

# Lint with fix (auto-corrects style violations)
regal lint --fix governance-packs/

# Output as JSON for CI parsing
regal lint --format json governance-packs/ | jq '.violations[] | {file, rule, message}'
```

**Regal config for governance packs** (`governance-packs/.regal/config.yaml`):

```yaml
rules:
  style:
    opa-fmt:
      level: error      # enforce opa fmt on all policy files
  testing:
    file-missing-test-suffix:
      level: error      # every policy file must have a _test.rego counterpart
    test-outside-test-package:
      level: error
  idiomatic:
    no-defined-entrypoint:
      level: ignore     # governance packs use decision.rego as implicit entrypoint
```

**The UBS equivalent for Rego is Regal.** It should be blocked-on-commit via
lefthook, just like UBS blocks on Python/TypeScript files.

---

## Section 12: Open Questions and Next Steps

### + ADDITION: Onboarding quickstart for a new policy author

Currently there is no answer to: "I'm new to this system. What do I read first?
How do I write my first policy? How do I know if it's correct?"

**Proposed quickstart (to be added as Section 0 or Appendix A):**

```markdown
## Quickstart: Writing Your First Governance Policy

### Prerequisites (5 minutes)

1. Install OPA: `brew install opa`
2. Install Regal: `brew install styrainc/packages/regal`
3. Clone governance-packs: `git clone <governance-packs-repo>`
4. Verify: `opa test governance-packs/ -v` → all tests pass

### The mental model (2 minutes)

Every policy answers one question: "Should this tool call be allowed?"
- `deny` rules add reasons why NOT
- `require_hil` rules add reasons why a human must approve
- `allow` is true when deny is empty and require_hil is empty (or approved)
- You almost never write an `allow` rule — you write `deny` rules

### Your first policy (15 minutes)

Goal: Block the Bash tool from running `curl` to external domains.

1. Create: `governance-packs/kellerai/grc/tool_guard.rego`
   (or add to the existing file in its package)

2. Write:
   deny contains msg if {
       input.tool_name == "Bash"
       re_match(`curl\s+https?://`, input.arguments.command)
       not re_match(`localhost|127\.0\.0\.1|\.internal`, input.arguments.command)
       msg := "Bash curl to external URLs is blocked. Use the 'http' MCP tool instead."
   }

3. Write the test:
   Create: governance-packs/kellerai/grc/tool_guard_test.rego
   test_curl_external_blocked if {
       "Bash curl to external URLs is blocked" in tool_guard.deny with input as {
           "tool_name": "Bash",
           "arguments": {"command": "curl https://api.example.com/data"},
           "agent": {"archetype": "editor"},
       }
   }
   test_curl_localhost_allowed if {
       count(tool_guard.deny) == 0 with input as {
           "tool_name": "Bash",
           "arguments": {"command": "curl http://localhost:8181/health"},
           "agent": {"archetype": "editor"},
       }
   }

4. Run: `opa test governance-packs/ -v -r test_curl`

5. Lint: `regal lint governance-packs/kellerai/grc/tool_guard.rego`

6. Add the policy documentation block (see Section 7 template)

7. Open PR. CI runs full test + lint suite.
```

### Map of the 15 example policies to packages (discoverability aid)

The 15 policies are numbered sequentially but they map to 7 different packages
that will eventually live in separate files. A new author looking for "where do I
add a file path restriction" should not have to read all 15 to find out.

```
Package                        | Policies (by number)  | File
-------------------------------|-----------------------|----------------------------------------
kellerai.grc.tool_guard        | 1, 2, 6, 15           | kellerai/grc/tool_guard.rego
kellerai.grc.param_guard       | 3, 11, 12             | kellerai/grc/param_guard.rego
kellerai.grc.budget_guard      | 4                     | kellerai/grc/budget_guard.rego
kellerai.grc.temporal_guard    | 5, 13                 | kellerai/grc/temporal_guard.rego
kellerai.grc.chain_guard       | 9                     | kellerai/grc/chain_guard.rego
kellerai.grc.audit_guard       | 7                     | kellerai/grc/audit_guard.rego
kellerai.grc.rate_guard        | 8                     | kellerai/grc/rate_guard.rego
kellerai.grc.concurrency_guard | 10                    | kellerai/grc/concurrency_guard.rego
kellerai.grc.memory_guard      | 14                    | kellerai/grc/memory_guard.rego
```

### + ADDITION: Address the open question on Policy Authoring UX directly

Open question 5 in Section 12 asks: "Should policies be authored in raw Rego, YAML
(compiled to Rego), or a custom DSL in servers.yaml?"

**Recommendation with rationale:**

**Tier A: YAML DSL for common patterns (covers ~70% of policies)**

Use a YAML-to-Rego compiler modeled on the `yaml-opa-llm-guardrails` project for
the high-frequency cases that don't require Rego expressiveness:

```yaml
# governance-packs/config/simple-rules.yaml
rules:
  - id: block-curl-external
    type: bash_command_block
    pattern: "curl https?://"
    exclude_pattern: "localhost|127\\.0\\.0\\.1"
    message: "External curl blocked. Use the 'http' MCP tool instead."
    layer: L2

  - id: require-correlation-id
    type: require_metadata_field
    tools: ["morph_edit_file", "Write", "Edit"]
    field: "meta.correlation_id"
    message: "Auditable tools require a correlation_id in metadata"
    layer: L1
```

The compiler outputs Rego. Policy authors never touch Rego unless the pattern is too
complex for the DSL. This is the Aegis approach and it works.

**Tier B: Raw Rego for complex policies (covers ~30% of policies)**

Delegation chain validation (Policy 9), rate limiting with time windows (Policy 8),
and budget composition logic require Rego. Accept this. Provide the authoring tools
(REPL, Regal, test fixtures) that make raw Rego tolerable.

**Do not** add a third DSL in `servers.yaml`. The existing `servers.yaml` already
manages MCP server config; mixing governance rules into it couples policy changes
to gateway restarts.

---

## Summary: Highest-Priority Amendments

| Priority | Section | Issue | Action |
|----------|---------|-------|--------|
| P0 | §5 Policy 15 | `semver.compare` does not exist | Fix with `split`/`to_number` implementation |
| P0 | §5 Policy 5  | `time.weekday` is always UTC, will mis-fire across timezones | Route via gateway-injected `meta.local_weekday` |
| P1 | §7           | No policy documentation template | Add filled-in template with good/bad examples |
| P1 | §5           | No composition example — 15 isolated packages | Add `decision.rego` aggregator pattern |
| P1 | §10          | No debug workflow for denied requests | Add decision replay with `opa eval --explain` |
| P2 | §7           | CI recipe missing | Add GitHub Actions + justfile targets |
| P2 | §5 Policy 8  | `data.recent_calls` fixture structure undocumented | Add test fixture example |
| P2 | §10          | No REPL/playground guidance | Add `opa run --watch` + play.openpolicyagent.org |
| P2 | §12          | No onboarding path for new policy authors | Add Quickstart section |
| P3 | §7           | Regal exists in repo but is not referenced anywhere | Wire into commit hooks and CI |
| P3 | §8           | T1/T2/T3 messages have no authorship or test protocol | Add `denial_messages.rego` + test |
| P3 | §5           | 15 policies not mapped to packages | Add discoverability table |
| P3 | §15          | `governance_pack_version` bump workflow missing | Add version.json + CHANGELOG protocol |
| P4 | §12 Q5       | Policy authoring UX question left open | Recommend YAML DSL + raw Rego split |
