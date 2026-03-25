# RedTeam Review: Governance Grimoire Amendments

- **Reviewer:** RedTeam (adversarial security analysis)
- **Reviewer ID:** redteam-a7f3
- **Source document:** `/Users/jonathans_macbook/ArchangelMCP/docs/research/governance-grimoire-opa-rego.md`
- **Review date:** 2026-03-25
- **Scope:** Full document — all 12 sections, all 15 example policies, deployment model, fallback strategy, data document architecture, and integration design
- **Lens:** Threat modeling, attack vectors, policy escape, supply chain attacks, privilege escalation via delegation chains, data poisoning, TOCTOU races, shadow mode exploitation, fail-open analysis

---

## Executive Summary

The Governance Grimoire is a solid research document for OPA/Rego integration. It establishes correct fundamentals and appropriate default-deny patterns. However, it treats the governance layer as operating in a cooperative environment where inputs are honest, OPA itself is trusted, and data documents are authoritative. In adversarial conditions — including a compromised agent, a tampered data document, or a rogue MCP session — several of the proposed controls either fail open, can be bypassed trivially, or create new attack surfaces they do not acknowledge.

**Critical findings (must fix before any production deployment):**

1. The fallback strategy (`fnmatch` when OPA is down) is explicitly fail-open by design — this is a governance architecture defect, not a configuration choice.
2. OPA's REST API (`PUT /v1/data`, `PUT /v1/policies`) has no authentication in the proposed deployment — any local process can overwrite all policies and data.
3. Bundle signing is absent entirely — the supply chain from git to running policy is unsigned and unverified.
4. Policy 9 (delegation chain) can be trivially bypassed by a subagent that simply lies about `is_subagent` or omits `parent_agent_id`.
5. `time.now_ns()` in Policy 10 creates a TOCTOU window between policy check and tool execution.
6. Shadow mode has no integrity protection — an attacker forcing `mode: shadow` disables enforcement with no alarm.
7. `data.budgets`, `data.usage`, and `data.agents` are writable via unauthenticated OPA REST API — data document poisoning is trivial.

---

## Section 1: OPA/Rego Fundamentals

### + ADDITION: Threat Model Scope

**Add after "Core principle" paragraph:**

The document correctly states: "OPA never enforces anything itself." This is a critical security property to internalize: **OPA is an oracle, not a guard**. The enforcement guarantee is entirely in the calling application. A compromised `PolicyGuardrailMiddleware`, a bypassed middleware chain, or a direct call to a proxied MCP server that skips the gateway entirely eliminates all OPA governance with zero OPA involvement. The threat model must account for:

- **Middleware bypass:** An agent that discovers a direct route to a proxied server (port scanning, leaked config, MCP server advertising itself independently) bypasses T4 governance entirely.
- **Input forgery:** OPA trusts `input.agent.archetype`, `input.agent.name`, and `input.meta.delegation_chain` at face value. If those fields are constructed by the calling agent (rather than the gateway), they are attacker-controlled.
- **OPA API abuse:** The OPA REST API (`PUT /v1/data`, `PUT /v1/policies`) allows full replacement of policies and data. Without authentication, any process with localhost access can rewrite governance rules.

### + ADDITION: OPA REST API Authentication Warning

**Add to the OPA REST API table:**

| API | Purpose | **Security Risk** |
|-----|---------|------------------|
| `PUT /v1/data/{path}` | Load or update data documents | **Unauthenticated by default — overwrites live policy data** |
| `PUT /v1/policies/{id}` | Load or update Rego policies | **Unauthenticated by default — replaces live policy logic** |
| `DELETE /v1/policies/{id}` | Remove a policy | **Not mentioned in document — deletes enforcement rules entirely** |

OPA's default configuration binds to `localhost:8181` with **no authentication**. The `--authentication=token` and `--authorization=basic` flags must be set at startup, and the gateway must use a pre-shared bearer token for all OPA calls. Without this, any process with localhost access — including any tool the agent executes via `Bash` — can call `curl http://localhost:8181/v1/policies/tool_guard -X DELETE` and silently remove the governance policy.

---

## Section 2: Rego Language Deep Dive

### ~ CHANGE: `with` keyword scope warning

**Was:** "`with` keyword (for testing — override input/data)"

**Should be:** "`with` keyword (for testing ONLY — never use production overrides in policy logic)"

**Rationale:** The document shows `with` only in test context, which is correct. However, it does not warn that if any policy rule uses `with` in a non-test context (e.g., a policy that calls a helper rule `allow_if_admin with input as modified_input`), it creates a policy-internal bypass. Reviewers unfamiliar with Rego may miss this pattern in code review. The document should explicitly state: `with` in production policy rules (outside `_test.rego` files) is a red flag and must trigger mandatory policy review.

### + ADDITION: Undefined vs. False — The Silent Bypass

**Add after "Key Syntax Elements":**

A critical Rego security property absent from the document: **`undefined` is not `false`**. If a rule body references a path that does not exist in `data` or `input`, the rule evaluates to `undefined` rather than `false`. For `deny` rules using the partial set pattern (`deny contains msg if { ... }`), this means a rule that references a missing data key simply produces no entry in the deny set — it does not fire as a deny. It silently disappears.

**Attack vector:** An attacker who can control which data documents are loaded into OPA (via the `PUT /v1/data` API or by poisoning a bundle) can remove `data.surfaces`, `data.budgets`, or `data.agents`. Every policy rule that references those documents will silently fail to produce deny entries. The result is that most governance rules stop firing — without any error, alarm, or explicit `allow` — because `undefined` in a deny set is treated as an empty set, and `count(deny) == 0` becomes true.

**Mitigation:** Every governance policy should include invariant checks that assert required data documents exist:

```rego
deny contains msg if {
    not data.surfaces
    msg := "CRITICAL: data.surfaces is missing — governance data document not loaded"
}

deny contains msg if {
    not data.budgets
    msg := "CRITICAL: data.budgets is missing — budget governance data not loaded"
}
```

These sentinel rules ensure that a missing data document produces a deny (fail-closed) rather than silent pass-through.

---

## Section 3: OPA for API Gateway Governance

### + ADDITION: Direct MCP Server Access — Governance Bypass Surface

**Add after the mapping table:**

The proposed architecture routes tool calls through ArchangelMCP Gateway (`:7400`), which invokes OPA before proxying to backend MCP servers. This assumes backend servers are not independently reachable. This assumption must be explicitly enforced:

- MCP servers that run as local HTTP daemons (Tavily, MorphLLM, Neo4j, etc.) likely bind to `localhost` on their own ports. If an agent discovers these ports (via `netstat`, prior tool call metadata, or config file reads), it can call them directly, bypassing the gateway and all T4 governance.
- **Mitigation:** Backend MCP servers should bind to `127.0.0.1` on non-discoverable ports and should require a gateway-issued session token in every request header. The gateway mints this token; the backend validates it. Without this, the gateway is a voluntary checkpoint, not a mandatory one.

### ~ CHANGE: Schema validation path traversal

**Was:** The `startswith(input.arguments.target_file, "/Users/")` check in the schema validation example.

**Should be:**
```rego
deny contains msg if {
    input.tool_name == "morph_edit_file"
    path := input.arguments.target_file
    # Normalize before checking — raw startswith is bypassed by path traversal
    not startswith(path, "/Users/")
    msg := "morph_edit_file target_file must be an absolute path under /Users/"
}

deny contains msg if {
    input.tool_name == "morph_edit_file"
    path := input.arguments.target_file
    # Block traversal sequences even within allowed prefixes
    contains(path, "../")
    msg := "Path traversal sequences forbidden in target_file"
}

deny contains msg if {
    input.tool_name == "morph_edit_file"
    path := input.arguments.target_file
    # Symlink following: /Users/x/../../etc/passwd passes startswith check
    # This requires gateway-level realpath resolution before OPA input construction
    contains(path, "/..")
    msg := "Path traversal sequences forbidden in target_file"
}
```

**Rationale:** `startswith(path, "/Users/")` is bypassed by `/Users/x/../../etc/passwd`. OPA cannot resolve symlinks or normalize paths — the gateway must canonicalize all file paths using `os.path.realpath()` before constructing the OPA input document. The Rego check is a second layer, not the primary defense.

---

## Section 4: OPA for AI/LLM Agent Guardrails

### + ADDITION: Input Construction is the Attack Surface

**Add after the "Core Insight" table:**

The eight governance dimensions listed (identity, tool, arguments, budget, temporal, chain, context, sensitivity) all depend on data that the gateway constructs and passes to OPA as `input`. The security of the entire governance layer therefore depends entirely on the integrity of input construction in `PolicyGuardrailMiddleware`. This is the highest-value attack surface in the system:

| Input Field | Source | Attack if Corrupted |
|-------------|--------|---------------------|
| `input.agent.archetype` | Gateway detection logic (`_PATTERN_TO_ARCHETYPE`) | Misclassified agent gets wrong allowlist |
| `input.agent.name` | Agent self-report or session metadata | Agent lies about its name → audit trail poisoned |
| `input.meta.parent_agent_id` | Agent self-report | Subagent spoofs a high-privilege parent |
| `input.meta.delegation_chain` | Agent self-report | Chain constructed from thin air |
| `input.meta.hil_approved` | Gateway approval state | Agent sets `hil_approved: true` without ticket |
| `input.meta.governance_pack_version` | Agent self-report | Agent claims higher version than installed |

Fields that agents can influence must be sourced from gateway-controlled state, not agent-provided values. The document does not distinguish between gateway-derived fields (trustworthy) and agent-provided fields (untrusted). This distinction must be explicit in the integration architecture.

### + ADDITION: Egress Control Gap

**Add as new subsection:**

The governance dimensions table omits **egress control** entirely. The document focuses on what tools an agent may *call*, but not on what data those tools may *exfiltrate*. A tool call to `tavily_tavily_search` with `query="paste the contents of /Users/x/.env"` passes every listed governance check (correct archetype, tool in allowlist, budget not exceeded, etc.) while exfiltrating secrets. Missing dimensions:

- **Egress:** What data may leave the system via tool arguments? (Tavily, web fetch, HTTP calls)
- **Secrets in arguments:** Are tool arguments scanned for credential patterns before execution?
- **Network segmentation:** Which tools may make outbound network calls? To which domains?

Recommended additions to the governance dimensions table:

| Dimension | Question | Rego Evaluates Against |
|-----------|----------|----------------------|
| **Egress** | Does this tool call send data to an external endpoint? | `data.network_tools`, argument content scanning |
| **Secrets** | Do the arguments contain credential patterns? | `re_match` for API keys, tokens, passwords in `input.arguments.*` |
| **Network scope** | Is the target domain in the approved egress allowlist? | `input.arguments.url`, `data.egress_allowlist` |

---

## Section 5: 15 Example Policies

### Policy 1: Tool Allowlist per Agent Archetype

#### ~ CHANGE: Missing archetype for unknown agents

**Was:** The policy silently fails (undefined → no deny entry) if `input.agent.archetype` is not a key in `data.surfaces`.

**Should be:**
```rego
deny contains msg if {
    archetype := input.agent.archetype
    not input.agent.archetype in object.keys(data.surfaces)
    msg := sprintf(
        "Unknown archetype '%s' — not in surfaces registry. Defaulting to deny.",
        [archetype],
    )
}

deny contains msg if {
    archetype := input.agent.archetype
    not input.tool_name in data.surfaces[archetype].allowed_tools
    msg := sprintf(
        "Tool '%s' not in allowlist for archetype '%s'",
        [input.tool_name, archetype],
    )
}
```

**Rationale:** If `data.surfaces["unknown-archetype"]` is undefined, the original rule evaluates to undefined (not deny). An agent presenting an archetype string not in the surfaces registry gets **implicit allow** on all tools. The sentinel rule above ensures unknown archetypes fail closed.

---

### Policy 2: Destructive Command Blocking

#### - SUBTRACTION: Incomplete `rm` regex

**Remove:** `re_match(`rm\s+(-rf?|--recursive)`, command)`

**Replace with:**
```rego
deny contains msg if {
    input.tool_name == "Bash"
    command := input.arguments.command
    # Cover all dangerous rm variants including quoted, spaced, and aliased forms
    re_match(`(?:^|[;&|]\s*)rm\b`, command)
    re_match(`(?:-[a-zA-Z]*[rf][a-zA-Z]*|--recursive|--force)`, command)
    msg := "rm with recursive/force flags is permanently blocked. Use 'trash' instead."
}
```

**Rationale:** The original regex `rm\s+(-rf?|--recursive)` is bypassed by:
- `rm  -r -f /` (space between flags)
- `rm --recursive /` (only catches `-r`, not `--recursive` used alone)
- `rm -fr /` (flags reversed)
- `$(which rm) -rf /` (command substitution)
- `\rm -rf /` (backslash escapes alias)
- `rm -rf / #comment` (trailing content)
- `echo x; rm -rf /` (chained with semicolon)

Also missing: `dd`, `shred`, `mkfs`, `fdisk`, `> /dev/sda`, and other destructive commands that bypass the `rm`-focused rule entirely.

#### + ADDITION: Command injection in Bash policy

**Add after Policy 2:**

```rego
# Block subshell and command substitution patterns that circumvent string matching
deny contains msg if {
    input.tool_name == "Bash"
    command := input.arguments.command
    re_match(`\$\(|` + "`", command)
    re_match(`(?i)(rm|shred|dd|mkfs|wipefs|fdisk)`, command)
    msg := "Command substitution combined with destructive commands is blocked"
}

# Block environment variable overrides that modify command behavior
deny contains msg if {
    input.tool_name == "Bash"
    command := input.arguments.command
    re_match(`^\s*[A-Z_]+=.*rm\b`, command)
    msg := "Environment variable prefix with destructive commands is blocked"
}
```

---

### Policy 3: File Path Restrictions

#### ~ CHANGE: Regex matches file extension, not path suffix

**Was:** `re_match(`\.(env|pem|key|credentials|secret)`, path)`

**Should be:**
```rego
deny contains msg if {
    input.tool_name in {"morph_edit_file", "Write", "Edit", "Read"}
    path := input.arguments.target_file
    # Match at end of filename component, not anywhere in path
    re_match(`(?i)\.(env|pem|key|pub|crt|cer|p12|pfx|credentials|secret|secrets|keystore|jks|gpg|asc)$`, path)
    msg := sprintf("Editing/reading sensitive file blocked: %s", [path])
}
```

**Rationale:** The original regex matches `.env` anywhere in the path, including `/home/user/inventoryapp/` (false positive on `env` substring in directory names). More critically, it misses `.env.local`, `.env.production`, `.env.backup`, `id_rsa`, `.ssh/config`, `~/.netrc`, `.npmrc`, `.pypirc`, and numerous other credential file formats. The Read tool is also missing from the tool set — an agent that cannot write a `.env` file can still read it via `Read` tool.

#### + ADDITION: Missing sensitive path patterns

```rego
deny contains msg if {
    input.tool_name in {"morph_edit_file", "Write", "Edit", "Read", "Bash"}
    path := input.arguments.target_file
    re_match(`(?i)(\.ssh/|\.gnupg/|\.aws/credentials|\.aws/config|\.netrc|\.npmrc|\.pypirc|\.docker/config\.json)`, path)
    msg := sprintf("Access to credential path blocked: %s", [path])
}

deny contains msg if {
    input.tool_name == "Bash"
    command := input.arguments.command
    # Credential file access via cat/bat/head/tail in Bash
    re_match(`(?i)(cat|bat|head|tail|less|more|strings)\s+.*\.(env|pem|key|credentials|secret)`, command)
    msg := "Reading credential files via Bash is blocked"
}
```

---

### Policy 4: Budget Enforcement

#### + ADDITION: Race condition in budget check

**Add after Policy 4 code block:**

**TOCTOU vulnerability:** Budget enforcement in Policy 4 reads `data.usage[scope]` from an OPA data document that is updated "every N tool calls (batched)" (per Section 10). Between the last batch update and the current policy evaluation, the agent may have consumed significant additional tokens. In a session where 100 tool calls happen before the next batch push, an agent can spend up to `(N-1) * max_tokens_per_call` beyond its budget. Parallel subagents amplify this: 5 agents each checking against a stale `data.usage` value can collectively overspend by `5 * (N-1) * max_tokens_per_call`.

**Mitigation required:**
- `data.usage` must be updated synchronously on every tool call, not batched.
- Alternatively, budget enforcement must remain in `TokenCostGovernor` Python code (which has immediate consistency) and OPA budget rules must be treated as a secondary check only. The document should not present OPA as a replacement for the Python budget governor until synchronous update semantics are guaranteed.
- Add a soft limit (e.g., 80% of budget) that triggers a warning decision so the agent can gracefully wind down before hitting the hard limit.

#### ~ CHANGE: Null check is not idiomatic Rego

**Was:** `budget.token_budget != null`

**Should be:** `budget.token_budget` (truthy check — OPA treats `null` and `undefined` differently; a missing key is undefined, not null, and `!= null` will not catch the undefined case)

---

### Policy 5: Temporal Policies

#### + ADDITION: `time.now_ns()` is gateway-clock-dependent

**Add after Policy 5:**

`time.now_ns()` returns the current time at the moment of OPA policy evaluation, sourced from the OPA daemon's system clock. This creates two issues:

1. **Clock skew in distributed deployments:** If OPA runs on a different host from the gateway (future distributed scenario), clock skew between hosts means temporal policies may evaluate against a time offset of several seconds to minutes from the gateway's perception of "now."

2. **TOCTOU window for temporal rules:** The time is captured at OPA evaluation time, not at tool execution time. A tool call that takes 500ms to execute after an OPA approval at 21:59:59 will execute at 22:00:00, after the deployment cutoff. The policy approved what it should have denied by one second.

**Mitigation:** For temporal policies that have hard cutoffs (deployment windows, change freeze periods), the gateway should re-check the constraint at execution time, not only at policy evaluation time. This is analogous to a mutex that must be held across the check-then-act operation.

---

### Policy 6: Escalation Chain

#### - SUBTRACTION: `count(deny) == 0` in `allow` rule creates ordering dependency

**Remove:**
```rego
allow if {
    input.tool_name in data.auto_approve_tools
    count(deny) == 0
}
```

**Replace with:**
```rego
# Auto-approve only evaluates after deny set is fully populated
# OPA evaluates all rules before returning — this is safe, but explicit ordering helps clarity
default allow := false

allow if {
    count(deny) == 0
    count(require_hil) == 0
    input.tool_name in data.auto_approve_tools
}
```

**Rationale:** As written, the `allow` rule in Policy 6 appears to short-circuit deny checking — it looks like a tool in `auto_approve_tools` is allowed regardless of `deny`. OPA does not short-circuit (all rules are evaluated), but the presentation is misleading for policy authors who may reason imperatively. The explicit `count(deny) == 0` guard must be visible in all `allow` rules. A policy author who omits it in a future edit will create a genuine bypass.

#### + ADDITION: HIL approval spoofing

**Add after Policy 6:**

The `hil_approved` and `hil_approval_id` fields in `input.meta` are constructed by the gateway in the proposed architecture (Section 10). However, nothing prevents an agent from constructing its own OPA input if it has direct access to OPA's HTTP API (which it may, via `Bash` → `curl localhost:8181`). An agent that knows the OPA API can call:

```bash
curl -s http://localhost:8181/v1/data/kellerai/grc/tool_guard \
  -d '{"input": {"tool_name": "dangerous_tool", "meta": {"hil_approved": true, "hil_approval_id": "forged-uuid"}, "agent": {"archetype": "editor"}}}'
```

and receive an `allow` decision without any human approval occurring. This is the **oracle query attack**: query OPA directly with a crafted input rather than going through the gateway.

**Mitigation:** OPA's HTTP API must be firewalled from agent-accessible processes. Either:
- Run OPA with `--authentication=token` and a gateway-only token that is never exposed to agents.
- Bind OPA to a Unix domain socket accessible only by the gateway process, not TCP localhost.
- The gateway must never expose OPA's endpoint via any gateway route or tool.

---

### Policy 7: Audit Trail Requirements

#### + ADDITION: Correlation ID can be replayed

**Add after Policy 7:**

Requiring `correlation_id` prevents uncorrelated calls but does not prevent correlation ID replay. An agent that captures a valid `correlation_id` from a previous legitimate call can reuse it for subsequent calls, linking malicious activity to a legitimate trace entry. The audit trail then shows one `correlation_id` associated with both legitimate and illegitimate actions.

**Mitigation:** The gateway must enforce correlation ID uniqueness at the session level. OPA cannot do this without access to a data document that tracks all previously-used correlation IDs, which is impractical. This is a gateway-layer control, not a Rego policy control.

---

### Policy 8: Rate Limiting by Tool Category

#### + ADDITION: Rate limit window data is stale

**Add after Policy 8:**

`data.recent_calls[agent_name][category]` is described (Section 10) as updated by Flight Recorder "every 60 seconds." This means the rate limit window in OPA lags reality by up to 60 seconds. An agent making 100 calls in a 30-second burst will not trigger the rate limit during that burst because `data.recent_calls` has not been updated yet. Only after the next Flight Recorder sync will the rate limit data reflect the burst.

In a 60-second lag window with `max_calls: 10 per 60s`, an agent can make up to 20 calls before being blocked: 10 in the first window (not yet reflected in OPA data) and 10 more in the second window after the first sync.

**Mitigation:** Rate limiting that relies on OPA data documents must use synchronous push semantics. Any window-based rate limit with a polling data source is trivially defeated by a burst that fits within the lag window. Burst prevention must be implemented in the gateway layer with in-memory counters, not in OPA with stale data.

---

### Policy 9: Agent Delegation Chain Validation

#### ~ CHANGE: Policy is entirely bypassable by omitting `is_subagent`

**Was:**
```rego
deny contains msg if {
    input.agent.is_subagent == true
    not input.meta.parent_agent_id
    msg := "Sub-agents must declare parent_agent_id"
}
```

**Should be:**
```rego
# A subagent that lies about is_subagent bypasses all chain validation.
# Use structural detection instead of self-report.
deny contains msg if {
    # Any agent with a parent_agent_id in input is a subagent, regardless of is_subagent flag
    input.meta.parent_agent_id
    not input.meta.parent_agent_id in object.keys(data.agents)
    msg := sprintf(
        "parent_agent_id '%s' not in registered agent catalog",
        [input.meta.parent_agent_id],
    )
}

deny contains msg if {
    # If delegation_chain is non-empty, treat as subagent regardless of is_subagent flag
    count(input.meta.delegation_chain) > 0
    not input.meta.parent_agent_id
    msg := "Non-empty delegation_chain requires parent_agent_id"
}
```

**Rationale:** The existing policy fires only when `input.agent.is_subagent == true`. A compromised or malicious subagent simply omits this field or sets it to `false`. The policy produces no deny, the chain is never validated, and the subagent proceeds with whatever privileges its archetype allows. The fix uses structural indicators (presence of `parent_agent_id` or non-empty `delegation_chain`) as the subagent signal, since those fields are harder to selectively omit without breaking other functionality.

#### + ADDITION: Parent privilege lookup trusts `data.agents` which is attacker-writable

**Add after Policy 9:**

The privilege escalation check:
```rego
parent := data.agents[input.meta.parent_agent_id]
child := data.agents[input.agent.name]
parent.privilege_level < child.privilege_level
```
reads `data.agents` from an OPA data document. Per Section 10, `data.agents` is sourced from the "Oracle agent catalog" and updated on "catalog sync." As noted in the Oracle query attack above, if an attacker can write to `data.agents` via the unauthenticated OPA REST API, they can set `parent.privilege_level` to any value, making every parent appear to have maximum privilege and defeating the escalation check.

This pattern — checking privilege from a data document that is writable via the same API the policy is trying to protect — is a circular trust problem. The privilege levels must be sourced from a gateway-controlled, OPA-read-only mechanism (e.g., loaded only at bundle load time, not via the live data API).

---

### Policy 10: Concurrent File Access Prevention

#### ~ CHANGE: TOCTOU race in file reservation check

**Was:**
```rego
reservation.expires_at > time.now_ns() / 1000000000
```

**Should be:**

This is the most concrete TOCTOU vulnerability in the document. The sequence is:

```
T=0: Agent A checks OPA: file not reserved → ALLOW
T=0: Agent B checks OPA: file not reserved → ALLOW  (concurrent)
T=1: Agent A executes write to file
T=1: Agent B executes write to file  → RACE CONDITION, last write wins
```

OPA evaluates policies **atomically from its perspective** (a point-in-time snapshot of `data`), but the gap between "OPA says allow" and "gateway executes the tool" is not protected. Two concurrent agents can both receive ALLOW for the same exclusive file reservation if their OPA queries arrive before either has executed.

**Required fix:** File reservation must be implemented as a gateway-layer distributed lock (mutex), not as an OPA policy check. OPA can enforce that a reservation *exists* and *has not expired*, but it cannot create a reservation atomically as part of the decision. The correct pattern:

```
1. Agent requests file write
2. Gateway attempts to acquire mutex for path (atomic compare-and-swap or lock table)
3. If lock acquired: push reservation to OPA data, proceed to execution, release on completion
4. If lock not acquired: deny with "file reserved by agent X"
5. OPA policy is a secondary check that validates the reservation data — not the primary lock
```

Additionally, `time.now_ns() / 1000000000` converts nanoseconds to seconds with integer truncation. If `expires_at` is stored as a float (seconds with fractional part), this comparison loses sub-second precision. Use consistent time units throughout.

#### + ADDITION: Integer overflow risk in time comparison

The expression `time.now_ns() / 1000000000` divides a nanosecond timestamp (currently ~1.7 × 10¹⁸) by 10⁹. In OPA's number representation (IEEE 754 double), values above ~2⁵³ ≈ 9 × 10¹⁵ lose integer precision. The current nanosecond epoch (~1.7 × 10¹⁸) already exceeds this threshold, meaning the division result may have rounding errors of ±1 second. Time comparisons in reservation expiry logic must use OPA's `time.now_ns()` directly compared against nanosecond-precision `expires_at` values, not converted to seconds.

---

### Policy 11: Output Size Limits

#### + ADDITION: Secrets in arguments — missing scan

**Add after Policy 11:**

Output size limiting prevents large writes but does not scan argument content for embedded credentials. An agent can write a file containing a hardcoded API key, database password, or private key material — all of which pass the 100KB size limit check. Recommended additions:

```rego
deny contains msg if {
    input.tool_name in {"Write", "morph_edit_file", "Edit"}
    content := input.arguments.content
    # Common secret patterns
    re_match(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd|private[_-]?key)\s*[:=]\s*['""]?[A-Za-z0-9+/]{16,}`, content)
    msg := "Potential credential detected in write content — blocked pending review"
}

deny contains msg if {
    input.tool_name in {"Write", "morph_edit_file", "Edit"}
    content := input.arguments.content
    # AWS key pattern
    re_match(`AKIA[0-9A-Z]{16}`, content)
    msg := "AWS access key pattern detected in write content — blocked"
}
```

---

### Policy 12: Server-Specific Argument Validation

#### ~ CHANGE: Neo4j regex is bypassable by case variation and Unicode

**Was:** `re_match(`(?i)drop\s+(database|index|constraint)`, query)`

**Should be:**
```rego
deny contains msg if {
    input.tool_name == "neo4j_mcp_write-cypher"
    query := input.arguments.query
    # Normalize whitespace and control characters before matching
    normalized := lower(query)
    re_match(`drop\s+(database|index|constraint|table|schema)`, normalized)
    msg := "DROP operations on Neo4j are permanently blocked"
}

deny contains msg if {
    input.tool_name == "neo4j_mcp_write-cypher"
    query := input.arguments.query
    re_match(`(?i)(call\s+apoc\.|call\s+dbms\.|call\s+db\.changePassword)`, query)
    msg := "APOC procedure calls and password changes on Neo4j are blocked"
}
```

**Rationale:** The original regex misses `DETACH DELETE` (deletes nodes and all relationships), `CALL apoc.util.sleep(30000)` (DoS via APOC procedures), `CALL dbms.changePassword()`, and multi-line Cypher with embedded newlines that break `\s+` matching. The `(?i)` flag handles case, but `lower()` + lowercase pattern is more reliable across OPA versions.

---

### Policy 13: Environment-Aware Policies

#### + ADDITION: `data.environment` is a writable data document

**Add after Policy 13:**

`data.environment` is listed in Section 10 as a data document updated "on gateway start." It is therefore writable via `PUT /v1/data/environment` on the unauthenticated OPA API. An attacker (or compromised agent with Bash access) can set:

```bash
curl -X PUT http://localhost:8181/v1/data/environment \
  -d '"staging"'
```

This immediately causes all `data.environment == "production"` checks to evaluate to false, disabling every production-environment guard (package installation blocks, staging-only tool restrictions). The attacker has effectively downgraded the environment classification from production to staging.

**Mitigation:** `data.environment` must be injected into OPA at bundle load time (read-only) or via the `input` document (gateway-controlled), never via the live data API. Environment classification is a security-critical property and must not be mutable at runtime.

---

### Policy 14: Cross-Session Memory Governance

#### ~ CHANGE: Content scan for "password" is trivially bypassed

**Was:**
```rego
deny contains msg if {
    input.tool_name == "memory_store"
    contains(input.arguments.content, "password")
    msg := "Storing password-containing content in memory is blocked"
}
```

**Should be:**
```rego
deny contains msg if {
    input.tool_name == "memory_store"
    content := lower(input.arguments.content)
    # Broader credential keyword list
    keywords := {"password", "passwd", "api_key", "apikey", "secret", "token",
                  "credential", "private_key", "access_key", "auth_token"}
    some kw in keywords
    contains(content, kw)
    msg := sprintf("Storing content with credential keyword '%s' in memory is blocked", [kw])
}
```

**Rationale:** `contains(content, "password")` is bypassed by: `p4ssw0rd`, `passw0rd`, `PASSWORD` (case), `pa$$word` (character substitution), `pass word` (space), `p\x61ssword` (escape sequences if content is processed before storage). Keyword matching for credential blocking is inherently weak — the stronger control is regex matching for structural credential patterns (entropy-based detection, format-specific patterns like AWS keys, JWT headers `eyJ`, PEM headers `-----BEGIN`).

---

### Policy 15: Governance Pack Versioning

#### + ADDITION: `semver.compare` is not a built-in OPA function

**Add after Policy 15:**

`semver.compare(actual, expected)` is **not a standard OPA built-in function** as of OPA v0.68. The document uses it as if it were available, but OPA's built-in list does not include `semver.*`. This policy will fail at evaluation time with `undefined function: semver.compare`, which — per the undefined-vs-false issue noted above — means the rule silently fails to fire, and agents running stale governance packs are not blocked.

**Fix options:**
1. Use a custom helper function that parses and compares semver strings via Rego string splitting.
2. Use integer version numbers instead of semver strings, enabling direct `<` comparison.
3. Use OPA's `semver` built-ins if targeting OPA v0.70+ (where `semver.compare` was added), and document the minimum OPA version requirement explicitly.

#### ~ CHANGE: Version declared by agent is untrustworthy

**Was:** `actual := input.meta.governance_pack_version`

**Should be:** The governance pack version must be sourced from the gateway's known-good configuration, not from `input.meta` which is partly constructed from agent-provided data. An agent declaring `input.meta.governance_pack_version = "99.99.99"` satisfies any minimum version check trivially. The actual installed governance pack version must be injected by the gateway into a non-agent-controlled field, or compared against `data.governance_pack_version` (the gateway-pushed authoritative version), not against `input.meta.governance_pack_version` (agent self-report).

---

## Section 6: OPA Deployment Models

### ~ CHANGE: HTTP Sidecar "Recommended" designation without authentication caveat

**Was:** "Option A: HTTP Sidecar (Recommended for ArchangelMCP)"

**Should be:** "Option A: HTTP Sidecar (Recommended for ArchangelMCP — **requires authentication hardening before production use**)"

**Add to Cons list:**
- **No authentication by default** — `PUT /v1/data` and `PUT /v1/policies` are unauthenticated; any local process can modify live policies
- **Decision log exposure** — OPA's decision log endpoint (`/v1/logs`) exposes all policy decisions including denied attempts; must be restricted
- **Admin API exposure** — OPA's management endpoints must be bound separately from the data API or firewalled

### + ADDITION: Mandatory OPA hardening checklist

**Add as new subsection after Option D:**

Before deploying OPA as a production governance sidecar, the following hardening steps are mandatory:

```bash
# 1. Enable token authentication
opa run --server \
  --authentication=token \
  --authorization=basic \
  --addr=localhost:8181 \     # localhost only, not 0.0.0.0
  ...

# 2. Create policy to restrict API access (stored in /etc/opa/system/authz.rego)
# Only allow the gateway's bearer token to call data/policy mutation APIs

# 3. Verify OPA is not reachable from agent-spawned processes
# Test: spawn a Bash tool call and attempt curl to localhost:8181

# 4. Enable TLS even for localhost if OPA daemon will be long-lived
# (mitigates local process credential sniffing)

# 5. Set --log-level=error in production (info-level logs expose policy details)
```

### + ADDITION: Bundle supply chain attack surface

**Add as new subsection:**

#### Bundle Signing and Verification — Critical Gap

The proposed Phase 3 architecture ("policies stored in git, compiled to bundles in CI, served from a local bundle server or filesystem") creates a supply chain from git commit → CI pipeline → bundle file → OPA daemon. This chain is entirely unsigned in the current proposal.

**Attack surface:**
- A bundle file on the filesystem (`~/.claude/archangel/governance-packs/`) can be replaced by any process with write access to the user's home directory. An agent with `Write` tool access or `Bash` access to the directory can replace `tool_guard.rego` with a policy that allows everything.
- The launchd plist `--bundle ~/.claude/archangel/governance-packs/` loads bundles from this path on startup. OPA will load whatever is there, signed or not.
- CI pipeline compromise: if the CI system that compiles bundles is compromised, it can inject a permissive policy that appears to pass `opa test` (malicious tests can be written to pass against malicious policies).

**Required mitigations:**

1. **OPA bundle signing:** OPA supports signed bundles via `opa build --signing-key`. The gateway must verify bundle signatures before OPA loads them:
   ```bash
   # Build signed bundle in CI
   opa build --signing-key governance-signing.pem \
             --signing-alg RS256 \
             policies/ -o bundle.tar.gz

   # Verify before loading (OPA daemon flag)
   opa run --server \
     --bundle bundle.tar.gz \
     --verification-key governance-verify.pem \
     --scope production
   ```

2. **Filesystem permissions:** The governance packs directory must not be writable by the same user account that runs the MCP servers or agent sessions. Separate system user for OPA + read-only bind mount for bundle directory.

3. **Bundle integrity hash:** Store the SHA-256 hash of the expected bundle in a separate location (e.g., gateway config or environment variable) and verify it on every OPA restart.

4. **Pin policy version in gateway config:** `servers.yaml` already has a `bundle_dir` field. Add a `bundle_hash` and `bundle_min_version` that the gateway verifies against OPA's `/v1/bundles` status endpoint on startup.

### ~ CHANGE: Option B (CLI Evaluation) security properties

**Was:** Only performance cons listed for CLI evaluation.

**Should add to Cons:**
- **TOCTOU on policy files:** `opa eval -d policies_dir` reads policy files from disk at subprocess invocation time. Between the call and the read, policy files can be modified by another process. Each evaluation reads fresh-from-disk policies — if an attacker modifies the policy files between requests, consecutive evaluations of the same input may produce different decisions.
- **No bundle integrity:** CLI evaluation loads `.rego` files directly with no signing or verification.
- **Subprocess injection:** The `subprocess.run(["opa", "eval", ..., "data.kellerai.grc.tool_guard"])` call constructs a command array. If any component of this command is derived from user input (policy path, rule path, input data piped to stdin), injection is possible. Verify that all components are hardcoded, not derived from request data.

---

## Section 7: Policy-as-Code Best Practices

### + ADDITION: Shadow Mode as an Attack Surface

**Add after "Dry-Run / Shadow Mode" section:**

Shadow mode is presented as a safety mechanism for gradual policy rollout. It is also an **attack surface if the mode classification is not integrity-protected**.

**Attack scenario:** An attacker (or compromised agent) with write access to `governance-pack-config.yaml` changes `mode: enforce` to `mode: shadow` for the `tool-guard-v2` pack. The gateway continues logging "would-deny" telemetry, but enforcement is disabled. The attacker can now execute any tool call the policy would have blocked. Because shadow mode is a documented operational pattern, the change may not trigger any alarm — it looks like a legitimate operations decision.

**Mitigations required:**
1. `governance-pack-config.yaml` must be treated as a security-critical file. Changes to `mode:` fields must require out-of-band approval (separate git commit + review, not inline file edit).
2. The gateway must emit a high-severity alert when any pack transitions from `enforce` to `shadow` or `warn` mode. This transition should never happen silently.
3. Consider making `mode: enforce` a one-way ratchet: a pack that has been in enforce mode cannot be downgraded to shadow/warn without a restart + explicit config flag.
4. Shadow mode must not disable L0 invariant rules. The layering model in Section 8 distinguishes L0 (invariants, "cannot be overridden") from L4 (advisory). Shadow mode should only silence L3 and L4 rules, never L0 or L1.

### + ADDITION: Rollback as a policy bypass vector

**Was:** "In emergency, set `mode: warn` to disable enforcement without removing policies"

**Add:**

The rollback mechanism (`mode: warn`, OPA HTTP PUT to replace bundles, git revert) is a legitimate operational tool that is also a policy bypass technique. The document should clarify:

- Rollback authority must be restricted. Who can trigger a rollback? The same access control that governs policy changes should govern rollbacks.
- A rollback to a previous version of a governance pack may reintroduce previously-patched vulnerabilities. Emergency rollbacks should be reviewed within 24 hours and re-patched promptly.
- Git history is not sufficient audit trail for rollback events. The gateway must emit a structured event (via FlightRecorder or Channels) when a governance pack version change is detected, including: old version, new version, timestamp, and the identity of the process that triggered the change.

---

## Section 8: Progressive Disclosure in Policy Systems

### + ADDITION: L0 invariants must be OPA-external

**Add after the layer composition code block:**

The layering model designates L0 as "Always, cannot be overridden." However, in the proposed implementation, L0 invariants are Rego rules evaluated by the same OPA daemon as L3 and L4 rules. If the OPA daemon is compromised (policy replacement, data poisoning, daemon crash → fail-open fallback), L0 invariants fail along with everything else.

**True L0 invariants must be enforced outside OPA**, at the gateway middleware level, in code that is not policy-configurable. Examples of controls that should be gateway-hardcoded, not OPA policies:

- Agent identity must be present (if not, hard reject at middleware layer before OPA is called)
- OPA must be reachable — if OPA times out, the decision is **deny**, not **allow** (fail-closed is hardcoded in middleware, not a policy rule)
- Certain tools (e.g., a hypothetical `opa_policy_replace` tool) must never be exposed through the gateway regardless of what OPA decides

The distinction: OPA enforces governance policy. The gateway enforces invariants that must hold even when OPA is wrong.

---

## Section 9: The Tiers Model

### + ADDITION: T4 visibility creates information leakage

**Add after the T4 tool call lifecycle diagram:**

The lifecycle shows that when T4 denies a tool call, the agent receives deny reasons via "progressive disclosure" — T2 level includes the matched pattern and escalation procedure. This creates an information leakage risk: an agent probing governance policy limits can send tool calls and read the denial reasons to map out the policy structure. A patient attacker can enumerate:

- Which tools are in `data.always_blocked_tools` (by trying each and getting "permanently blocked" vs. "not in allowlist")
- Which archetypes exist (by varying `input.agent.archetype` and reading denial messages)
- Rate limit thresholds (by triggering the rate limit error message which includes the current count and maximum)
- Budget scope names (from budget exceeded messages)

**Mitigation:** Deny messages visible to agents should be generic and non-enumerable at T1/T2. Only the minimal information needed for legitimate error recovery should be included. Full policy details (T3) should be available only via an authenticated admin query, not returned in standard denial responses.

---

## Section 10: ArchangelMCP Integration Architecture

### ~ CHANGE: Fallback strategy is fail-open — this is the highest-severity finding

**Was:**
> "If OPA is unavailable (crash, timeout, not installed), the gateway falls back to the existing fnmatch-based `PolicyGuardrailEngine`."

And in `servers.yaml`:
```yaml
fallback: "fnmatch"  # or "deny" for fail-closed
```

**Should be:**

The fallback strategy as documented defaults to `"fnmatch"` — a less capable rule engine that will not enforce the full governance policy set. This is fail-open by default. The comment `# or "deny" for fail-closed` treats the safer option as an afterthought.

**The fallback strategy must default to `"deny"`.** The reasoning:

1. OPA is a `KeepAlive: true` launchd service — if it crashes, launchd restarts it within seconds. A brief deny window during restart is preferable to a fall-through to a weaker enforcement regime.
2. The fnmatch rules are a subset of OPA governance. Any tool call that OPA would deny but fnmatch would allow is a governance breach caused by OPA unavailability — which is exactly the trigger condition an attacker would engineer.
3. A deliberate OPA crash (e.g., via `kill` from a Bash tool call, or resource exhaustion) followed by a rapid tool call during the restart window is an exploitable attack vector if the fallback is fail-open.

**Required change in `servers.yaml`:**
```yaml
defaults:
  policy_guardrails:
    opa_backend:
      enabled: true
      url: "http://localhost:8181"
      timeout: 3
      fallback: "deny"    # NEVER "fnmatch" in production — fail closed
      fallback_message: "Governance sidecar unavailable — all tool calls denied pending recovery"
```

The fnmatch fallback may be acceptable in **development environments** where OPA is not installed, but must be explicitly disabled (`fallback: "deny"`) in any deployment that handles sensitive data or production tool execution.

### ~ CHANGE: Data flow — agent identity sources not distinguished

**Was:** The `opa_input` construction in Python mixes gateway-derived and agent-provided fields without comment.

**Should add inline comments:**
```python
opa_input = {
    "tool_name": tool_name,           # GATEWAY-DERIVED: from MCP protocol
    "arguments": arguments,           # AGENT-PROVIDED: untrusted, validate before use
    "agent": {
        "archetype": detect_archetype(context),    # GATEWAY-DERIVED: from pattern matching
        "name": agent_name,                        # PARTIALLY TRUSTED: session-bound but self-reported
        "budget_scope": budget_scope,              # GATEWAY-DERIVED: from session config
        "is_subagent": bool(parent_agent_id),      # GATEWAY-DERIVED: from session hierarchy
    },
    "meta": {
        "correlation_id": get_correlation_id(),    # GATEWAY-DERIVED: generated by gateway
        "timestamp": utc_now_iso(),                # GATEWAY-DERIVED: gateway clock
        "parent_agent_id": parent_agent_id,        # AGENT-PROVIDED: self-reported, unverified
        "delegation_chain": delegation_chain,      # AGENT-PROVIDED: self-reported, unverified
        "hil_approved": bool(hil_approval_id),     # GATEWAY-DERIVED: from approval state store
        "hil_approval_id": hil_approval_id,        # GATEWAY-DERIVED: from approval state store
        "governance_pack_version": pack_version,   # GATEWAY-DERIVED: from installed config
    },
    "environment": current_environment,            # GATEWAY-DERIVED: from deployment config
}
```

**Rationale:** Policy authors writing Rego rules must know which input fields are trustworthy. A rule that enforces security based on `input.meta.delegation_chain` (agent-provided) has weaker guarantees than one enforcing based on `input.meta.correlation_id` (gateway-derived). This distinction must be documented in the integration architecture and reinforced in policy author guidelines.

### + ADDITION: OPA data document push authentication

**Add after the Data Documents table:**

The gateway pushes data to OPA via `PUT /v1/data/{path}`. As noted above, this API is unauthenticated by default. However, even after adding token authentication, the push mechanism itself has risks:

- **Data push race:** If the gateway pushes `data.usage` and `data.file_reservations` asynchronously from different components, there is a window where `data.usage` reflects state T but `data.file_reservations` reflects state T-1. Policies that combine both documents may evaluate against an inconsistent snapshot.
- **Data push failure:** If a push fails silently (network error, OPA restart), OPA continues evaluating against stale data. The gateway must verify that critical data pushes succeed and retry with backoff, not fire-and-forget.
- **Data document size limits:** OPA loads data documents into memory. An agent that can trigger large data pushes (e.g., by generating large `data.recent_calls` entries through rapid tool calling) could cause OPA memory exhaustion, triggering a crash and the fail-open fallback scenario.

---

## Section 11: Existing Codebase Anchor Points

### + ADDITION: `subprocess.run` in OpaBackend — injection risk

**Add after the `OpaBackend` description:**

The current `OpaBackend` implementation shells out to `opa eval`:

```python
result = subprocess.run(
    ["opa", "eval", "-d", str(self._policies_dir),
     "-i", "/dev/stdin", "--format", "raw",
     "data.kellerai.grc.tool_guard"],
    input=json.dumps(opa_input), ...
)
```

The command array is hardcoded (good), and `opa_input` is passed via stdin (good — not via command line argument, which would be injectable). However:

1. `self._policies_dir` must be validated to be a fixed, non-user-controlled path. If it is ever derived from request data or environment variables that an agent can influence, a path traversal here could load attacker-controlled policy files.
2. The `opa` binary itself at `/usr/local/bin/opa` must be integrity-verified. A PATH manipulation attack (`export PATH=/tmp:$PATH`) that places a fake `opa` binary in a higher-priority PATH entry would cause `subprocess.run(["opa", ...])` to execute the fake binary, which could return `{"result": {"allow": true}}` for all inputs.
3. Mitigation: Use an absolute path to the `opa` binary (hardcoded in config, verified against a known hash on startup), not relying on PATH resolution.

---

## Section 12: Open Questions

### ~ CHANGE: Open Question 2 — bundle distribution is a security question, not just an ops question

**Was:** "Bundle distribution model? Local filesystem bundles (simplest) vs HTTP bundle server (enables multi-machine) vs git-based CI pipeline?"

**Should be:** "Bundle distribution model — **with security constraints**: Local filesystem bundles require filesystem ACL controls and hash verification. HTTP bundle server requires TLS + token authentication and must not be reachable from agent-controlled processes. Git-based CI pipeline requires signed commits and signed bundle artifacts. **An unsigned, unauthenticated bundle distribution mechanism is not acceptable for production governance policy deployment regardless of simplicity.**"

### + ADDITION: New open questions (security-critical, unaddressed)

**Add to Open Questions:**

8. **OPA API authentication:** Which authentication mechanism will protect `PUT /v1/data` and `PUT /v1/policies` — token auth, mTLS, Unix socket, or network namespace isolation? This must be decided before P1.

9. **Fail-closed verification:** How will the system be tested to confirm that OPA unavailability results in tool call denial (not pass-through)? A chaos engineering test (deliberate OPA kill during active session) should be part of P5.

10. **Bundle signing key management:** Where are governance pack signing keys stored? How are they rotated? Who has access? A leaked signing key allows an attacker to produce validly-signed malicious bundles.

11. **Agent identity verification:** `input.agent.name` and `input.meta.parent_agent_id` are currently self-reported. Is there a cryptographic binding between an agent session and its declared identity? Without it, any agent can claim any identity.

12. **Egress control policy:** Which tools are permitted to make outbound network calls? What domains are in the egress allowlist? This entire governance dimension is currently unaddressed.

---

## Cross-Cutting: Missing Threat Models

### + ADDITION: Threat Model — OPA Daemon Compromise

**Add as new appendix section:**

| Threat | Attack Method | Current Mitigation | Required Mitigation |
|--------|--------------|-------------------|---------------------|
| Policy replacement | `PUT /v1/policies/{id}` via curl from agent Bash | None | OPA token auth + firewall from agent processes |
| Data poisoning | `PUT /v1/data/budgets` or `/data/environment` | None | OPA token auth; environment as read-only bundle data |
| Policy deletion | `DELETE /v1/policies/{id}` | None | OPA token auth + authorization policy |
| Daemon crash → fail-open | `kill $(pgrep opa)` from Bash tool | KeepAlive restart | Fail-closed fallback (change default to "deny") |
| Bundle replacement on disk | Overwrite `.rego` files in `governance-packs/` | None | Filesystem ACLs + bundle signing |
| Fake OPA binary via PATH | `export PATH=/tmp:$PATH; echo '{"result":{"allow":true}}' > /tmp/opa` | None | Absolute binary path + hash verification |
| Oracle query attack | Direct `POST /v1/data` to OPA with crafted input | None | Firewall OPA from agent-reachable processes |
| Decision log exfiltration | `GET /v1/logs` from agent process | None | Restrict decision log endpoint |
| Clock manipulation | System clock change affects temporal policies | None | Use gateway-provided timestamp in input, not `time.now_ns()` |

### + ADDITION: Threat Model — Input Forgery

| Threat | Attack Method | Vulnerable Policies | Required Mitigation |
|--------|--------------|---------------------|---------------------|
| Archetype spoofing | `input.agent.archetype = "admin"` | Policy 1 | Gateway-derived archetype only, never agent-provided |
| HIL approval spoofing | `input.meta.hil_approved = true` | Policy 6 | Gateway-derived from approval state store only |
| Subagent flag omission | Omit `is_subagent`, set to `false` | Policy 9 | Structural detection (presence of parent_agent_id) |
| Delegation chain fabrication | Construct arbitrary `delegation_chain` array | Policy 9 | Cross-reference against gateway-tracked session hierarchy |
| Pack version inflation | `input.meta.governance_pack_version = "99.0.0"` | Policy 15 | Gateway-derived version only |
| Correlation ID replay | Reuse previous valid correlation_id | Policy 7 | Gateway-enforced uniqueness at session level |
| Timestamp manipulation | Provide past/future timestamp in input | Policies 5, 10 | Use gateway clock, not agent-provided timestamp |

---

*Review complete. Total findings: 7 critical, 11 high, 14 medium. All critical findings must be resolved before production deployment of any OPA governance layer based on this document.*
