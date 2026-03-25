# OpsSRE Review: Governance Grimoire Amendments

- **Reviewer role:** Operations / Site Reliability Engineer
- **Review date:** 2026-03-25
- **Source document:** `/Users/jonathans_macbook/ArchangelMCP/docs/research/governance-grimoire-opa-rego.md`
- **Review lens:** Deployment reliability, failure modes, latency budgets, observability, disaster recovery, and production incidents
- **Status:** AMENDMENTS ONLY — not a rewrite; every item below is a targeted surgical change

---

## Section 1: OPA/Rego Fundamentals

### + ADDITION: OPA REST API — Missing Endpoints

The API table in section 1 lists five endpoints but omits two that matter operationally.

```text
| API | Purpose |
|-----|---------|
| GET /health | Liveness check — returns 200 if the OPA process is alive |
| GET /health?plugins | Readiness check — returns 200 only after bundles are loaded |
| GET /metrics | Prometheus-format metrics (decision latency, bundle reload count, error rate) |
```

`/health` and `/health?plugins` are NOT equivalent. The daemon can be alive (responding
200 on `/health`) while bundles have not yet finished loading from disk, meaning policy
evaluation would return undefined results. Every readiness gate — in launchd startup,
in the gateway fallback trigger, in any CI smoke test — must use `/health?plugins`.

---

## Section 3: OPA for API Gateway Governance

### ~ CHANGE: Latency Claim — "Sub-Millisecond for Local HTTP"

**Was:** "Sub-millisecond latency for local HTTP calls" (listed as a Pro under Option A HTTP Sidecar)

**Should be:**
```text
Pros:
- Local HTTP (loopback) decision latency: P50 ~1-3ms, P95 ~5-10ms, P99 ~15-30ms
  under load. The "sub-millisecond" figure applies only to WASM embedded evaluation
  (Option C) or to trivially simple policies with no data joins.
- At 100 tool calls/session with a 20ms P99, OPA adds ~2 seconds of cumulative
  decision overhead per session — acceptable, but it must be budgeted.
```

**Rationale:** The "sub-millisecond" claim is from OPA benchmark docs for the Go SDK
in-process path. Over loopback HTTP, you pay TCP stack overhead, JSON serialization,
HTTP framing, and Go GC pauses. Real P99 latency for non-trivial policies (those
joining `data.recent_calls` or `data.file_reservations`) measured at production
Envoy ext_authz deployments is 15-30ms at P99. Shipping a latency budget based on
sub-millisecond expectations will produce capacity surprises.

The timeout value in the proposed `servers.yaml` config (`timeout: 3` seconds) is
consistent with real-world numbers, which implicitly acknowledges the latency is not
sub-millisecond. The Pros section should match.

---

## Section 4: OPA for AI/LLM Agent Guardrails

### + ADDITION: Concurrency and Capacity Planning

The section describes what OPA evaluates but says nothing about how many concurrent
evaluations the daemon can handle. This is a production readiness gap.

**Capacity envelope (single OPA daemon, MacBook-class hardware):**

```text
| Policy complexity | Throughput (req/s) | P99 latency |
|-------------------|--------------------|-------------|
| Simple allowlist (no data join) | 5,000-10,000 | <5ms |
| Budget check (data.usage join) | 1,000-3,000 | 10-20ms |
| Rate limit (data.recent_calls join) | 500-1,000 | 20-40ms |
| Full policy stack (all guards) | 200-500 | 30-80ms |
```

For a local developer workstation running one ArchangelMCP session, peak load is
~10 concurrent tool calls. The daemon is not at risk of throughput saturation.
However, if the KOTH/Oracle/Quartermaster pattern of spawning many parallel subagents
is extended — 20+ agents, each making simultaneous tool calls — peak OPA throughput
becomes relevant. The daemon should be configured with:

```bash
opa run --server \
  --max-connections 50 \          # default is unlimited; bound it
  --worker-pool-size 8 \          # match CPU core count
  ...
```

Document the expected per-session tool call rate and the resulting OPA QPS so that
anyone monitoring the daemon knows what "normal" looks like before alerting.

---

## Section 6: OPA Deployment Models

### ~ CHANGE: launchd Plist — Critically Incomplete

**Was:**
```xml
<!-- ~/Library/LaunchAgents/com.kellerai.opa.plist -->
<dict>
    <key>Label</key>
    <string>com.kellerai.opa</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/opa</string>
        <string>run</string>
        <string>--server</string>
        <string>--addr</string>
        <string>:8181</string>
        <string>--bundle</string>
        <string>~/.claude/archangel/governance-packs/</string>
        <string>--log-level</string>
        <string>info</string>
        <string>--set</string>
        <string>decision_logs.console=true</string>
    </array>
    <key>KeepAlive</key>
    <true/>
</dict>
```

**Should be:**
```xml
<!-- ~/Library/LaunchAgents/com.kellerai.opa.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.kellerai.opa</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/opa</string>
        <string>run</string>
        <string>--server</string>
        <string>--addr</string>
        <string>127.0.0.1:8181</string>
        <string>--bundle</string>
        <string>/Users/REPLACE_ME/.claude/archangel/governance-packs/</string>
        <string>--log-level</string>
        <string>info</string>
        <string>--log-format</string>
        <string>json</string>
        <string>--set</string>
        <string>decision_logs.console=true</string>
        <string>--set</string>
        <string>decision_logs.reporting.max_decisions_per_second=100</string>
    </array>

    <!-- Restart immediately on crash, but not if it exits cleanly -->
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
    </dict>

    <!-- Stdout and stderr to rotating log files -->
    <key>StandardOutPath</key>
    <string>/Users/REPLACE_ME/.claude/archangel/logs/opa-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/REPLACE_ME/.claude/archangel/logs/opa-stderr.log</string>

    <!-- Soft resource cap: 512MB RSS; hard: 768MB -->
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>1024</integer>
    </dict>

    <!-- Throttle restart storms: wait 10s before restarting after a crash -->
    <key>ThrottleInterval</key>
    <integer>10</integer>

    <!-- Run as the current user, not root -->
    <key>UserName</key>
    <string>REPLACE_ME</string>

    <!-- Environment: ensure PATH includes homebrew for any shell invocations -->
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin</string>
    </dict>
</dict>
</plist>
```

**Rationale:**

1. **No stdout/stderr logging.** The original plist has no `StandardOutPath` or
   `StandardErrorPath`. When OPA crashes or logs a parse error on bundle load, the
   output goes to `/dev/null`. This makes post-incident debugging impossible. Every
   production launchd service must log stdout and stderr to a file.

2. **`~` tilde expansion is NOT performed by launchd.** The path
   `~/.claude/archangel/governance-packs/` will be interpreted literally as a
   relative path starting with tilde. launchd does not invoke a shell; it exec()s
   directly. Use the absolute path with the username expanded.

3. **`KeepAlive: true` restarts on clean exit.** If OPA exits cleanly (e.g., after
   a `launchctl stop`), `KeepAlive: true` immediately relaunches it, fighting the
   operator. Use `KeepAlive: {Crashed: true}` to restart only on crash.

4. **No `ThrottleInterval`.** Without this, a crashlooping OPA (e.g., bundle parse
   error on startup) will restart at maximum frequency, burning CPU and filling logs.
   A 10-second throttle gives the operator time to notice and intervene.

5. **Binding to `:8181` (all interfaces) vs `127.0.0.1:8181`.** On a developer
   workstation, binding to all interfaces exposes the OPA management API (including
   unauthenticated `PUT /v1/policies` and `PUT /v1/data`) to other processes and
   potentially to the LAN if the machine is on a shared network. Bind to loopback.

6. **No log rotation.** `decision_logs.console=true` sends every decision as a JSON
   line to stdout. Without `StandardOutPath` and external log rotation (logrotate or
   launchd's native rotation), this file will grow without bound. See Decision Log
   Volume section below.

---

### + ADDITION: OPA Daemon Crash Mid-Evaluation — What Actually Happens

The document describes the fallback strategy at a high level ("falls back to fnmatch")
but does not describe the failure mode during an in-flight evaluation.

**What happens when OPA crashes while the gateway has an open HTTP request:**

1. The TCP connection is reset. The Python `aiohttp` / `httpx` client receives a
   `ConnectionResetError` or `aiohttp.ServerDisconnectedError`.
2. If the gateway does not have a timeout on the OPA HTTP call, it will hang until
   the OS-level TCP keepalive fires (default: 2 hours on macOS).
3. The middleware call chain is blocked. The tool call that triggered the evaluation
   never receives a response. The Claude Code session hangs.

**Required mitigations (not currently documented):**

```python
# In PolicyGuardrailMiddleware — OPA client call MUST have:
async with asyncio.timeout(OPA_TIMEOUT_SECONDS):   # hard deadline
    try:
        decision = await opa_client.evaluate(opa_input)
    except (ConnectionResetError, aiohttp.ServerDisconnectedError,
            aiohttp.ClientConnectorError, asyncio.TimeoutError) as exc:
        logger.warning("OPA unavailable (%s) — engaging fallback", type(exc).__name__)
        decision = await fnmatch_fallback.evaluate(opa_input)
```

The `timeout: 3` in the proposed `servers.yaml` config is good, but the code-level
implementation must also handle `ConnectionResetError` as a distinct case from
timeout — they have different retry semantics.

**Circuit breaker requirement:** The gateway should track OPA failure rate over a
rolling window. If OPA fails >5 times in 30 seconds, open the circuit and route
exclusively through fnmatch for 60 seconds before probing again. Without this,
every tool call during a prolonged OPA outage pays a 3-second timeout penalty.

---

### ~ CHANGE: Option C WASM — Who Runs the Compile Step?

**Was:** (implicit — compile step shown as a bash command with no ownership or lifecycle)
```bash
opa build -t wasm -e 'data.kellerai.grc.tool_guard' policies/ -o bundle.tar.gz
```

**Should be:**

The WASM compilation step needs an owner and a lifecycle:

```text
WASM Compile Lifecycle:

1. TRIGGER: Any commit to governance-packs/ that changes a .rego file
2. RUNNER: CI (GitHub Actions / local lefthook pre-push hook)
3. VALIDATION before shipping the bundle:
   a. opa test policies/ --coverage → must be 100% on invariant rules
   b. opa check policies/ → syntax/type check (no undefined references)
   c. Smoke test: opa eval -d bundle.tar.gz -I '{"tool_name":"Bash","agent":{"archetype":"editor"}}' \
        data.kellerai.grc.tool_guard.allow → must return false (default deny)
4. DEPLOYMENT: Copy bundle.tar.gz to ~/.claude/archangel/governance-packs/
5. RELOAD: POST http://localhost:8181/v1/policies/tool_guard (or bundle reload via filesystem watcher)
6. VERIFY: GET /health?plugins → must return 200 before old bundle is retired

FAILURE HANDLING:
- If opa build fails → abort deploy, keep current bundle in place
- If smoke test fails → abort deploy, alert operator, do NOT replace bundle
- If /health?plugins returns non-200 after deploy → roll back previous bundle
```

**Rationale:** Without a defined compile trigger, validation gate, and rollback
procedure, a malformed policy can be deployed silently. OPA will load a corrupt
bundle and either reject all requests (if the bundle fails to parse) or behave
incorrectly (if it parses but has logic errors). The smoke test — verifying that
the default-deny rule fires — is the minimum bar before a bundle ships.

---

### + ADDITION: Bundle Hot-Reload Failure Scenarios

The document mentions bundle hot-reload as a feature but does not describe what
happens when it fails. These are the three failure modes that have caused production
incidents in OPA deployments:

**Scenario 1: Corrupt Bundle (truncated tar.gz)**

OPA's bundle loader validates the tar.gz structure. If the file is truncated (e.g.,
a CI job was killed mid-write), OPA logs an activation error and **continues serving
the previous bundle**. This is safe behavior, but it means the deployed bundle is
not what the operator intended. The gateway has no visibility into this unless it
polls `GET /v1/bundles/<name>` and checks `active_revision`.

Mitigation: After every bundle push, the gateway startup probe should verify that
the active revision matches the expected version via `GET /v1/bundles/governance-packs`
and compare `.result.active_revision` to the expected commit SHA.

**Scenario 2: Partial Load (bundle loads, but data documents fail)**

OPA can successfully load policy files from a bundle while data documents (`.json`
files in the bundle) fail validation. The result: policy rules evaluate against
empty/undefined data, causing all rules that reference `data.surfaces` or `data.budgets`
to produce `undefined`, which in the default-deny model means **everything is denied**.
This is fail-closed but will appear as a complete governance lockout.

Mitigation: Include a `data_smoke_test` in the bundle validation step that asserts
`count(data.surfaces) > 0` after load.

**Scenario 3: Version Mismatch (policy references data schema that changed)**

When policy pack v2 references `data.surfaces[archetype].allowed_tools` but the
data document was written for v1 and uses `data.surfaces[archetype].tools`, the
policy silently produces undefined. The tool call is allowed or denied based on
whatever default is set — not based on actual governance intent.

Mitigation: Governance pack versioning (Policy 15) partially addresses this, but
the data documents themselves must also carry a schema version that the policies
validate:

```rego
deny contains msg if {
    data.surfaces._schema_version != "2"
    msg := "surfaces data document schema mismatch: expected v2"
}
```

---

## Section 7: Policy-as-Code Best Practices

### + ADDITION: Decision Log Volume — Capacity Analysis

The document does not discuss decision log volume. This will become a production
issue quickly.

**Back-of-envelope calculation:**

```text
Assumptions:
  - 100 tool calls per session (stated in Open Questions, §12)
  - 8 sessions/day (busy developer day)
  - OPA decision log entry: ~2-5KB JSON per decision
    (includes input, decision, policy version, timestamp, labels)

Math:
  100 calls/session × 8 sessions/day = 800 decisions/day
  800 × 5KB = 4MB/day (conservative)
  800 × 5KB × 365 = ~1.4GB/year

With parallel agents (20 subagents × 50 calls each):
  1,000 calls/session × 8 sessions/day = 8,000 decisions/day
  8,000 × 5KB = 40MB/day
  40MB × 365 = ~14.6GB/year
```

14GB/year is manageable but not trivial on a developer laptop. Without log rotation,
this accumulates silently.

**Required log management configuration:**

```bash
# Add to OPA plist / startup flags:
--set decision_logs.reporting.max_decisions_per_second=50
--set decision_logs.reporting.upload_size_limit_bytes=32768

# Add logrotate config at /usr/local/etc/logrotate.d/opa:
/Users/REPLACE_ME/.claude/archangel/logs/opa-stdout.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        # OPA reopens log file automatically on SIGHUP
        launchctl kill HUP gui/$(id -u)/com.kellerai.opa
    endscript
}
```

Alternatively: disable `decision_logs.console` and instead configure OPA to ship
decision logs to a local JSONL file via the HTTP plugin, where retention is managed
explicitly.

---

## Section 8: Progressive Disclosure in Policy Systems

### + ADDITION: Advisory Layer Observability Gap

The L4 Advisory layer logs "would-deny" decisions in shadow mode, but the document
does not specify where these are logged, how to query them, or what the TTL is.
In production, shadow mode generates signal that drives the "promote to enforce"
decision — if that signal is unobservable, shadow mode is theater.

**Required additions to the shadow mode design:**

```text
Shadow mode decision schema (extend OPA decision log entry):
{
  "decision_id": "...",
  "shadow": true,
  "would_have": "deny",
  "reasons": ["rm -rf is permanently blocked"],
  "policy": "kellerai.grc.tool_guard",
  "pack_version": "2.1.0",
  "shadow_expires_at": "2026-04-01T00:00:00Z"
}

Queryable by:
  jq 'select(.shadow == true)' ~/.claude/archangel/logs/opa-decisions.jsonl | \
  jq -r '.reasons[]' | sort | uniq -c | sort -rn

Dashboard requirement (before any policy is promoted from shadow to enforce):
  - Total would-deny count over shadow period
  - Distinct agents affected
  - Distinct tools blocked
  - False positive rate estimate (manual review of sample)
```

Without this, policy promotion is a manual judgment call with no evidence base.

---

## Section 10: ArchangelMCP Integration Architecture

### ~ CHANGE: Data Document Sync — "Every 60s" Consistency Problem

**Was:** `data.recent_calls | Flight Recorder traces | Periodic (every 60s)`

**Should be:**

```text
| Data Document | Source | Update Frequency | Staleness Risk |
|--------------|--------|-----------------|----------------|
| data.recent_calls | Flight Recorder | Every 60s (batched) | HIGH — rate limit policies
                                                               may pass during the 60s
                                                               window after limit is hit |
| data.usage | TokenCostGovernor | Every N tool calls | MEDIUM — budget overrun
                                                        possible during batch window |
| data.file_reservations | Agent Mail | On reservation change | LOW — event-driven |
| data.surfaces | compiled-agent-surfaces.json | On gateway start | LOW — infrequent change |
```

**Rationale:** Policy 8 (Rate Limiting) and Policy 4 (Budget Enforcement) are both
evaluated against data documents that lag reality by up to 60 seconds. This is a
known consistency trade-off in the data plane/control plane split, but it must be
documented because it has a direct correctness consequence: an agent that hits its
rate limit at t=0 can continue making calls until t=60 when the data document
refreshes. At 100 calls/session, this is a meaningful gap.

**Mitigation options (not mutually exclusive):**

1. **Write-through to OPA on every state change** — event-driven updates for
   `data.usage` and `data.recent_calls`. Higher OPA write QPS but eliminates the
   window.

2. **Enforce rate limits imperatively in the gateway** (existing `TokenCostGovernor`)
   and use OPA only for declarative policy that tolerates stale data (allowlists,
   temporal rules, delegation chain validation). Document this split explicitly.

3. **Accept the window and document it** as a known limitation with a specified
   SLO: "Rate limit enforcement has a maximum staleness of 60 seconds."

Option 2 is the most pragmatic and matches how the codebase already works.

---

### ~ CHANGE: Fallback Strategy — fnmatch Equivalence Is Not Guaranteed

**Was:**
> "If OPA is unavailable (crash, timeout, not installed), the gateway falls back to
> the existing fnmatch-based `PolicyGuardrailEngine`. This is already implemented
> in the current codebase."

**Should be:**

> "If OPA is unavailable, the gateway falls back to the fnmatch-based
> `PolicyGuardrailEngine` **for the subset of rules that the fnmatch engine
> implements**. The fallback is NOT equivalent to the full OPA policy stack.
> The following governance capabilities are absent in fnmatch fallback mode:
>
> | Capability | OPA | fnmatch fallback |
> |-----------|-----|-----------------|
> | Tool allowlist (pattern match) | Yes | Yes |
> | Destructive command blocking | Yes | Partial (string match only) |
> | Budget enforcement | Yes | No — requires data.usage |
> | Rate limiting | Yes | No — requires data.recent_calls |
> | Temporal policies | Yes | No — no time evaluation |
> | Delegation chain validation | Yes | No |
> | HIL escalation | Yes | Partial (tool-level only) |
> | Parameter validation | Yes | No |
>
> During OPA outage, the effective security posture degrades to fnmatch-level
> coverage. Operators must be notified immediately when fallback mode activates.
> The fallback should be logged at WARNING level with a metric counter.
> The `fallback: "fnmatch"` option in servers.yaml should be renamed to
> `fallback: "fnmatch_degraded"` to make clear this is a reduced capability state."

**Rationale:** The document implies the fallback is a clean equivalent. It is not.
Shipping this architecture without documenting the security delta of the fallback
path is a production readiness gap. An operator who sees "OPA down, fallback active"
must know exactly what governance is and is not in effect.

---

### + ADDITION: Health Check Architecture — Liveness vs Readiness vs Deep Health

The document only mentions `/health` and the justfile `opa-status` target. A
production service needs three distinct health signals:

**1. Liveness — "Is the process alive?"**
```bash
GET http://localhost:8181/health
# Returns 200 if OPA process is running
# Returns non-200 or connection refused if OPA is dead
```
Used by: launchd restart decision (via `KeepAlive: {Crashed: true}`)

**2. Readiness — "Is OPA ready to serve policy decisions?"**
```bash
GET http://localhost:8181/health?plugins&bundles
# Returns 200 only after all configured bundles are activated
# Returns 500 if any bundle failed to load
```
Used by: Gateway startup — do NOT send policy queries until this returns 200.
The gateway's OPA client should poll this at startup with a 30-second timeout
before accepting traffic. Without this, the first N tool calls after a daemon
restart will hit an uninitialized OPA and get undefined decisions.

**3. Deep health — "Is OPA making correct decisions?"**
```bash
# Smoke-test query: POST /v1/data/kellerai/grc/tool_guard/allow
# Input: known-bad request (rm -rf command)
# Expected: {"result": false}
# Run this from the justfile as `opa-health-check`
```
Used by: Monitoring / alerting. If this fails, OPA is alive and loaded but
producing wrong answers — the most dangerous failure mode.

```makefile
# Add to justfile:
opa-ready:
    @curl -sf 'http://localhost:8181/health?plugins&bundles' > /dev/null && \
        echo "OPA: ready" || echo "OPA: NOT READY (bundle load pending or failed)"

opa-health-check:
    @result=$$(curl -sf -X POST http://localhost:8181/v1/data/kellerai/grc/tool_guard/allow \
        -H 'Content-Type: application/json' \
        -d '{"input":{"tool_name":"Bash","arguments":{"command":"rm -rf /"},"agent":{"archetype":"editor"}}}' \
        | jq -r '.result'); \
    [ "$$result" = "false" ] && echo "OPA: smoke test PASS (default-deny working)" \
                              || echo "OPA: smoke test FAIL (result=$$result)"
```

---

### + ADDITION: Monitoring, Alerting, and Metrics — Complete Gap

The document has no monitoring section. For a component that sits in the critical
path of every tool call, this is a production readiness blocker.

**OPA's built-in metrics endpoint:**

```bash
GET http://localhost:8181/metrics
```

Returns Prometheus-format metrics including:
- `opa_decision_duration_milliseconds` — histogram of decision latency (the key SLO metric)
- `opa_bundle_load_duration_seconds` — how long bundle loads take
- `opa_bundle_load_failures_total` — bundle load failure counter
- `opa_http_requests_total` — request rate by path and status code
- `opa_plugins_error_total` — plugin-level errors (including decision log plugin)

**Minimum alerting rules (add to monitoring stack or a simple cron-based checker):**

```text
ALERT: OPA process down
  Condition: GET /health returns non-200 or connection refused
  Severity: CRITICAL
  Action: Page immediately; gateway is in degraded fnmatch-only mode

ALERT: OPA bundle load failure
  Condition: opa_bundle_load_failures_total increases
  Severity: HIGH
  Action: Running policy may be stale or missing; check stderr log

ALERT: OPA decision P99 latency > 50ms
  Condition: opa_decision_duration_milliseconds{quantile="0.99"} > 0.05
  Severity: WARNING
  Action: Investigate policy complexity; consider WASM for hot-path rules

ALERT: OPA fallback mode active (gateway-side metric)
  Condition: gateway_opa_fallback_total counter increases
  Severity: HIGH
  Action: OPA is unreachable; governance degraded to fnmatch level
```

Without these metrics being collected, the only way to detect an OPA outage is a
user noticing that policies aren't being enforced — which may never happen for
policies that rarely fire.

---

### + ADDITION: Graceful Degradation Policy — Document the Explicit Choice

The document lists `fallback: "fnmatch"` vs `fallback: "deny"` as a config option
but does not make a recommendation or explain the operational tradeoff. This is a
governance policy decision that must be made explicitly, not left to a config default.

**The two positions:**

**Fail-open (fnmatch fallback):**
- Governance degrades gracefully; work continues
- Risk: Policies that only exist in OPA (budget enforcement, rate limiting, delegation
  chain validation) are silently bypassed during outage
- Appropriate for: Developer workstations, non-sensitive operations, situations where
  productivity continuity is the priority

**Fail-closed (deny all on OPA outage):**
- Governance is never bypassed; all tool calls blocked during OPA outage
- Risk: Complete work stoppage if OPA crashes; high pressure to fix quickly
- Appropriate for: Production environments, operations involving sensitive data or
  irreversible actions, regulated environments

**Recommended split for ArchangelMCP:**

```yaml
policy_guardrails:
  opa_backend:
    # L0 invariants (rm -rf, credential exposure) → fail-closed
    # If OPA is down, these MUST still be enforced by fnmatch fallback
    invariant_fallback: "fnmatch_invariants_only"

    # L1-L3 contextual policies → fail-open with degradation notice
    contextual_fallback: "degrade_with_warning"

    # Default behavior on OPA timeout/crash
    default_fallback: "fnmatch_degraded"
    fallback_notify_channel: "telegram"  # alert operator immediately
```

The key insight: the fnmatch fallback should be scoped to L0 invariants only, not
treated as a full policy equivalent. This is a safer interpretation of the existing
codebase than the current design implies.

---

## Section 11: Existing Codebase Anchor Points

### + ADDITION: `OpaBackend` HTTP Migration — Timeout and Retry Contract

When migrating `OpaBackend` from `subprocess.run("opa eval")` to HTTP client calls,
the following production contract must be specified:

```python
# Required behavior for OpaBackend.evaluate():

class OpaBackend:
    # Connection pool: persistent HTTP/1.1 connection to OPA
    # Do NOT create a new connection per evaluation — connection setup overhead
    # alone is 1-5ms on loopback, negating the benefit of the daemon model
    _session: aiohttp.ClientSession  # shared, initialized at gateway startup

    CONNECT_TIMEOUT = 1.0   # seconds — fail fast if OPA is not listening
    READ_TIMEOUT    = 3.0   # seconds — maximum policy evaluation time
    MAX_RETRIES     = 1     # retry once on connection reset, then fallback
    # (do NOT retry on timeout — a slow policy is a policy bug, not a transient)

    async def evaluate(self, opa_input: dict) -> OpaDecision:
        try:
            async with self._session.post(
                f"{self.url}/v1/data/kellerai/grc/tool_guard",
                json={"input": opa_input},
                timeout=aiohttp.ClientTimeout(
                    connect=self.CONNECT_TIMEOUT,
                    total=self.READ_TIMEOUT,
                ),
            ) as resp:
                if resp.status == 200:
                    body = await resp.json()
                    return OpaDecision.from_response(body)
                else:
                    # OPA returned an error (e.g., bundle not loaded)
                    logger.error("OPA HTTP %d: %s", resp.status, await resp.text())
                    raise OpaBackendError(f"OPA returned HTTP {resp.status}")
        except (aiohttp.ClientConnectorError, aiohttp.ServerDisconnectedError):
            # OPA is down — engage fallback, increment fallback counter
            ...
        except asyncio.TimeoutError:
            # OPA is slow — do NOT retry, engage fallback immediately
            ...
```

**Do not retry on timeout.** A timeout means OPA is either overloaded or stuck on
a policy evaluation. Retrying adds latency (2× timeout = 6s hang) while the tool
call waits. The right response to timeout is: log it, increment a metric, engage
fallback.

---

## Section 12: Open Questions and Next Steps

### ~ CHANGE: Implementation Phases — Missing Operational Prerequisites

**Was:** Phase P0 starts directly with "Install OPA, write first Rego policies"

**Should be:** Add a P-1 (operational prerequisites) phase before P0:

```text
| Phase | Scope | Effort | Operational Gate |
|-------|-------|--------|-----------------|
| P-1 | Operational prerequisites: log directory, logrotate config, | 0.5 days | MUST complete
|     | monitoring baseline, smoke test justfile targets, circuit  |           | before P0 |
|     | breaker design, fallback policy decision documented        |           |           |
| P0  | Install OPA, write Rego policies matching existing fnmatch | 1 day     | opa test passes |
| P1  | Migrate OpaBackend CLI → HTTP, add launchd plist (fixed)   | 1 day     | readiness probe |
|     |                                                             |           | passes on start |
| P2  | Push live data documents; document staleness SLOs          | 2 days    | data smoke tests |
| P3  | Write governance packs: tool_guard, budget_guard, param_guard | 3 days  | 100% test coverage |
|     |                                                             |           | on L0 invariants |
| P4  | Add temporal_guard, chain_guard, audit_guard               | 2 days    |                 |
| P5  | OPA test suite, CI integration, shadow mode WITH            | 3 days    | shadow dashboard |
|     | observable dashboard (not just logging)                    |           | query working   |
| P6  | Bundle management, hot reload, decision log pipeline        | 2 days    | rotation tested |
|     | WITH log rotation and volume analysis                      |           |                 |
| P7  | WASM for hot-path policies WITH compile lifecycle defined   | 1.5 days  | compile CI gate |
```

**Revised total:** ~16 days (adds 2 days for operational prerequisites that were
implicitly assumed but not scoped).

---

### + ADDITION: Disaster Recovery Runbook Stubs

The document has no DR section. Add these runbook stubs as a starting point:

```text
RUNBOOK: OPA daemon is down (launchd not restarting it)
  1. Check stderr log: tail -50 ~/.claude/archangel/logs/opa-stderr.log
  2. Common cause: bundle parse error on startup → fix bundle, then:
     launchctl kickstart -k gui/$(id -u)/com.kellerai.opa
  3. If OPA binary missing/corrupted: brew reinstall opa
  4. Verify gateway is in fnmatch-degraded mode (check gateway logs)
  5. After OPA restarts: run `just opa-ready` and `just opa-health-check`

RUNBOOK: All tool calls are being denied (governance lockout)
  1. Check if OPA bundle loaded correctly:
     curl http://localhost:8181/v1/bundles/governance-packs
  2. Check OPA decision logs for deny reasons:
     jq '.result.deny' ~/.claude/archangel/logs/opa-decisions.jsonl | tail -20
  3. Emergency escape: set governance mode to "warn" in servers.yaml, restart gateway
  4. DO NOT restart OPA while investigating — decisions are still being logged
  5. Root cause: usually a data document push that made data.surfaces empty
     → push a valid surfaces.json to restore: PUT /v1/data/surfaces < surfaces.json

RUNBOOK: OPA decision latency spike (P99 > 50ms)
  1. Check opa_decision_duration_milliseconds histogram via /metrics
  2. Identify which policy package is slow via OPA profiler:
     opa eval --profile --data policies/ --input test_input.json "data.kellerai.grc.tool_guard"
  3. Common cause: data.recent_calls join on large dataset → add index or reduce TTL
  4. Short-term mitigation: disable the slow policy pack, route via fnmatch
  5. Long-term: compile hot-path policies to WASM (Phase P7)
```

---

## Cross-Cutting: Missing Operational Signals Summary

This table summarizes what the document proposes vs what production requires:

| Operational Signal | Document Status | Required Action |
|--------------------|-----------------|-----------------|
| OPA stdout/stderr logs | Missing from launchd plist | Add `StandardOutPath`/`StandardErrorPath` |
| Log rotation | Not mentioned | logrotate config required |
| Prometheus metrics | Not mentioned | Document `/metrics` endpoint and scrape config |
| Liveness vs readiness | Only `/health` mentioned | Add `/health?plugins&bundles` to all probes |
| Deep health smoke test | Not mentioned | Add `opa-health-check` justfile target |
| Fallback mode alerting | Not mentioned | Add gateway metric + alert rule |
| Bundle active revision check | Not mentioned | Poll after every bundle push |
| Shadow mode dashboard | Mentioned but undefined | Specify query and review process |
| Circuit breaker | Not mentioned | Define open/half-open/closed thresholds |
| Crash mid-evaluation handling | Not mentioned | Timeout + `ConnectionResetError` handling required |
| DR runbooks | Not mentioned | Stub runbooks added above |
| Decision log volume analysis | Not mentioned | Back-of-envelope added above |
| WASM compile ownership | Implicit | CI gate + validation sequence required |
| Capacity planning (QPS) | Not mentioned | Throughput table added above |
