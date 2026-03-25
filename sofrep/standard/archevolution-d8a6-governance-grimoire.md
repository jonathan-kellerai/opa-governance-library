# ArchEvolution Review: Governance Grimoire Amendments

- **Reviewer:** ArchEvolution (Systems Architecture Lens)
- **Document under review:** `ArchangelMCP/docs/research/governance-grimoire-opa-rego.md`
- **Review date:** 2026-03-25
- **Codebase snapshot:** `src/archangel/policy_guardrails.py`, `agent_surface_policy.py`, `cost_governor.py`, `middleware/*.py`, `gateway.py`

---

## Scoring Summary

| Dimension | Score | Notes |
|-----------|-------|-------|
| Codebase accuracy | 6/10 | Several anchor-point claims are wrong or missing |
| Architecture coherence | 7/10 | Diagram is directionally correct but misses two middleware layers |
| Migration realism | 4/10 | "Drop-in" claim is materially false; significant breaking changes |
| Package decomposition | 6/10 | 7 packages is the wrong cut; 3 of them duplicate existing Python |
| Phase plan realism | 3/10 | 14 days for full governance grimoire is hallucinatory |
| Data freshness model | 5/10 | Staleness problem acknowledged but consistency model unspecified |

---

## Section 10: Existing Codebase Anchor Points (Primary Concern)

### ~ CHANGE: PolicyGuardrailEngine Description is Misleading

**Was:**
> `PolicyGuardrailEngine` — Exists — fnmatch rules + OPA fallback

**Should be:**
> `PolicyGuardrailEngine` — Exists — fnmatch rules as **primary** path, OPA as **opt-in secondary** path (disabled by default). The engine is a full stateful system with in-memory `ApprovalTicket` store, `PolicyDecision` audit history (ring-buffer, configurable max), and separate `warn`/`enforce` modes. OPA is only consulted when `opa_backend.enabled: true` AND `active_packs` is non-empty in config. The default installed state has OPA entirely inactive.

**Rationale:** The grimoire makes OPA sound like the fallback, but the code at `policy_guardrails.py:371-419` shows the opposite: fnmatch is the primary path; OPA is reached only when `self._opa_backend and self._active_packs` are both truthy. This matters for migration planning — the "drop-in replacement" framing presupposes OPA is already primary. It is not. It is not even enabled by default.

---

### ~ CHANGE: OpaBackend Is CLI-Only, Not HTTP-Capable

**Was:**
> `OpaBackend` class (line 120): Replace CLI `subprocess.run("opa eval")` with HTTP client calls to `POST /v1/data/kellerai/grc/tool_guard`.

**Should be:**
> The current `OpaBackend` (`policy_guardrails.py:120-182`) uses `subprocess.run(["opa", "eval", "-d", str(self._policies_dir), "-i", "/dev/stdin", "--format", "raw", "data.kellerai.grc.tool_guard"])` — a process-per-evaluation CLI invocation. It has **no HTTP client capability whatsoever**. The migration to HTTP is a complete class rewrite, not a parameter change. The existing class must be replaced (or subclassed) with an async HTTP client using `httpx.AsyncClient`. This is not a drop-in replacement.

**Rationale:** The grimoire's Section 11 uses the phrase "drop-in replacement" twice and frames the HTTP migration as a minor change. The actual delta is: delete subprocess logic, add `httpx` dependency, rewrite `evaluate()` from sync to async, handle HTTP errors, add connection pooling, add health-check ping on startup. Each of these is a non-trivial surface change in a hot path.

---

### + ADDITION: The OpaBackend Input Schema Is Missing Three Required Fields

The current `OpaBackend.evaluate()` builds this input document (`policy_guardrails.py:154-157`):

```python
opa_input = {
    "tool_name": tool_name,
    "arguments": arguments,
    "active_packs": active_packs,
}
```

The grimoire's proposed Rego policies (Sections 4 and 5) reference these input fields that are **absent from the current schema**:

| Missing Field | Used By | Grimoire Reference |
|--------------|---------|-------------------|
| `input.agent.archetype` | Policy 1 (tool allowlist), Policy 6 (escalation) | §5 Policy 1 |
| `input.agent.name` | Policy 7 (audit trail), Policy 9 (delegation chain) | §5 Policy 7 |
| `input.agent.budget_scope` | Policy 4 (budget enforcement) | §5 Policy 4 |
| `input.agent.is_subagent` | Policy 9 (delegation chain) | §5 Policy 9 |
| `input.meta.correlation_id` | Policy 7 (audit trail) | §5 Policy 7 |
| `input.meta.parent_agent_id` | Policy 9 (delegation chain) | §5 Policy 9 |
| `input.meta.delegation_chain` | Policy 9 (delegation chain) | §5 Policy 9 |
| `input.meta.hil_approved` | Default-deny pattern | §2 Default-deny |
| `input.meta.governance_pack_version` | Policy 15 (versioning) | §5 Policy 15 |

The archetype information exists on the request — `AgentSurfaceGuardMiddleware` extracts it at `agent_surface.py:186-187` from `meta["agent_archetype"]` — but `PolicyGuardrailMiddleware` currently does not forward it to `OpaBackend.evaluate()`. Wiring these fields requires modifying the `PolicyGuardrailMiddleware.on_call_tool()` method to pass agent identity from request context into `OpaBackend.evaluate()`, and the method signature must be extended. This is a breaking change to `OpaBackend.evaluate()`'s signature.

---

### ~ CHANGE: AgentSurfacePolicy Catalog Reload Is Not a Push — It Is a Pull

**Was:**
> `AgentSurfacePolicy` (line 47): Currently loads a compiled JSON catalog. Could push this catalog to OPA as `data.surfaces` so Rego policies can reference it.

**Should be:**
> `AgentSurfacePolicy.reload()` (`agent_surface_policy.py:92-118`) reads `~/.claude/token-triage/artifacts/compiled-agent-surfaces.json` from disk into an in-memory `_profiles` dict. There is no push mechanism. To make `data.surfaces` available in OPA, the gateway would need to call `PUT /v1/data/surfaces` on OPA's REST API after each `reload()`. The `reload()` method would need a callback or the OPA HTTP client would need to observe the catalog file via inotify/polling. Neither mechanism exists today.

**Rationale:** The grimoire implies this is a simple wiring exercise. It requires adding an OPA data-push hook to the `AgentSurfacePolicy.reload()` call site and coordinating with OPA startup ordering (OPA must be healthy before the first push succeeds).

---

### + ADDITION: `TokenCostGovernor` Has Its Own Budget Enforcement — OPA Budget Guard Is a Duplicate

The `TokenCostGovernor` (`cost_governor.py:37-381`) already enforces per-scope token and cost budgets imperatively:

- `evaluate_budget()` (`cost_governor.py:184-242`) checks `_scopes[scope]` against `_usage[scope]` and returns `allow: False` with `action: block` or `action: throttle`.
- `CostGovernorMiddleware.on_call_tool()` (`cost_governor.py:383-426`) calls this on every tool invocation.
- Budget scopes are populated from the `compiled-agent-surfaces.json` catalog via `create_archetype_scopes_from_surfaces()` (`cost_governor.py:323-380`).
- Archetype-specific defaults exist in `_ARCHETYPE_BUDGET_DEFAULTS` (`cost_governor.py:280-286`): planner=50K tokens, explorer=80K, editor=120K, reviewer=60K, researcher=100K.

The proposed `kellerai.grc.budget_guard` Rego package would **duplicate** this enforcement. The grimoire does not acknowledge this overlap. Adding OPA budget guard without removing `CostGovernorMiddleware` creates double enforcement with potentially divergent decisions (e.g., OPA blocks but Python allows, or vice versa, because `data.usage` in OPA is stale while `_usage` in Python is current).

**Architectural decision required:** Either (a) OPA becomes the single budget authority and `TokenCostGovernor.evaluate_budget()` is replaced by an OPA call, or (b) `budget_guard.rego` is never written and `data.budgets`/`data.usage` are only used as read-only context in other policies (e.g., temporal guard pre-checks). Option (a) is architecturally cleaner but requires pushing every `record_usage()` call result to OPA — which is a real-time write on the hot path. Option (b) is safer for migration but leaves a confusing redundancy in the grimoire.

---

## Section 10 (Continued): The Middleware Chain

### ~ CHANGE: The Architecture Diagram Omits Half the Middleware Stack

**Was (grimoire §9 diagram):**
```
[T4: Governance Grimoire] → [Middleware chain: Correlation, rate limit, logging] → [Proxied MCP server] → [Flight Recorder]
```

**Should be (actual `gateway.py:510-564`):**

FastMCP processes middleware in **reverse registration order** (last-added = outermost = runs first). The actual execution order for a tool call is:

```
TimingMiddleware                    ← outermost (last registered)
MetricsMiddleware
ObservabilityMiddleware
CorrelationMiddleware               ← assigns correlation_id
AgentSurfaceMiddleware              ← filters tools/list (NOT tool calls)
SessionSurfaceMiddleware            ← auto-applies session surface on first call
DynamicToolSurface                  ← hides tools for unhealthy servers / exhausted budgets
FlightRecorderMiddleware            ← records trace BEFORE enforcement (outer wrapper)
CostGovernorMiddleware              ← budget enforcement (pre-call check + post-call record)
AgentSurfaceGuardMiddleware         ← exact tool allowlist + reservation enforcement
PolicyGuardrailMiddleware           ← fnmatch rules + optional OPA eval
ArgsNormalizerMiddleware            ← fixes JSON-string-encoded args
ErrorHandlingMiddleware             ← innermost
```

**Critical implications:**

1. `CorrelationMiddleware` runs BEFORE `PolicyGuardrailMiddleware`, so `get_correlation_id()` is available when OPA input is built. The grimoire's code sample correctly uses `get_correlation_id()` — but only when metrics are enabled (`enable_metrics=True`). When metrics are disabled, `CorrelationMiddleware` is never registered and `get_correlation_id()` returns `None`. The OPA input builder must handle this.

2. `FlightRecorderMiddleware` sits OUTSIDE `PolicyGuardrailMiddleware`. This means flight recorder records the attempt even if policy denies it. This is intentional and correct for audit purposes, but the grimoire's diagram implies FlightRecorder is downstream of governance — it is not.

3. OPA's proposed position (inside `PolicyGuardrailMiddleware`) means it runs AFTER `AgentSurfaceGuardMiddleware`. The archetype has already been enforced by the time OPA sees the call. This creates a redundancy: `AgentSurfaceGuardMiddleware.allows_tool()` checks the exact allowlist from `compiled-agent-surfaces.json`, and `kellerai.grc.surface_policy` in OPA would check `data.surfaces[archetype].allowed_tools` — the same data source. If both check the same catalog, one of them is redundant. If they diverge, you have a split-brain policy system.

4. There is no `RateLimitMiddleware` in the production middleware chain from `gateway.py`. The rate limiter (`RateLimitMiddleware`) exists as a module (`middleware/rate_limit.py`) and is an adapter over FastMCP's `RateLimitingMiddleware`, but it is not registered in `create_gateway()`. The grimoire's diagram references "rate limit" as a middleware chain component — this is incorrect for the current production gateway.

**Rationale:** The grimoire's architecture diagram was written without reading `gateway.py`. The actual chain order changes fundamental assumptions about what data is available when OPA is consulted.

---

## Section 9: The T4 Tier Concept

### ~ CHANGE: T4 Is Not a New Tier — It Is a Rename of Existing Enforcement

**Was:**
> The proposed T4 Governance tier sits beneath all of these as the enforcement foundation.

**Should be:**
> The "T4" label is editorial framing for governance, not a new architectural tier. The enforcement already exists across three separate systems: `PolicyGuardrailMiddleware` (tool-name pattern matching), `AgentSurfaceGuardMiddleware` (archetype allowlist + reservation), and `CostGovernorMiddleware` (budget). The grimoire's T4 concept consolidates the policy-decision logic into OPA while leaving enforcement in these same middlewares. The diagram showing T4 as a new layer beneath T1-T3 is conceptually coherent but architecturally misleading — T4 is a refactoring of the decision-making within the existing middleware stack, not a new enforcement point.

**Rationale:** This distinction matters for migration planning. There is no "add T4" step. There is "move decision logic from fnmatch/Python into Rego." The middlewares remain; only what they consult changes.

---

### + ADDITION: T4 Must Account for the Session Surface System

The grimoire's T4 diagram (`§9`) places governance before the tool call but does not model how T4 interacts with `SessionSurfaceMiddleware`. The session surface system (`middleware/session_surface.py`) operates on `tools/list` — it uses `ctx.disable_components()` and `ctx.enable_components()` to control which tools are visible per session. This is a pre-call filter, not a per-call check.

The grimoire states:
> "T4 policies evaluate the agent's archetype, budget, environment. Tools denied by T4 are removed from the surface before T1 descriptions are generated."

This is architecturally desirable but not how the current system works. Today, `SessionSurfaceMiddleware` resolves the surface via `resolve_session_surface()` using profile-based YAML bindings — it does not consult OPA. Integrating OPA decisions into surface resolution would require either:

(a) `gateway_session_surface_apply` calling OPA to further filter the resolved tool list before calling `ctx.enable_components()`, or
(b) `DynamicToolSurface` (which already hides tools based on budget exhaustion and server health) gaining an OPA query hook.

Neither path is described in the grimoire. The current `DynamicToolSurface.get_hidden_tools()` (`dynamic_surface.py:141-158`) accepts a `context` argument that is "reserved for future use" — this is the natural extension point for OPA-driven surface suppression.

---

## Section 10: Data Document Freshness

### ~ CHANGE: The Consistency Model Is Undefined and Dangerous for Budget Enforcement

**Was (§10 data document table):**
> `data.usage` — Source: `TokenCostGovernor` usage counters — Update Frequency: Every N tool calls (batched)

**Should be:**
> This design has an undefined consistency model with concrete failure modes that must be specified:

**The staleness problem in detail:**

`TokenCostGovernor.record_usage()` (`cost_governor.py:244-261`) updates `_usage` in-memory on every tool call with a `threading.RLock`. If `data.usage` in OPA is only pushed every N calls (batched), OPA's `budget_guard.rego` will evaluate against a stale usage figure. An agent that is 50 calls into a 50-call window will appear to have 0 usage to OPA until the next batch push.

At 100 tool calls per session (the grimoire's cited figure), a batch size of N=10 means OPA has stale usage data for up to 10 calls at any point — roughly 10% of session activity. If the budget limit is tight (e.g., 50K tokens), a 10-call staleness window allows significant overspend before OPA catches it.

**Required specification additions:**

1. **Write-through vs. write-behind:** Should `record_usage()` push to OPA synchronously (adds ~2-5ms per call), or fire-and-forget async (stale window exists)?
2. **Staleness tolerance:** What is the acceptable stale window for budget enforcement? Token budget enforcement at 10% staleness is materially different from cost budget enforcement.
3. **Ownership:** If `data.usage` in OPA diverges from `_usage` in Python, which is authoritative? The Python `CostGovernorMiddleware` blocks first (it runs before OPA in the middleware chain). If Python allows and OPA (with stale data) also allows, but the true usage is over budget, the safeguard has failed silently.
4. **Reconciliation:** What happens on OPA restart? `data.usage` resets to empty. The Python `_usage` dict is the ground truth and must be the data source for OPA re-hydration on startup.

**Recommendation:** `data.usage` should be write-through (async, non-blocking) or OPA budget enforcement should be abandoned in favor of keeping `CostGovernorMiddleware` as the sole budget authority. Mixed enforcement with stale data is worse than single enforcement.

---

## Section 6: Deployment Models

### ~ CHANGE: Latency Analysis Is Optimistic for the Hot Path

**Was:**
> HTTP overhead per decision: ~1-5ms. Process spawn per evaluation: ~50-200ms.

**Should be:**
> The grimoire's latency figures need qualification against the actual call rate and middleware chain depth.

**Measured context:**

- Current fnmatch evaluation in `PolicyGuardrailEngine._match_rule()` (`policy_guardrails.py:527-532`) is a simple loop over `self.rules` with `fnmatch.fnmatch()`. At 4 default rules, this is ~1-5 microseconds — three orders of magnitude faster than the proposed HTTP call.
- At 100 tool calls per session, an HTTP OPA call of 5ms adds 500ms of latency per session — 0.5 seconds of pure governance overhead. At P99 (say, 20ms), this becomes 2 seconds per session.
- The existing `OpaBackend` CLI path (`subprocess.run`) is correctly identified as 50-200ms per call (process spawn + disk load). At 100 calls/session, this is 5-20 seconds of governance overhead — clearly unacceptable. The grimoire correctly recommends migrating away from CLI.

**The HTTP sidecar is necessary but not sufficient.** The grimoire recommends HTTP sidecar in Phase 1 and WASM in Phase 2 for hot-path policies. This is architecturally correct. However, the grimoire does not specify which policies go to WASM versus HTTP. The actual split should be:

| Policy | Volume | Recommended Path |
|--------|--------|-----------------|
| Tool allowlist (`surface_policy`) | Every call | WASM (or eliminated — duplicate of `AgentSurfaceGuardMiddleware`) |
| Budget check (`budget_guard`) | Every call | Eliminated or Python-only (consistency argument above) |
| Argument validation (`param_guard`) | Every call | WASM |
| Temporal restrictions (`temporal_guard`) | Every call | HTTP sidecar (needs real-time clock) |
| Chain validation (`chain_guard`) | Subagent calls only | HTTP sidecar |
| Audit requirements (`audit_guard`) | Auditable tools only | HTTP sidecar |
| Destructive command blocking (`tool_guard`) | Bash/Write calls | WASM |

The grimoire defers the WASM split to Phase 7 with 1 day of effort. Given that WASM requires a separate compile step, Python `wasmtime` bindings, and a policy reload mechanism, 1 day is insufficient.

---

## Section 12: Phase Plan

### ~ CHANGE: The 14-Day Estimate Is Not Grounded in the Codebase Complexity

**Was:**
| Phase | Scope | Effort |
|-------|-------|--------|
| P0 | Install OPA, write first Rego policies | 1 day |
| P1 | Migrate OpaBackend to HTTP client | 1 day |
| P2 | Push live data documents to OPA | 2 days |
| P3 | Write governance packs: tool_guard, budget_guard, param_guard | 3 days |
| P4 | Add temporal_guard, chain_guard, audit_guard | 2 days |
| P5 | OPA test suite, CI integration, shadow mode rollout | 2 days |
| P6 | Bundle management, hot reload, decision log pipeline | 2 days |
| P7 | WASM compilation for hot-path policies | 1 day |

**Should be (revised estimates with codebase justification):**

| Phase | Scope | Revised Effort | Why |
|-------|-------|---------------|-----|
| P0 | Install OPA, write Rego matching existing 4 default fnmatch rules | 0.5 days | Only 4 rules to port: `*delete*`, `*remove*`, `*drop*`, `morph_edit_file` |
| P1 | Rewrite `OpaBackend` as async HTTP client, add `httpx` dep, modify `evaluate()` signature to accept agent identity | 2 days | Breaking signature change + async refactor of sync code + OpaBackend unit test rewrites |
| P1.5 | Extend `PolicyGuardrailMiddleware.on_call_tool()` to extract and forward agent identity, archetype, delegation chain from request context | 1 day | Currently only extracts `hil_approval_id` from meta; needs full context extraction |
| P2 | Implement data-push hooks: `AgentSurfacePolicy.reload()` → `PUT /v1/data/surfaces`, `TokenCostGovernor.record_usage()` → async `PUT /v1/data/usage` | 3 days | Two separate push paths; startup ordering (OPA health check before push); reconciliation on OPA restart |
| P3 | Write tool_guard and param_guard packs; resolve `surface_policy` vs `AgentSurfaceGuardMiddleware` overlap | 3 days | Overlap resolution is a design decision requiring ADR, not just Rego authoring |
| P4 | Resolve budget_guard vs `CostGovernorMiddleware` overlap; write temporal_guard, chain_guard, audit_guard | 3 days | Budget overlap requires architecture decision; chain_guard requires delegation metadata that currently does not exist in request context |
| P5 | Shadow mode rollout, `would-deny` telemetry, test suite | 3 days | `AgentSurfacePolicy` already has shadow mode telemetry in JSONL format; OPA decision logs are a separate pipeline |
| P6 | Bundle management, launchd plist, justfile targets, `opa-restart` / `opa-status` | 1 day | Straightforward; mirrors existing Oracle/KOTH launchd patterns |
| P7 | WASM: compile, `wasmtime` Python bindings, policy reload | 3 days | `wasmtime` Python API is non-trivial; WASM does not support all Rego built-ins; need fallback path for unsupported built-ins |

**Revised total: ~20-21 days** for full governance grimoire, assuming no discovered blockers. P1 through P4 are the high-risk phases. P3 and P4 are blocked on architectural decisions (overlap resolution) that may require additional design work before implementation begins.

---

## Section 5: Example Policies (Missing Integration Point)

### + ADDITION: Policy 10 (File Reservations) Duplicates `AgentSurfaceGuardMiddleware` Logic That Already Runs

Policy 10 in the grimoire (`§5 Policy 10`) blocks concurrent file access via `data.file_reservations`. However, `AgentSurfaceGuardMiddleware.on_call_tool()` (`agent_surface.py:233-247`) already enforces this identically:

```python
if self.policy.required_reservation(tool_name, meta, task_pattern=task_pattern):
    target_path = str(args.get("path") or args.get("target_file") or "")
    lease = self.policy.reservation_for_path(meta, target_path) if target_path else None
    if lease is None:
        self._deny(meta, tool_name, "missing_active_reservation", ...)
```

And reservation state is managed by `AgentSurfacePolicy.register_reservation()` / `release_reservation()` / `renew_reservation()` with `ReservationLease` objects that have `expires_at` TTLs. The grimoire's Policy 10 would need `data.file_reservations` to be synchronized from `AgentSurfacePolicy._reservations` — a per-session in-memory dict. Exporting per-session reservation state to a process-external OPA daemon is architecturally complex (session isolation, concurrent sessions, TTL synchronization) and provides no value over the existing Python implementation. Policy 10 should be cut.

---

## Section 5 (Continued): Missing Policies That Are Architecturally Required

### + ADDITION: Missing Policy — OPA Interaction with `DynamicToolSurface` for Governance-Driven Surface Suppression

The grimoire proposes 15 example policies but omits the most architecturally significant one: using OPA decisions to dynamically suppress tools from `tools/list`. `DynamicToolSurface` (`middleware/dynamic_surface.py:141-158`) already has four suppression rules (mail unconfigured, canary unregistered, server unhealthy, budget exhausted) and a `context` parameter that is "reserved for future use." A 16th policy type should be documented:

```rego
# Policy 16: Governance-driven tool visibility suppression
# (feeds into DynamicToolSurface, not PolicyGuardrailMiddleware)
package kellerai.grc.surface_visibility

import rego.v1

# Tools that should be hidden from tools/list for this archetype+context
hide contains tool_name if {
    archetype := input.agent.archetype
    tool_name := data.surfaces[archetype].hidden_tools[_]
}

hide contains tool_name if {
    # Hide tools from servers the agent has no budget for
    scope := input.agent.budget_scope
    data.usage[scope].exhausted == true
    tool_name := data.surfaces[input.agent.archetype].budget_gated_tools[_]
}
```

This policy would be queried by `DynamicToolSurface.on_list_tools()` rather than `PolicyGuardrailMiddleware`. This is the missing integration point between the session surface system and OPA governance — and it is a different query endpoint (`/v1/data/kellerai/grc/surface_visibility`) from the tool-call enforcement endpoint (`/v1/data/kellerai/grc/tool_guard`).

---

## Section 7: Policy-as-Code Best Practices

### + ADDITION: CASS Integration — Past Violations Should Inform Policy Adaptation

The grimoire does not mention CASS (procedural memory, `cass_memory_cm_context` MCP tool), which is the system that learns from tool call outcomes across sessions. There is an architectural opportunity that the grimoire misses entirely:

**Current state:** CASS records tool outcomes (success/failure/timeout) and surfaces relevant playbook rules at `SessionStart`. It operates independently of `PolicyGuardrailEngine`.

**Missing integration:** OPA decision logs (when `decision_logs.console=true` in the launchd plist) produce structured JSON records of every allow/deny/require_hil decision. These could be fed into CASS as policy-outcome events, enabling:

1. **Adaptive HIL thresholds:** If an agent has consistently received HIL approvals for `morph_edit_file` in a given project context, CASS could recommend relaxing the HIL requirement to `allow` for that archetype/project pair — and that recommendation could be surfaced as a governance pack amendment suggestion.
2. **Violation pattern detection:** Repeated deny events for the same tool from the same archetype signal either a policy miscalibration or an agent attempting unauthorized operations. CASS memory across sessions can distinguish the two.
3. **Policy effectiveness measurement:** CASS can track the ratio of `would-deny` (shadow mode) to actual call volume — a governance metric that is currently unavailable.

The concrete integration point: `cass_outcome_tracker.py` (PostToolUse hook) should receive `PolicyDecision` outcomes alongside tool results. This does not require OPA to be the source — the existing `PolicyGuardrailEngine._decisions` ring buffer is sufficient to feed CASS today without any OPA migration.

---

## Section 6: Deployment Models

### - SUBTRACTION: Remove the WASM "Pros" Claim That All Rego Built-ins Are Supported

**Remove:** The implication in Option C (§6) that WASM evaluation is equivalent to HTTP sidecar evaluation.

**Rationale:** OPA's WASM target has known built-in limitations. As of OPA 0.70.x, the following built-ins are **not** supported in WASM (relevant to the proposed policies):

- `time.now_ns()` — used in Policy 5 (temporal restrictions) and Policy 10 (file reservation TTLs)
- `semver.compare()` — used in Policy 15 (governance pack versioning)
- `http.send()` — used for any policies that need to validate external URLs

This means temporal policies (Policy 5), file reservation TTL checks (Policy 10), and governance pack version enforcement (Policy 15) **cannot** be compiled to WASM. The WASM path is only viable for pure data-lookup policies (tool allowlists, argument validation, budget thresholds) that do not use time functions or external calls. The grimoire's Phase 7 estimate of 1 day assumes full WASM compilation of all policies — this is wrong. A subset WASM compilation with HTTP sidecar fallback for time-dependent policies adds at least 2 days to Phase 7.

---

## Section 9: Rego Package Decomposition

### ~ CHANGE: 7 Packages Is the Wrong Cut — 3 Overlap Existing Python

**Was (§9 T4 Governance Components):**

| Package | Purpose |
|---------|---------|
| `kellerai.grc.tool_guard` | Allow/deny/HIL per tool call |
| `kellerai.grc.surface_policy` | Per-archetype tool visibility |
| `kellerai.grc.budget_guard` | Token/cost enforcement |
| `kellerai.grc.temporal_guard` | Time-of-day and day-of-week rules |
| `kellerai.grc.chain_guard` | Delegation chain validation |
| `kellerai.grc.audit_guard` | Require metadata for auditable operations |
| `kellerai.grc.param_guard` | Argument validation and sanitization |

**Should be (architecturally grounded decomposition):**

| Package | Purpose | Decision |
|---------|---------|---------|
| `kellerai.grc.tool_guard` | Invariants (destructive commands, path restrictions, HIL for sensitive tools) | **Keep** — this is OPA's clearest value-add |
| `kellerai.grc.param_guard` | Argument validation (schema checks, size limits, injection prevention) | **Keep** — no Python equivalent, clean OPA use case |
| `kellerai.grc.temporal_guard` | Time-of-day / day-of-week restrictions | **Keep** — no Python equivalent, HTTP sidecar only (WASM cannot) |
| `kellerai.grc.chain_guard` | Delegation chain depth and privilege validation | **Keep** — no Python equivalent, requires new input fields |
| `kellerai.grc.surface_visibility` | OPA-driven `tools/list` suppression (feeds `DynamicToolSurface`) | **Add** (missing from grimoire, see above) |
| `kellerai.grc.surface_policy` | Per-archetype tool allowlist | **Eliminate** — duplicates `AgentSurfaceGuardMiddleware` exactly |
| `kellerai.grc.budget_guard` | Token/cost budget enforcement | **Eliminate or read-only** — duplicates `CostGovernorMiddleware`; if retained, must be read-only context for other packages, not an enforcement point |
| `kellerai.grc.audit_guard` | Require correlation_id and agent identity | **Fold into `tool_guard`** — 2 rules, too thin for a standalone package |

**Net result:** 5 packages (not 7), with cleaner separation of concerns and no duplicate enforcement.

---

## Section 11: Open Questions (Additions to §12)

### + ADDITION: Five Unaddressed Architectural Questions

The grimoire's open questions are good but miss five codebase-specific questions:

**Q1: Who owns the decision when `AgentSurfaceGuardMiddleware` and OPA disagree?**
`AgentSurfaceGuardMiddleware` runs after `PolicyGuardrailMiddleware` in the middleware chain (reverse registration order means AgentSurface is outer, PolicyGuardrail is inner). This means `PolicyGuardrailMiddleware` (which calls OPA) runs first. If OPA allows but `AgentSurfaceGuardMiddleware` denies, the call is blocked (correct). If OPA denies but `AgentSurfaceGuardMiddleware` would have allowed, the call is blocked (OPA wins). This is the desired behavior, but it means OPA effectively has veto power over the surface policy. Document this explicitly in the architecture decision record.

**Q2: How does OPA handle `human_root` archetype?**
`AgentSurfacePolicy._normalize_archetype()` (`agent_surface_policy.py:169-181`) returns `"human_root"` for Codex provider sessions via `is_codex_provider()`. When archetype is `human_root`, the policy returns `None` and all tools are allowed. OPA's `surface_policy` package needs to know about `human_root` as an unrestricted archetype — otherwise Rego rules that check `data.surfaces[archetype].allowed_tools` will fail with `undefined` for human_root sessions, potentially defaulting to deny.

**Q3: Where does delegation chain data come from?**
Policy 9 references `input.meta.delegation_chain` and `input.meta.parent_agent_id`. These fields do not exist in the current MCP request metadata schema. The Agent Mail system (`mail_macro_start_session`) has agent identity concepts, but there is no in-flight delegation chain propagation in `PolicyGuardrailMiddleware.on_call_tool()` today. Implementing chain guard requires adding a delegation chain header/metadata convention to the MCP request, which is a protocol-level change affecting every agent that spawns subagents.

**Q4: Is there a `RateLimitMiddleware` in production?**
`RateLimitMiddleware` exists in `middleware/rate_limit.py` and is exported from `middleware/__init__.py`, but `gateway.py:510-564` does not register it. Policy 8 (rate limiting by tool category) in the grimoire relies on `data.recent_calls` from the flight recorder. If rate limiting is supposed to be an OPA responsibility, the existing (unregistered) `RateLimitMiddleware` should be explicitly removed from the module to avoid confusion, or registered and coordinated with OPA.

**Q5: What is the failure mode when OPA is healthy but returns an unexpected schema?**
`OpaBackend.evaluate()` (`policy_guardrails.py:178-181`) handles `returncode != 0` and `JSONDecodeError` by returning `None` (fall back to fnmatch). But if OPA returns `{"allow": true}` without a `deny` key, `opa_result.get("deny", [])` returns `[]` — all denials are silently dropped. If OPA returns a malformed response (e.g., a Rego evaluation error where the package path is wrong), the gateway allows the call through. This silent-allow-on-schema-mismatch is a security hole. The fallback should be configurable: `fallback: "deny"` for fail-closed operation (mentioned in §11 `servers.yaml` config but not implemented in the `OpaBackend` class).

---

## Section 3: API Gateway Patterns

### - SUBTRACTION: Remove the Kong/Envoy Latency Claim Without Context

**Remove:** The claim that OPA delivers "sub-millisecond latency for local HTTP calls" in the HTTP Sidecar pros list.

**Rationale:** The OPA documentation qualifies sub-millisecond performance as requiring prepared queries and in-memory policy caching on a warmed-up daemon. A cold OPA daemon receiving a first request will parse, compile, and evaluate in 5-20ms. The "sub-millisecond" figure applies to warmed prepared queries on production hardware. For ArchangelMCP's use case (local developer machine, launchd-managed daemon, 100 calls/session), a realistic P50 is 1-3ms and P99 is 10-20ms. The grimoire should cite the OPA policy performance documentation and qualify the claim.

---

## Architectural Verdict

The Governance Grimoire is a well-researched survey of OPA/Rego that correctly identifies the integration surface in ArchangelMCP. However, it was written with insufficient reading of the actual codebase. The core issues are:

1. **The migration is not drop-in.** Three signature changes, one async refactor, two new data-push mechanisms, and two overlap-resolution architectural decisions are required before a single Rego policy provides value over the existing fnmatch rules.

2. **Three of the seven proposed packages duplicate existing enforcement.** `surface_policy`, `budget_guard`, and (partly) `audit_guard` re-implement logic that already runs in `AgentSurfaceGuardMiddleware` and `CostGovernorMiddleware`. Adding OPA versions without removing the Python versions creates split-brain governance.

3. **The middleware chain order changes what data is available at what point.** The grimoire's architecture diagram is wrong. Reading `gateway.py` first would have caught this.

4. **The session surface system is the most important missing integration point.** OPA driving `DynamicToolSurface` for governance-aware `tools/list` suppression is more architecturally valuable than most of the proposed 15 policies — and it is completely absent from the grimoire.

5. **CASS integration is a free win that requires no OPA migration.** The `PolicyGuardrailEngine._decisions` ring buffer already captures the data CASS needs. This should be P0, not a future enhancement.

The grimoire is useful as a reference document and policy vocabulary guide. It should not be treated as an implementation plan without the amendments above.
