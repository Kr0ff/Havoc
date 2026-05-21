# HVC-035 — Teamserver Operator UX Improvements

**Status:** Pending

---

## Problem

In red team operations with multiple concurrent operators, the current teamserver provides no mechanisms to manage accountability, agent organisation, or coordinated tasking:

- **No audit trail.** When multiple operators work the same engagement, there is no record of who ran which command against which agent and when. Post-engagement reconstruction of activity (required for deconfliction, lessons-learned, and client reporting) must rely on individual operator notes or incomplete client-side logs.
- **No RBAC.** Any authenticated operator can task any agent. On engagements where different operators own different target segments, an accidental task sent to the wrong agent can trigger alerts in the wrong part of the network.
- **No agent grouping.** With 50+ active agents, operators must manually identify which agents belong to which subnet, campaign phase, or target organisation. There is no way to address a logical group with a single command.
- **No scheduled tasking.** Operators who want to run commands during off-hours must remain logged in or rely on manual execution at the right time. There is no mechanism to queue a job for future delivery to an agent.
- **No bulk dispatch.** Sending the same command (e.g., `sleep 300 0`) to all agents requires one interaction per agent — a friction point that scales badly.

---

## Scope

| Layer | Files |
|-------|-------|
| Teamserver | `teamserver/cmd/server/dispatch.go`, `teamserver/cmd/server/types.go`, `teamserver/pkg/agent/types.go`, `teamserver/pkg/agent/agent.go`, `teamserver/pkg/db/`, `teamserver/pkg/events/` |
| Client | `client/src/Havoc/Demon/ConsoleInput.cc`, `client/src/UserInterface/Widgets/SessionTable.cc` |

---

## Design

### Sub-1: Operator Audit Log

**Goal:** Record every command dispatched to an agent — who dispatched it, which agent it targeted, and when — in a persistent, queryable log.

**New DB table:**

```sql
CREATE TABLE IF NOT EXISTS operator_actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,    -- unix epoch seconds
    operator    TEXT    NOT NULL,    -- operator username from authenticated session
    agent_id    TEXT    NOT NULL,    -- agent ID (hex string, matches agents table)
    command     TEXT    NOT NULL,    -- command name or numeric ID as string
    args        TEXT,                -- JSON-serialised argument map (nullable)
    request_id  TEXT                 -- correlation UUID for response tracking; nullable
);
```

Index `(agent_id, timestamp)` for efficient per-agent queries and `(operator, timestamp)` for per-operator queries.

**Implementation steps:**

1. `pkg/db/` — add `audit.go` (or extend `agents.go`) with:
   ```go
   func (db *DB) LogOperatorAction(operator, agentID, command, args, requestID string) error
   func (db *DB) GetOperatorActions(agentID string, limit int) ([]OperatorAction, error)
   ```
   `LogOperatorAction` is a single `INSERT` and must not block the dispatch path — call it in a goroutine or accept that the tiny SQLite write latency is acceptable (it typically is).

2. `cmd/server/dispatch.go` — in `DispatchEvent()`, immediately before the job is enqueued onto the agent's job queue, call `db.LogOperatorAction(...)`. Pass the operator name from the authenticated WebSocket session context, the agent ID, the command name, JSON-marshalled args, and the request correlation ID.

3. New client-facing command: `audit [agent_id] [limit]`
   - No `agent_id`: returns last 50 actions across all agents for the current operator.
   - With `agent_id`: returns last 50 actions for that agent across all operators.
   - With `limit`: overrides the default 50.
   - Server formats response as a table (timestamp, operator, command, args) and sends via the existing console output event path.

**Privacy note:** `args` may contain sensitive data (credentials passed as shell arguments, file paths). Operators must be made aware that audit logs persist in the SQLite DB file. Document that `args` truncates at 2048 bytes to prevent log bloat from large upload buffers.

---

### Sub-2: Agent Tags / Labels

**Goal:** Allow operators to attach arbitrary string tags to agents. Tags enable logical grouping without modifying the agent or its registration data.

**New DB table:**

```sql
CREATE TABLE IF NOT EXISTS agent_tags (
    agent_id TEXT NOT NULL,
    tag      TEXT NOT NULL,
    PRIMARY KEY (agent_id, tag)
);
```

Tags are case-insensitive lowercase strings, max 64 characters. Permitted characters: `[a-z0-9_-]`. Validation enforced server-side.

**New client commands:**

```
tag add    <agent_id>  <tag> [tag2 ...]   -- add one or more tags to a specific agent
tag add    all         <tag>              -- add tag to all currently active agents
tag remove <agent_id>  <tag>             -- remove a tag from an agent
tag list   [tag]                         -- list all agents; with tag, filter to those matching
```

**Implementation steps:**

1. `pkg/db/` — add methods:
   ```go
   func (db *DB) TagAdd(agentID, tag string) error
   func (db *DB) TagRemove(agentID, tag string) error
   func (db *DB) TagList(tag string) ([]string, error)      // returns agent IDs
   func (db *DB) GetAgentTags(agentID string) ([]string, error)
   ```

2. `cmd/server/dispatch.go` — handle `tag add`, `tag remove`, `tag list` commands. After a tag mutation, broadcast a `EventAgentTagsUpdated` event via `pkg/events/` so all connected clients can refresh their session table.

3. `pkg/events/` — add `EventAgentTagsUpdated` event type carrying `{ agent_id, tags: [] }`.

4. `client/src/UserInterface/Widgets/SessionTable.cc` — on receipt of `EventAgentTagsUpdated`, update the in-memory agent model and redraw the session table. Tags are displayed as a comma-separated string in a new "Tags" column, or as a tooltip on the agent row if column space is constrained. The column is hidden by default and can be toggled via the column header context menu.

5. `tag add all <tag>` resolves to iterating all active agent IDs server-side and calling `TagAdd` for each — no client-side loop needed.

---

### Sub-3: Bulk Command Dispatch

**Goal:** Allow operators to send a single command to multiple agents in one operation, identified by tag, literal ID list, or the keyword `all`.

**New client command syntax:**

```
batch  tag:<tag>          <command> [args...]
batch  all                <command> [args...]
batch  <id1> [id2 ...]    <command> [args...]
```

**Examples:**

```
batch tag:dmz     shell whoami
batch all         sleep 300 0
batch A1B2 C3D4   screenshot
```

**Implementation steps:**

1. Client-side (`ConsoleInput.cc`) parses `batch`:
   - If first argument starts with `tag:`, resolve matching agent IDs via a `tag list` DB query (or from the in-memory session table if tags are cached there).
   - If `all`, use the full active agent ID list from the session table model.
   - Otherwise, treat the argument list as agent IDs until a non-hex token is encountered.
   - For each resolved agent ID, enqueue a standard `DispatchEvent` with the remaining arguments as the command.

2. Teamserver: no protocol changes required. Each agent receives its own independent job, just as if the operator had issued the command in each agent's individual console.

3. Audit log (Sub-1) automatically captures each individual dispatch. To correlate bulk-dispatched commands, generate a single batch UUID in the client and pass it as the `request_id` for all dispatches in the batch.

4. Client feedback: after issuing a `batch` command, the client console prints a summary:
   ```
   [batch] Dispatched <command> to 12 agents (batch_id: 3f7a...)
   ```

---

### Sub-4: Scheduled Job Dispatch

**Goal:** Allow operators to queue a job for delivery to an agent at a future time, without needing to remain logged in.

**New client command syntax:**

```
schedule <delay | absolute-time>  <command> [args...]
```

**Examples:**

```
schedule 2h         shell whoami
schedule 30m        upload /tmp/tool.exe C:\Windows\Temp\tool.exe
schedule 2026-05-21T02:00:00  screenshot
```

Delay format: `<N>s`, `<N>m`, `<N>h`, `<N>d`. Absolute time: ISO 8601 with optional timezone (UTC assumed if absent).

**Implementation steps:**

1. `pkg/agent/types.go` — add `FireAfter int64` (unix epoch seconds, zero means "immediately") to the job struct. This is a backward-compatible addition: existing code that reads `FireAfter == 0` dispatches the job immediately.

2. `pkg/agent/agent.go` in `GetQueuedJobs()` (or equivalent function that returns pending jobs to the polling agent): filter out any job where `FireAfter > time.Now().Unix()`. Those jobs remain in the queue without being returned. When the agent next polls and the time has passed, they are included.

3. `cmd/server/dispatch.go` — when a `schedule` command is received, parse the delay/time argument, compute `FireAfter`, and set it on the created job before enqueueing.

4. New client command: `pending [agent_id]` — lists scheduled jobs with their `FireAfter` time and time remaining, formatted as a table.

5. Persistence: scheduled jobs must survive teamserver restarts. Ensure job queue is persisted in the SQLite DB (verify whether jobs are currently persisted; if they are ephemeral, Sub-4 requires adding DB persistence for the job queue, which is a larger change — note this dependency explicitly).

**Edge cases:**
- If the agent is offline when `FireAfter` passes, the job remains queued until the agent next checks in. This is the desired behaviour.
- Cancellation: `cancel <job_id>` removes a scheduled job from the queue. Job IDs are already generated (verify existing UUID assignment in job struct); surface them in the `pending` output.

---

### Sub-5: Per-Agent Operator RBAC (Lower Priority)

**Goal:** Restrict individual operators to a subset of agents based on explicit access grants. An operator with `viewer` role on an agent can see its output but cannot task it. An operator with `operator` role can task it. An operator with `owner` role can also modify its tags, delete it, and grant access to other operators. A special `admin` role configured in the profile bypasses all ACL checks.

**New DB table:**

```sql
CREATE TABLE IF NOT EXISTS operator_agent_acl (
    operator TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    role     TEXT NOT NULL CHECK(role IN ('viewer', 'operator', 'owner')),
    PRIMARY KEY (operator, agent_id)
);
```

**Access control logic:**

- When a new agent checks in, the operator whose listener received the registration is assigned `owner` role automatically.
- In `dispatch.go`, before any operation on an agent, call `db.CheckACL(operator, agentID, requiredRole)`. If the operator is the `admin` user (configured in the profile), skip the check.
- Operators without at least `viewer` access to an agent do not see it in their session table — filter on the `EventAgentNew` broadcast to send only to operators with access, or filter client-side after receiving the full list.
- `acl grant <agent_id> <operator> <role>` — operator command to grant access; caller must have `owner` role on the agent.
- `acl revoke <agent_id> <operator>` — revoke access.
- `acl list <agent_id>` — show current access grants.

**Implementation note:** The client session table currently receives all agent events. Filtering per-operator requires either server-side event routing (broadcast to specific WebSocket connections rather than all) or client-side filtering on a per-operator basis. Server-side filtering is more secure. This is the largest single change in this spec and should be implemented last.

---

## File Map

| File | Change |
|------|--------|
| `teamserver/pkg/db/audit.go` (new) | `LogOperatorAction`, `GetOperatorActions` |
| `teamserver/pkg/db/tags.go` (new) | `TagAdd`, `TagRemove`, `TagList`, `GetAgentTags` |
| `teamserver/pkg/db/acl.go` (new) | `CheckACL`, `GrantACL`, `RevokeACL`, `ListACL` (Sub-5) |
| `teamserver/pkg/agent/types.go` | Add `FireAfter int64` to job struct |
| `teamserver/pkg/agent/agent.go` | Filter `FireAfter` in `GetQueuedJobs()` |
| `teamserver/cmd/server/dispatch.go` | Call audit log; handle `tag`, `batch`, `schedule`, `pending`, `audit`, `acl` commands |
| `teamserver/pkg/events/listeners.go` | Add `EventAgentTagsUpdated` event type |
| `client/src/Havoc/Demon/ConsoleInput.cc` | Add help text and parse logic for new commands |
| `client/src/UserInterface/Widgets/SessionTable.cc` | Display tags column; handle `EventAgentTagsUpdated` |

---

## Tests

- **Audit log (Sub-1):** Dispatch a `shell whoami` command as operator `alice` to agent `A1B2`. Query `operator_actions` table. Verify one row with `operator = "alice"`, `agent_id = "A1B2"`, `command` matching the command name, and `timestamp` within 1 second of dispatch time.
- **Audit query command:** Run `audit A1B2` in the client console. Verify the returned table includes the row from the previous test.
- **Tags add/list (Sub-2):** Add tag `dmz` to agent `A1B2`. Run `tag list dmz`. Verify `A1B2` appears in the result.
- **Tags remove (Sub-2):** Remove tag `dmz` from `A1B2`. Run `tag list dmz`. Verify `A1B2` is absent.
- **Tags session table (Sub-2):** Add tag `pivot` to an agent. Verify the Tags column in the session table updates within one event cycle.
- **Batch (Sub-3):** With three active agents tagged `test`, run `batch tag:test shell echo ok`. Verify three separate jobs appear in the agent queues (one per agent) and three audit log entries are created with the same `request_id`.
- **Scheduled job (Sub-4):** Create a job with `FireAfter = now + 5s`. Verify `GetQueuedJobs()` returns zero jobs immediately. Wait 6 seconds. Verify `GetQueuedJobs()` returns the job.
- **Scheduled persistence (Sub-4):** Create a scheduled job, restart the teamserver, verify the job is still pending.

---

## Notes

- **Sub-1 (audit log)** is the highest-priority item. It is security-critical for multi-operator engagements and requires no client changes beyond the `audit` command. Implement and ship independently of the other sub-items.
- **Sub-2 (tags)** and **Sub-3 (batch)** are naturally paired — bulk dispatch is most useful once agents can be addressed by tag. Implement together in a single PR.
- **Sub-4 (scheduled jobs)** depends on whether the job queue is currently persisted. Audit the `pkg/db/` and `pkg/agent/` code before starting implementation to determine whether DB job persistence needs to be added first.
- **Sub-5 (RBAC)** is the most architecturally invasive change. It requires agreement on the filtering strategy (server-side vs. client-side) before implementation begins. Defer until Sub-1 through Sub-4 are stable.
