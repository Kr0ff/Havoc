# Task System Deep Analysis

## Overview

The Havoc task system is the mechanism by which operator commands flow from the
client GUI through the teamserver and are delivered to and executed by the Demon
agent. It is a **pull-based** system: the Demon periodically checks in (HTTP
GET/POST or SMB pipe read), the teamserver sends any queued tasks, and the
Demon returns the results in its next check-in.

---

## 1. End-to-End Data Flow

```
┌─────────────┐   WebSocket    ┌─────────────────┐   HTTP/SMB    ┌─────────────────┐
│  Client GUI  │ ──────────►   │   Teamserver     │ ◄──────────  │  Demon Agent    │
│  (Qt5 C++)   │ packager.Pkg  │   (Go)           │  check-in    │  (C / Win32)    │
│              │               │                  │              │                 │
│  User types  │               │  1. DispatchEvent │              │  1. SleepObf()  │
│  "shell      │               │  2. TaskPrepare   │              │  2. PkgTxAll()  │
│   whoami"    │               │  3. AddJobToQueue │              │  3. Parse resp  │
│              │               │  4. → JobQueue[]  │              │  4. Dispatch cmd│
│              │               │                  │              │  5. PkgTransmit │
└──────────────┘               └──────────────────┘              └─────────────────┘
```

### Step-by-step

1. **Client** → Operator types a command. The client serialises it into a
   `packager.Package` with `SubEvent = Session.Input`, containing `DemonID`,
   `CommandID`, `Arguments`, `TaskID`, `CommandLine`. Sent over the WebSocket.

2. **Teamserver: `DispatchEvent`** (`cmd/server/dispatch.go:21`) — The
   WebSocket handler calls `DispatchEvent` for every incoming package. For
   `Session.Input`, it finds the target Agent by `DemonID` and calls
   `TaskPrepare`.

3. **Teamserver: `TaskPrepare`** (`pkg/agent/demons.go:129`) — Converts the
   high-level command into a `Job` struct:
   ```go
   type Job struct {
       Command     uint32           // e.g. COMMAND_SLEEP (11)
       RequestID   uint32           // random or from TaskID
       Data        []interface{}    // typed arguments (int, string, []byte)
       Payload     []byte           // pre-built binary payload (optional)
       CommandLine string           // display text for operator
       TaskID      string           // hex task ID
       Created     string           // timestamp
       Encryption  struct{ Key, IV []byte }
   }
   ```
   `TaskPrepare` is a giant switch statement (1000+ lines) that marshals each
   command's arguments into the `Data` slice using the correct types (int32,
   string, []byte) that match the Demon's parser expectations.

4. **Teamserver: `AddJobToQueue`** (`pkg/agent/agent.go:677`) — Appends the
   Job to the agent's `JobQueue []Job` slice. Also calls `AddRequest` which
   copies the job into `Tasks []Job` (the "known request IDs" list for
   validation).

   For **SMB pivot agents**: `PivotAddJob` wraps the job in a `COMMAND_PIVOT`
   envelope. The inner job is serialised with `BuildPayloadMessage` using the
   child agent's AES key, then wrapped with the child's AgentID. For chained
   pivots, this is repeated up the parent chain. The final COMMAND_PIVOT job
   lands on the **root HTTP parent's** `JobQueue`.

5. **Demon checks in** — The Demon's `CommandDispatcher` main loop
   (`payloads/Demon/src/core/Command.c:62`) calls:
   - `SleepObf()` — sleep with optional memory encryption
   - `PackageTransmitAll()` — sends all queued response packages AND asks for
     new tasks

6. **Teamserver: `handleDemonAgent`** (`pkg/handlers/handlers.go:121`) — On
   receiving the check-in:
   - Parses the outer header (SIZE, Magic, AgentID)
   - Extracts the per-request IV and decrypts
   - Decompresses if LZNT1 bit is set
   - Iterates over embedded command/result pairs
   - If `COMMAND_GET_JOB` is found, calls `GetQueuedJobs()` and
     `BuildPayloadMessage()` to serialise the response

7. **Teamserver: `GetQueuedJobs`** (`pkg/agent/agent.go:694`) — Drains jobs
   from the front of `JobQueue`, accumulating size until
   `DEMON_MAX_RESPONSE_LENGTH` (30 MB) is reached. Returns the batch and
   leaves any remaining jobs for next check-in.

8. **Teamserver: `BuildPayloadMessage`** (`pkg/agent/agent.go:30`) — Serialises
   each job into the wire format:
   ```
   For each job:
     [CommandID    ] 4 bytes (LE)
     [RequestID    ] 4 bytes (LE)
     [DataSize     ] 4 bytes (LE)
     [Data (AES enc)] variable — each field serialised by type
   ```
   The Data region of each job is AES-256-CTR encrypted with the agent's
   session key. The outer response is then transmitted through the HTTP/SMB
   transport layer.

9. **Demon: parse and dispatch** (`Command.c:109-143`) — The Demon parses the
   response buffer in a loop:
   ```c
   do {
       CommandID  = ParserGetInt32(&Parser);  // 4 bytes
       RequestID  = ParserGetInt32(&Parser);  // 4 bytes
       TaskBuffer = ParserGetBytes(&Parser, &TaskBufferSize);
       Instance->CurrentRequestID = RequestID;

       if (CommandID != DEMON_COMMAND_NO_JOB) {
           ParserNew(&TaskParser, TaskBuffer, TaskBufferSize);
           ParserDecrypt(&TaskParser, AES.Key, AES.IV);

           // Linear scan of DemonCommands[] table
           for (i = 0; DemonCommands[i].Function != NULL; i++) {
               if (DemonCommands[i].ID == CommandID) {
                   DemonCommands[i].Function(&TaskParser);
                   break;
               }
           }
       }
   } while (Parser.Length > 12);
   ```

10. **Demon: response generation** — Each command handler (e.g.
    `CommandSleep`, `CommandFS`) creates response packages:
    ```c
    PPACKAGE Package = PackageCreate(DEMON_COMMAND_SLEEP);
    PackageAddInt32(Package, delay);
    PackageTransmit(Package);  // queued, not sent immediately
    ```
    `PackageTransmit` appends to the `Instance->Packages` linked list.
    On the next `PackageTransmitAll` call (next check-in cycle), all queued
    packages are bundled into one HTTP request.

11. **Teamserver: `TaskDispatch`** (`pkg/agent/demons.go:2286`) — Processes
    the Demon's response. Validates `RequestID` against the known `Tasks[]`
    list, dispatches by `CommandID`, and calls `RequestCompleted` to remove
    the task from tracking.

---

## 2. Wire Format Detail

### Teamserver → Demon (task delivery)

```
Outer HTTP response body (Base64-encoded):

[CommandID_1 ] 4 bytes LE   ─┐
[RequestID_1 ] 4 bytes LE    │ Job 1
[DataSize_1  ] 4 bytes LE    │
[AES(Data_1) ] DataSize bytes─┘
[CommandID_2 ] 4 bytes LE   ─┐
[RequestID_2 ] 4 bytes LE    │ Job 2
[DataSize_2  ] 4 bytes LE    │
[AES(Data_2) ] DataSize bytes─┘
...
```

Each `Data` blob is AES-256-CTR encrypted per-job using the agent's session
key and IV. The outer frame is NOT encrypted — only individual job payloads
are.

### Demon → Teamserver (check-in + results)

```
[SIZE         ] 4 bytes BE   — total bytes after this field
[Magic        ] 4 bytes BE   — 0xDEADBEEF
[AgentID      ] 4 bytes BE
[COMMAND_GET_JOB] 4 bytes BE — command ID = 1
[RequestID    ] 4 bytes BE
[IV           ] 16 bytes     — per-request random IV [HVC-004]
[AES(payload) ] variable     — compressed if bit 31 of SIZE set [HVC-007]

payload (after decrypt + decompress):
  [CommandID_1 ] [RequestID_1] [DataSize_1] [Data_1]  — result 1
  [CommandID_2 ] [RequestID_2] [DataSize_2] [Data_2]  — result 2
  ...
```

After AES decryption + LZNT1 decompression (if flagged), the teamserver
iterates over embedded command/result pairs. Bytes 4-19 of the wire header
are XOR-masked with `SIZE ^ HEADER_MASK_SEED` [HVC-003]. A 32-byte HMAC-SHA256
tag is appended after the AES ciphertext [HVC-006].

---

## 3. Key Data Structures

### Teamserver side

| Structure | Location | Purpose |
|-----------|----------|---------|
| `Agent.JobQueue []Job` | `types.go:149` | FIFO queue of pending tasks. Drained by `GetQueuedJobs`. |
| `Agent.Tasks []Job` | `types.go:150` | Known request IDs. Used by `IsKnownRequestID` to validate Demon responses. Populated by `AddRequest`, cleared by `RequestCompleted`. |
| `Job` struct | `types.go:81-95` | Task container: CommandID, RequestID, typed Data slice, metadata. |
| `Agent.Encryption` | `types.go:171-174` | AES-256 key (32 bytes) + IV (16 bytes) for this session. |
| `Agent.TaskedOnce` | `types.go:175` | Whether the agent has been tasked at least once (used for MemFile initial task). |

### Demon side

| Structure | Location | Purpose |
|-----------|----------|---------|
| `Instance->Packages` | `Demon.h:542` | Singly-linked list of `PACKAGE` structs awaiting transmission. Head of the outbound queue. |
| `PACKAGE` struct | `Package.h:8-18` | `CommandID`, `RequestID`, `Buffer`, `Length`, `Encrypt`, `Destroy`, `Included`, `Next`. |
| `Instance->CurrentRequestID` | `Demon.h:55` | Set before dispatching each inbound task so response packages inherit the correct RequestID. |
| `DemonCommands[]` | `Command.c:17` | Static array of `{ID, Function}` pairs mapping CommandIDs to handler functions. Linear scan. |
| `DEMON_MAX_REQUEST_LENGTH` | `Package.h:6` | 3 MiB. Max total outbound package size per `PackageTransmitAll` call. |

---

## 4. Concurrency Model

### Teamserver

- **No mutex on JobQueue or Tasks.** `AddJobToQueue`, `GetQueuedJobs`,
  `PivotAddJob`, `TeamserverTaskPrepare` (task::list, task::clear) all
  directly read/write `Agent.JobQueue` without synchronisation.
- HTTP handlers run in separate goroutines (gin framework). Each incoming
  Demon check-in is a new goroutine that calls `handleDemonAgent` →
  `GetQueuedJobs`.
- `DispatchEvent` is called from the WebSocket handler goroutine when an
  operator submits a command → `TaskPrepare` → `AddJobToQueue`.
- **Race condition:** If an operator submits a command at the exact moment
  the Demon checks in, two goroutines concurrently access `Agent.JobQueue`
  (one appending, one slicing). This is a data race on a Go slice.
- `PortFwds`, `SocksCli`, `SocksSvr` have dedicated mutexes, but `JobQueue`
  and `Tasks` do not.

### Demon

- Single-threaded in the task loop. `CommandDispatcher` is a sequential
  `do { sleep; send/receive; parse; dispatch } while (Connected)` loop.
- Command handlers run synchronously on the same thread (blocking the main
  loop until complete).
- Long-running commands (assembly execution, downloads) use the Job system
  (`JobAdd`) to run in background threads. Output is collected by
  `JobCheckList()` and queued via `PackageTransmit` for the next check-in.
- The `Instance->Packages` linked list is only accessed from the main loop
  thread and from background job threads via `PackageTransmit`. There is
  **no lock** on this linked list either.

---

## 5. Identified Issues and Improvement Suggestions

### ISSUE-1: No mutex on Agent.JobQueue (DATA RACE)

**Severity: HIGH**

`Agent.JobQueue` is a Go slice accessed from multiple goroutines without
synchronisation:
- **Writer:** `AddJobToQueue` (from WebSocket dispatch goroutine)
- **Writer:** `PivotAddJob` (appends COMMAND_PIVOT jobs)
- **Reader/Writer:** `GetQueuedJobs` (from HTTP handler goroutine, slices the queue)
- **Reader/Writer:** `TeamserverTaskPrepare` (task::clear sets to nil; task::list iterates)
- **Reader:** `handleDemonAgent` (iterates `Agent.JobQueue` for pivot count logging)

Go slices are not safe for concurrent access. If an operator queues a task
while the Demon is checking in, a concurrent slice append + slice reslice
can corrupt the slice header (pointer, length, capacity), causing panics,
lost tasks, or duplicated tasks.

**Fix:** Add a `sync.Mutex` to the `Agent` struct and acquire it around all
`JobQueue` and `Tasks` access:

```go
type Agent struct {
    // ...
    JobMtx   sync.Mutex  // protects JobQueue and Tasks
    JobQueue []Job
    Tasks    []Job
    // ...
}
```

All methods that touch `JobQueue` or `Tasks` (`AddJobToQueue`,
`GetQueuedJobs`, `AddRequest`, `RequestCompleted`, `PivotAddJob`,
`TeamserverTaskPrepare`) must `Lock()`/`Unlock()` this mutex.

---

### ISSUE-2: No mutex on Instance->Packages linked list (DATA RACE)

**Severity: MEDIUM**

On the Demon side, `Instance->Packages` is a singly-linked list manipulated
by:
- **Main thread:** `PackageTransmitAll` (iterates, marks `Included`, removes entries)
- **Background job threads:** `PackageTransmit` (appends to the end of the list)

If a background job (e.g. assembly execution, SOCKS proxy, port forward)
calls `PackageTransmit` while the main thread is inside `PackageTransmitAll`,
the linked list can be corrupted (lost nodes, use-after-free).

**Fix:** Use a critical section (`CRITICAL_SECTION` or a spinlock via
`InterlockedExchange`) around `Instance->Packages` access:

```c
// In PackageTransmit:
EnterCriticalSection(&Instance->PackagesLock);
// ... append to list ...
LeaveCriticalSection(&Instance->PackagesLock);

// In PackageTransmitAll:
EnterCriticalSection(&Instance->PackagesLock);
// ... iterate, mark, remove ...
LeaveCriticalSection(&Instance->PackagesLock);
```

However, `CRITICAL_SECTION` requires kernel32 initialisation which may not
be available. An alternative is an interlocked spinlock using ntdll-safe
`_InterlockedExchange`:

```c
while (_InterlockedExchange(&Instance->PackagesLock, 1) != 0) {
    YieldProcessor();
}
// ... critical section ...
_InterlockedExchange(&Instance->PackagesLock, 0);
```

---

### ISSUE-3: Linear command dispatch table scan

**Severity: LOW (performance)**

`CommandDispatcher` uses a linear scan over `DemonCommands[]` (21 entries)
to find the handler for each `CommandID`:

```c
for (FunctionCounter = 0;; FunctionCounter++) {
    if (DemonCommands[FunctionCounter].Function == NULL) break;
    if (DemonCommands[FunctionCounter].ID == CommandID) {
        DemonCommands[FunctionCounter].Function(&TaskParser);
        break;
    }
}
```

With 21 commands and sequential IDs that are sparse (1, 10, 11, 12, 15, 20,
21, 22, 24, 26, 27, 40, 100, 0x1010, 0x1011, 0x2001, 0x2003, 2100, 2500,
2510, 2520, ...), the worst case is 21 comparisons.

**This is not a real performance problem** — 21 comparisons is negligible
compared to network I/O and sleep time. No change needed unless the command
table grows significantly.

---

### ISSUE-4: GetQueuedJobs size calculation duplicates BuildPayloadMessage logic

**Severity: LOW (maintainability)**

`GetQueuedJobs` (`agent.go:694`) manually calculates the serialised size of
each job's Data fields using a type-switch. `BuildPayloadMessage`
(`agent.go:30`) has the same type-switch for actual serialisation. These two
functions must stay in sync — if a new type is added to one but not the
other, jobs will be incorrectly sized or serialised.

**Fix:** Extract a shared `JobDataSize(job Job) int` function:

```go
func JobDataSize(job Job) int {
    size := 0
    for _, d := range job.Data {
        switch v := d.(type) {
        case int, int32, uint32, bool: size += 4
        case int64, uint64:            size += 8
        case int16, uint16:            size += 2
        case string:                   size += 4 + len(v)
        case []byte:                   size += 4 + len(v)
        case byte:                     size += 1
        }
    }
    return size
}
```

Then `GetQueuedJobs` calls `JobDataSize` and `BuildPayloadMessage` can assert
that its output matches.

---

### ISSUE-5: PackageTransmit drops oversized SMB packages silently

**Severity: MEDIUM (data loss)**

For SMB transport, `PackageTransmit` checks:
```c
if (sizeof(UINT32) * 8 + Package->Length > PIPE_BUFFER_MAX) {
    // discard and notify operator
    Package = PackageCreateWithRequestID(DEMON_PACKAGE_DROPPED, RequestID);
    PackageAddInt32(Package, Length);
    PackageAddInt32(Package, PIPE_BUFFER_MAX);
}
```

The comment says `// TODO: support packet fragmentation`. Large responses
(e.g. process list, directory listing, screenshot) are silently dropped and
replaced with a "package dropped" notification. The operator sees the error
but the data is lost.

**Fix:** Implement SMB packet fragmentation. Split oversized packages into
chunks of `PIPE_BUFFER_MAX - overhead` and send them with a sequence/total
header so the parent can reassemble. Alternatively, increase `PIPE_BUFFER_MAX`
or use a multi-read protocol on the parent side.

---

### ISSUE-6: Tasks[] list grows without bounds for lost requests

**Severity: LOW (memory leak)**

`AddRequest` appends every job to `Agent.Tasks`. `RequestCompleted` removes
it when the Demon responds. If a Demon dies or never responds to a task
(network error, crash), the entry remains in `Tasks` forever.

**Fix:** Add a TTL or periodic cleanup. When `Died()` is called, clear the
agent's `Tasks` list. Alternatively, add a timestamp to each task and
periodically prune entries older than N × the agent's sleep interval.

---

### ISSUE-7: RequestID collision risk

**Severity: LOW**

`TaskPrepare` uses `rand.Uint32()` for `RequestID`. With `math/rand` (not
`crypto/rand`), collisions are unlikely but possible, especially if the
global rand source is poorly seeded. A collision means two tasks share the
same RequestID; `IsKnownRequestID` would accept a response from one task as
valid for the other.

**Fix:** Use an atomic counter instead of random:
```go
var nextRequestID atomic.Uint32

func nextReqID() uint32 {
    return nextRequestID.Add(1)
}
```

Or accept the current approach as low-risk (2^32 space, typically < 1000
active tasks).

---

### ISSUE-8: No task priority or cancellation

**Severity: LOW (feature gap) — PARTIALLY FIXED**

`JobQueue` is a strict FIFO. There is no way to:
- **Prioritise** a task (e.g. emergency kill command jumps the queue)
- ~~**Cancel** a specific queued task (only `task::clear` wipes the entire queue)~~

**Cancellation:** ✅ FIXED in TASK-UX (v0.8.6). `task cancel <id>` removes
a specific task by TaskID. `task cancel all` clears the entire queue, Tasks
list, and InFlightRequestIDs. In-flight tasks return a distinct error message.

**Priority:** Still a feature gap. Add a `Priority` field to `Job` and
insert high-priority jobs at the front of the queue.

---

### ISSUE-9: Demon-side PackageTransmitAll includes all packages indiscriminately

**Severity: LOW**

On HTTP transport, `PackageTransmitAll` bundles ALL queued packages into
one HTTP request, up to `DEMON_MAX_REQUEST_LENGTH` (3 MiB). If background
jobs produce many small packages, a single check-in can carry a very large
response. On SMB transport, the `PIPE_BUFFER_MAX` guard exists, but HTTP
has no per-package limit — only the aggregate limit.

If the total exceeds 3 MiB, the loop breaks early:
```c
if (Package->Length > DEMON_MAX_REQUEST_LENGTH)
    break;
```

But the remaining packages stay in the list for next cycle. This is correct
but can cause perpetual backlogs if the Demon produces data faster than it
can send (e.g. rapid SOCKS proxy traffic).

**Possible improvement:** Add flow control — if the package list grows beyond
a threshold, temporarily suspend background jobs that are producing the most
data.

---

## 6. Summary Table

| ID | Issue | Severity | Category |
|----|-------|----------|----------|
| ISSUE-1 | No mutex on Agent.JobQueue | HIGH | Data race / correctness |
| ISSUE-2 | No mutex on Instance->Packages | MEDIUM | Data race / correctness |
| ISSUE-3 | Linear command dispatch scan | LOW | Performance (acceptable) |
| ISSUE-4 | Duplicated size calculation logic | LOW | Maintainability |
| ISSUE-5 | SMB oversized package drop | MEDIUM | Data loss |
| ISSUE-6 | Tasks[] unbounded growth | LOW | Memory leak |
| ISSUE-7 | RequestID collision risk | LOW | Correctness (unlikely) |
| ISSUE-8 | No task priority/cancellation | LOW | Feature gap |
| ISSUE-9 | No HTTP per-package flow control | LOW | Reliability |

### Priority recommendation

1. **ISSUE-1** — ✅ FIXED. Added `sync.Mutex` (`JobMtx`) to Agent struct.
   All `JobQueue`/`Tasks` accesses now locked: `AddJobToQueue`, `GetQueuedJobs`,
   `RequestCompleted`, `IsKnownRequestID`, `PivotAddJob`, `TeamserverTaskPrepare`
   (task::list, task::clear), and handlers.go snapshot reads.
   Lock ordering: child→parent for PivotAddJob to prevent deadlock.

2. **ISSUE-2** — ✅ FIXED. Added `volatile LONG PackagesLock` to INSTANCE struct.
   Spinlock via GCC `__sync_lock_test_and_set`/`__sync_lock_release` built-ins.
   `PackageDestroyInner` (static, no lock) split from `PackageDestroy` (acquires lock)
   to avoid deadlock in `PackageTransmitAll`. All linked-list operations protected.

3. **ISSUE-5** — ✅ FIXED. Two-part implementation:
   - **Demon side (Package.c):** Oversized SMB packages split into
     `DEMON_PACKAGE_FRAGMENT` (2580) chunks with header
     `[FragID][SeqNum][TotalFrags][OrigCmdID][OrigReqID][ChunkData]`.
     Max chunk size = `PIPE_BUFFER_MAX / 2` (32KB).
   - **Teamserver side (demons.go):** `COMMAND_PACKAGE_FRAGMENT` case in
     `TaskDispatch` collects chunks by FragID in `FragmentBuffer` map,
     reassembles when all fragments arrive, then recursively dispatches
     as the original command. Stale fragments cleaned up after 5 minutes.

4. **SEQ-EXEC** — ✅ FIXED. Sequential task execution (one-task-per-check-in).
   `InFlightRequestIDs` map tracks dispatched RequestIDs. `GetQueuedJobs()`
   returns nil while in-flight. MEM_FILE chunks grouped atomically with their
   consuming command. 10-minute stale timeout prevents permanent stalls.
   `task::clear` resets in-flight state. Version bumped to 0.8.5.

5. **TASK-UX** — ✅ FIXED. Task system UX improvements (v0.8.6):
   - COMMAND_CHECKIN excluded from in-flight tracking (no longer blocks queue).
   - `AgentConsoleWithTaskID` wrapper injects TaskID into all ~40 console
     output calls in TaskDispatch. COMMAND_SOCKET calls intentionally excluded
     (async, not task-correlated).
   - `task cancel <id>` / `task cancel all` — removes tasks from queue.
     In-flight tasks return distinct error. `clear`/`cancel all` also wipe
     the Tasks tracking slice.
   - ISSUE-8 partially resolved (cancellation done, priority still open).

6. Everything else is low priority and can be addressed incrementally.
