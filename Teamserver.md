# Teamserver Reference

Authoritative technical reference for the Havoc teamserver component. Read this before working on any code under `teamserver/`. Covers startup, operator WebSocket protocol, listener lifecycle, agent request pipeline, Job serialization, event system, database schema, and service API.

---

## Source Layout

```
teamserver/
├── main.go                     # Entry point → cmd.HavocCli.Execute()
├── cmd/server/
│   ├── types.go                # Teamserver, Client, Listener, Endpoint structs
│   ├── teamserver.go           # Start(), handleRequest(), auth, event system
│   ├── agent.go                # AgentAdd, AgentSendNotify, AgentConsole, Died
│   ├── dispatch.go             # DispatchEvent() — master event router
│   └── listener.go             # ListenerStart, ListenerRemove, ListenerAdd
├── pkg/
│   ├── agent/
│   │   ├── types.go            # Agent, AgentInfo, Job, Header, TeamServer interface
│   │   ├── commands.go         # All COMMAND_* / DEMON_* integer constants
│   │   ├── agent.go            # BuildPayloadMessage, ParseHeader, RegisterInfoToInstance
│   │   └── demons.go           # TaskPrepare (big switch), TeamserverTaskPrepare
│   ├── handlers/
│   │   ├── types.go            # HTTPConfig, SMBConfig, ExternalConfig, handler structs
│   │   ├── http.go             # HTTP.Start(), request(), fake404()
│   │   └── handlers.go         # parseAgentRequest, handleDemonAgent, handleServiceAgent
│   ├── events/
│   │   ├── events.go           # Authenticated, UserAlreadyExits, SendProfile
│   │   ├── demons.go           # Demons.NewDemon(), Demons.DemonOutput()
│   │   ├── listeners.go        # Listener.ListenerAdd/Edit/Remove/Error/Mark
│   │   ├── gate.go             # Gate.SendStageless, Gate.SendConsoleMessage
│   │   ├── chatlog.go          # ChatLog event constructors
│   │   ├── service.go          # Service event constructors
│   │   └── teamserver.go       # Teamserver event constructors
│   ├── packager/
│   │   ├── types.go            # Package, Head, Body, Types structs + Type constants
│   │   └── packages.go         # NewPackager(), CreatePackage()
│   ├── profile/
│   │   ├── profile.go          # Profile.SetProfile(), ServerHost(), ServerPort()
│   │   └── config.go           # HavocConfig and all sub-structs (YAOTL tags)
│   ├── db/
│   │   └── db.go               # SQLite wrapper; DatabaseNew(), init() creates tables
│   ├── service/
│   │   └── service.go          # Service WebSocket for 3rd-party agent integration
│   ├── common/
│   │   ├── packer/packer.go    # Little-endian binary serializer (outgoing to agent)
│   │   └── parser/parser.go    # Big-endian binary deserializer (incoming from agent)
│   └── builder/                # Payload builder (see Demon.md)
```

---

## Core Types (`cmd/server/types.go`)

```go
type Teamserver struct {
    Flags      TeamserverFlags
    Profile    *profile.Profile
    Clients    sync.Map          // map[string]*Client; keyed by ClientID
    Users      []Users
    EventsList []packager.Package // server-side replay log
    Service    *service.Service
    WebHooks   *webhook.WebHook
    DB         *db.DB
    Server     struct {
        Path   string
        Engine *gin.Engine
    }
    Agents    agent.Agents
    Listeners []*Listener
    Endpoints []*Endpoint
    Settings  struct {
        Compiler64, Compiler32, Nasm string
    }
}

type Client struct {
    ClientID, Username, GlobalIP, ClientVersion string
    Connection    *websocket.Conn
    Packager      *packager.Packager
    Authenticated bool
    SessionID     string
    Mutex         sync.Mutex
}

type Listener struct {
    Name   string
    Type   int    // handlers.LISTENER_HTTP / LISTENER_PIVOT_SMB / LISTENER_EXTERNAL
    Config any    // *handlers.HTTP | *handlers.SMB | *handlers.External
}

type Endpoint struct {
    Endpoint string
    Function func(ctx *gin.Context)
}
```

---

## Startup Sequence (`cmd/server/teamserver.go`)

`Start()` runs at server launch:

1. Initialize gin engine with `gin.New()` (no default middleware)
2. Register `/havoc/` WebSocket upgrade handler (gorilla/websocket, TLS)
3. Register any custom `t.Endpoints`
4. Open SQLite database via `db.DatabaseNew()`
5. Start listeners defined in the YAOTL profile (`t.Profile.Config.Listener`)
6. Restore listeners from DB (`DB.ListenersList()`) not already started
7. Restore agents from DB (`DB.AgentsList()`) → `RegisterInfoToInstance` → `AgentSendNotify`
8. Start the Service WebSocket endpoint if `t.Profile.Config.Service != nil`
9. Call `http.Server.ListenAndServeTLS()` in a goroutine, block on done channel

Every `/havoc/` connection spawns `handleRequest(conn)` as a goroutine.

---

## Operator WebSocket Protocol

### Transport

- Endpoint: `wss://<host>:<port>/havoc/`
- Binary WebSocket messages carrying JSON-encoded `packager.Package` values
- All messages use `websocket.BinaryMessage`
- Client mutex (`Client.Mutex`) guards every write

### Message Envelope

```go
type Package struct {
    Head Head
    Body Body
}
type Head struct {
    Event   int    `json:"Event"`    // top-level event type (packager.Type.*.Type)
    User    string `json:"User"`
    Time    string `json:"Time"`     // "02/01/2006 15:04:05"
    OneTime string `json:"OneTime"`  // "true" → not replayed to new clients
}
type Body struct {
    SubEvent int            `json:"SubEvent"` // sub-type within the event
    Info     map[string]any `json:"Info"`     // payload fields
}
```

### Event Type Constants (`packager.Type`)

| Constant                        | Type  | SubEvent values                                              |
|---------------------------------|-------|--------------------------------------------------------------|
| `InitConnection.Type` = 0x1     | 0x1   | Success=0x1, Error=0x2, OAuthRequest=0x3, InitInfo=0x4, Profile=0x5 |
| `Listener.Type` = 0x2           | 0x2   | Add=0x1, Edit=0x2, Remove=0x3, Mark=0x4, Error=0x5          |
| `Credentials.Type` = 0x3        | 0x3   | Add=0x1, Edit=0x2, Remove=0x3                                |
| `Chat.Type` = 0x4               | 0x4   | NewMessage=0x1, NewListener=0x2, NewSession=0x3, NewUser=0x4, UserDisconnected=0x5 |
| `Gate.Type` = 0x5               | 0x5   | Staged=0x1, Stageless=0x2, MSOffice=0x3                     |
| `HostFile.Type` = 0x6           | 0x6   | Add=0x1, Remove=0x2                                          |
| `Session.Type` = 0x7            | 0x7   | NewSession=0x1, Remove=0x2, Input=0x3, Output=0x4, MarkAsDead=0x5 |
| `Service.Type` = 0x9            | 0x9   | RegisterAgent=0x1, RegisterListener=0x2                      |
| `Teamserver.Type` = 0x10        | 0x10  | Log=0x1, Profile=0x2                                         |

### Client Authentication Flow (`handleRequest`)

1. Read first WebSocket message → `CreatePackage(jsonStr)` → `Package`
2. Validate `pkg.Head.Event == packager.Type.InitConnection.Type`
3. Check username exists in profile operators (send `UserDoNotExists` if not)
4. Check no duplicate username in `t.Clients` (send `UserAlreadyExits` if dup)
5. Call `ClientAuthenticate(client, pkg)`:
   - Verify `pkg.Body.SubEvent == packager.Type.InitConnection.OAuthRequest`
   - Hash submitted password: `sha3.Sum256([]byte(password))` → hex string
   - Compare against profile user's password (pre-hashed in profile or raw; compared as hex strings)
   - Return `events.Authenticated(true/false)` package
6. Send auth result; if failed, return and close connection
7. Send `events.SendProfile(t.Profile)` — Demon config + server IPs
8. Call `SendAllPackagesToNewClient(client)` — replays `EventsList` + `EventNewDemon` for each active agent
9. Enter read loop: `handleRequest` → `DispatchEvent(client, pkg)` for each message

### Event Broadcast Helpers

```go
// Send to all clients except one
func (t *Teamserver) EventBroadcast(ExcludeID string, pk packager.Package)

// Send to one client (JSON-encode + WebSocket write, locked)
func (t *Teamserver) SendEvent(client *Client, pk packager.Package)

// Append to replay log unless OneTime == "true"
func (t *Teamserver) EventAppend(pk packager.Package)

// EventAppend + EventBroadcast("")
func (t *Teamserver) EventAppendAndBroadcast(pk packager.Package)
```

### Event Replay (`EventsList`)

- `EventsList []packager.Package` holds all non-OneTime packages
- `SendAllPackagesToNewClient` replays every entry in `EventsList` then sends each active agent's `EventNewDemon` package
- OneTime packages (e.g. `OAuthRequest` challenge, `Gate.Stageless` payload downloads) are never replayed

---

## Listener Lifecycle (`cmd/server/listener.go`)

### Listener Types

```go
const (
    LISTENER_HTTP       = 1  // HTTP/HTTPS
    LISTENER_PIVOT_SMB  = 2  // Named pipe (SMB pivot)
    LISTENER_EXTERNAL   = 3  // External C2 (relayed via Service WebSocket)
    LISTENER_SERVICE    = 4  // 3rd-party service agent
)
```

### Starting a Listener

`ListenerStart(FromUser, Type, Config)`:
1. Deduplication: check no existing listener with same name
2. Construct handler instance (`*handlers.HTTP`, `*handlers.SMB`, or `*handlers.External`)
3. Call `handler.Start()` — registers gin routes, starts `net/http` server
4. On error: send `events.Listener.ListenerError` package back to client, return
5. On success: append to `t.Listeners`, call `ListenerAdd()` → serialize to DB → return `events.Listener.ListenerAdd` package
6. `EventAppendAndBroadcast` the add package

### Removing a Listener

`ListenerRemove(Name)`:
1. Find listener in `t.Listeners` by name
2. For HTTP: call `HTTP.Stop()` with 5s context timeout (`http.Server.Shutdown`)
3. Remove from DB (`DB.ListenerRemove`)
4. Remove from `EventsList` (filter by listener name in Info map)
5. Broadcast `events.Listener.ListenerRemove` package

### HTTP Listener Handler (`pkg/handlers/http.go`)

`HTTP.Start()`:
- Creates a new gin engine per listener (isolated from the operator engine)
- Registers `POST /*endpoint` → `request()`
- Registers `GET /*endpoint` → `fake404()` (nginx-mimicking 404)
- Starts `http.Server.ListenAndServe[TLS]` in goroutine

`request()` validation pipeline:
1. Check configured Headers (case-insensitive value match against request headers)
2. Check configured URIs (request path must match one of the URIs list)
3. Check User-Agent (must match configured UserAgent)
4. On any failure: serve `fake404()`
5. On pass: read body → `parseAgentRequest()`

---

## Agent Request Pipeline (`pkg/handlers/handlers.go`)

### `parseAgentRequest(body []byte)`

1. `agent.ParseHeader(body)` → extracts `Header{Size, MagicValue, AgentID, Data *parser.Parser}`
2. Dispatch on `Header.MagicValue`:
   - `DEMON_MAGIC_VALUE (0xDEADBEEF)` → `handleDemonAgent()`
   - Anything else → `handleServiceAgent()` (3rd-party agents registered via Service API)

### `handleDemonAgent(listener, header, requestIP)`

**Known agent** (AgentID found in `Agents`):
1. Decrypt `Header.Data` buffer with agent's AES key/IV
2. Loop: read `Command(4-LE) + RequestID(4-LE)` pairs until buffer exhausted
3. For each pair: dispatch to `Agent.TaskDispatch(Command, RequestID, Parser)` or set `asked_for_jobs = true` when `Command == COMMAND_GET_JOB`
4. Update `Agent.Info.LastCallIn`; broadcast `AgentLastTimeCalled` event
5. Response: if `asked_for_jobs` and queue non-empty → `BuildPayloadMessage(GetQueuedJobs(), key, iv)`; else → `BuildPayloadMessage([]Job{{Command: COMMAND_NOJOB}}, key, iv)`

**Unknown agent** + `Command == DEMON_INIT (99)`:
1. `agent.ParseDemonRegisterRequest(parser)` → `map[string]any` of session metadata
2. `RegisterInfoToInstance(header, map)` → `*Agent`
3. `AgentAdd(agent)` → DB persist + append to `t.Agents.Agents`
4. `AgentSendNotify(agent)` → broadcast `EventNewDemon` to all clients
5. Reply: 4-byte LE AgentID

### Incoming Packet Header (big-endian, parsed by `parser.Parser`)

```
Offset  Size  Field
0       4     Size (total packet size)
4       4     MagicValue (0xDEADBEEF for Demon)
8       4     AgentID
12      *     Data (command responses / checkin payload)
```

Parser reads big-endian by default (`binary.BigEndian`).

---

## Job Queuing and Task Preparation

### `Job` struct (`pkg/agent/types.go`)

```go
type Job struct {
    Command     uint32
    RequestID   uint32
    Data        []interface{}  // typed values serialized by BuildPayloadMessage
    Payload     []byte         // pre-built binary blob (bypasses Data serialization)
    CommandLine string
    TaskID      string
    Created     string
    Encryption  struct {
        Enable bool
        Key    []byte
        IV     []byte
    }
}
```

### `TaskPrepare(command, info)` → `*Job` (`pkg/agent/demons.go`)

Large switch on `command` string (e.g. `"dir"`, `"download"`, `"shell"`, `"execute-assembly"`). Each case:
- Parses `info map[string]any` for its required fields
- Populates `job.Data []interface{}` with typed Go values
- Returns the Job; caller passes it to `AddJobToQueue`

**Argument encoding conventions in `Data`:**
- Strings → `common.EncodeUTF16(str)` produces a `string` with UTF-16LE bytes (no size prefix in Data; `BuildPayloadMessage` adds the 4-byte LE size)
- Paths with base64-encoded components → `base64.StdEncoding.DecodeString` first
- Sub-command selectors → plain `int`
- Booleans → `win32.TRUE` / `win32.FALSE` (int aliases)
- File content → chunked via `UploadMemFileInChunks` → `uint32` mem-file ID

### `BuildPayloadMessage(jobs, aesKey, aesIv)` → `[]byte` (`pkg/agent/agent.go`)

For each Job:
1. Serialize `job.Data` elements into `DataPayload` (little-endian):
   - `int/int32/uint32` → 4 bytes LE
   - `int64/uint64` → 8 bytes LE
   - `int16/uint16` → 2 bytes LE
   - `string` → 4-byte LE length + null-terminated UTF-8/UTF-16 bytes
   - `[]byte` → 4-byte LE length + raw bytes
   - `byte` → 1 byte
   - `bool` → 4 bytes LE (0 or 1)
2. If `DataPayload` non-empty: AES-256-CTR encrypt via `crypt.XCryptBytesAES256`
3. Append to `PayloadPackage`: `CommandID(4-LE) + RequestID(4-LE) + DataLength(4-LE) + EncryptedData`

The outer HTTP response body is the raw `PayloadPackage` bytes (no additional framing).

### `DispatchEvent` (`cmd/server/dispatch.go`)

Master switch on `pk.Head.Event`:

| Event | Action |
|-------|--------|
| `Session.Type` + `Session.Input` | `TaskPrepare` → `AddJobToQueue`; special-cases "Python Plugin" and "Teamserver" command IDs |
| `Listener.Type` + `Add` | `ListenerStart` |
| `Listener.Type` + `Remove` | `ListenerRemove` |
| `Listener.Type` + `Edit` | `ListenerEdit` |
| `Gate.Type` + `Stageless` | goroutine: `builder.NewBuilder().Build()` → `events.Gate.SendStageless` → `EventAppendBroadcast` |
| `Chat.Type` | `EventBroadcast` |

---

## Agent State (`pkg/agent/types.go`)

### `Agent` struct (key fields)

```go
type Agent struct {
    NameID     string         // hex AgentID, e.g. "deadbeef"
    Active     bool
    SessionDir string
    Info       *AgentInfo
    Encryption struct {
        Enable bool
        Key    []byte
        IV     []byte
    }
    JobQueue  []Job
    Pivots    struct {
        Parent *Agent
        Links  []*Agent       // child SMB pivot agents
    }
    Downloads []*Download
    PortFwds  []*PortFwd
    SocksCli  []*SocksCli
    SocksSvr  []*SocksSvr
}

type AgentInfo struct {
    MagicValue   int
    FirstCallIn  string
    LastCallIn   string
    SleepDelay   int
    SleepJitter  int
    KillDate     int64
    WorkingHours int32
    Hostname     string
    Username     string
    DomainName   string
    InternalIP   string
    ExternalIP   string
    ProcessName  string
    ProcessPath  string
    ProcessPID   int
    ProcessTID   int
    ProcessPPID  int
    ProcessArch  string
    Elevated     string
    OSVersion    string
    OSArch       string
    BaseAddress  int64
}
```

### Key Agent Methods (`cmd/server/agent.go`)

```go
// Persist to DB, append to Agents list, fire webhook
AgentAdd(agent *agent.Agent)

// Construct EventNewDemon package, EventAppend + EventBroadcast
AgentSendNotify(agent *agent.Agent)

// Broadcast COMMAND_NOJOB event with Last/Sleep/Jitter/KillDate/WorkingHours
AgentLastTimeCalled(agent *agent.Agent)

// Broadcast DemonOutput event (command output) to all clients
AgentConsole(AgentID, MsgType, Message string)

// Mark inactive, unlink pivots, update DB
Died(agent *agent.Agent)
```

---

## Events Package (`pkg/events/`)

All functions return `packager.Package`. Callers pass the result to `EventAppend`, `EventBroadcast`, or `SendEvent`.

### `events.go` (top-level, no receiver)

| Function | SubEvent | Description |
|----------|----------|-------------|
| `Authenticated(bool)` | InitConnection.Success / Error | Auth result package |
| `UserAlreadyExits()` | InitConnection.Error | Duplicate username |
| `UserDoNotExists()` | InitConnection.Error | Unknown username |
| `SendProfile(profile)` | InitConnection.Profile | Sends JSON-encoded Demon config + server IPs |

### `var Demons demons` (`events/demons.go`)

```go
Demons.NewDemon(agent)   // Session.NewSession — full agent info map (all AgentInfo fields,
                         //   AES key/IV base64-encoded, pivot parent if set)
Demons.DemonOutput(...)  // Session.Output — command output to UI console
```

### `var Listener listeners` (`events/listeners.go`)

```go
Listener.ListenerAdd(user, type, config)    // Listener.Add — full config map (HTTP/SMB/External)
Listener.ListenerEdit(type, config)         // Listener.Edit
Listener.ListenerRemove(name)               // Listener.Remove
Listener.ListenerError(user, name, err)     // Listener.Error
Listener.ListenerMark(name, mark)           // Listener.Mark — online/offline status
```

### `var Gate gate` (`events/gate.go`)

```go
Gate.SendStageless(format, payload)         // Gate.Stageless — base64 payload bytes
Gate.SendConsoleMessage(msgType, text)      // Gate.Stageless — UI console message
```

---

## YAOTL Profile Configuration (`pkg/profile/config.go`)

Profile file format: HCL-based (parsed via embedded `hclsimple`). Decoded into `HavocConfig`:

```go
type HavocConfig struct {
    Server    *ServerProfile  // Teamserver block
    Operators *OperatorsBlock // Operators block
    Listener  *Listeners      // Listeners block
    Demon     *Demon          // Demon block
    Service   *ServiceConfig  // Service block
    WebHook   *WebHookConfig  // WebHook block
}
```

### `Teamserver` block → `ServerProfile`

```
Host  string   // bind address
Port  int      // WebSocket port (operator connections)
Build block:
  Compiler64  string
  Compiler86  string
  Nasm        string
```

### `Operators` block → `OperatorsBlock`

```
user "Name" {
    Password = "sha3-256-hex"
}
```

### `Listeners` block → `Listeners`

Three sub-block types:

**Http block → `ListenerHTTP`:**
```
Name, KillDate, WorkingHours, Hosts[], HostBind, HostRotation,
PortBind, PortConn, Method, UserAgent, Headers[], Uris[],
Secure, Cert{Cert, Key}, Response{Headers[]}, Proxy{Host, Port, Username, Password}
```

**Smb block → `ListenerSMB`:**
```
Name, PipeName, KillDate, WorkingHours
```

**External block → `ListenerExternal`:**
```
Name, Endpoint
```

### `Demon` block → `Demon` (profile struct)

```
Sleep, Jitter, IndirectSyscall, StackDuplication, SleepTechnique,
ProxyLoading, AmsiEtwPatching, TrustXForwardedFor, DotNetNamePipe,
Injection{ Spawn64, Spawn32 },
Binary{
    Header{ MagicMz-x64, MagicMz-x86, CompileTime, ImageSize-x64, ImageSize-x86 },
    ReplaceStrings-x64, ReplaceStrings-x86
}
```

### `Service` block → `ServiceConfig`

```
Endpoint  string   // WebSocket path for 3rd-party agents
Password  string
```

### `WebHook` block → `WebHookConfig`

```
Discord{ Url, AvatarUrl, User }
```

---

## Database Schema (`pkg/db/db.go`)

SQLite file, opened via `mattn/go-sqlite3`. Created on first run:

```sql
CREATE TABLE "TS_Listeners" (
    "Name"     text UNIQUE,
    "Protocol" text,
    "Config"   text    -- JSON-serialized listener config
);

CREATE TABLE "TS_Agents" (
    "AgentID"      int,
    "Active"       int,
    "Reason"       string,
    "AESKey"       string,
    "AESIv"        string,
    "Hostname"     string,
    "Username"     string,
    "DomainName"   string,
    "ExternalIP"   string,
    "InternalIP"   string,
    "ProcessName"  string,
    "BaseAddress"  int,
    "ProcessPID"   int,
    "ProcessTID"   int,
    "ProcessPPID"  int,
    "ProcessArch"  string,
    "Elevated"     string,
    "OSVersion"    string,
    "OSArch"       string,
    "SleepDelay"   int,
    "SleepJitter"  int,
    "KillDate"     int,
    "WorkingHours" int,
    "FirstCallIn"  string,
    "LastCallIn"   string
);

CREATE TABLE "TS_Links" (
    "ParentAgentID" int,
    "LinkAgentID"   int
);
```

On startup with an existing DB: listeners and agents are restored from these tables.

---

## Service API for 3rd-Party Agents (`pkg/service/service.go`)

A separate WebSocket endpoint for external agent integrations:

- Endpoint: `ws[s]://<host>:<port>/<Config.Endpoint>`
- Authentication: SHA3-256 password check (same mechanism as operator auth)
- Once authenticated, allows:
  - **RegisterAgent** (`Service.RegisterAgent = 0x1`): register a custom agent type; teamserver relays jobs/output between operator clients and the external service
  - **RegisterListener** (`Service.RegisterListener = 0x2`): register a listener handled entirely by the external service
- The `TeamServer` interface in `pkg/agent/types.go` exposes all callback methods the service handlers need

---

## Binary Serialization Primitives

### `packer.Packer` (`pkg/common/packer/packer.go`) — outgoing to agent

Little-endian. Used to build responses sent back to the Demon.

```go
p := packer.NewPacker(nil)
p.AddInt32(val int32)
p.AddInt64(val int64)
p.AddUInt32(val uint32)
p.AddInt(val int)
p.AddString(val string)     // 4-byte LE size + string bytes
p.AddWString(val string)    // UTF-16LE encoded, 4-byte LE size + bytes
p.AddBytes(val []byte)      // 4-byte LE size + raw bytes
data := p.Build()
```

### `parser.Parser` (`pkg/common/parser/parser.go`) — incoming from agent

Big-endian by default. Used to parse Demon HTTP POST bodies.

```go
p := parser.NewParser(data)
p.Length() int
p.CanIRead(n int) bool
p.ParseInt32() int
p.ParseInt64() int64
p.ParseBytes() []byte       // reads 4-byte BE size prefix, then that many bytes
p.ParseBool() bool
p.DecryptBuffer(key, iv []byte) []byte  // AES-256-CTR decrypt remaining buffer
```

---

## Coding Conventions

- **No `var` keyword inside functions in the main server files** — assignments use `:=` or plain `=` with prior `var` block declarations.
- **`map[string]any`** for `Body.Info` — never `map[string]interface{}` in new code (they are equivalent; existing code may use either).
- **`structs.Map(config)`** (github.com/fatih/structs) — used in events/listeners.go to convert handler config structs to `map[string]interface{}` for the Info payload.
- **No error wrapping** — errors are logged with `logger.Error` / `logger.DebugError` and returned as-is.
- **Listener type constants** are plain untyped `int` — no iota.
- **`win32.TRUE` / `win32.FALSE`** — integer aliases (1/0) used in `Job.Data` for boolean fields going to the agent; avoids the bool→4-byte serialization path when an explicit int value is required.
- **UTF-16 strings for Windows paths/names** — always `common.EncodeUTF16(str)` before adding to `job.Data`; `BuildPayloadMessage` handles the size prefix automatically for `string` type.
- **Base64 argument passing from client** — many `TaskPrepare` cases `base64.StdEncoding.DecodeString` their arguments before encoding to UTF-16; this is the client's convention for passing binary-safe strings over the JSON Info map.
