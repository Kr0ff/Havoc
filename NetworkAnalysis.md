# Havoc Network Architecture Analysis

Analysis of how the Demon agent communicates with the teamserver across all supported transports. Covers packet structure, encryption, static detection artifacts, and data flow.

---

## 1. Transport Overview

The transport is selected at **compile time** via preprocessor defines. Only one transport is compiled into a given Demon binary.

| Transport | Macro | Direction | Protocol |
|-----------|-------|-----------|----------|
| HTTP/HTTPS | `TRANSPORT_HTTP` | Demon → Teamserver (polling) | Raw binary HTTP POST |
| SMB Named Pipe | `TRANSPORT_SMB` | Child Demon → Parent Demon (pivot) | Named pipe message framing |
| External C2 | — | Third-party agent → Teamserver | HTTP POST (same endpoint, different magic) |

---

## 2. HTTP/HTTPS Transport

### 2.1 Outer Packet Header — Always Plaintext, Big-Endian

Every HTTP POST body from the Demon starts with a fixed **20-byte plaintext header**:

```
Offset  Size  Field        Value / Notes
------  ----  -----------  ------------------------------------------------
0       4     SIZE         Total body length − 4 (does not include itself)
4       4     MAGIC VALUE  0xDEADBEEF — static, every single request
8       4     AGENT ID     32-bit random demon identifier
12      4     COMMAND ID   DEMON_INITIALIZE=99, DEMON_COMMAND_GET_JOB=1, etc.
16      4     REQUEST ID   Task correlation ID
20      ...   PAYLOAD      AES-256-CTR encrypted (with one exception, see §2.2)
```

Source: `PackageCreateWithMetaData()` + `Int32ToBuffer()` in `payloads/Demon/src/core/Package.c`.

### 2.2 Registration Packet — DEMON_INITIALIZE (Command ID = 99)

Sent once on first check-in. The 20-byte header is followed by session metadata that is **sent entirely in plaintext on HTTP**. Encryption skips the key/IV fields:

```
Offset  Size  Field
------  ----  -----
0       4     SIZE
4       4     0xDEADBEEF
8       4     AGENT ID
12      4     99  (DEMON_INITIALIZE)
16      4     REQUEST ID
20      32    AES-256 SESSION KEY       ← plaintext on HTTP
52      16    AES-256 SESSION IV        ← plaintext on HTTP
68      4     Agent ID (repeated)
72      var   Hostname     (4-byte LE length prefix + bytes)
?       var   Username     (4-byte LE length prefix + bytes)
?       var   Domain       (4-byte LE length prefix + bytes)
?       var   Internal IP  (4-byte LE length prefix + bytes)
?       var   Process path (4-byte LE length prefix + UTF-16 bytes)
?       4     PID
?       4     TID
?       4     PPID
?       4     Architecture (PROCESS_AGENT_ARCH)
?       4     IsAdmin      (bool as uint32: 1 or 0)
?       8     ModuleBase   (64-bit address)
?       4     OS Major version
?       4     OS Minor version
?       4     OS ProductType
?       4     OS ServicePackMajor
?       4     OS BuildNumber
?       4     OS Architecture
?       4     Sleep interval (ms)
?       4     Jitter percentage
?       8     KillDate (int64 unix timestamp)
?       4     WorkingHours bitmask
```

Source: `DemonMetaData()` in `payloads/Demon/src/Demon.c:95`, padding logic in `PackageTransmitNow()` in `Package.c:253`.

**There is no Diffie-Hellman or asymmetric key exchange.** The AES key is baked into the binary at payload-generation time and transmitted to the teamserver in the first check-in request. On plain HTTP this is fully exposed; on HTTPS it is protected by TLS.

### 2.3 Subsequent Beacon Packets — DEMON_COMMAND_GET_JOB (Command ID = 1)

Each beacon (polling interval) sends all pending result packages in a single HTTP POST:

```
[20-byte plaintext header]
[AES-256-CTR encrypted region from offset 20 onwards]
  ↳ One or more sub-packages concatenated inside the ciphertext:
     [CMD ID    ] 4 bytes big-endian
     [REQUEST ID] 4 bytes big-endian
     [LENGTH    ] 4 bytes big-endian  (length of DATA)
     [DATA      ] variable
```

Maximum request body size: `DEMON_MAX_REQUEST_LENGTH = 0x300000` (3 MiB), defined in `Package.h`.

### 2.4 Teamserver → Demon Response Format

`BuildPayloadMessage()` in `teamserver/pkg/agent/agent.go:29` serializes jobs as (note: **little-endian** on this side):

```
Per job:
  [COMMAND ID ] 4 bytes LE — plaintext
  [REQUEST ID ] 4 bytes LE — plaintext
  [DATA SIZE  ] 4 bytes LE — plaintext
  [DATA       ] AES-256-CTR encrypted
```

**Endianness inconsistency:** Demon writes the outer header in big-endian (`Int32ToBuffer`), but the teamserver response uses little-endian (`binary.LittleEndian`). The parser handles this correctly because each side owns its own serialization path.

### 2.5 HTTP Request Mechanics

| Property | Detail |
|----------|--------|
| HTTP method | POST only. GET requests receive a fake nginx 404 page |
| URL | Randomly selected from configured URI list each request |
| User-Agent | Configured at build time; sent with every request |
| Header validation | Profile-defined headers must match exactly (case-insensitive value); mismatch → fake 404 |
| URI validation | Request URI must match a configured URI; mismatch → fake 404 |
| HTTPS | `WINHTTP_FLAG_SECURE`; all certificate errors ignored (`SECURITY_FLAG_IGNORE_*`) |
| Session handle | `hHttpSession` is reused across requests |
| Proxy | WPAD auto-detect (WinHttpGetProxyForUrl) → IE proxy fallback → manual config |
| Token | `TokenImpersonate(FALSE)` before WinHttp call to avoid impersonation-induced access errors |
| Host failover | Round-robin or random rotation with configurable max retries per host |

---

## 3. Encryption

| Property | Detail |
|----------|--------|
| Algorithm | AES-256 in CTR (counter) mode |
| Key size | 32 bytes |
| IV/nonce | 16 bytes; increments as big-endian counter for each 16-byte block |
| Key source | Embedded in binary at generation time; sent to teamserver in first registration request |
| Encrypted scope | Everything after the 20-byte outer header (inner payload only) |
| Demon implementation | Custom `AesCrypt.c` (`payloads/Demon/src/crypt/AesCrypt.c`) — no Windows CNG/BCrypt |
| Teamserver implementation | Go standard library `crypto/cipher` AES-CTR (`teamserver/pkg/common/crypt/aes.go`) |

AES-CTR mode is a stream cipher: `ciphertext = plaintext XOR AES(counter)`. Encryption and decryption use the identical operation (`AesXCryptBuffer` / `XCryptBytesAES256`).

### What is and isn't encrypted

| Data | Encrypted? |
|------|-----------|
| Packet size field (bytes 0–3) | **No** — always plaintext |
| Magic value 0xDEADBEEF (bytes 4–7) | **No** — always plaintext |
| Agent ID (bytes 8–11) | **No** — always plaintext |
| Command ID (bytes 12–15) | **No** — always plaintext |
| Request ID (bytes 16–19) | **No** — always plaintext |
| AES session key + IV (registration only) | **No** — sent in cleartext on HTTP |
| All command data and task results | **Yes** — AES-256-CTR |
| HTTPS transport wrapper | **Yes** — TLS (self-signed cert, errors ignored) |

---

## 4. SMB Named Pipe Transport (Pivot)

### 4.1 Architecture

An SMB Demon runs on a host with no direct internet access. It connects to a **parent HTTP Demon** via a named pipe. The parent relays all traffic to the teamserver over HTTP.

```
SMB Demon ──[named pipe]──▶ HTTP Demon ──[HTTP/S POST]──▶ Teamserver
```

### 4.2 Named Pipe Configuration

Created with `CreateNamedPipeW` in `TransportSmb.c`:

| Setting | Value |
|---------|-------|
| Access | `PIPE_ACCESS_DUPLEX` (read + write) |
| Type | `PIPE_TYPE_MESSAGE \| PIPE_READMODE_MESSAGE \| PIPE_WAIT` |
| Max instances | `PIPE_UNLIMITED_INSTANCES` |
| Security | Everyone SID (`SECURITY_WORLD_RID`) with `SPECIFIC_RIGHTS_ALL \| STANDARD_RIGHTS_ALL`; Low integrity label (`SECURITY_MANDATORY_LOW_RID`) — allows cross-integrity connections |

### 4.3 Pipe Framing

`SmbRecv()` reads:

```
[DEMON ID  ] 4 bytes — validated against Session.AgentID; mismatch → disconnect
[PKG SIZE  ] 4 bytes — size of payload that follows
[PAYLOAD   ] variable bytes
```

### 4.4 SMB Encryption

There is no independent encryption layer at the SMB transport. The payload carried through the pipe is the same binary Demon package (20-byte plaintext header + AES-256-CTR encrypted body) used in HTTP. Encryption is end-to-end between Demon and teamserver, not pipe-hop to pipe-hop.

### 4.5 SMB Packet Size Limit

Packets larger than `PIPE_BUFFER_MAX` are discarded at the sender and replaced with a `DEMON_PACKAGE_DROPPED` notification package containing the original size and the limit. No fragmentation/reassembly is implemented.

### 4.6 Registration over SMB

SMB Demon sends MetaData via `PackageTransmitNow()` with no response expected (`NULL, NULL` response args). Session is immediately marked `Connected = TRUE` after the pipe write succeeds.

---

## 5. External / Service Agent C2

- Third-party agents (not Demon) use the same HTTP POST endpoint
- Differentiated from Demon by `Header.MagicValue != 0xDEADBEEF`
- The teamserver looks up a registered service agent plugin by magic value and delegates the entire request to it
- The External listener is a separate WebSocket endpoint used by the service plugin process to register itself with the teamserver
- No Demon-specific parsing is applied to service agent traffic

---

## 6. Detection Artifacts (Static IOCs)

### 6.1 Magic Bytes

**`0xDEADBEEF` at byte offset 4 of every HTTP POST body** is the single highest-confidence network indicator of Havoc Demon traffic.

- Defined as `DEMON_MAGIC_VALUE 0xDEADBEEF` in `payloads/Demon/include/common/Defines.h:15`
- Mirrored on the teamserver in `teamserver/pkg/agent/commands.go:4`
- Present in **every** Demon HTTP request without exception
- Bytes at wire: `DE AD BE EF` at offset 4 of the POST body

### 6.2 Packet Structure Signatures

| Signature | Description |
|-----------|-------------|
| SIZE field = body_length − 4 | First 4 bytes always equal total body length minus 4 |
| 20-byte binary preamble | All Demon HTTP POST bodies start with a 20-byte binary header, no JSON/form encoding |
| Command ID `0x00000063` at bytes 12–15 | Big-endian 99; present only in registration packets |
| 48-byte high-entropy block at offsets 20–67 | AES key + IV in registration packet (HTTP only) |

### 6.3 Teamserver Response Headers

The `fake404()` handler (`teamserver/pkg/handlers/http.go:80`) responds to any request that fails header, URI, or User-Agent validation with:

```
HTTP 404
Server: nginx
X-Havoc: true       ← detection artifact
Content-Type: text/html
```

The `X-Havoc: true` response header is a fingerprint of a Havoc teamserver listener.

### 6.4 HTTPS Certificate

When HTTPS mode is used without a custom cert, the teamserver auto-generates a self-signed RSA certificate. The subject and SAN are set to the listener bind IP. Demon ignores all certificate validation errors.

---

## 7. Complete Data Flow Diagrams

### 7.1 HTTP — First Registration

```
Demon                                       Teamserver (Gin HTTP)
  │                                               │
  │  POST /configured-uri                         │
  │  Body:                                        │
  │    [00 00 xx xx]  SIZE                        │
  │    [DE AD BE EF]  MAGIC (plaintext)           │  ParseHeader()
  │    [xx xx xx xx]  AGENT ID                    │
  │    [00 00 00 63]  CMD=DEMON_INITIALIZE=99     │
  │    [xx xx xx xx]  REQUEST ID                  │
  │    [32 bytes   ]  AES KEY  (plaintext!)       │  ParseDemonRegisterRequest()
  │    [16 bytes   ]  AES IV   (plaintext!)       │  stores key+IV for agent
  │    [hostname, user, domain, IP, ...]          │
  │──────────────────────────────────────────────▶│
  │                                               │
  │◀─────────────────────────────────────────────│
  │  HTTP 200                                     │
  │  Body:                                        │
  │    [AGENT ID LE]  AES-encrypted               │  Packer.Build() → AES-CTR
```

### 7.2 HTTP — Regular Beacon (Polling)

```
Demon                                       Teamserver
  │                                               │
  │  POST /random-uri-from-list                   │
  │  Body:                                        │
  │    [SIZE      ]  plaintext                    │
  │    [DEADBEEF  ]  MAGIC (plaintext)            │  magic check
  │    [AGENT ID  ]  plaintext                    │  agent lookup
  │    [CMD ID = 1]  GET_JOB (plaintext)          │
  │    [REQUEST ID]  plaintext                    │
  │    [encrypted ]  AES-CTR payload              │  DecryptBuffer()
  │      ↳ optional result sub-packages           │  TaskDispatch()
  │──────────────────────────────────────────────▶│
  │                                               │
  │◀─────────────────────────────────────────────│
  │  HTTP 200                                     │
  │  Body (if jobs pending):                      │
  │    [CMD_ID LE ][REQ_ID LE][SIZE LE]           │  BuildPayloadMessage()
  │    [encrypted task data  ]  AES-CTR           │
  │                                               │
  │  HTTP 200 (if no jobs):                       │
  │    [COMMAND_NOJOB][0][0]                      │
```

### 7.3 SMB Pivot

```
SMB Demon             Parent HTTP Demon           Teamserver
  │                          │                        │
  │──[named pipe]───────────▶│                        │
  │  [DEMON_ID][PKG_SIZE]    │                        │
  │  [Demon packet payload]  │  POST /uri             │
  │                          │──[relayed as HTTP]────▶│
  │                          │  [DEADBEEF header]     │  handleDemonAgent()
  │                          │  [encrypted body]      │
  │                          │◀──[HTTP 200 response]──│
  │◀─[pipe response]─────────│                        │
```

---

## 8. Key Source File Index

| File | Relevant Content |
|------|-----------------|
| `payloads/Demon/include/common/Defines.h:15` | `#define DEMON_MAGIC_VALUE 0xDEADBEEF` |
| `payloads/Demon/include/core/Package.h` | `PACKAGE` struct, `DEMON_MAX_REQUEST_LENGTH` |
| `payloads/Demon/include/core/Command.h:38` | `#define DEMON_INITIALIZE 99` |
| `payloads/Demon/src/Demon.c:95` | `DemonMetaData()` — builds registration packet |
| `payloads/Demon/src/core/Package.c` | Packet construction, AES padding logic, transmission |
| `payloads/Demon/src/core/Transport.c` | `TransportInit` (first check-in), `TransportSend` |
| `payloads/Demon/src/core/TransportHttp.c` | `HttpSend()` — WinHttp-based HTTP/HTTPS |
| `payloads/Demon/src/core/TransportSmb.c` | `SmbSend()`, `SmbRecv()`, pipe security setup |
| `payloads/Demon/src/crypt/AesCrypt.c` | AES-256-CTR implementation (Demon side) |
| `teamserver/pkg/handlers/http.go` | HTTP listener, header/URI/UA validation, fake404 |
| `teamserver/pkg/handlers/handlers.go` | `parseAgentRequest()`, `handleDemonAgent()`, magic routing |
| `teamserver/pkg/handlers/smb.go` | SMB listener stub (pipe handled by agent package) |
| `teamserver/pkg/handlers/external.go` | External C2 request handler |
| `teamserver/pkg/agent/agent.go:29` | `BuildPayloadMessage()` — server response serialization |
| `teamserver/pkg/agent/agent.go:181` | `ParseHeader()` — parses 20-byte Demon header |
| `teamserver/pkg/agent/commands.go:4` | `DEMON_MAGIC_VALUE = 0xDEADBEEF` (Go) |
| `teamserver/pkg/common/crypt/aes.go` | `XCryptBytesAES256()` — Go AES-256-CTR |
| `teamserver/pkg/common/packer/packer.go` | Response packer (AES encrypt on Build) |
| `teamserver/pkg/common/parser/parser.go` | `DecryptBuffer()` — inbound AES decrypt |
