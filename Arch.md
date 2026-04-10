# Havoc C2 Protocol Architecture

This document is a canonical reference for the full wire protocol, encryption pipeline,
and transport-channel semantics as of v1.2 "Iron Spectre".  It covers all HVC changes
(001–008) and all known BUGFIX patches.  Read this before touching any transport or
cryptography code in Teamserver or Demon.

---

## 1. System Overview

```
Operator UI (Qt5 C++)
       |  WebSocket (JSON events)
       v
 Teamserver (Go)  ←──────── HTTP/HTTPS/SMB/External ──────→  Demon Agent (C)
       |
    SQLite DB
```

The Teamserver is the single source of truth.  Multiple operators connect via WebSocket.
Demons call home on their configured transport (HTTP, HTTPS, SMB pivot, or External C2).

---

## 2. Transport Channels

### 2.1 HTTP / HTTPS (TRANSPORT_HTTP)

**Direction:** Demon ─► Teamserver (POST request), Teamserver ─► Demon (response body)

**Request flow (per-checkin):**
1. Demon calls `PackageTransmitAll` → `TransportSend` → `HttpSend`
2. `HttpSend` base64-encodes (HVC-002) the fully-assembled wire buffer
3. Sends as HTTP POST body; reads response body
4. Response is base64-decoded (HVC-002) and handed back as the job payload

**Response:** The teamserver writes the job payload (BuildPayloadMessage output)
base64-encoded into the HTTP response body with status 200.

**Connection lifecycle:**
- `TransportInit` (`PackageTransmitNow`) handles registration (DEMON_INITIALIZE)
- `CommandDispatcher` do-while loop handles the normal checkin cycle
- On any network error: retry after sleep (BUGFIX-004) rather than dying permanently
- All hosts exhausted: `CommandExit` (controlled shutdown)

### 2.2 HTTPS

Identical to HTTP.  `WINHTTP_FLAG_SECURE` is set on the WinHttp request.
Self-signed certificate errors are suppressed by `SECURITY_FLAG_IGNORE_*` options.

### 2.3 SMB Named Pipe Pivot (TRANSPORT_SMB)

**Direction:** Parent Demon ─► Child Demon (named pipe, message mode)

The child (pivot) Demon creates and listens on `CreateNamedPipeW`.
The parent Demon connects to it and relays jobs from the teamserver.

**SMB pipe framing (HVC-008):**
- Parent writes `[DemonId XOR HEADER_MASK_SEED][PackageSize XOR (HEADER_MASK_SEED>>8)][payload]`
- Child (`SmbRecv`) unmasks both fields before reading the payload

**Relay path:**
```
Teamserver → HTTP Parent Demon → Named Pipe → Child Demon (SMB)
                        ↑                          ↓
                  PivotPush()            DEMON_PIVOT_SMB_COMMAND
```

**BatchLimit (BUGFIX-003 BUG-D):**
`PackageTransmitAll` batch constraint for SMB is `PIPE_BUFFER_MAX - AES_BLOCKLEN - HMAC_SHA256_SIZE`
to prevent the wire buffer from exceeding one `WriteFile` message.  Splitting a
`PIPE_TYPE_MESSAGE` write into two messages produces an unreadable orphan tail.

**Connection lifecycle:**
- SMBGetJob polls with PeekNamedPipe; `continue` on failure (no break)
- BUG-B (BUGFIX-003): any `PipeWrite` failure closes handle and sets `Connected=FALSE`
- BUG-C (BUGFIX-003): `LocalAlloc` failure in `SmbRecv` returns FALSE, no NULL deref
- BUG-A (BUGFIX-003): `PackageDestroy` called on early return in `CommandPivot`

### 2.4 External C2 (LISTENER_EXTERNAL)

Handled by `external.go`.  Identical HVC-002 base64 wrapping.  `parseAgentRequest`
is shared with the HTTP handler.  The external endpoint is a WebSocket registered
on the gin router.

---

## 3. Packet Wire Format

### 3.1 Normal Checkin Packet (PackageTransmitAll → HTTP/HTTPS)

```
┌────────────────────────────────────────────────────────────┐
│  HVC-003 masked outer header (bytes 4-19 XOR'd)            │
│                                                            │
│  Byte 0-3:   SIZE  (big-endian, 32-bit, bit31=compress)    │
│  Byte 4-7:   MAGIC (0xDEADBEEF, XOR masked)                │
│  Byte 8-11:  AgentID (XOR masked)                          │
│  Byte 12-15: CommandID (XOR masked)  [outer: GET_JOB=1]    │
│  Byte 16-19: RequestID (XOR masked)                        │
├────────────────────────────────────────────────────────────┤
│  HVC-004: Random IV, 16 bytes (plaintext)                  │
├────────────────────────────────────────────────────────────┤
│  HVC-007 (optional): LZNT1-compressed inner payload        │
│  AES-256-CTR encrypted with above IV                       │
│                                                            │
│  Inner payload (per sub-package):                          │
│    [CommandID (4 BE)][RequestID (4 BE)][SIZE (4 BE)][data] │
├────────────────────────────────────────────────────────────┤
│  HVC-006: HMAC-SHA256 tag, 32 bytes (over all bytes above) │
└────────────────────────────────────────────────────────────┘
   ← entire structure base64-encoded (HVC-002) on the wire →
```

**HVC-003 mask derivation:**
- `mask = SIZE ^ HEADER_MASK_SEED` (where `HEADER_MASK_SEED = 0xA3F1C2B4`)
- Bytes 4-19 XOR'd with repeating 4-byte `mask` (big-endian byte order)
- SIZE includes bit 31 when HVC-007 compression is active; mask uses full SIZE

**HVC-006 MAC key:**
- `macKey = HMAC-SHA256(AES_session_key, "mac")`
- `tag = HMAC-SHA256(macKey, wire_buffer_without_tag)`

### 3.2 Registration Packet (PackageTransmitNow → DEMON_INITIALIZE)

```
┌────────────────────────────────────────────────────────────┐
│  Outer header: 20 bytes (HVC-003 masked)                   │
│    [SIZE][MAGIC][AgentID][DEMON_INITIALIZE=0][RequestID]   │
├────────────────────────────────────────────────────────────┤
│  HVC-005: RSA-2048-OAEP-SHA256 ciphertext, 256 bytes       │
│    Wraps: [AES_session_key (32)][AES_session_IV (16)]      │
│    Encrypted under teamserver's RSA public key             │
├────────────────────────────────────────────────────────────┤
│  AES-256-CTR encrypted metadata (session IV, no random IV) │
│    [DemonID][Hostname][Username][Domain][IP][ProcessName]  │
│    [PID][PPID][Arch][Elevated][BaseAddr][OsVersion][...]   │
└────────────────────────────────────────────────────────────┘
   ← NO HMAC tag (HVC-006 is only in PackageTransmitAll) →
   ← base64-encoded (HVC-002) on the wire →
```

**Notes:**
- No HVC-004 random IV; the session IV is used directly
- `MetaData->Destroy = FALSE` so the package survives for reconnects
- BUGFIX-004: AesCtx re-initialized before reverse decrypt to restore plaintext buffer
- Server skips HMAC check for DEMON_INIT from known agents (BUGFIX-004)

### 3.3 Server Response to Demon (BuildPayloadMessage)

```
Per-job frame (repeated for each queued job):
┌─────────────────────────────────────────────────┐
│  CommandID  (4 bytes, little-endian)             │
│  RequestID  (4 bytes, little-endian)             │
│  PayloadLen (4 bytes, little-endian)             │
│  Payload    (PayloadLen bytes, AES-256-CTR)      │
│    encrypted with session key+IV (NOT random IV) │
└─────────────────────────────────────────────────┘
   ← entire response base64-encoded (HVC-002) →
```

**NOJOB** (`CommandID=10, RequestID=0, PayloadLen=0`): 12 bytes, no encryption.

**Parsing on Demon side** (`CommandDispatcher`):
- `ParserGetInt32` reads CommandID (LE, no bswap)
- `ParserGetInt32` reads RequestID (LE)
- `ParserGetBytes` reads PayloadLen (LE) then PayloadLen bytes
- If `PayloadLen > 0`: `ParserDecrypt` with session IV
- Loop exits when `Parser.Length <= 12`

### 3.4 SMB Pipe Framing (HVC-008)

```
Parent writes to pipe:
[DemonId ^ HEADER_MASK_SEED (4 bytes)]
[PackageSize ^ (HEADER_MASK_SEED>>8) (4 bytes)]
[PackageTransmitAll wire buffer (PackageSize bytes)]
```

The PackageSize field reflects the full wire buffer length including
the HVC-006 HMAC tag (BUGFIX-002: `PivotPush` allocates `WireLength + HMAC_SHA256_SIZE`).

---

## 4. Encryption and Authentication Pipeline

### 4.1 Session Key Exchange (HVC-005)

```
Demon generates:
  AES_key   = 32 random bytes (via RandomNumber32, LSB per byte)
  AES_IV    = 16 random bytes

RSA encrypt:
  ciphertext = RSA-OAEP-SHA256( server_pubkey, [AES_key || AES_IV] )

Teamserver (ParseDemonRegisterRequest):
  keyMaterial = RSA-OAEP-SHA256 decrypt( server_privkey, ciphertext )
  agent.AESKey = keyMaterial[0:32]
  agent.AESIv  = keyMaterial[32:48]
```

### 4.2 Packet Encryption (HVC-004 + AES-CTR)

```
Per checkin (PackageTransmitAll):
  RandIV = 4 × RandomNumber32() stored big-endian
  encrypted_payload = AES-256-CTR( AES_key, RandIV, plaintext_payload )
  wire = [header (20)] [RandIV (16)] [encrypted_payload] [HMAC (32)]

Teamserver decryption (handleDemonAgent first_iter):
  PacketIV = Header.Data.ParseAtLeastBytes(16)
  Header.Data.DecryptBuffer(AES_key, PacketIV)
```

Go's `cipher.NewCTR` does not mutate the IV; Demon's `AesXCryptBuffer` uses a
local `AESCTX` stack variable — neither side mutates the session IV.

### 4.3 HMAC Authentication (HVC-006)

```
macKey = HMAC-SHA256(AES_session_key, "mac")   # derived once per session
tag    = HMAC-SHA256(macKey, wire_buffer)       # computed per packet

Appended after wire_buffer before base64 encoding.
Teamserver verifies before parsing (constant-time comparison via crypto/hmac.Equal).
```

**Only applies to `PackageTransmitAll` packets.  Registration packets (PackageTransmitNow)
do NOT carry an HMAC tag.**

### 4.4 LZNT1 Compression (HVC-007)

```
Demon side (PackageTransmitAll):
  if payload > 256 bytes AND RtlCompressBuffer available:
    compressed = RtlCompressBuffer(LZNT1, payload)
    if compressed_len < original_len:
      set bit 31 of wire SIZE field
      use compressed as payload for AES encryption

Teamserver side (handleDemonAgent first_iter):
  if Header.Compressed:
    decompressed = DecompressLZNT1(Header.Data.Buffer())
    Header.Data = NewParser(decompressed)
```

Registration packets (DEMON_INITIALIZE via PackageTransmitNow) are NEVER compressed.

### 4.5 HVC-003 Header Obfuscation

Applied in both `PackageTransmitAll` (on WireBuffer copy) and `PackageTransmitNow`
(directly on Package->Buffer, reversed after send).

```
mask_int = SIZE ^ HEADER_MASK_SEED   (HEADER_MASK_SEED = 0xA3F1C2B4)
mask_bytes = [mask_int>>24, mask_int>>16, mask_int>>8, mask_int]
bytes[4..19] ^= mask_bytes[i%4]
```

The SIZE used for the mask includes bit 31 (compression flag) before stripping.

---

## 5. Transport Compatibility Matrix

| Feature              | HTTP | HTTPS | SMB Pivot | External C2 |
|----------------------|------|-------|-----------|-------------|
| HVC-001 X-Havoc hdr  | ✓    | ✓     | N/A       | N/A         |
| HVC-002 Base64 body  | ✓    | ✓     | N/A       | ✓           |
| HVC-003 Header XOR   | ✓    | ✓     | ✓         | ✓           |
| HVC-004 Random IV    | ✓    | ✓     | ✓         | ✓           |
| HVC-005 RSA key wrap | ✓    | ✓     | ✓         | ✓           |
| HVC-006 HMAC-SHA256  | ✓    | ✓     | ✓         | ✓           |
| HVC-007 LZNT1 compr. | ✓    | ✓     | ✓         | ✓           |
| HVC-008 Pipe masking | N/A  | N/A   | ✓         | N/A         |

---

## 6. Endianness Reference

| Field                        | Endian | Where                        |
|------------------------------|--------|------------------------------|
| Outer header (SIZE, MAGIC, …)| Big    | Int32ToBuffer (Demon)        |
| Inner sub-package CommandID  | Big    | Int32ToBuffer (Demon)        |
| Inner sub-package RequestID  | Big    | Int32ToBuffer (Demon)        |
| Inner sub-package SIZE field | Big    | Int32ToBuffer (Demon) → `PackageAddBytes` |
| Server response CommandID    | Little | binary.LittleEndian (Go)     |
| Server response RequestID    | Little | binary.LittleEndian (Go)     |
| Server response PayloadLen   | Little | binary.LittleEndian (Go)     |
| SMB pipe DemonId             | Little | native x86 struct field      |
| SMB pipe PackageSize         | Little | native x86 struct field      |

**Demon `ParserGetInt32`:** `parser->Endian = 0` (no bswap) → reads little-endian.
**Go `parser.ParseInt32`:** `bigEndian = true` by default → reads big-endian.
**Go `BuildPayloadMessage`:** always writes little-endian fields.

---

## 7. Connection Lifecycle State Machine

```
                [DEMON_INITIALIZE] ──► TransportInit
                                             │ success
                                             ▼
                                    Session.Connected = TRUE
                                             │
                                             ▼
                                   ┌──CommandDispatcher──┐
                                   │                     │
                             PackageTransmitAll          │
                                   │ fails               │ OK
                                   ▼                     ▼
                             HostCheckup          parse response
                                   │ dead                │
                                   ▼                     ▼
                              CommandExit         dispatch tasks
                                                        │
                                               ◄────────┘ (loop)
```

**HTTP retry (BUGFIX-004):** `PackageTransmitAll` failure → `continue` (retry after sleep).
**SMB retry (pre-existing):** `SMBGetJob` failure → `continue` (retry after sleep).

---

## 8. Applied Changes Summary

| ID         | Description                          | Key Files                                  |
|------------|--------------------------------------|--------------------------------------------|
| HVC-001    | X-Havoc header validation            | http.go, client                            |
| HVC-002    | Base64 HTTP body encoding            | TransportHttp.c, http.go, external.go      |
| HVC-003    | Header XOR obfuscation               | Package.c, agent.go (ParseHeader)          |
| HVC-004    | Per-request random IV                | Package.c, handlers.go                     |
| HVC-005    | RSA-2048-OAEP session key wrap       | Package.c, Demon.c, handlers.go, rsa.go    |
| HVC-006    | HMAC-SHA256 authentication           | Package.c, handlers.go, crypt/aes.go       |
| HVC-007    | LZNT1 payload compression            | Package.c, Demon.c, lznt1.go, handlers.go  |
| HVC-008    | SMB pipe frame masking               | Command.c, TransportSmb.c                  |
| BUGFIX-002 | SMBPivot: PivotPush HMAC alloc       | Pivot.c                                    |
| BUGFIX-003 | SMBPivot: 4 stability fixes (A-D)    | Command.c, TransportSmb.c, Package.c       |
| BUGFIX-004 | HTTP beacon stability: 3 fixes       | Command.c, handlers.go, Package.c          |

---

## 9. BUGFIX-004 Detail (HTTP Beacon Stability)

**Symptom:** HTTP beacon crashes after a few checkins.

**Root cause A — `CommandDispatcher` HTTP `else { break; }`:**
When `PackageTransmitAll` fails (network error, HMAC reject, server down), DataBuffer=NULL
and the `else { break; }` permanently killed the beacon.  Fixed: separate failure detection
from data check; retry with `continue` on transient failures.

**Root cause B — `parseAgentRequest` HMAC check on re-registration:**
A reconnecting beacon sends DEMON_INITIALIZE (via `PackageTransmitNow`) without an HMAC tag.
Because the agent was already registered, the server applied HMAC verification and always
failed → HTTP 404 → beacon could never reconnect.  Fixed: detect DEMON_INIT in outer CMD
field (bodyCopy[12:16] after XOR unmask) and skip HMAC for re-registration packets.

**Root cause C — `PackageTransmitNow` AES-CTR double-call:**
The reverse-decrypt after transmission used an already-advanced AES-CTR counter, producing
a wrong keystream that corrupted `Package->Buffer`.  Subsequent reconnects sent garbage.
Fixed: re-initialize `AesCtx` before the reverse `AesXCryptBuffer` call.

---

## 10. Development Checklist

When modifying transport or crypto code:

1. **Read this file and `Demon.md` / `Teamserver.md` first.**
2. Verify HVC-003 mask: does SIZE include bit31 before masking? Does teamserver match?
3. Verify HVC-004 IV: is it prepended to WireBuffer (not PackageBuffer)?  Random, not session?
4. Verify HVC-006 HMAC: computed on the masked wire buffer; 32-byte tag appended last.
5. Verify HVC-007: bit31 of SIZE set before masking; teamserver strips bit31 after unmask.
6. Verify HVC-008 (SMB): DemonId and PackageSize masked/unmasked with correct constants.
7. Registration vs checkin: PackageTransmitNow has NO random IV, NO HMAC.
8. Endianness: outer header = big-endian; server response = little-endian.
9. Write a unit test for any new wire-format change.
10. Update `CHANGES.md`, bump client version in `client/src/global.cc`.
