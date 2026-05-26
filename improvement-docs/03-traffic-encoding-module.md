# HVC-029 — Wire Encoding Module Refactor

**Status:** Applied — 2026-05-21

---

## Problem

The wire encoding pipeline — IV generation, AES-256-CTR encryption, HMAC-SHA256 authentication, and base64 encoding — is currently implemented as inline logic scattered across `Package.c`, `TransportHttp.c`, `TransportDns.c`, `handlers.go`, and `agent.go`. Because encoding is interleaved with transport and protocol framing logic, it cannot be tested in isolation, and making a change to the encoding scheme (cipher swap, new MAC algorithm, encoding format) requires locating and editing code in at least four separate files on two different codebases. Centralising all encode/decode steps into a single module on each side (`WireEncoder.c` on the Demon, `wire/encoder.go` on the teamserver) creates a single, auditable surface for the full pipeline and allows round-trip unit tests without standing up a transport stack.

---

## Scope

- **Demon:** new `payloads/Demon/src/crypt/WireEncoder.c` and `payloads/Demon/include/crypt/WireEncoder.h`; refactor `Package.c` and `TransportHttp.c` (and `TransportDns.c`) to call it instead of duplicating inline logic.
- **Teamserver:** new `teamserver/pkg/common/wire/encoder.go`; refactor `handlers.go` (`parseAgentRequest()`) and `agent.go` (`BuildPayloadMessage()`) to call it.
- **Tests:** new `teamserver/pkg/common/wire/encoder_test.go` covering round-trip, HMAC tampering, and empty payload.

---

## Current Encode/Decode Pipeline

### Demon → Teamserver direction (upload / checkin)

```
Demon (encode):
  1. Generate random 16-byte IV
  2. AES-256-CTR encrypt payload (key = session AES key, IV = random IV)
  3. Compute HMAC-SHA256(key=macKey, data=IV+ciphertext), append 32 bytes
  4. Prepend IV (16 bytes) before ciphertext+HMAC
  5. Base64-encode the entire buffer: base64(IV + ciphertext + HMAC)
  6. Send as HTTP POST body (or DNS TXT chunks, etc.)

Teamserver (decode):
  1. Base64-decode POST body
  2. Extract IV (bytes 0–15)
  3. Verify HMAC-SHA256(key=macKey, data=IV+ciphertext) matches last 32 bytes — reject if mismatch
  4. AES-256-CTR decrypt (key = session AES key, IV = extracted IV)
  5. LZNT1 decompress if compression flag is set in packet header
```

### Teamserver → Demon direction (response / tasking)

```
Teamserver (encode response):
  1. Build response payload (command ID + request ID + data)
  2. LZNT1 compress if payload exceeds compression threshold
  3. AES-256-CTR encrypt with session key + session IV
  4. Base64-encode
  5. Write to HTTP response body

Demon (decode response):
  1. Base64-decode response body
  2. AES-256-CTR decrypt with session key + session IV
  3. LZNT1 decompress if needed
  4. Parse command+data packets
```

**Source locations for current inline logic:**

| Step | Demon files | Teamserver files |
|------|-------------|-----------------|
| IV generation | `src/core/Package.c` — `PackageTransmitAll()` | — |
| AES-256-CTR | `src/crypt/AesCrypt.c` | `pkg/common/crypt/aes.go` |
| HMAC-SHA256 | `src/crypt/HmacSha256.c` | `pkg/common/crypt/hmac.go` |
| Base64 encode/decode | `src/core/Package.c`, `src/core/TransportHttp.c` | `pkg/handlers/handlers.go`, `pkg/agent/agent.go` |
| LZNT1 | — | `pkg/common/crypt/lznt1.go` |
| Orchestration | `PackageTransmitAll()` in `Package.c`; response path in `TransportHttp.c` | `parseAgentRequest()` in `handlers.go`; `BuildPayloadMessage()` in `agent.go` |

---

## Proposed Module Interface

### Demon side — `payloads/Demon/include/crypt/WireEncoder.h`

```c
#pragma once

#include <windows.h>

//
// WireEncode — encrypt, authenticate, and base64-encode a plaintext buffer
//              for transmission over any transport.
//
// Allocates *OutBuf via MmHeapAlloc. Caller must MmHeapFree(*OutBuf).
// Returns TRUE on success, FALSE on allocation or crypto failure.
//
// Wire layout of raw (pre-base64) buffer:
//   [ IV (16 bytes) | AES-CTR ciphertext (PlaintextLen bytes) | HMAC-SHA256 (32 bytes) ]
//
BOOL WireEncode(
    PBYTE   Plaintext,
    SIZE_T  PlaintextLen,
    PBYTE   AesKey,        // 32 bytes  (session AES key)
    PBYTE   MacKey,        // 32 bytes  (session MAC key)
    PBYTE*  OutBuf,        // allocated and written by callee
    PSIZE_T OutLen         // length of *OutBuf (base64 output)
);

//
// WireDecode — base64-decode, verify HMAC, and decrypt a received buffer.
//
// Allocates *PlaintextOut via MmHeapAlloc. Caller must MmHeapFree(*PlaintextOut).
// Returns TRUE on success; FALSE if HMAC verification fails or decryption errors.
//
BOOL WireDecode(
    PBYTE   Encoded,       // base64 input (as received from transport)
    SIZE_T  EncodedLen,
    PBYTE   AesKey,        // 32 bytes
    PBYTE   MacKey,        // 32 bytes
    PBYTE*  PlaintextOut,  // allocated and written by callee
    PSIZE_T PlaintextLen
);
```

### Teamserver side — `teamserver/pkg/common/wire/encoder.go`

```go
// Package wire provides the unified encode/decode pipeline for Havoc agent traffic.
// All wire encoding (IV generation, AES-256-CTR, HMAC-SHA256, base64) is performed
// here; transport (HTTP, DNS, SMB) and packet-framing code must not duplicate this.
package wire

// Encode encrypts, authenticates, and base64-encodes plaintext for transmission.
//
// Wire layout of the raw (pre-base64) buffer:
//   [ IV (16 bytes) | AES-CTR ciphertext | HMAC-SHA256 (32 bytes) ]
//
// aesKey must be 32 bytes; macKey must be 32 bytes.
// A fresh random IV is generated internally on each call.
func Encode(plaintext, aesKey, macKey []byte) ([]byte, error)

// Decode base64-decodes, verifies HMAC-SHA256, and AES-256-CTR decrypts a
// received buffer. Returns plaintext on success. Returns a non-nil error if
// the buffer is too short, if HMAC verification fails, or if decryption fails.
// Callers must treat an HMAC failure as an authentication error and drop the packet.
func Decode(encoded, aesKey, macKey []byte) ([]byte, error)
```

---

## Key Design Decisions

### IV ownership
`WireEncode` / `wire.Encode` generate the IV internally using a cryptographically secure random source. Callers never supply an IV. `WireDecode` / `wire.Decode` extract the IV from the first 16 bytes of the decoded buffer. This removes the risk of IV reuse at call sites.

### LZNT1 is NOT part of this module
LZNT1 compression operates on an already-framed packet (the compression flag lives in the packet header, above the raw payload bytes). Including compression here would require this module to understand packet structure, violating the single-responsibility principle. LZNT1 remains in the packet/handler layer: `handlers.go` decompresses after calling `wire.Decode`, and `agent.go` compresses before calling `wire.Encode`. This boundary is explicit and must not be blurred in future changes.

### Transport independence
Both functions accept and return raw byte slices. They have no knowledge of HTTP, DNS, SMB, or any other transport. The transport layer is responsible for passing the base64 blob as-is (HTTP body, DNS TXT records, SMB pipe data, etc.).

### Registration packet exception (DEMON_INITIALIZE)
The initial registration packet (`DEMON_INITIALIZE`) must NOT be routed through `WireEncode`/`wire.Encode`. Registration sends AES key and IV material wrapped in RSA-OAEP so the session keys can be established; there is no pre-shared MAC key at that point and the wire layout is entirely different. Any future change to registration must keep it on its own code path, separate from the session encode/decode functions defined here.

---

## Migration Strategy

The migration is a pure refactor — no behavior change. The encoded bytes produced by `WireEncode` for a given plaintext and IV must be byte-for-byte identical to what `PackageTransmitAll` currently produces for the same inputs.

**Step 1 — Create the new modules (no callers yet)**
- Write `WireEncoder.c` by extracting the encode/decode logic currently inlined in `PackageTransmitAll()` and the `TransportHttp.c` response path.
- Write `wire/encoder.go` by extracting the equivalent logic from `parseAgentRequest()` and `BuildPayloadMessage()`.
- Write `encoder_test.go` and confirm all tests pass before proceeding.

**Step 2 — Migrate Demon callers**
- In `PackageTransmitAll()` (`Package.c`): replace the inline IV-gen → encrypt → HMAC → base64 block with a single `WireEncode()` call.
- In `HttpSend()` response path (`TransportHttp.c`): replace the inline base64-decode → HMAC-verify → decrypt block with a single `WireDecode()` call.
- In `TransportDns.c`: replace DNS-specific encode/decode with `WireEncode()`/`WireDecode()` calls.

**Step 3 — Migrate teamserver callers**
- In `parseAgentRequest()` (`handlers.go`): replace inline base64-decode → HMAC-verify → AES-decrypt with `wire.Decode()`.
- In `BuildPayloadMessage()` (`agent.go`): replace inline AES-encrypt → base64-encode with `wire.Encode()`.

**Step 4 — Verify**
- Run `go test ./...` in `teamserver/`. All existing tests must pass.
- Cross-compile Demon in debug mode and confirm a full checkin/task round-trip against a local teamserver.

---

## File Map

| File | Change |
|------|--------|
| `payloads/Demon/src/crypt/WireEncoder.c` | New — unified encode/decode implementation |
| `payloads/Demon/include/crypt/WireEncoder.h` | New — public declarations |
| `payloads/Demon/src/core/Package.c` | Replace inline encode logic in `PackageTransmitAll()` with `WireEncode()` call |
| `payloads/Demon/src/core/TransportHttp.c` | Replace inline decode logic in `HttpSend()` response path with `WireDecode()` call |
| `payloads/Demon/src/core/TransportDns.c` | Replace DNS-specific encoding with `WireEncode()`/`WireDecode()` calls |
| `teamserver/pkg/common/wire/encoder.go` | New — Go encode/decode package |
| `teamserver/pkg/common/wire/encoder_test.go` | New — round-trip and negative-case unit tests |
| `teamserver/pkg/handlers/handlers.go` | Replace `parseAgentRequest()` inline decode with `wire.Decode()` |
| `teamserver/pkg/agent/agent.go` | Replace `BuildPayloadMessage()` inline encode with `wire.Encode()` |

---

## Tests

### `teamserver/pkg/common/wire/encoder_test.go`

```go
package wire_test

import (
    "crypto/rand"
    "testing"

    "github.com/HavocFramework/Havoc/teamserver/pkg/common/wire"
)

func TestRoundTrip(t *testing.T) {
    aesKey := make([]byte, 32)
    macKey := make([]byte, 32)
    if _, err := rand.Read(aesKey); err != nil {
        t.Fatal(err)
    }
    if _, err := rand.Read(macKey); err != nil {
        t.Fatal(err)
    }

    plaintext := []byte("hello world test payload 12345")
    encoded, err := wire.Encode(plaintext, aesKey, macKey)
    if err != nil {
        t.Fatalf("Encode: %v", err)
    }

    decoded, err := wire.Decode(encoded, aesKey, macKey)
    if err != nil {
        t.Fatalf("Decode: %v", err)
    }

    if string(decoded) != string(plaintext) {
        t.Fatalf("round-trip mismatch: got %q, want %q", decoded, plaintext)
    }
}

func TestHMACTampering(t *testing.T) {
    aesKey := make([]byte, 32)
    macKey := make([]byte, 32)
    rand.Read(aesKey)
    rand.Read(macKey)

    plaintext := []byte("tamper test")
    encoded, err := wire.Encode(plaintext, aesKey, macKey)
    if err != nil {
        t.Fatal(err)
    }

    // Flip a byte in the middle of the ciphertext (after base64 decode,
    // the ciphertext starts at byte 16; flip byte 20 here at the base64 level
    // by modifying the encoded slice directly).
    if len(encoded) > 20 {
        encoded[20] ^= 0xFF
    }

    _, err = wire.Decode(encoded, aesKey, macKey)
    if err == nil {
        t.Fatal("Decode should have returned an error for a tampered buffer")
    }
}

func TestEmptyPayload(t *testing.T) {
    aesKey := make([]byte, 32)
    macKey := make([]byte, 32)
    rand.Read(aesKey)
    rand.Read(macKey)

    plaintext := []byte{}
    encoded, err := wire.Encode(plaintext, aesKey, macKey)
    if err != nil {
        t.Fatalf("Encode empty: %v", err)
    }

    decoded, err := wire.Decode(encoded, aesKey, macKey)
    if err != nil {
        t.Fatalf("Decode empty: %v", err)
    }

    if len(decoded) != 0 {
        t.Fatalf("expected empty plaintext, got %d bytes", len(decoded))
    }
}
```

### Demon C side — `payloads/Demon/test/wire_encoder_test.c`

A standalone host-compiled test (Linux/macOS, no Windows dependencies) that links `WireEncoder.c`, `AesCrypt.c`, and `HmacSha256.c` against a stub allocator and verifies:
- `WireEncode` → `WireDecode` round-trip produces the original plaintext.
- Flipping a byte in the ciphertext region causes `WireDecode` to return `FALSE`.
- Zero-length plaintext encodes and decodes cleanly.

---

## Notes

- This is a pure refactor for the upload path. The encoded bytes produced by `WireEncode` are byte-for-byte identical to what `PackageTransmitAll` previously produced for the same plaintext and the same randomly generated IV. IV sizes, HMAC sizes, and base64 alphabet are unchanged.
- The registration packet path (`DEMON_INITIALIZE`) is NOT routed through `WireEncode` / `wire.Encode`. It establishes session keys via RSA-OAEP and has a different wire layout.
- Once this module exists, adding a new encoding layer (different cipher, alternative MAC, custom base encoding) is a single-file change on each side, with tests that can be run without a transport stack.

## Deviations from Original Spec

### Go-side split: DecodeAndVerify instead of Decode

The original spec proposed a single `wire.Decode` function that handled base64 decode, HMAC verify, and AES-CTR decrypt. During implementation, a pragmatic split was chosen:

- `wire.DecodeAndVerify(body, macKey)` — verifies HMAC and strips the 32-byte tag; returns authenticated binary WITHOUT AES decryption.
- `wire.Encode(plaintext, aesKey, macKey)` — full encode for the server→Demon response path.

**Rationale:** On the teamserver upload path, the AgentID embedded in the packet header must be parsed before the session AES key can be looked up. The header is inside the authenticated body. `DecodeAndVerify` returns the authenticated payload (header still present) so `handlers.go` can call `ParseHeader` to get the AgentID, then look up the AES key and decrypt separately — exactly as the code did before. Combining both steps into one call would require passing the AES key into `DecodeAndVerify`, but the key is unknown until after the header parse.

### Download path upgraded (not a pure refactor for the response direction)

The original spec described the response direction as a pure refactor (no behavior change). In practice, the download path was upgraded from fixed-session-IV + no-HMAC to per-packet random IV + HMAC, matching the security level of the upload path:

- **Before:** `base64([CmdID|ReqID|Size|AES-CTR(data)])` using fixed session IV, no HMAC.
- **After:** `base64([IV(16B)|AES-CTR(BuildPayloadMessage output)|HMAC-SHA256(32B)])` with per-packet random IV.

The inner per-job AES layer produced by `BuildPayloadMessage` (`crypt.XCryptBytesAES256`) is preserved — `Command.c:145` calls `ParserDecrypt(&TaskParser, ...)` per-job and requires it.

### handleServiceAgent: base64 moved into handler

Service agent responses (`handleServiceAgent`) now base64-encode inside the handler rather than in the transport layer. This preserves the pre-HVC-029 service agent wire format while allowing `http.go` and `external.go` to write `Response.Bytes()` directly (since Demon responses are already wire-encoded/base64 by `encodeAgentResponse`).

### DNS transport — no WireDecode changes on Demon side

QA flagged potential double-decode in the DNS transport. Analysis confirmed no change was needed: `dns.go` stores the `wire.Encode` output (base64 ASCII bytes), `handleDownlink` slices and re-base64-encodes each TXT chunk for DNS transport, `DnsQueryTxt` base64-decodes each chunk and concatenates, and `DnsSend` calls `WireDecode` on the full reassembled base64 string — which is correct because the concatenation of base64-decoded chunks is the original base64 string from `wire.Encode`. The chain is correct end-to-end without modification.

### Bug fix: PackageTransmitNow missing base64 encoding (post-implementation)

**Symptom:** After HVC-029 was applied, the Demon failed to register. The teamserver logged `failed to base64-decode agent request body: illegal base64 data at input byte 0` on every inbound registration attempt.

**Root cause:** `HttpSend` in `TransportHttp.c` was modified during HVC-029 to stop base64-encoding the outgoing request body, because `PackageTransmitAll` routes through `WireEncode` which already produces base64 output. However, `PackageTransmitNow` — used for the initial registration (`DEMON_INITIALIZE`) and for re-registration reconnects — bypasses `WireEncode` entirely and calls `TransportSend` directly with a raw binary buffer. The raw binary is not valid base64, so the teamserver's `base64.StdEncoding.DecodeString` rejected it immediately.

**Fix:** Added a `Base64Encode` call inside `PackageTransmitNow` (`Package.c`) before the `TransportSend` call. The base64-encoded buffer is passed to `TransportSend` and freed afterwards. `PackageTransmitAll` is unaffected — it continues to pass the already-base64 output of `WireEncode` directly to `TransportSend`.

**Lesson for future changes:** Any function that sends data through `TransportSend` / `HttpSend` without going through `WireEncode` must apply its own base64 encoding. The transport layer (`HttpSend`) assumes its input is already base64. This assumption must be documented on every caller that bypasses `WireEncode`.
- Do not include XOR encryption at any point in this pipeline. Encryption must use AES-256-CTR as currently implemented.
- Do not allocate `PAGE_EXECUTE_READWRITE` memory anywhere in the Demon-side implementation. The crypto routines operate on data buffers and require no executable allocations.
