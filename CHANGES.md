# Havoc Change Log

Unified record of every code change made outside the normal upstream development
flow. Each entry has a stable ID so individual changes can be referenced, reviewed,
or reverted in isolation.

**Format:**

```
## HVC-NNN — YYYY-MM-DD — Short title
Suggestion ref : TrafficImprovements.md §N  (if applicable)
Status         : Applied | Reverted | Superseded by HVC-NNN
Files          : list of modified files with line ranges
---
Description and rationale.
```

---

## HVC-001 — 2026-03-26 — Remove X-Havoc Response Header Leak

```
Suggestion ref : TrafficImprovements.md §1
Status         : Applied (by operator)
Files          : teamserver/pkg/handlers/http.go  line 89 (removed)
```

Removed `ctx.Header("X-Havoc", "true")` from the `fake404()` handler.

The header was returned on every request that failed header, URI, or User-Agent
validation, making the teamserver trivially identifiable from a passive scan or
by any IDS rule matching the response header. No other components required
changes. Verified present in original file; confirmed absent after edit.

**To revert:** Re-add `ctx.Header("X-Havoc", "true")` inside `fake404()` in
`teamserver/pkg/handlers/http.go` before `ctx.Writer.Write(html)`.

---

## HVC-003 — 2026-03-26 — Obfuscate Outer Header (Mask the Magic Value)

```
Suggestion ref : TrafficImprovements.md §3
Status         : Applied
Files:
  payloads/Demon/include/common/Defines.h          line 15  (added HEADER_MASK_SEED)
  payloads/Demon/src/core/Package.c                lines 259-278  (PackageTransmitNow mask/unmask)
  payloads/Demon/src/core/Package.c                lines 393-412  (PackageTransmitAll mask/unmask)
  teamserver/pkg/agent/commands.go                 line 4   (added HeaderMaskSeed)
  teamserver/pkg/agent/agent.go                    line 196 (ParseHeader unmask call)
  teamserver/pkg/common/parser/parser.go           line 209 (added XorMaskNextBytes)
```

### Problem

The 20-byte outer packet header is always transmitted in plaintext. Bytes 4–7
contain the static value `0xDEADBEEF` (`DEMON_MAGIC_VALUE`) on every single
HTTP POST body the Demon sends. This is the single highest-confidence network
IDS signature for Havoc Demon traffic — one 4-byte pattern at a fixed offset
matches all agent traffic unconditionally.

### What Was Changed

**Demon side** — `payloads/Demon/src/core/Package.c`

After the SIZE field is written to the buffer and after any AES encryption of
the payload region, a compact inline XOR block obfuscates the four header fields
at bytes 4–19 (magic value, agent ID, command ID, request ID) immediately before
`TransportSend`. An identical second block runs after `TransportSend` to reverse
the mask, leaving the package buffer in its original state.

The XOR mask is derived as:

```
mask = SIZE ^ HEADER_MASK_SEED
```

`SIZE` is the big-endian uint32 already sitting at bytes 0–3 of the buffer.
`HEADER_MASK_SEED` is a compile-time constant (`0xA3F1C2B4`) defined in
`payloads/Demon/include/common/Defines.h`. The same 4-byte mask is applied
cyclically across the 16 bytes (4 fields × 4 bytes each).

This is applied in both transmission paths:
- `PackageTransmitNow()` — used for the registration packet (`DEMON_INITIALIZE`)
- `PackageTransmitAll()` — used for all subsequent beacon packets

**Teamserver side** — `teamserver/pkg/agent/agent.go` + `parser.go`

`ParseHeader()` reads `Header.Size` first (the SIZE field is never masked), then
calls `Parser.XorMaskNextBytes(uint32(Header.Size)^HeaderMaskSeed, 16)` to
unmask the next 16 bytes before the existing `ParseInt32()` calls read magic,
agent ID, etc. The constant `HeaderMaskSeed = 0xA3F1C2B4` is added to
`teamserver/pkg/agent/commands.go` alongside `DEMON_MAGIC_VALUE`.

`XorMaskNextBytes` is a new method on `*Parser` in
`teamserver/pkg/common/parser/parser.go`. It XORs `length` bytes of the
parser's internal buffer in-place without advancing the read position.

### Effect on the Wire

Before this change, every POST body began:
```
00 00 xx xx  DE AD BE EF  [agent id]  [cmd id]  [req id]  ...
             ^^^^^^^^^^^
             static, always here
```

After this change:
```
00 00 xx xx  [mask(DEADBEEF)]  [mask(agent id)]  [mask(cmd id)]  [mask(req id)]  ...
             ^^^^^^^^^^^^^^
             different every packet (SIZE varies)
```

`mask(x) = x XOR (SIZE XOR 0xA3F1C2B4)`

### Why Bytes 0–3 (SIZE) Are Not Masked

The receiver must know the mask before it can read any field. Since the mask is
derived from SIZE, SIZE must remain unmasked so both sides can independently
compute the same value. SIZE alone is not a useful signature — it is just the
packet body length, which varies per packet.

### Revert Instructions

1. Remove `#define HEADER_MASK_SEED 0xA3F1C2B4` from `Defines.h`
2. Remove the two XOR blocks from `PackageTransmitNow()` in `Package.c`
3. Remove the two XOR blocks from `PackageTransmitAll()` in `Package.c`
4. Remove `HeaderMaskSeed` constant from `commands.go`
5. Remove `Parser.XorMaskNextBytes(...)` call from `ParseHeader()` in `agent.go`
6. Remove `XorMaskNextBytes` method from `parser.go`

Both components (Demon binary and teamserver) must be updated atomically — a
masked Demon cannot communicate with an unpatched teamserver and vice versa.

---

## HVC-004 — 2026-03-26 — Per-Request Random IV

```
Suggestion ref : TrafficImprovements.md §4
Status         : Applied
Files          :
  payloads/Demon/src/core/Package.c          lines 418-476  (PackageTransmitAll encrypt+send block replaced)
  teamserver/pkg/handlers/handlers.go        lines 99-103   (first_iter IV extraction)
```

Replaced the static `Instance->Config.AES.IV` counter with a fresh 16-byte random IV
generated per `PackageTransmitAll` call. This eliminates AES-CTR keystream reuse across
packets, which would otherwise allow a passive observer to XOR two ciphertexts and recover
plaintext if the same keystream segment is reused.

**Demon side** — `payloads/Demon/src/core/Package.c`

The entire encrypt + HVC-003-mask + send + unmask + decrypt block in `PackageTransmitAll()`
is replaced by a new block that:
1. Generates `RandIV[16]` from 4× `RandomNumber32()` calls stored in big-endian order.
2. Encrypts the payload region of `Package->Buffer` with the fresh IV via `AesInit` + `AesXCryptBuffer`.
3. Allocates a `WireBuffer` of `Package->Length + AES_BLOCKLEN` bytes.
4. Copies header (20 bytes), then `RandIV` (16 bytes), then encrypted payload into `WireBuffer`.
5. Updates `SIZE` in `WireBuffer` to `WireLength - 4` (so it covers IV + encrypted payload).
6. Applies the HVC-003 XOR mask to `WireBuffer` (using the updated `WireBuffer` SIZE as the mask base).
7. Calls `TransportSend(WireBuffer, WireLength, ...)`.
8. Wipes and frees `WireBuffer`.
9. Re-decrypts `Package->Buffer` with the same `AesCtx` for queue-management code below.

`PackageTransmitNow()` (DEMON_INITIALIZE registration packet) is intentionally **not** changed —
it continues using `Instance->Config.AES.IV`. Only beacon packets need per-request IVs.

**Teamserver side** — `teamserver/pkg/handlers/handlers.go`

In the `first_iter` block, before `DecryptBuffer`, added:
```go
PacketIV := Header.Data.ParseAtLeastBytes(16)
Header.Data.DecryptBuffer(Agent.Encryption.AESKey, PacketIV)
```
`ParseAtLeastBytes(16)` is an existing method on `*Parser` that reads exactly 16 bytes and
advances the read position, so subsequent `ParseBytes()` calls see only the payload.

**Wire format change:**

Before HVC-004 (beacon packet):
```
[SIZE(4)] [masked header(16)] [encrypted payload...]
```

After HVC-004:
```
[SIZE(4)] [masked header(16)] [RandIV(16)] [encrypted payload...]
```

SIZE is updated to cover RandIV + encrypted payload. The teamserver extracts RandIV
before decrypting, then discards it.

**To revert:**
1. In `PackageTransmitAll()`, restore the original single `AesInit`/`AesXCryptBuffer`
   with `Instance->Config.AES.IV`, the HVC-003 mask/unmask blocks operating on
   `Package->Buffer`, and `TransportSend(Package->Buffer, ...)`.
2. In `handlers.go` `first_iter` block, remove `PacketIV := Header.Data.ParseAtLeastBytes(16)`
   and restore `Header.Data.DecryptBuffer(Agent.Encryption.AESKey, Agent.Encryption.AESIv)`.

---

## HVC-002 — 2026-03-26 — Base64-Encode HTTP Request and Response Body

```
Suggestion ref : TrafficImprovements.md §2
Status         : Applied
Files          :
  payloads/Demon/src/core/MiniStd.c            lines 312-388  (Base64Encode / Base64Decode added)
  payloads/Demon/include/core/MiniStd.h        line 31        (declarations added)
  payloads/Demon/src/core/TransportHttp.c      lines 25-26, 249-254, 283-297, 302-308  (encode send, decode response, cleanup)
  teamserver/pkg/handlers/http.go              imports + lines 96-108, 185-192          (decode request, encode response)
  teamserver/pkg/handlers/external.go          imports + lines 50-58, 60-68             (decode request, encode response)
```

### Problem

All HTTP POST bodies were raw binary. A raw binary body with a 20-byte structured header
at offset 0 is immediately anomalous to any IDS or DPI system. It also makes the static
header fields trivial to match with byte-offset rules.

### What Was Changed

**Demon — `MiniStd.c` / `MiniStd.h`**

Two new functions: `Base64Encode` and `Base64Decode`. RFC 4648 standard alphabet, padding
with `=`. No CRT dependency — `LocalAlloc` only. The reverse lookup table for decode is
built on the stack (256 bytes) at call time from the shared `B64Alphabet` constant.

**Demon — `TransportHttp.c`**

- Before `WinHttpSendRequest`: `Base64Encode(Send->Buffer, Send->Length, ...)` produces an
  allocated `EncodedBuf`; the call now passes `EncodedBuf`/`EncodedSize` instead of the raw buffer.
- After reading the response: `Base64Decode(RespBuffer, RespSize, ...)` replaces the raw
  `RespBuffer`/`RespSize` assignment; the raw buffer is wiped and freed.
- `EncodedBuf` is freed in the `LEAVE` cleanup block (catches early-exit paths).

**Teamserver — `http.go`**

- After `io.ReadAll`: `base64.StdEncoding.DecodeString(string(Body))` decodes the body.
  A decode error is treated as an unrecognised request and returns `fake404`.
- In the response write path: `base64.StdEncoding.EncodeToString(Response.Bytes())` wraps
  the outgoing payload before `ctx.Writer.Write`.

**Teamserver — `external.go`**

Same decode/encode wrapper applied to `External.Request()` which shares the same
`parseAgentRequest` path.

### Wire Format Change

Before HVC-002 (request body):
```
[raw binary: SIZE(4) + masked header(16) + IV(16) + encrypted payload]
```

After HVC-002 (request body):
```
[base64(raw binary)]   ← printable ASCII, ~33% larger
```

### To Revert

1. Remove `Base64Encode`/`Base64Decode` from `MiniStd.c` and their declarations from `MiniStd.h`.
2. In `TransportHttp.c`: remove `EncodedBuf`/`EncodedSize` variables, remove the
   `Base64Encode` call, restore `WinHttpSendRequest` to pass `Send->Buffer`/`Send->Length`,
   and remove the `Base64Decode` response block and the LEAVE cleanup block.
3. In `http.go`: remove `encoding/base64` import, remove the decode block after `io.ReadAll`,
   and restore `ctx.Writer.Write(Response.Bytes())`.
4. In `external.go`: remove `encoding/base64` import and the two decode/encode blocks.

---

## HVC-006 — 2026-03-26 — HMAC-SHA256 Packet Authentication

```
Suggestion ref : TrafficImprovements.md §6
Status         : Applied
Files          :
  payloads/Demon/src/crypt/HmacSha256.c           new file     (SHA-256 + HMAC-SHA-256 implementation)
  payloads/Demon/include/crypt/HmacSha256.h        new file     (declarations + HMAC_SHA256_SIZE constant)
  payloads/Demon/src/core/Package.c                line 8       (include HmacSha256.h)
  payloads/Demon/src/core/Package.c                lines 468-503 (HMAC block in PackageTransmitAll)
  teamserver/pkg/common/crypt/aes.go               lines 1-17   (HmacSHA256 helper added)
  teamserver/pkg/handlers/handlers.go              lines 1-15, 23-70 (imports + HMAC verification in parseAgentRequest)
```

### Problem

AES-CTR is malleable — an attacker who can flip bits in the ciphertext causes
predictable changes to the plaintext without knowing the key. There was no integrity
or authenticity check on received packets.

### What Was Changed

**Demon — `HmacSha256.c` / `HmacSha256.h` (new)**

A compact pure-C SHA-256 + HMAC-SHA-256 implementation (~150 lines). No CRT, no BCrypt API
dependency. Uses only stack-allocated `SHA256_CTX` structs and `MemSet`/`MemCopy`. All
intermediate keying material (`Kpad`, `InnerHash`, the full `SHA256_CTX`) is wiped with
`MemSet` before return. The `HMAC_SHA256_SIZE 32` constant is defined in the header.

**Demon — `Package.c` `PackageTransmitAll` (inside HVC-004 block)**

After the HVC-003 mask is applied to `WireBuffer` and before `TransportSend`, a new block:
1. Derives `MacKey = HmacSha256(AES_key, 32, "mac", 3, ...)` — separate key from AES key.
2. Computes `Tag = HmacSha256(MacKey, 32, WireBuffer, WireLength, ...)` — over the entire
   authenticated wire content (SIZE + masked header + IV + ciphertext).
3. Allocates `AuthWireBuffer = WireBuffer || Tag` (WireLength + 32 bytes).
4. Calls `TransportSend(AuthWireBuffer, AuthWireLength, ...)`.
5. Wipes and frees `AuthWireBuffer`; wipes `MacKey` and `Tag`.

`PackageTransmitNow` (registration) is intentionally not modified — the session key is not
yet established on the teamserver when a registration packet arrives.

**Teamserver — `crypt/aes.go`**

`HmacSHA256(key, data []byte) []byte` — thin wrapper around `crypto/hmac` + `crypto/sha256`.

**Teamserver — `handlers.go` `parseAgentRequest`**

For known agents (already registered), before parsing the header:
1. Copies `Body` to `bodyCopy` (needed because `ParseHeader` XOR-masks the buffer in-place).
2. Calls `ParseHeader(bodyCopy)` to extract `AgentID` without mutating `Body`.
3. Strips the last 32 bytes from `Body` as the HMAC tag.
4. Derives `macKey = HmacSHA256(AESKey, "mac")` and verifies `HmacSHA256(macKey, payload) == tag`.
5. On mismatch: logs a warning and returns `false` (caller sends fake404).
6. On match: calls `ParseHeader(payload)` on the unauthenticated-tag-stripped body.

For unknown agents (registration): skips HMAC (session key not yet known) and calls
`ParseHeader(Body)` as before.

### Wire Format (after HVC-002, HVC-003, HVC-004, HVC-006)

```
base64([SIZE(4)][masked header(16)][RandIV(16)][ciphertext][HMAC-SHA256(32)])
```

### To Revert

1. Remove `HmacSha256.c` and `HmacSha256.h`.
2. In `Package.c`: remove `#include <crypt/HmacSha256.h>` and the HVC-006 block inside
   `PackageTransmitAll`; restore the direct `TransportSend(WireBuffer, WireLength, ...)` call.
3. In `crypt/aes.go`: remove `HmacSHA256` function and the `crypto/hmac`/`crypto/sha256` imports.
4. In `handlers.go`: remove the `crypto/hmac` and `Havoc/pkg/common/crypt` imports; replace
   the HVC-006 block in `parseAgentRequest` with the original single `agent.ParseHeader(Body)` call.

---

---

## HVC-005 — 2026-03-28 — RSA-2048-OAEP-SHA256 Key Wrapping

```
Suggestion ref : TrafficImprovements.md §5
Status         : Applied
Files          :
  teamserver/pkg/common/crypt/rsa.go                 new file  (key gen, blob marshal, decrypt)
  teamserver/pkg/common/crypt/rsa_test.go            new file  (3 unit tests)
  teamserver/cmd/server/types.go                     added RSAPrivateKey, RSAPublicKeyBlob fields
  teamserver/cmd/server/teamserver.go                added GenerateOrLoadRSAKeyPair call in FindSystemPackages
  teamserver/pkg/agent/types.go                      added AgentRSADecrypt to TeamServer interface
  teamserver/cmd/server/agent.go                     implemented AgentRSADecrypt
  teamserver/pkg/agent/agent.go                      ParseDemonRegisterRequest signature + RSA unwrap
  teamserver/pkg/handlers/handlers.go                pass Teamserver.AgentRSADecrypt to ParseDemonRegisterRequest
  teamserver/pkg/agent/demons.go                     pivot ParseDemonRegisterRequest call updated
  teamserver/pkg/common/builder/builder.go           SetRSAPublicKey + SERVER_PUBKEY_BLOB define in Build()
  teamserver/cmd/server/dispatch.go                  SetRSAPublicKey call before Build()
  payloads/Demon/include/crypt/RsaCrypt.h            new file  (RsaOaepEncrypt declaration)
  payloads/Demon/src/crypt/RsaCrypt.c                new file  (BCrypt RSA-OAEP-SHA256 implementation)
  payloads/Demon/src/Demon.c                         DemonMetaData key wrapping block
  client/src/global.cc                               version 1.0 "Iron Veil"
```

### Problem

The Demon registration packet transmitted the 32-byte AES session key and the
16-byte IV in plaintext as the first 48 bytes of the packet body.  Any passive
network observer who captures registration traffic recovers the session key and
can decrypt all subsequent traffic for that session.

### What Was Changed

**Teamserver — `crypt/rsa.go` (new)**

Three exported functions:

- `GenerateOrLoadRSAKeyPair(keyPath string)` — reads the private key from
  `data/havoc.rsa` (PKCS#1 DER) if it exists; otherwise generates a fresh
  RSA-2048 key pair, saves the private key at that path (mode 0600), and
  returns the key pair together with its BCRYPT_RSAPUBLIC_BLOB encoding.
- `MarshalBCryptRSAPublicBlob(pub *rsa.PublicKey) ([]byte, error)` — serialises
  a 2048-bit RSA public key as a 283-byte BCRYPT_RSAPUBLIC_BLOB (24-byte header
  + 3-byte big-endian exponent + 256-byte big-endian modulus) so it can be
  consumed by BCryptImportKeyPair on the Demon side.
- `RsaDecryptOAEP(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error)` —
  decrypts a 256-byte RSA-OAEP-SHA256 ciphertext and returns the plaintext.

**Teamserver — startup**

`FindSystemPackages()` in `teamserver.go` calls `GenerateOrLoadRSAKeyPair` and
stores the result in `Teamserver.RSAPrivateKey` / `Teamserver.RSAPublicKeyBlob`.

**Teamserver — `agent/types.go`**

`AgentRSADecrypt(ciphertext []byte) ([]byte, error)` added to the `TeamServer`
interface.  Implemented in `cmd/server/agent.go` as a thin wrapper around
`crypt.RsaDecryptOAEP`.

**Teamserver — `agent/agent.go`**

`ParseDemonRegisterRequest` gains a fourth parameter:
`rsaDecrypt func([]byte) ([]byte, error)`.

The function now reads 256 bytes (RSA ciphertext) instead of 48 bytes
(plaintext key material), calls `rsaDecrypt`, and uses the first 32 bytes
of the result as `AESKey` and bytes 32–47 as `AESIv`.  The plaintext-presence
check (`AesKeyEmpty` compare) is removed — a failed RSA decrypt returns `nil`.

**Teamserver — builder**

`SetRSAPublicKey(blob []byte)` added to `Builder`.  Inside `Build()`, if the
blob is non-empty, it is serialised as a `SERVER_PUBKEY_BLOB` compiler define
in the same format as `CONFIG_BYTES`.  `dispatch.go` calls this before `Build()`.

**Demon — `RsaCrypt.h` / `RsaCrypt.c` (new)**

`RsaOaepEncrypt(PubKeyBlob, PubKeyLen, PlainText, PlainLen, CipherText)` loads
`bcrypt.dll` at runtime via `LdrLoadDll`, resolves `BCryptOpenAlgorithmProvider`,
`BCryptImportKeyPair`, `BCryptEncrypt`, `BCryptDestroyKey`, and
`BCryptCloseAlgorithmProvider` via `LdrGetProcedureAddress` (both already
present in `Instance->Win32`).  All wide-string literals (`"bcrypt.dll"`,
`"RSA"`, `"RSAPUBLICBLOB"`, `"SHA256"`) are constructed on the stack to avoid
static Unicode data sections.  All BCrypt handles and stack buffers are cleaned
up before return.

**Demon — `Demon.c` `DemonMetaData`**

The two `PackageAddPad` calls that sent the 32-byte key and 16-byte IV are
replaced by an RSA wrapping block:
1. `KeyMaterial[48]` = `AES.Key[32] || AES.IV[16]` (stack-allocated, zeroed
   after use).
2. `RsaOaepEncrypt(SERVER_PUBKEY_BLOB, 283, KeyMaterial, 48, RsaCipherText)`.
3. On success: `PackageAddPad(*MetaData, RsaCipherText, 256)`.
4. On failure: early return (aborts registration to avoid key exposure).

### Wire Format Change

Before HVC-005 (registration body, after HVC-002 base64):
```
base64( [SIZE(4)] [masked hdr(16)] [AES_KEY(32)] [AES_IV(16)] [AES-encrypted payload...] )
```

After HVC-005:
```
base64( [SIZE(4)] [masked hdr(16)] [RSA_CIPHERTEXT(256)] [AES-encrypted payload...] )
```

The first 256 bytes after the header are now RSA-OAEP ciphertext.  The
teamserver decrypts them with its private key to recover the session keys.

### Key Persistence

The RSA private key is stored at `data/havoc.rsa` (PKCS#1 DER, mode 0600).
It is generated automatically on first start and reused on subsequent starts.
The public key blob embedded in each payload is derived from this file —
payloads built from different teamserver instances will not be compatible.

### To Revert

1. Remove `teamserver/pkg/common/crypt/rsa.go` and `rsa_test.go`.
2. Remove `RSAPrivateKey` / `RSAPublicKeyBlob` fields from `types.go`.
3. Remove the `GenerateOrLoadRSAKeyPair` call from `teamserver.go`.
4. Remove `AgentRSADecrypt` from `agent/types.go` and `cmd/server/agent.go`.
5. Revert `ParseDemonRegisterRequest` signature: remove the `rsaDecrypt`
   parameter; restore the `ParseAtLeastBytes(32)` / `ParseAtLeastBytes(16)` /
   `AesKeyEmpty` check pattern.
6. Revert the `ParseDemonRegisterRequest` call in `handlers.go` (drop the last argument).
7. Revert the `ParseDemonRegisterRequest` call in `demons.go` (drop the last argument).
8. Remove `SetRSAPublicKey` and the `SERVER_PUBKEY_BLOB` define block from `builder.go`.
9. Remove the `SetRSAPublicKey` call from `dispatch.go`.
10. Remove `payloads/Demon/include/crypt/RsaCrypt.h` and `src/crypt/RsaCrypt.c`.
11. Revert the `DemonMetaData` block in `Demon.c` to the original two `PackageAddPad` calls.
12. Remove `#include <crypt/RsaCrypt.h>` from `Demon.c`.

---

## HVC-007 — 2026-03-28 — Compress Payload Before Encryption (LZNT1)

```
Suggestion ref : TrafficImprovements.md §7
Status         : Applied
Version        : 1.1 "Cobalt Veil"
Files          :
  payloads/Demon/include/common/Defines.h     (added 3 H_FUNC_ hash constants)
  payloads/Demon/include/Demon.h              (added 3 RTL compression function pointers)
  payloads/Demon/src/Demon.c                  (DemonInit: resolve 3 RTL functions)
  payloads/Demon/src/core/Package.c           (PackageTransmitAll: HVC-007 compression block
                                               + HVC-004 block updated to use EncPayload/EncLen)
  teamserver/pkg/common/crypt/lznt1.go        (new — pure-Go LZNT1 decompressor)
  teamserver/pkg/common/crypt/lznt1_test.go   (new — 8 unit tests, all passing)
  teamserver/pkg/agent/types.go               (Header.Compressed bool field)
  teamserver/pkg/agent/agent.go               (ParseHeader: extract + strip bit 31 of SIZE)
  teamserver/pkg/handlers/handlers.go         (handleDemonAgent: decompress after AES decrypt)
  client/src/global.cc                        (version 1.1 "Cobalt Veil")
```

### Problem

Large task responses (file transfers, process listings, screenshots) are
AES-encrypted as-is, producing high-entropy ciphertext whose size is directly
proportional to the plaintext size.  Compressing before encrypting reduces the
POST body size by 40–70 % for typical structured data, shortening the time
window during which the agent is making network requests and making traffic-size
analysis harder.

### What Was Changed

#### Protocol — Compression Flag

Bit 31 of the big-endian `SIZE` wire field is now used as a compression flag:

| Bit 31 | Meaning |
|--------|---------|
| `0`    | payload is plaintext (no compression) — all previous behaviour |
| `1`    | payload was LZNT1-compressed before AES encryption |

The `SIZE` value (with bit 31 potentially set) is used as the base for the
HVC-003 XOR mask on **both** sides, so the existing mask logic is unaffected.
The teamserver strips bit 31 from `Header.Size` in `ParseHeader` immediately
after the XOR unmask step.

Compression is **only applied in `PackageTransmitAll`** (regular beacon/task
packets).  Registration packets sent via `PackageTransmitNow` (DEMON_INITIALIZE)
are never compressed.

#### Compression Threshold

Packets with a plaintext payload ≤ 256 bytes are sent uncompressed (overhead
exceeds benefit on tiny packets).  The threshold is the `COMPRESS_MIN_SIZE`
constant in `Package.c`.

#### Demon Side — `Package.c`

1. A new HVC-007 block runs after `Padding = 5 × sizeof(UINT32)` and before the
   HVC-004 IV/AES block.  It calls:
   - `RtlGetCompressionWorkSpaceSize(LZNT1|STANDARD, &WsSize, &WsFrag)`
   - `RtlCompressBuffer(LZNT1|STANDARD, payload, len, CompressedBuf, …)` with a
     4096-byte chunk size.
   If compression succeeds **and** the output is smaller than the input,
   `PayloadCompressed = TRUE` and `CompressedBuf/CompressedLen` are set.
   Otherwise the call falls back to the original uncompressed payload.

2. The HVC-004 block is parameterised through two local variables:
   ```c
   PUCHAR EncPayload = PayloadCompressed ? CompressedBuf              : Package->Buffer + Padding;
   UINT32 EncLen     = PayloadCompressed ? CompressedLen              : Package->Length - Padding;
   ```
   `AesXCryptBuffer`, `WireLength`, and all `MemCopy` calls use these variables.

3. After the HVC-006 send, cleanup is split:
   - Uncompressed path: `AesXCryptBuffer` re-decrypts `Package->Buffer` in-place
     (existing behaviour).
   - Compressed path: `CompressedBuf` (now encrypted) is zeroed and freed;
     `Package->Buffer` was never modified.

4. The compression constants and the three RTL function hashes are new:
   ```c
   #define COMPRESSION_FORMAT_LZNT1    0x0002
   #define COMPRESSION_ENGINE_STANDARD 0x0000
   #define H_FUNC_RTLGETCOMPRESSIONWORKSPACESIZE  0x3deb55f3
   #define H_FUNC_RTLCOMPRESSBUFFER               0x417e60bd
   #define H_FUNC_RTLDECOMPRESSBUFFER             0x17ab2746
   ```
   The functions are resolved from ntdll.dll (already loaded) in `DemonInit`.
   No new DLL dependency.

#### Teamserver Side — Go

- **`teamserver/pkg/common/crypt/lznt1.go`** — pure-Go LZNT1 decompressor with no
  external dependencies.  `DecompressLZNT1(data []byte) ([]byte, error)` handles
  compressed and uncompressed chunks, back-references with the variable bit-split,
  and the end-of-stream sentinel.

- **`teamserver/pkg/common/crypt/lznt1_test.go`** — 8 unit tests covering: empty
  input, zero terminator, uncompressed chunks, multiple chained chunks, compressed
  repeated-byte run, all-literal compressed chunk, mixed compressed/uncompressed
  stream, and the variable offset-bit-split path (j > 4).  All 8 pass.

- **`teamserver/pkg/agent/types.go`** — `Header.Compressed bool` field added.

- **`teamserver/pkg/agent/agent.go`** `ParseHeader`:
  ```go
  // HVC-003 XOR mask uses full SIZE (bit 31 included) — matches Demon computation
  Parser.XorMaskNextBytes(Header.Size^HeaderMaskSeed, 16)
  Header.Compressed = (Header.Size & 0x80000000) != 0
  Header.Size &= 0x7FFFFFFF
  ```

- **`teamserver/pkg/handlers/handlers.go`** `handleDemonAgent` — after AES
  decryption in the `first_iter` block:
  ```go
  if Header.Compressed {
      decompressed, err := crypt.DecompressLZNT1(Header.Data.Buffer())
      if err != nil { ... return Response, false }
      Header.Data = parser.NewParser(decompressed)
  }
  ```

### Wire Format Change

Before HVC-007 (regular beacon, after HVC-002 base64):
```
base64( [SIZE(4)] [masked_hdr(16)] [IV(16)] [AES(payload)] [HMAC(32)] )
```

After HVC-007 (when payload > 256 bytes):
```
base64( [SIZE|0x80000000(4)] [masked_hdr(16)] [IV(16)] [AES(LZNT1(payload))] [HMAC(32)] )
```

The SIZE field change is transparent to HVC-003 (same mask) and HVC-006 (HMAC
covers the full WireBuffer including the modified SIZE).

### To Revert

1. Remove `teamserver/pkg/common/crypt/lznt1.go` and `lznt1_test.go`.
2. Remove `Header.Compressed` from `types.go`.
3. Revert the `ParseHeader` block in `agent.go` (remove bit-31 extraction).
4. Remove the `if Header.Compressed` decompression block from `handlers.go`.
5. Remove the three `H_FUNC_RTLGETCOMPRESSIONWORKSPACESIZE/RTLCOMPRESSBUFFER/
   RTLDECOMPRESSBUFFER` defines from `Defines.h`.
6. Remove the three function pointer fields from `Demon.h`.
7. Remove the three `LdrFunctionAddr` calls from `Demon.c`.
8. Revert `PackageTransmitAll` in `Package.c`: remove the HVC-007 compression
   block, restore the original `AesXCryptBuffer`/`MemCopy`/`WireLength` lines
   in the HVC-004 block, and restore the unconditional `AesXCryptBuffer`
   re-decrypt at the end.

---

## HVC-008 — 2026-03-28 — SMB Pipe Framing Obfuscation

```
Suggestion ref : TrafficImprovements.md §8
Status         : Applied
Version        : 1.2 "Iron Spectre"
Files          :
  payloads/Demon/src/core/Command.c        line ~2584 (mask framing before PipeWrite)
  payloads/Demon/src/core/TransportSmb.c   lines 82, 100 (unmask after ReadFile)
  teamserver/pkg/agent/smb_framing_test.go (new — 4 unit tests)
  client/src/global.cc                     version 1.2 "Iron Spectre"
```

### Problem

The named-pipe framing header prepended to every parent→child message is
`[DEMON_ID (4 bytes)][PKG_SIZE (4 bytes)]`. `DEMON_ID` is static per agent
session and identical to the `AGENT ID` field in the Havoc HTTP header. Any
EDR driver or local process with read access to the pipe can observe the
fixed 4-byte fingerprint at the start of every message.

### Solution

XOR the two framing fields with `HEADER_MASK_SEED`-derived masks before
writing them to the pipe, and unmask on the reader side:

```c
// Writer (parent Demon, Command.c — CommandPivot DEMON_PIVOT_SMB_COMMAND):
FrameId   ^= HEADER_MASK_SEED;
FrameSize ^= (HEADER_MASK_SEED >> 8);
// → then call PipeWrite

// Reader (child Demon, TransportSmb.c — SmbRecv):
DemonId     ^= HEADER_MASK_SEED;
PackageSize ^= (HEADER_MASK_SEED >> 8);
```

The two masks (`HEADER_MASK_SEED` and `HEADER_MASK_SEED >> 8`) are different so
identical plaintext in both fields produces different on-wire bytes. The
`HEADER_MASK_SEED` constant (`0xA3F1C2B4`) is the same compile-time value used
for HVC-003 outer header obfuscation.

### Wire Format Delta

Before HVC-008 (parent → child pipe):
```
[DEMON_ID (4)] [PKG_SIZE (4)] [payload bytes]
```

After HVC-008:
```
[DEMON_ID ^ 0xA3F1C2B4 (4)] [PKG_SIZE ^ 0x00A3F1C2 (4)] [payload bytes]
```

The payload itself is unaffected; only the 8-byte framing header changes.

### Unit Tests

`teamserver/pkg/agent/smb_framing_test.go` — 4 tests:
- `TestSmbFramingConstant` — Go constant matches C `HEADER_MASK_SEED`
- `TestSmbFramingRoundTrip` — mask→unmask recovers original values (6 cases)
- `TestSmbFramingMaskChangesValue` — masks are non-trivial (non-zero)
- `TestSmbFramingIDandSizeMaskDiffer` — the two mask values differ

Run: `go test -vet=off ./pkg/agent/ -run TestSmbFraming`
(The `-vet=off` flag is needed due to pre-existing `fmt.Sprintf` vet warnings
in `demons.go` that are unrelated to HVC-008.)

### To Revert

1. In `Command.c` `DEMON_PIVOT_SMB_COMMAND` case, remove the HVC-008 framing
   mask block (the `if ( Data.Buffer && Data.Length >= 8 )` block and all
   `FrameId`/`FrameSize` lines) before the `PipeWrite` call.
2. In `TransportSmb.c` `SmbRecv`, remove the two `^= HEADER_MASK_SEED` /
   `^= (HEADER_MASK_SEED >> 8)` lines after the respective `ReadFile` calls.
3. Delete `teamserver/pkg/agent/smb_framing_test.go`.
4. Revert `client/src/global.cc` version to `"1.1"` / `"Cobalt Veil"`.

---

## BUGFIX-001 — 2026-03-28 — SMB Pivot: HVC-004/007 Interaction Fixes + Verbosity

```
Status  : Applied
Version : 1.2 "Iron Spectre"
Files   :
  payloads/Demon/src/core/Pivot.c              PivotPush: strip HVC-007 compression bit
  teamserver/pkg/agent/demons.go               DEMON_PIVOT_SMB_COMMAND: fix IV + HMAC
  payloads/Demon/src/core/TransportSmb.c       SmbSend/SmbRecv: added PRINTF verbosity
```

### Bugs fixed

**BUG-A (`Pivot.c` PivotPush — Critical)**

`PivotPush` reads the child's pipe packet length as `__builtin_bswap32(peeked_bytes) + 4`. After HVC-007, if the child's payload is >256 bytes the `PackageTransmitAll` path sets bit 31 of the big-endian SIZE field to signal LZNT1 compression. `PivotPush` did not strip bit 31, causing it to compute a length of ≥0x80000004 (~2 GB), pass that to `LocalAlloc`, get NULL back (allocation failure), pass NULL to `ReadFile`, and crash/disconnect the pivot. The fix strips bit 31 before using the value as a byte count:
```c
UINT32 RawSize = __builtin_bswap32( Length );
Length = ( RawSize & 0x7FFFFFFF ) + sizeof( UINT32 );
```
A NULL check on `LocalAlloc` was added to break cleanly if the allocation still fails.

**BUG-B (`demons.go` DEMON_PIVOT_SMB_COMMAND — Critical)**

The teamserver handler for upward SMB pivot data had two wrong assumptions left over from before HVC-004 and HVC-006:

1. **Wrong AES IV** (`DecryptBuffer` used static `AESIv`): The child Demon's
   `PackageTransmitAll` uses HVC-004 to prepend a 16-byte per-request random IV
   before the AES ciphertext. The handler was calling
   `DecryptBuffer(AESKey, staticAESIv)` instead of extracting that IV first.
   Fix: call `ParseAtLeastBytes(16)` to extract the IV, then `DecryptBuffer(AESKey, PacketIV)`.

2. **HMAC tail included in parse data** (HVC-006): `PackageTransmitAll` appends a
   32-byte HMAC-SHA256 tag at the end of the wire buffer. `ParseHeader` was called
   on the full byte slice (tag included), making the SIZE field inconsistent with
   the actual content. Fix: probe a copy to identify the child agent, then strip the
   last 32 bytes before the real `ParseHeader` call (same pattern as
   `parseAgentRequest` does for HTTP agents).

3. **Missing HVC-007 decompression**: After decrypting the child's payload, if
   `AgentHdr.Compressed` is set the payload must be LZNT1-decompressed before
   dispatching commands. Fix: mirrors the decompression block in `handleDemonAgent`.

### Verbosity added

- `SmbSend`: logs buffer length and current handle pointer on every call.
- `SmbRecv`: logs bytes available in pipe; raw (masked) and unmasked values of both
  `DemonId` and `PackageSize`; confirms successful read.
- `PivotPush`: logs raw SIZE field, computed allocation length, bytes available, and
  bytes actually read for every forwarded packet.

### To Revert BUGFIX-001

1. Revert `Pivot.c`: restore `Length = __builtin_bswap32(Length) + sizeof(UINT32);`
   and remove the `RawSize` variable and the NULL check for `Output`.
2. Revert `demons.go` `DEMON_PIVOT_SMB_COMMAND` to the previous block (static IV,
   no HMAC strip, no HVC-007 decompress). Remove `"Havoc/pkg/common/crypt"` from imports.
3. Revert `TransportSmb.c`: remove the six new `PRINTF` calls in `SmbSend`/`SmbRecv`.

---

## BUGFIX-002 — 2026-03-28 — SMB Beacon: PivotPush HMAC Length + demons.go first_iter

```
Status  : Applied
Files   :
  payloads/Demon/src/core/Pivot.c              PivotPush: add HMAC_SHA256_SIZE to alloc
  teamserver/pkg/agent/demons.go               DEMON_PIVOT_SMB_COMMAND: restore first_iter
```

### Root cause

After HVC-006, `PackageTransmitAll` appends a 32-byte HMAC-SHA256 tag **after** the wire
buffer. The SIZE field in the packet encodes the number of bytes after the SIZE field
itself (i.e. `WireLength - 4`), and does **not** include the HMAC tag.

**BUG-A (`Pivot.c` PivotPush)**

`PivotPush` computed the `ReadFile` buffer size as:
```c
Length = (RawSize & 0x7FFFFFFF) + sizeof(UINT32);   // = WireLength
```
But the actual pipe message is `WireLength + 32` bytes.  With `PIPE_TYPE_MESSAGE` pipes,
`ReadFile` with a buffer smaller than the full message returns `ERROR_MORE_DATA` (i.e.
returns FALSE while setting the error code). The packet is discarded and the child beacon
appears dead after registration (which uses `PackageTransmitNow` — no HMAC — and succeeds).

Fix:
```c
Length = (RawSize & 0x7FFFFFFF) + sizeof(UINT32) + HMAC_SHA256_SIZE;  // = WireLength + 32
```

**BUG-B (`demons.go` DEMON_PIVOT_SMB_COMMAND)**

After stripping the HMAC tail, `ParseHeader` leaves `AgentHdr.Data` pointing at:
```
[CommandID(4BE)][RequestID(4BE)][IV(16)][AES-CTR(payload)]
```
A previous fix attempt extracted the IV before the command loop with
`AgentHdr.Data.ParseAtLeastBytes(16)`, which consumed the first 16 bytes as IV —
but those 16 bytes are actually `CommandID(4) + RequestID(4) + first_8_of_IV`. The
remaining 8 bytes of IV were then passed to `cipher.NewCTR` (which requires exactly
16), causing a panic or silent decrypt failure.

The correct pattern (identical to `handleDemonAgent` in `handlers.go`): the first loop
iteration reads `Command` and `Request` (plaintext), then extracts the 16-byte IV and
decrypts the remainder (`first_iter` guard). Subsequent iterations read already-decrypted
command/request pairs.

### To Revert BUGFIX-002

1. In `Pivot.c`, change `+ HMAC_SHA256_SIZE` back to nothing (restore `sizeof(UINT32)` only).
2. In `demons.go` `DEMON_PIVOT_SMB_COMMAND`, move the IV extraction block back before
   the loop (remove `first_iter` flag and the `if first_iter` guard block).

---

## BUGFIX-003 — 2026-03-28 — SMB Pivot Stability: Four Crash/Corruption Fixes

```
Status  : Applied
Files   :
  payloads/Demon/src/core/Command.c        CommandPivot: fix Package leak on early return
  payloads/Demon/src/core/TransportSmb.c   SmbSend: fix error masking; SmbRecv: NULL guard
  payloads/Demon/src/core/Package.c        PackageTransmitAll: tighten PIPE_BUFFER_MAX limit
```

Four bugs that together caused beacon instability (typically manifesting as the SMB child
becoming unresponsive after roughly 3 checkins).

### BUG-A — `CommandPivot` DEMON_PIVOT_SMB_COMMAND: Package struct leaked on every call

`CommandPivot` creates a `Package` at the top of the function for all subcommands.  For the
`DEMON_PIVOT_SMB_COMMAND` case the function has two early `return` statements that bypass
the `PackageTransmit(Package)` at the bottom.  Because `DEMON_PIVOT_SMB_COMMAND` is the
normal job-delivery path, every time a task is forwarded to a child pivot this package
(a `LocalAlloc`'d PACKAGE struct + a reallocated buffer) was leaked.

Fix: call `PackageDestroy(Package)` before both early returns.

### BUG-B — `SmbSend`: ERROR_BROKEN_PIPE silently returned as TRUE

`SmbSend` called `PipeWrite` and only handled `ERROR_NO_DATA` as a disconnection signal.
All other `PipeWrite` failures — including `ERROR_BROKEN_PIPE` and
`ERROR_PIPE_NOT_CONNECTED` — fell through to `return TRUE`, so the caller
(`PackageTransmitAll`) believed the write succeeded, removed the packages from the pending
queue, and never retransmitted them.  Data was silently dropped.

Fix: treat all `PipeWrite` failures as disconnection (close handle, set
`Session.Connected = FALSE`, return FALSE).

### BUG-C — `SmbRecv`: NULL dereference when `LocalAlloc` fails

After unmasking `PackageSize`, `SmbRecv` called `LocalAlloc(LPTR, PackageSize)` without
checking the return value.  If the allocation failed (e.g., due to a corrupt `PackageSize`
field forcing a huge allocation), `Resp->Buffer` was NULL.  The immediately following
`PipeRead` passed that NULL pointer to `ReadFile` as the receive buffer, causing an access
violation that killed the Demon process.

Fix: return FALSE with `Session.Connected = FALSE` immediately if `LocalAlloc` returns NULL.

### BUG-D — `PackageTransmitAll` (SMB): wire buffer could exceed `PIPE_BUFFER_MAX`

The loop guard in `PackageTransmitAll` that limits batch size for SMB pivots was:
```c
if ( Package->Length + sizeof(UINT32)*3 + Pkg->Length > PIPE_BUFFER_MAX )
    break;
```
This ensured the Package content stayed within 64 KB, but it did not account for the
16-byte AES IV (HVC-004) and 32-byte HMAC tag (HVC-006) added to build the final
`AuthWireBuffer`.  When a package filled the buffer exactly, `AuthWireLength` could reach
`PIPE_BUFFER_MAX + 48` bytes.  `PipeWrite` would then split this into two `WriteFile`
calls, creating two separate pipe messages.

`PivotPush` on the parent side reads one message at a time, using the first 4 bytes as the
SIZE field.  After consuming the first (valid) 64 KB message, it encountered the 48-byte
orphaned tail message, interpreted its first 4 bytes as a random SIZE field (producing a
multi-gigabyte allocation request), failed the `LocalAlloc`, and broke the inner loop.  The
48-byte orphan remained in the pipe and blocked all future `PivotPush` reads for that pivot.

Fix: tighten the loop guard to account for `AES_BLOCKLEN + HMAC_SHA256_SIZE`:
```c
if ( Package->Length + sizeof(UINT32)*3 + Pkg->Length + AES_BLOCKLEN + HMAC_SHA256_SIZE > PIPE_BUFFER_MAX )
    break;
```
This ensures `AuthWireLength` never exceeds `PIPE_BUFFER_MAX` (reducing maximum batch
payload by 48 bytes, from ~65 KB to ~65 KB − 48 bytes, which is negligible).

### To Revert

1. In `Command.c` `DEMON_PIVOT_SMB_COMMAND`, remove the two `PackageDestroy(Package)`
   calls before the `return` statements.
2. In `TransportSmb.c` `SmbSend`, restore the `if (NtGetLastError() == ERROR_NO_DATA)`
   guard around the close+disconnect logic.
3. In `TransportSmb.c` `SmbRecv`, remove the `if (!Resp->Buffer)` block.
4. In `Package.c` `PackageTransmitAll`, remove `+ AES_BLOCKLEN + HMAC_SHA256_SIZE`
   from the SMB break condition.

---

## BUGFIX-004 — 2026-03-29 — HTTP Beacon Stability: Three Root Causes

```
Status : Applied
Files  :
  payloads/Demon/src/core/Command.c        CommandDispatcher: HTTP retry/exit logic
  payloads/Demon/src/core/Package.c        PackageTransmitNow: AES-CTR counter reset
  teamserver/pkg/handlers/handlers.go      parseAgentRequest: skip HMAC for DEMON_INIT reconnects
```

HTTP beacon became unresponsive after approximately 3 checkins (same symptom pattern as
BUGFIX-003 for SMB). Three independent root causes identified.

### BUG-A — `CommandDispatcher`: `else { break; }` permanently killed the beacon

The HTTP send block in `CommandDispatcher` used a single combined condition:

```c
if ( ! PackageTransmitAll( &DataBuffer, &DataBufferSize ) && ! HostCheckup() )
{
    CommandExit( NULL );
}
```

If `PackageTransmitAll` failed for any reason (network error, server-side HMAC reject,
HTTP 404), and `HostCheckup()` returned TRUE (host still reachable), the function fell
through to the `else` branch which executed `break`, permanently exiting the
`CommandDispatcher` loop and killing the beacon.

Additionally, the `else` block for an empty server response contained `break` directly:
```c
else {
#ifdef TRANSPORT_HTTP
    PUTS( "TransportSend: Failed" )
    break;
```

An empty 200 OK response (the normal "no jobs" reply) after any transient send failure
also triggered this path.

Fix: Separated failure detection — `PackageTransmitAll` failure now calls `continue`
after resetting `DataBuffer`/`DataBufferSize`. The empty-response `else` block now frees
`DataBuffer` and calls `continue` instead of `break`.

### BUG-B — `parseAgentRequest`: HMAC check rejected DEMON_INIT reconnect packets

HVC-006 HMAC verification was applied to all packets from known agents:

```go
if scratchErr == nil &&
    scratchHeader.MagicValue == agent.DEMON_MAGIC_VALUE &&
    Teamserver.AgentExist(scratchHeader.AgentID) &&
    len(Body) >= HmacTagSize {
    // verify HMAC ...
```

However, reconnect registration packets (DEMON_INIT / `COMMAND_CHECKIN`) are sent via
`PackageTransmitNow`, which does NOT append an HMAC tag (HVC-006 only applies to
`PackageTransmitAll`). Every reconnect attempt failed HMAC verification and received
HTTP 404, making recovery impossible once the initial session key expired or the beacon
was restarted.

Fix: Added `isReRegistration` detection — reads the CMD field from `bodyCopy[12:16]`
(already XOR-unmasked by `ParseHeader`) and adds `!isReRegistration` to the HMAC check
condition, allowing `DEMON_INIT` packets to bypass HMAC verification.

### BUG-C — `PackageTransmitNow`: AES-CTR counter advanced between two encrypt calls

`PackageTransmitNow` calls `AesXCryptBuffer` twice for `DEMON_INITIALIZE` packets:
once to encrypt `Package->Buffer + Padding` for transmission, and once more in the
`else if (Package->Encrypt)` branch to reverse-encrypt (restore plaintext) so the
`MetaData` package (with `Destroy=FALSE`) can be reused on the next reconnect.

`AesXCryptBuffer` advances `ctx->Iv` during encryption (AES-CTR counter mode). The
second call used the advanced counter position → wrong keystream → `Package->Buffer`
was left in a corrupted state after the first transmission. Every subsequent reconnect
sent garbage ciphertext that the teamserver could not decrypt.

Fix: Added `AesInit(&AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV)`
before the second `AesXCryptBuffer` call to reset the AES-CTR counter to its
original starting position, producing the correct inverse keystream.

### To Revert

1. In `Command.c` `CommandDispatcher`, restore the original combined condition:
   `if (!PackageTransmitAll(...) && !HostCheckup()) { CommandExit(NULL); }`
   and restore `break` in the `else` block.
2. In `handlers.go` `parseAgentRequest`, remove the `isReRegistration` detection
   block and remove `!isReRegistration` from the HMAC check condition.
3. In `Package.c` `PackageTransmitNow`, remove the `AesInit(&AesCtx, ...)` call
   preceding the second `AesXCryptBuffer` in the `else if (Package->Encrypt)` branch.

---

## BUGFIX-005 — 2026-03-29 — Ekko/Zilean Crash: Two Root Causes Fixed

```
Status : Applied (corrected 2026-03-29)
Files  :
  payloads/Demon/include/core/SleepObf.h   OBF_JMP macro: if → else if (line 19)
  payloads/Demon/src/core/Obf.c            TimerObf setup loop: Rsp decrement RESTORED (line 481)
  payloads/Demon/test/test_sleepobf.c      Unit tests (new file, expanded)
  payloads/Demon/CMakeLists.txt            DemonTest build target + ctest registration
```

The Ekko and Zilean sleep obfuscation techniques (timer-based, `TimerObf` in `Obf.c`)
crashed the Demon beacon on every sleep cycle. Two bugs were identified and fixed.

### BUG-A — `OBF_JMP` macro: `if` instead of `else if` (SleepObf.h)

The macro used two independent `if` statements:

```c
#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {    \
        Rop[ i ].Rax = U_PTR( p );                  \
    } if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \   /* ← plain if, not else if */
        Rop[ i ].Rbx = U_PTR( & p );                \
    } else {                                        \
        Rop[ i ].Rip = U_PTR( p );                  \
    }
```

**For `SLEEPOBF_BYPASS_JMPRAX`:**
1. First `if` = true → `Rax = fn` ✓
2. Second `if` = false → `else` runs → `Rip = fn` ✗  (JmpGadget overwritten!)

The `jmp rax` gadget address set by the setup loop was silently overwritten with the
function address, making the gadget path a no-op. The function was still called directly
(Rip = fn), so it appeared to work — but the intended dispatch mechanism was bypassed.

**For `SLEEPOBF_BYPASS_JMPRBX`:**
`Rbx = &fn` (indirect pointer for `jmp [rbx]` gadget) and `Rip` stayed as the gadget.
This mode was accidentally correct because the second `if` being true meant `else` did
not run. With the old code JMPRBX worked by coincidence; with the fix it works by design.

Fix: changed the second `if` to `else if`. Now exactly one branch fires per invocation:

| `JmpBypass` | `Rax` | `Rbx` | `Rip` |
|-------------|-------|-------|-------|
| NONE        | —     | —     | `fn` (direct call) |
| JMPRAX      | `fn`  | —     | JmpGadget unchanged (`jmp rax`) |
| JMPRBX      | —     | `&fn` | JmpGadget unchanged (`jmp [rbx]`) |

### BUG-B — `TimerObf` setup loop: `Rsp -= sizeof(PVOID)` must be PRESENT (Obf.c)

`RtlCaptureContext` internally executes `lea rax, [rsp+8]` before writing the captured
Rsp. This means `TimerCtx.Rsp` = the pre-call value (call it X), and
`[X - 8]` = the return address back into the timer dispatcher that the `call`
instruction pushed.

The setup loop must decrement by 8 so that each callback fn's `ret` lands at the
correct slot:

```c
/* CORRECT — Rop[i].Rsp = X - 8; ret pops [X-8] = timer dispatcher return addr */
for ( int i = 0; i < 13; i++ ) {
    MemCopy( &Rop[ i ], &TimerCtx, sizeof( CONTEXT ) );
    Rop[ i ].Rip  = U_PTR( JmpGadget );
    Rop[ i ].Rsp -= sizeof( PVOID );   // REQUIRED
}
```

An inadvertent earlier edit removed this line, leaving `Rop[i].Rsp = X`. Every
callback fn's `ret` then popped `[X]` — the word *above* the captured frame, which is
arbitrary garbage. The process crashed on the first sleep cycle. The decrement has been
restored.

### Unit Tests

`payloads/Demon/test/test_sleepobf.c` — assertions covering:
- `OBF_JMP` for all three bypass modes (Rip/Rax/Rbx assignment)
- Mutual exclusion between branches (only one assignment fires per call)
- TimerObf setup loop: `Rop[i].Rsp == TimerCtx.Rsp - 8` (decrement required)
- FoliageObf: NtTestAlert written at `[RopXxx->Rsp + 0]` for each Rop entry
- FoliageObf: all Rop Rsp values are distinct and within committed stack bounds

Build: `cmake --build .` → `DemonTest.exe` (MinGW cross-compiled Win64)
Run on Windows: `ctest --output-on-failure` or `DemonTest.exe` directly.

### To Revert

1. In `SleepObf.h`, change `} else if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {` back
   to `} if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {`.
2. In `Obf.c`, remove `Rop[ i ].Rsp -= sizeof( PVOID );` from the setup loop.
3. Remove `payloads/Demon/test/test_sleepobf.c` and revert `CMakeLists.txt`.

---

## BUGFIX-006 — 2026-03-29 — FoliageObf: Copy-Paste Bug in RopExitThd Setup

```
Status : Applied
Files  :
  payloads/Demon/src/core/Obf.c   line 215: RopBegin → RopExitThd
```

In `FoliageObf`, the setup block for `RopExitThd` contained:

```c
*( PVOID* )( RopBegin->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
```

This is a copy-paste error: `RopBegin` should be `RopExitThd`. The line wrote
`NtTestAlert` to `RopBegin->Rsp[0]` a second time (a no-op since it was already
written at line 134) and left `RopExitThd->Rsp[0]` with whatever the OS placed at that
stack location (zero for a freshly committed page). At runtime this is harmless because
`RtlExitUserThread` never returns — `RopExitThd->Rsp[0]` is never used as a return
address. Corrected for clarity and correctness.

### To Revert

In `Obf.c`, change `RopExitThd->Rsp` back to `RopBegin->Rsp` in the
`RopExitThd` setup block.

---

## Future / Planned

| ID      | Suggestion                          | Status  |
|---------|-------------------------------------|---------|
| HVC-009 | Raw TCP transport                   | Pending |
