# HVC-033 — Cryptographic Improvements

**Status:** Pending

## Problem

The current session security model has three structural weaknesses:

1. **No independent key derivation.** The MAC key is derived as
   `HMAC-SHA256(session_key, "mac")`. While functionally distinct from the encryption key, this
   is not compliant HKDF and does not provide cryptographic independence: an attacker who recovers
   the session key can immediately derive both the encryption key and the MAC key. There is no
   salt, no extract step, and no domain separation between key derivation uses.

2. **No replay protection.** Packet authentication (HMAC-SHA256 over IV + ciphertext) proves
   authenticity but not freshness. A network-adjacent attacker who captures a valid Demon packet
   can replay it indefinitely. The teamserver has no mechanism to detect or reject repeated
   packets.

3. **No forward secrecy.** Session keys are established once via RSA-2048-OAEP during
   registration and never rotated. An attacker who later recovers the RSA private key (from
   teamserver compromise, forensic image, etc.) can retrospectively decrypt all session traffic
   captured to date. The AES session key does not change over the lifetime of an implant.

These issues are independent and can be addressed incrementally. Sub-1 (HKDF) and Sub-2 (replay
counter) are straightforward engineering tasks. Sub-3 (ECDH) and Sub-4 (AES-GCM) are
architectural changes with higher complexity and are lower priority.

## Scope

| Component | Files affected |
|-----------|---------------|
| Demon | `payloads/Demon/src/crypt/Kdf.c` — new HKDF implementation |
| Demon | `payloads/Demon/include/crypt/Kdf.h` — declarations |
| Demon | `payloads/Demon/src/Demon.c` — call KDF after session key extraction in `DemonConfig()` |
| Demon | `payloads/Demon/src/core/Package.c` — use derived keys; embed SeqNo in HMAC input |
| Demon | `payloads/Demon/include/Demon.h` — add `Transport.EncKey`, `Transport.MacKey`, `Transport.SendSeqNo`, `Transport.RecvSeqNo` |
| Teamserver | `teamserver/pkg/common/crypt/kdf.go` — Go HKDF implementation |
| Teamserver | `teamserver/pkg/agent/types.go` — add `EncKey`, `MacKey`, `SendSeqNo`, `RecvSeqNo` to Agent struct |
| Teamserver | `teamserver/pkg/handlers/handlers.go` — use derived keys; verify and increment SeqNo |
| Teamserver | `teamserver/pkg/agent/agent.go` — use derived keys in `BuildPayloadMessage` |

---

## Sub-1: HKDF-Based Session Key Derivation

### Goal

Derive an independent encryption key and MAC key from the RSA-unwrapped session material using
HKDF-SHA256 (RFC 5869). Compromise of the derived encryption key must not imply compromise of
the derived MAC key, and vice versa. The current `HMAC(session_key, "mac")` derivation does not
satisfy this property.

### Algorithm

HKDF operates in two steps:

**Step 1 — Extract:**
```
PRK = HMAC-SHA256(salt, IKM)
  salt = "HavocC2KDF"  (10-byte ASCII constant)
  IKM  = session_key   (32-byte AES key from RSA-OAEP unwrap during registration)
```

**Step 2 — Expand (one call per derived key):**
```
EncKey = HKDF-Expand(PRK, info="enc", L=32)
MacKey = HKDF-Expand(PRK, info="mac", L=32)
```

`HKDF-Expand` per RFC 5869 §2.3:
```
T(0) = ""
T(1) = HMAC-SHA256(PRK, T(0) || info || 0x01)
T(2) = HMAC-SHA256(PRK, T(1) || info || 0x02)
OKM  = T(1) || T(2) || ... (truncated to L bytes)
```

For L=32 (one SHA-256 block), only T(1) is needed.

### Demon Implementation

New file: `payloads/Demon/src/crypt/Kdf.c`

```c
/* payloads/Demon/include/crypt/Kdf.h */
#ifndef DEMON_KDF_H
#define DEMON_KDF_H

#include <windows.h>

VOID HkdfExtract(
    IN  PBYTE  Salt,
    IN  SIZE_T SaltLen,
    IN  PBYTE  Ikm,
    IN  SIZE_T IkmLen,
    OUT PBYTE  Prk        /* caller-allocated, 32 bytes */
);

VOID HkdfExpand(
    IN  PBYTE  Prk,
    IN  PBYTE  Info,
    IN  SIZE_T InfoLen,
    OUT PBYTE  Out,
    IN  SIZE_T OutLen
);

#endif /* DEMON_KDF_H */
```

`HkdfExtract` and `HkdfExpand` are implemented using the existing `HmacSha256()` function in
`payloads/Demon/src/crypt/HmacSha256.c`. No new Win32 functions or hash constants are required
for Sub-1.

**Integration point in `Demon.c`:**

After the RSA-OAEP unwrap delivers the 32-byte session key in `DemonConfig()`, immediately call:

```c
BYTE Prk[ 32 ] = { 0 };
BYTE Salt[]    = "HavocC2KDF";
BYTE InfoEnc[] = "enc";
BYTE InfoMac[] = "mac";

HkdfExtract( Salt, sizeof(Salt)-1, SessionKey, 32, Prk );
HkdfExpand(  Prk, InfoEnc, sizeof(InfoEnc)-1, Instance->Transport.EncKey, 32 );
HkdfExpand(  Prk, InfoMac, sizeof(InfoMac)-1, Instance->Transport.MacKey, 32 );

/* Securely zero the PRK and session key — they are no longer needed */
MemSet( Prk,        0, 32 );
MemSet( SessionKey, 0, 32 );
```

Add `Transport.EncKey[32]` and `Transport.MacKey[32]` to the `INSTANCE` struct's `Transport`
sub-struct in `payloads/Demon/include/Demon.h`.

Replace all uses of the raw `session_key` for AES and HMAC operations in `Package.c` with
`Instance->Transport.EncKey` and `Instance->Transport.MacKey` respectively.

### Teamserver Implementation

New file: `teamserver/pkg/common/crypt/kdf.go`

```go
package crypt

import (
    "crypto/hmac"
    "crypto/sha256"
)

const hkdfSalt = "HavocC2KDF"

// HkdfExtract computes PRK = HMAC-SHA256(salt, ikm).
func HkdfExtract(ikm []byte) []byte {
    mac := hmac.New(sha256.New, []byte(hkdfSalt))
    mac.Write(ikm)
    return mac.Sum(nil)
}

// HkdfExpand derives a key of length outLen from PRK using info.
// Implements RFC 5869 §2.3 for outLen <= 32 (single SHA-256 block).
func HkdfExpand(prk []byte, info string, outLen int) []byte {
    mac := hmac.New(sha256.New, prk)
    mac.Write([]byte(info))
    mac.Write([]byte{0x01})
    t := mac.Sum(nil)
    return t[:outLen]
}

// DeriveSessionKeys derives EncKey and MacKey from a raw session key.
// The session key is the 32-byte value extracted from the RSA-OAEP-wrapped
// registration payload. Returns (encKey, macKey).
func DeriveSessionKeys(sessionKey []byte) (encKey []byte, macKey []byte) {
    prk := HkdfExtract(sessionKey)
    encKey = HkdfExpand(prk, "enc", 32)
    macKey = HkdfExpand(prk, "mac", 32)
    return
}
```

Call `DeriveSessionKeys` in `handlers.go` immediately after unwrapping the session key from the
`DEMON_INITIALIZE` packet, before storing any key material in the `Agent` struct.

Add `EncKey []byte` and `MacKey []byte` to the `Agent` struct in
`teamserver/pkg/agent/types.go`. Use these fields everywhere the session key was previously
used for AES and HMAC operations.

---

## Sub-2: Replay Protection via Sequence Counter

### Goal

Prevent a captured valid packet from being replayed by an adversary. Each packet direction gets
an independent monotonically increasing 32-bit counter embedded in the HMAC-authenticated data.
The teamserver rejects any packet whose counter is not strictly greater than the last seen value.

### Wire Format Change

This is a breaking wire format change. Both Demon and Teamserver binaries must be updated
atomically — a Demon built against the new format will not communicate with an old teamserver,
and vice versa.

**Before:**
```
base64(
    IV[16] ||
    AES-CTR(payload)[N] ||
    HMAC-SHA256(MacKey, IV[16] || AES-CTR(payload)[N])[32]
)
```

**After:**
```
base64(
    SeqNo[4, big-endian] ||
    IV[16] ||
    AES-CTR(payload)[N] ||
    HMAC-SHA256(MacKey, SeqNo[4] || IV[16] || AES-CTR(payload)[N])[32]
)
```

The 4-byte sequence number is included in the HMAC input so it cannot be tampered with without
invalidating the MAC.

### Demon Implementation

Add two fields to the `Transport` sub-struct in `payloads/Demon/include/Demon.h`:

```c
UINT32 SendSeqNo;   /* incremented before each PackageTransmitAll() call */
UINT32 RecvSeqNo;   /* last received SeqNo from teamserver; verify strictly increasing */
```

In `Package.c`, modify the encode path (`PackageTransmitAll` or the equivalent wire-encode
function) to:

1. Increment `Instance->Transport.SendSeqNo` before building the packet (starts at 1 after
   registration; registration itself uses SeqNo = 0 and does not perform replay checking since
   no session is yet established).
2. Write `SendSeqNo` as a big-endian 4-byte prefix before the IV in the output buffer.
3. Include `SeqNo[4] || IV[16] || ciphertext` as the HMAC input (instead of just `IV || ciphertext`).

On the decode path (incoming teamserver packets), verify:
```c
UINT32 ReceivedSeqNo = ReadBigEndianU32(packet);
if ( ReceivedSeqNo <= Instance->Transport.RecvSeqNo ) {
    /* Replay detected — discard packet, do not process */
    return;
}
Instance->Transport.RecvSeqNo = ReceivedSeqNo;
```

### Teamserver Implementation

Add to the `Agent` struct in `teamserver/pkg/agent/types.go`:

```go
SendSeqNo uint32   // next sequence number to embed in teamserver→Demon packets
RecvSeqNo uint32   // last valid sequence number received from Demon
```

In `handlers.go`, on receiving a Demon packet:
1. Parse the 4-byte big-endian SeqNo from the packet prefix.
2. Verify `receivedSeqNo > agent.RecvSeqNo`. If not, log and discard.
3. Update `agent.RecvSeqNo = receivedSeqNo`.
4. Include `SeqNo || IV || ciphertext` as HMAC input for verification.

In `agent.go`, when building a teamserver→Demon payload (`BuildPayloadMessage` or equivalent):
1. Atomically increment `agent.SendSeqNo`.
2. Write the new SeqNo as the first 4 bytes of the packet.
3. Include it in the HMAC input.

**Thread safety:** `SendSeqNo` and `RecvSeqNo` may be accessed from concurrent goroutines if
the agent processes multiple simultaneous connections (e.g., pivot chains). Protect with a mutex
or use atomic operations (`sync/atomic`).

---

## Sub-3: Optional ECDH Post-Registration Renegotiation

**Priority:** Lower — implement Sub-1 and Sub-2 first.

### Goal

After the initial RSA-based session establishment, perform an ephemeral ECDH P-256 key exchange
to derive forward-secret session keys. The RSA session key is then discarded. A future attacker
who recovers the RSA private key cannot decrypt previously captured traffic because the ECDH
ephemeral keys are never persisted.

### Protocol

```
1. Teamserver generates ephemeral ECDH P-256 key pair (ServerEphemPub, ServerEphemPriv).
   ServerEphemPub is included in the registration response packet (encrypted under the
   RSA-established session key).

2. Demon generates its own ephemeral ECDH P-256 key pair (ClientEphemPub, ClientEphemPriv).
   Demon computes shared secret: SharedSecret = ECDH(ClientEphemPriv, ServerEphemPub).

3. Demon sends ClientEphemPub to the teamserver in a key exchange packet (a new command ID,
   e.g., DEMON_COMMAND_KEXCHANGE), encrypted under the current RSA-derived session key.

4. Teamserver computes: SharedSecret = ECDH(ServerEphemPriv, ClientEphemPub).

5. Both sides independently run HKDF (Sub-1) on SharedSecret to derive new EncKey and MacKey.
   The RSA-derived EncKey and MacKey are replaced and the old values are securely zeroed.

6. All subsequent packets use the ECDH-derived keys. ServerEphemPriv is discarded on the
   teamserver after the shared secret is computed.
```

### Implementation Notes

**BCrypt APIs (Demon side):** BCrypt is already loaded for RSA operations in `RsaCrypt.c`. The
same resolved function pointers (`BCryptOpenAlgorithmProvider`, `BCryptGenerateKeyPair`,
`BCryptFinalizeKeyPair`, `BCryptSecretAgreement`, `BCryptDeriveKey`) are reused. No new module
loads are required.

Algorithm handle: `BCRYPT_ECDH_P256_ALGORITHM` (`L"ECDH_P256"`).

**Key serialization:** Export the public key using `BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, ...)`.
The `BCRYPT_ECCKEY_BLOB` header (8 bytes) followed by the X and Y coordinates (32 bytes each)
gives a 72-byte public key blob for transmission.

**Teamserver side (Go):** Use `crypto/elliptic` with `elliptic.P256()` and `ecdh.P256()` from
`crypto/ecdh` (Go 1.20+). Generate ephemeral key pair with `ecdh.P256().GenerateKey(rand.Reader)`.

**New command ID:**
```c
#define DEMON_COMMAND_KEXCHANGE  2590  /* ephemeral key exchange handshake */
```

**Rollback:** If ECDH fails (e.g., the teamserver is an older build that does not send
`ServerEphemPub` in the registration response), Demon continues using the HKDF-derived RSA
session keys. The ECDH step is optional and negotiated via the presence of the public key blob
in the registration response.

---

## Sub-4: AES-GCM Alternative

**Priority:** Deferred until Sub-3 is implemented.

### Goal

Replace AES-CTR + HMAC-SHA256 with AES-GCM (authenticated encryption with associated data) to
eliminate the separate MAC computation and reduce the risk of implementation errors in the
Encrypt-then-MAC construction.

### Trade-Off Analysis

| Criterion | AES-CTR + HMAC (current) | AES-GCM |
|-----------|--------------------------|---------|
| Code complexity | Higher — two separate cryptographic operations | Lower — single AEAD primitive |
| Bug surface | MAC-then-encrypt order mistakes are exploitable | AEAD eliminates ordering issue |
| BCrypt dependency in Demon | None for AES/HMAC (custom implementations) | Requires `BCryptEncrypt` with `BCRYPT_AES_GCM_ALGORITHM` |
| Detectability | Custom crypto avoids BCrypt call patterns | BCrypt calls are visible in ETW traces |
| Availability | All Windows versions | Windows Vista+ (BCrypt available) |

**Conclusion:** AES-GCM is architecturally superior but adds a BCrypt dependency to the Demon's
AES encryption path. If Sub-3 (ECDH) is implemented, BCrypt is already being loaded at runtime
for the key exchange — at that point the incremental cost of adding `BCRYPT_AES_GCM_ALGORITHM`
is minimal. Defer Sub-4 until Sub-3 is stable.

**Wire format change (when implemented):**
```
base64(
    SeqNo[4] ||
    Nonce[12] ||           /* 12-byte GCM nonce (replaces 16-byte CTR IV) */
    AES-GCM(payload)[N] ||
    GCM-Tag[16]            /* replaces HMAC-SHA256[32]; GCM tag is 16 bytes */
)
```

Note the packet is 4 bytes shorter per direction (12-byte nonce + 16-byte tag vs 16-byte IV +
32-byte HMAC). This is a wire format change requiring coordinated Demon and Teamserver update.

---

## File Map

| File | Change |
|------|--------|
| `payloads/Demon/src/crypt/Kdf.c` | New — `HkdfExtract()` and `HkdfExpand()` using existing `HmacSha256()` |
| `payloads/Demon/include/crypt/Kdf.h` | New — declarations for `HkdfExtract` and `HkdfExpand` |
| `payloads/Demon/src/Demon.c` | Call `HkdfExtract`/`HkdfExpand` after RSA unwrap in `DemonConfig()`; zero raw session key |
| `payloads/Demon/src/core/Package.c` | Replace raw session key usage with `Instance->Transport.EncKey` / `Instance->Transport.MacKey`; add SeqNo to encode/decode paths |
| `payloads/Demon/include/Demon.h` | Add `EncKey[32]`, `MacKey[32]`, `SendSeqNo`, `RecvSeqNo` to `DEMON_TRANSPORT` (or equivalent sub-struct) |
| `payloads/Demon/CMakeLists.txt` | Add `src/crypt/Kdf.c` to source list |
| `teamserver/pkg/common/crypt/kdf.go` | New — `HkdfExtract()`, `HkdfExpand()`, `DeriveSessionKeys()` |
| `teamserver/pkg/common/crypt/kdf_test.go` | New — RFC 5869 test vectors + round-trip tests |
| `teamserver/pkg/agent/types.go` | Add `EncKey []byte`, `MacKey []byte`, `SendSeqNo uint32`, `RecvSeqNo uint32` to `Agent` struct |
| `teamserver/pkg/handlers/handlers.go` | Call `DeriveSessionKeys` after RSA unwrap; verify and increment `RecvSeqNo` |
| `teamserver/pkg/agent/agent.go` | Use `agent.EncKey`/`agent.MacKey`; embed and increment `SendSeqNo` |

---

## Tests

### Sub-1: HKDF

**Go unit tests** (`teamserver/pkg/common/crypt/kdf_test.go`):
- Verify `HkdfExtract` output matches RFC 5869 Appendix A.1 test vector.
- Verify `HkdfExpand` output matches RFC 5869 Appendix A.1 test vector (L=42 case uses two T
  blocks; verify both).
- Verify `DeriveSessionKeys` produces 32-byte non-identical keys for a given session key.
- Verify different `info` strings produce different output keys (domain separation).

**Cross-implementation parity test:**
- Generate a session key; derive keys on the Go side; derive the same keys on a test harness
  linked against the Demon `Kdf.c` implementation; verify byte-for-byte equality. This ensures
  Demon and Teamserver agree on the derived keys before any integration testing.

### Sub-2: Replay Counter

- **Accepted packet:** Send a packet with SeqNo=1; verify teamserver accepts and processes it.
- **Exact replay:** Replay the same packet (SeqNo=1 again); verify teamserver drops it.
- **Reordering:** Send SeqNo=3 then SeqNo=2; verify SeqNo=2 is rejected (counter-based, not
  window-based — simpler and sufficient for a single-direction stream).
- **Overflow:** Advance SeqNo to `0xFFFFFFFF`; verify next packet with SeqNo=0 is rejected.
  Handle counter exhaustion by triggering a re-registration or connection teardown.
- **Round-trip:** Full encode→transmit→decode with derived keys + SeqNo; verify correct
  decryption and no false rejections on valid sequential packets.

### Sub-3: ECDH (when implemented)

- Verify shared secrets match on both sides for a known key pair.
- Verify that traffic captured before the ECDH exchange cannot be decrypted using only the RSA
  private key (forward secrecy property).
- Verify rollback to RSA-derived keys when the teamserver does not include `ServerEphemPub`.

---

## Notes

### Implementation Order

1. **Sub-1 (HKDF)** first — pure library code, no wire format change, no coordination required.
   Can be merged independently.
2. **Sub-2 (Replay counter)** second — requires coordinated Demon and Teamserver update because
   it changes the wire format. Both components must be rebuilt together.
3. **Sub-3 (ECDH)** third — highest complexity; depends on BCrypt already being resolved for RSA.
   Implement only after Sub-1 and Sub-2 are stable in a real deployment.
4. **Sub-4 (AES-GCM)** last — deferred until Sub-3 is in place and BCrypt is already a Demon
   dependency.

### Registration Packet Carve-Out

The `DEMON_INITIALIZE` packet (agent registration) cannot use derived keys because no session is
established yet. It continues to use the embedded AES key from the payload configuration, wrapped
in RSA-2048-OAEP. Only post-registration packets use `EncKey`/`MacKey` derived via HKDF.
The SeqNo for the registration packet is 0 and is not replay-checked (the teamserver should reject
duplicate registrations by Agent ID via existing logic, not via SeqNo).

### Never Use XOR for Encryption

None of the cryptographic functions introduced here may use XOR as an encryption primitive. The
HKDF implementation uses HMAC-SHA256. The AES-CTR encryption key must be the HKDF-derived
`EncKey`, not a raw XOR key. The MAC key must be the HKDF-derived `MacKey`.

### No BCrypt in Sub-1 or Sub-2

Sub-1 and Sub-2 deliberately avoid adding BCrypt as a dependency to the Demon's main
communication path. `HkdfExtract` and `HkdfExpand` are built from the existing standalone
`HmacSha256()` implementation in `HmacSha256.c`. This preserves the current property that the
AES + HMAC crypto path has no Windows API dependency and cannot be blocked by API hooking.
