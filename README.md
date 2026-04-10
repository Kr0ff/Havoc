<div align="center">
  <img width="125px" src="assets/Havoc.png" />
  <h1>Havoc</h1>
  <br/>

  <p><i>Havoc is a modern and malleable post-exploitation command and control framework, created by <a href="https://twitter.com/C5pider">@C5pider</a>.</i></p>
  <br />

  <img src="assets/Screenshots/FullSessionGraph.jpeg" width="90%" /><br />
  <img src="assets/Screenshots/MultiUserAgentControl.png" width="90%" /><br />

</div>

### Quick Start

> Please see the [Wiki](https://github.com/HavocFramework/Havoc/wiki) for complete documentation.

Havoc works well on Debian 10/11, Ubuntu 20.04/22.04 and Kali Linux. It's recommended to use the latest versions possible to avoid issues. You'll need a modern version of Qt and Python 3.10.x to avoid build issues.

See the [Installation](https://havocframework.com/docs/installation) docs for instructions. If you run into issues, check the [Known Issues](https://github.com/HavocFramework/Havoc/wiki#known-issues) page as well as the open/closed [Issues](https://github.com/HavocFramework/Havoc/issues) list.

---

### What's New in 0.8 "Silent Storm"

This release focuses on hardening the HTTP(S) transport layer against network-level detection and packet analysis. All changes are applied to the Demon agent and the teamserver; the client and SMB transport are unaffected. Full details and revert instructions are in [`CHANGES.md`](CHANGES.md).

#### Removed Teamserver Fingerprint Header (HVC-001)

- Removed the `X-Havoc: true` response header that was returned on every rejected HTTP request. This header made the teamserver trivially identifiable by passive scanners and IDS rules matching the response.

#### Base64-Encoded HTTP Bodies (HVC-002)

- All HTTP POST bodies sent by the Demon are now Base64-encoded before transmission; the teamserver decodes them before parsing.
- The teamserver Base64-encodes all responses before writing them to the wire; the Demon decodes them after reading.
- A compact RFC 4648 Base64 encode/decode implementation was added to the Demon (`MiniStd.c`) with no CRT dependency.
- Applies to both the HTTP listener (`http.go`) and the External C2 handler (`external.go`).
- Raw binary POST bodies are immediately anomalous to DPI systems. Base64 payloads are indistinguishable from the token fields and encoded data that appear routinely in legitimate web traffic.

#### Obfuscated Outer Packet Header (HVC-003)

- The 20-byte outer packet header contains the static value `0xDEADBEEF` at a fixed byte offset in every POST body. This was the single highest-confidence network IDS signature for Havoc traffic.
- The four header fields that follow the SIZE field (magic value, agent ID, command ID, request ID — bytes 4–19) are now XOR-masked before transmission using a mask derived from the packet SIZE field: `mask = SIZE ^ 0xA3F1C2B4`.
- Because SIZE varies per packet, the masked magic value is different on every transmission and no longer matchable by a static byte pattern.
- The teamserver reverses the mask before parsing. Both sides derive the same mask independently from the SIZE field alone — no additional key material is required.

#### Per-Request Random AES IV (HVC-004)

- Previously, all beacon packets were encrypted with the same static AES-CTR IV embedded in the Demon binary. Reuse of the same keystream allows an observer to XOR two captured ciphertexts and recover plaintext differences.
- A fresh 16-byte random IV is now generated for every `PackageTransmitAll` call using `RandomNumber32()`. The IV is prepended in plaintext between the outer header and the encrypted payload so the teamserver can extract it.
- The registration packet (`DEMON_INITIALIZE`) continues to use the compiled-in IV; only post-registration beacon packets use per-request IVs.

#### HMAC-SHA256 Packet Authentication (HVC-006)

- AES-CTR provides confidentiality but not integrity — an attacker who can observe and modify ciphertext can flip bits in a predictable way without knowing the key.
- A 32-byte HMAC-SHA256 tag is now appended to every beacon packet after encryption (encrypt-then-MAC). The tag is computed over the entire wire buffer (SIZE, masked header, random IV, and ciphertext).
- A separate MAC key is derived per session: `HMAC-SHA256(AES_session_key, "mac")`, keeping the authentication key independent from the encryption key.
- The teamserver verifies the tag before parsing any packet fields. Packets with an invalid or missing tag are silently dropped with a fake 404 response.
- A pure-C SHA-256 and HMAC-SHA256 implementation was added to the Demon (`src/crypt/HmacSha256.c`) with no CRT or BCrypt API dependency. All intermediate keying material is wiped from the stack before return.
- Registration packets are not authenticated with HMAC (the session key is not yet established when they arrive at the teamserver).

#### Combined Wire Format

After all transport hardening changes, every beacon POST body has the following structure on the wire:

```
base64(
  [SIZE(4 bytes)]
  [XOR-masked header fields(16 bytes)]
  [random AES IV(16 bytes)]
  [AES-CTR encrypted payload]
  [HMAC-SHA256 tag(32 bytes)]
)
```

---

### Features

#### Client

> Cross-platform UI written in C++ and Qt

- Modern, dark theme based on [Dracula](https://draculatheme.com/)


#### Teamserver

> Written in Golang

- Multiplayer
- Payload generation (exe/shellcode/dll)
- HTTP/HTTPS listeners
- Customizable C2 profiles
- External C2

#### Demon

> Havoc's flagship agent written in C and ASM

- Sleep Obfuscation via [Ekko](https://github.com/Cracked5pider/Ekko), Ziliean or [FOLIAGE](https://github.com/SecIdiot/FOLIAGE)
- x64 return address spoofing
- Indirect Syscalls for Nt* APIs
- SMB support
- Token vault
- Variety of built-in post-exploitation commands
- Patching Amsi/Etw via Hardware breakpoints
- Proxy library loading
- Stack duplication during sleep.

<div align="center">
  <img src="assets/Screenshots/SessionConsoleHelp.png" width="90%" /><br />
</div>

#### Extensibility

- [External C2](https://github.com/HavocFramework/Havoc/wiki#external-c2)
- Custom Agent Support
  - [Talon](https://github.com/HavocFramework/Talon)
- [Python API](https://github.com/HavocFramework/havoc-py)
- [Modules](https://github.com/HavocFramework/Modules)

---

### Community

You can join the official [Havoc Discord](https://discord.gg/z3PF3NRDE5) to chat with the community!

### Note

Please do not open any issues regarding detection.

The Havoc Framework hasn't been developed to be evasive. Rather it has been designed to be as malleable & modular as possible. Giving the operator the capability to add custom features or modules that evades their targets detection system.
