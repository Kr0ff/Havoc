<div align="center">
  <img width="125px" src="assets/Havoc.png" />
  <h1>Havoc</h1>
  <br/>

  <p><i>Havoc is a modern and malleable post-exploitation command and control framework, originally created by <a href="https://twitter.com/C5pider">@C5pider</a></i></p>
  <p><i>The free upstream version of Havoc is no longer maintained. This is a private fork actively maintained by @Kr0ff with substantial protocol hardening, agent stability fixes, and operator UX improvements.</i></p>
  <br />

  <img src="assets/Screenshots/FullSessionGraph.jpeg" width="90%" /><br />
  <img src="assets/Screenshots/MultiUserAgentControl.png" width="90%" /><br />

</div>

### Quick Start

> Please see the [Wiki](https://github.com/HavocFramework/Havoc/wiki) for complete documentation.

Havoc works well on Debian 10/11, Ubuntu 20.04/22.04 and Kali Linux. It's recommended to use the latest versions possible to avoid issues. You'll need a modern version of Qt and Python 3.10.x to avoid build issues.

See the [Installation](https://havocframework.com/docs/installation) docs for instructions. If you run into issues, check the [Known Issues](https://github.com/HavocFramework/Havoc/wiki#known-issues) page as well as the open/closed [Issues](https://github.com/HavocFramework/Havoc/issues) list.

---

### What's New in 0.9.4 "Eclipse Anchor"

A major capability and stability release. Full details in [`CHANGES.md`](CHANGES.md).

#### New Post-Exploitation Commands (HVC-032)

- **Lateral movement** — `wmi exec` and `dcom exec` execute commands on remote hosts via COM-based WMI and DCOM without touching disk. All COM interfaces dynamically resolved via `RtOle32()` — no import table entries.
- **Persistence** — `persist reg` (HKCU/HKLM Run key), `persist schtask` (ITaskService COM chain), `persist com` (CLSID registry hijack), and `persist remove` cover the most common persistence primitives.
- **Credential access** — `creds lsass` dumps LSASS via `PssCaptureSnapshot` (with MiniDumpWriteDump fallback); `creds sam` saves SAM/SECURITY/SYSTEM hives using `RegSaveKeyExW`. `dbghelp.dll` is loaded inline at call time only to avoid startup artifacts.
- **Privilege escalation** — `privesc uac` supports three UAC bypass methods (`fodhelper`, `computerdefaults`, `eventvwr`) with automatic registry key cleanup on all exit paths.

#### Command.c Architectural Refactor (HVC-032)

- The monolithic `Command.c` (3 576 lines) has been split into per-group files under `src/commands/`. `Command.c` now holds only the `DemonCommands[]` dispatch table. New command groups follow the established pattern — no changes to `Command.c` required.

#### Stack Spoofing (HVC-044)

- **KaynLoader entry spoofing** — `KaynSpoofEntry` (x64 ASM) writes `BaseThreadInitThunk` and `RtlUserThreadStart` fake frames before jumping to `KaynDllMain`, giving the loader thread a clean-looking callstack on entry.
- **Injection thread spoofing** — `NtCreateThreadEx` receives `RtlUserThreadStart` as `StartRoutine` and the shellcode entry as `Argument`. `TEB.StartAddress` records ntdll's `RtlUserThreadStart` instead of the shellcode address, clearing pe-sieve `SUS_START` for injected payloads.

#### EDR Evasion Improvements

- **ntdll unhooking** (`HVC-031 Sub-4`) — At startup, Demon opens `\KnownDlls\ntdll.dll`, maps a clean view, and overwrites the loaded ntdll `.text` using `SysNtProtectVirtualMemory` (indirect syscall, bypasses EDR hook) + a custom QWORD copy loop. Removes all usermode inline hooks before any injection or network code runs.
- **Module hiding** (`HVC-031 Sub-2`) — Opt-in `HideModules` flag unlinks each dynamically loaded module from all three PEB loader lists immediately after load, defeating `CreateToolhelp32Snapshot`, `EnumProcessModules`, and direct PEB walks.
- **PE header stomping** (`HVC-030 Sub-2`, `ISS-037`) — Zeros the first 4 KB of the Demon image before each sleep and restores from a saved backup on wake. Opt-in (`PeStomp = false` by default) to avoid crashes in injected processes. Auto-disabled in shellcode/KaynLdr mode via MZ signature check.
- **pe-sieve fixes** (`HVC-030 Sub-3/4`) — Foliage worker thread now has a 4-frame fake callstack (`NtTestAlert / BaseThreadInitThunk / RtlUserThreadStart / NULL`) at the `WaitForSingleObjectEx` step; thread start address changed to `RtlUserThreadStart`. `PAGE_NOACCESS` applied to the encrypted image region during sleep prevents entropy measurement (`implanted_shc`).

#### New Profile Config Options (HVC-038)

- `Verbose`, `CoffeeVeh`, `CoffeeThreaded`, `SleepObfStartAddr`, and `InjectSpoofAddr` are now configurable in the YAOTL profile at payload generation time.

#### Stability Fixes

- **Parser safety** (`ISS-005/006/007`) — UINT32 bounds check before length subtraction; `ParserGetBytes` returns a static `EmptyBuf` sentinel (never NULL) to prevent NULL-source `MemCopy`; MZ signature guard before PE header field access.
- **Injection stability** (`ISS-001/002/003/004`) — Thread suspension around ntdll text rewrite; LoaderLock held on all PEB LDR walks; `MmHeapAlloc` NULL check in `LdrModulePebByString`; explicit `return` added to `SysInitialize`.

---

### What's New in 0.9 "Warden's Eye"

A collection of operator experience and agent capability improvements. Full details and revert instructions are in [`CHANGES.md`](CHANGES.md).

#### WPAD Full URL Fix (HVC-027)

- Fixed a pre-existing bug where `WinHttpGetProxyForUrl` received a bare URI path (e.g. `/beacon`) instead of a full URL (e.g. `https://c2.example.com:443/beacon`).
- The function requires a fully-qualified URL so WPAD/PAC scripts can evaluate the request destination; passing a path caused both DHCP/DNS auto-detect and PAC file fallback to silently fail on every beacon.
- The fix assembles the correct URL from `Config.Transport.Secure`, `Host->Host`, `Host->Port`, and `HttpEndpoint` using only `MemCopy` and integer arithmetic — no stdlib dependency.

#### Auto Proxy Detection (HVC-026)

- Demon agents now detect and use the Windows system proxy at startup rather than lazily on the first beacon send.
- A new "Auto Proxy Detection" checkbox (on by default) in the payload builder lets operators enable or disable the feature per payload.
- When enabled, the agent reads `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` directly via Advapi32 (no WinHTTP dependency) to extract `ProxyServer`, strips the `http=` protocol prefix from multi-protocol strings, and sets `Proxy.Url` before the first beacon. If no registry proxy is found, the WinHTTP WPAD/IE fallback still fires on the first connect — and with HVC-027 applied, that WPAD lookup now works correctly.

#### Listener Column in Session Table (HVC-025)

- The agent session table now includes a "Listener" column showing which listener each agent is using, making it easier to manage deployments with multiple active listeners.

#### Listener Dialog Theming (HVC-024)

- The Listener configuration dialog now fully adapts to dark and light theme switches, using `ThemeManager` colours for background, text, accent borders, and scroll areas.

#### Last-Checkin Time Fixes (HVC-023)

- Fixed three bugs that caused the "last checkin" column to display incorrect elapsed times: timezone mismatch between server (Go `time.Now()`) and client (Qt local time), CDN transit latency absorbed into the server-side timestamp, and a deprecated `QDateTime::fromTime_t` day-count calculation.

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

> Cross-platform UI written in C++ and Qt5

- Multi-theme UI (dark/light) using `ThemeManager` — all dialogs, widgets, and the Listener dialog adapt automatically
- Multi-operator session graph and session table views with live agent state; "Listener" column shows which listener each agent uses
- Payload builder dialog with profile-driven defaults; per-payload options for sleep obfuscation, proxy loading, AMSI/ETW patch technique, indirect syscalls, auto proxy detection, and more
- Sleep obfuscation option selectability — invalid combinations (e.g. JmpGadget or Stack Duplication with non-timer techniques) are automatically disabled in the builder
- Task queue management commands: `task list`, `task clear`, `task cancel <id|all>`
- TaskID injected into all console output messages so operators can correlate output to specific queued tasks
- File browser, process list, loot vault, and credential manager widgets
- Event viewer, session notes (editable per-agent, synced to the interacted console)
- Script manager with Python API integration
- Connect dialog with saved profile support

#### Teamserver

> Written in Go

- Multiplayer with WebSocket-based client connections
- Payload generation (exe / shellcode / DLL / service exe)
- HTTP/HTTPS listeners with malleable profile support
- SMB pivot listener (parent → child relay over named pipes)
- External C2 endpoint for third-party agents
- Customizable C2 profiles via YAOTL (HCL-based) with full spec test suite
- SQLite persistence layer for agent sessions, tasks, and credentials
- Discord webhook integration for new-agent notifications
- RSA-2048-OAEP-SHA256 session key wrapping for the registration packet (HVC-005)
- Per-request random AES-256-CTR IV for every beacon packet (HVC-004)
- HMAC-SHA256 encrypt-then-MAC authentication on all post-registration traffic (HVC-006)
- LZNT1 payload compression for large beacon responses (HVC-007)
- XOR-masked outer wire header — eliminates the static `0xDEADBEEF` magic-value signature (HVC-003)
- Base64-encoded HTTP request and response bodies (HVC-002)
- SMB pipe framing obfuscation — XOR-masks the `[DemonID][PkgSize]` header on parent↔child pipes (HVC-008)
- Removed `X-Havoc: true` response header that previously fingerprinted the teamserver (HVC-001)
- Mutex-protected agent job queue and task list (data-race fix, ISSUE-1)
- SMB packet fragmentation — large responses (>64 KB) are split into `DEMON_PACKAGE_FRAGMENT` chunks and reassembled server-side (ISSUE-5)
- HTTP beacon stability fixes for retransmission, HMAC handling on reconnect, and AES-CTR counter reuse (BUGFIX-004)
- SMB pivot stability fixes for package leaks, error masking, NULL allocation, and PIPE_BUFFER_MAX overflow (BUGFIX-003)

#### Demon

> Havoc's flagship agent written in C and x86/x64 ASM

- Sleep obfuscation via [Ekko](https://github.com/Cracked5pider/Ekko), Zilean, or [FOLIAGE](https://github.com/SecIdiot/FOLIAGE)
- Sleep obfuscation source split into per-technique files (`ObfTimer.c`, `ObfFoliage.c`) with compile-time `SLEEPOBF_USE_TIMER` / `SLEEPOBF_USE_FOLIAGE` guards — only the selected technique is compiled into the binary
- Sleep jump gadget bypass: `jmp rax` and `jmp [rbx]` ROP-chain dispatch (Ekko/Zilean); runtime gadget randomization picks a different gadget address each sleep cycle to defeat per-cycle EDR fingerprinting
- x64 return address spoofing during indirect syscalls
- Indirect syscalls for `Nt*` APIs with dynamically resolved SSNs
- SMB transport for child agents over named pipes; DNS transport with configurable resolver and chunked query sequence
- Token vault and impersonation primitives
- Kerberos authentication support
- Hardware-breakpoint-based AMSI / ETW patching (HwBpEngine)
- Memory-patch AMSI/ETW bypass as an alternative to the HWBP technique
- Proxy library loading via `RtlRegisterWait` / `RtlCreateTimer` / `RtlQueueWorkItem`
- Stack duplication / call-stack spoofing during sleep; KaynLoader entry spoofing via `KaynSpoofEntry` ASM; injection thread start address spoofed to `RtlUserThreadStart`
- BOF (Beacon Object File) loader and inline .NET assembly execution
- Per-process AES-256-CTR session encryption with embedded key material
- Pure-C SHA-256 + HMAC-SHA-256 implementation (no CRT, no BCrypt dependency)
- LZNT1 compression of large response payloads via `RtlCompressBuffer`
- Auto proxy detection at startup: reads `HKCU\...\Internet Settings` via Advapi32 registry API (no WinHTTP); falls back to WinHTTP WPAD/IE detection on first connect (HVC-026); WPAD detection now passes the full `scheme://host:port/path` URL to `WinHttpGetProxyForUrl` so DHCP/DNS and PAC file evaluation work correctly (HVC-027)
- ntdll unhooking at startup — overwrites loaded ntdll `.text` with clean `\KnownDlls\ntdll.dll` copy via indirect syscall; removes all EDR usermode inline hooks before network or injection code runs
- Module hiding — opt-in PEB LDR unlink for all dynamically loaded modules, defeating `CreateToolhelp32Snapshot` and direct PEB walks
- PE header stomping during sleep — zeros the first 4 KB of the Demon image before each sleep and restores on wake; auto-disabled in KaynLdr shellcode mode
- New post-exploitation commands: lateral movement (`wmi exec`, `dcom exec`), persistence (`persist reg/schtask/com/remove`), credential access (`creds lsass`, `creds sam`), privilege escalation (`privesc uac`)
- Modular command architecture — `Command.c` holds only the dispatch table; all handlers live in per-group `src/commands/Command_<Group>.c` files
- Spinlock-protected `Instance->Packages` linked list (data-race fix, ISSUE-2)
- mingw-w64 v15 / GCC 14+ compilation compatibility (MINGW-COMPAT)
- Hardware breakpoint engine fixes: thread handle leaks, NULL guards, parameter handling (HVC-009)
- Working-hours scheduling and kill-date enforcement

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
