# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Havoc is a post-exploitation C2 (command and control) framework with three main components:
- **Teamserver** — Go backend that orchestrates agents, listeners, and client connections
- **Client** — Qt5/C++ GUI that operators use to interact with the teamserver
- **Demon** — Windows agent written in C + x86/x64 ASM that runs on target hosts

**`Demon.md`** (repo root) is the full technical reference for the Demon agent. Read it before working on any code in `payloads/Demon/`.

**`Teamserver.md`** (repo root) is the full technical reference for the teamserver. Read it before working on any code in `teamserver/`.

**`Client.md`** (repo root) is the full technical reference for the client. Read it before working on any code in `client/`.

## Build Commands

### Full Build
```bash
make all          # Build both teamserver and client
make ts-build     # Build teamserver only (runs Install.sh first)
make client-build # Build client only (runs CMake)
make clean        # Clean all build artifacts
```

### Teamserver (Go)
```bash
cd teamserver
go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go
```

### Client (C++ + Qt5)
```bash
cd client
mkdir -p Build && cd Build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
```

### Dependencies Setup
```bash
cd teamserver && bash Install.sh   # Installs Go, NASM, MinGW, downloads cross-compilers
```

**Requirements:**
- Go 1.21.0+
- CMake 3.15+, C++20 compiler
- Qt5 (Core, Gui, Widgets, Network, WebSockets, Sql)
- Python 3.10+ (for module/scripting support)
- NASM assembler
- MinGW-w64 (downloaded by Install.sh into `data/`)

On macOS, Qt5 and Python paths are resolved via Homebrew in `client/CMakeLists.txt`.

## Running Tests

```bash
cd teamserver
go test ./...                          # All Go tests
go test ./pkg/profile/yaotl/...        # YAOTL config parser tests only
```

Test files are primarily in `teamserver/pkg/profile/yaotl/specsuite/`.

## Architecture

### Communication Flow

```
Client (Qt5 C++) ←─ WebSocket ─→ Teamserver (Go) ←─ HTTP/HTTPS/SMB ─→ Demon Agent (C)
```

### Teamserver (`teamserver/`)

Entry point: `main.go` → `cmd/server/teamserver.go`

Key packages:
- `cmd/server/` — Main server logic: `teamserver.go` (core), `agent.go`, `listener.go`, `dispatch.go`, `service.go`, `types.go`
- `pkg/agent/` — Agent session state management
- `pkg/handlers/` — HTTP/WebSocket request handling
- `pkg/packager/` — Payload/implant generation
- `pkg/profile/` — YAOTL config parsing (HCL-based format)
- `pkg/db/` — SQLite persistence layer
- `pkg/events/` — Event broadcasting to connected clients
- `pkg/service/` — External C2 API support
- `pkg/webhook/` — Discord webhook integration

The `Teamserver` struct (in `types.go`) is the central data structure holding all state. Clients connect via WebSocket and receive events broadcast through `pkg/events`.

### Client (`client/`)

Entry point: `src/Main.cc` → `src/Havoc/` core logic

Key areas:
- `src/Havoc/Connector.cc` — Teamserver WebSocket connection
- `src/Havoc/Packager.cc` — Payload generation UI logic
- `src/Havoc/PythonApi/` — Python scripting integration
- `src/UserInterface/Widgets/` — SessionTable, SessionGraph, Listeners, FileExplorer, ScriptManager
- `src/UserInterface/Dialogs/` — Connect, Payload, Listener dialogs
- `data/` — Qt resources (icons, themes, UI files)

### Demon Agent (`payloads/Demon/`)

Multiple entry points for different deployment modes:
- `src/main/MainExe.c` — Standalone executable
- `src/main/MainDll.c` — DLL injection
- `src/main/MainSvc.c` — Windows service

Core modules in `src/core/`:
- `Command.c` — All agent command implementations (largest file ~120KB)
- `Win32.c` — Windows API wrappers with dynamic resolution
- `Syscalls.c` — Indirect syscall stubs
- `Transport*.c` — HTTP and SMB transport layers
- `Token.c` — Token manipulation/impersonation
- `Obf.c` — Sleep obfuscation (Ekko, Ziliean, FOLIAGE)
- `HwBpEngine.c` — Hardware breakpoint-based AMSI/ETW patching
- `CoffeeLdr.c` — BOF (Beacon Object File) and .NET loader
- `Kerberos.c` — Kerberos authentication support

Assembly stubs in `src/asm/` handle syscall invocation and return address spoofing.

## Configuration

Profiles use the **YAOTL** format (TOML-based dialect), stored in `profiles/`. See `profiles/havoc.yaotl` for a full example.

Key profile sections:
- `Teamserver {}` — Host, port, build compiler paths
- `Operators {}` — User credentials
- `Demon {}` — Agent defaults (sleep, jitter, injection settings)
- `Service {}` — External C2 endpoint (optional)

To run the teamserver:
```bash
./havoc server --profile profiles/havoc.yaotl
```

## Code Constraints

### AMSI / ETW Patching

**Never use memory byte patching for AMSI or ETW evasion.** The only permitted technique is the hardware breakpoint (HWBP) engine already implemented in `src/core/HwBpEngine.c`.

- Do not write `0xC3`, `0xB8 0x57 0x00 0x07 0x80 0xC3`, or any other byte sequence directly over `AmsiScanBuffer`, `NtTraceEvent`, or any other AMSI/ETW function entry point.
- Do not call `NtProtectVirtualMemory` + `memcpy`/`MemCopy` to patch function prologues for evasion purposes.
- All AMSI/ETW suppression must go through `HwBpEngine` — add a breakpoint via `HwBpEngineAdd()`, handle it in the VEH, and return cleanly. This applies to any new evasion code, any refactoring of existing evasion code, and any improvement spec that touches AMSI or ETW.

This rule overrides any improvement spec (including HVC-031) that proposes a memory-patch approach. If an improvement doc conflicts with this rule, follow this rule and note the deviation in the PR description.

### Pe-Sieve / Memory Scanner Evasion Constraints

When working on sleep obfuscation (`ObfFoliage.c`, `ObfTimer.c`, `Obf.c`) or any code that creates worker threads:

**Thread start address:** Never use a syscall stub (e.g., `NtTestAlert`) as the `NtCreateThreadEx` start address for a long-lived worker thread. Use `Instance->Win32.RtlUserThreadStart` (ntdll). `NtTestAlert` is a well-known red-team indicator flagged by pe-sieve (`SUS_START`) and EDR products. `RtlUserThreadStart` is the standard Windows thread entry point.

**Fake callstack for sleeping threads:** Any APC ROP chain that places a thread in `WaitForSingleObjectEx` must build a plausible fake callstack at the sleeping ROP step. `[RSP+0]` **must remain `NtTestAlert`** — this is the required return address that triggers APC delivery when `WaitForSingleObjectEx` returns; replacing it breaks the APC chain and deadlocks the agent. Write pe-sieve evasion frames above it: `[RSP+8]` = `BaseThreadInitThunk`, `[RSP+16]` = `RtlUserThreadStart`, `[RSP+24]` = `NULL`. This produces a 4-frame callstack that pe-sieve accepts as legitimate. A 1-frame callstack (one visible frame = `WaitForSingleObjectEx`) is detected as `SUS_CALLSTACK_CORRUPT` by pe-sieve and equivalent EDR callstack scanners.

**Main fiber callstack spoof:** When spoofing the main fiber's context (`NtSetContextThread(hDupObj, RopSpoof)`), set `RopSpoof->Rsp` to a location near `StackBase` that has the same `BaseThreadInitThunk → RtlUserThreadStart → NULL` fake frames written into it. Setting `Rsp = StackBase` with no frames is flagged as a corrupted callstack.

**PAGE_NOACCESS after encryption:** After RC4-encrypting the image region (Foliage), add a `NtProtectVirtualMemory(PAGE_NOACCESS)` ROP step before the sleep and a matching `NtProtectVirtualMemory(PAGE_READWRITE)` step after wake. This prevents entropy measurement of the encrypted region by pe-sieve, avoiding the `implanted_shc` detection. See improvement-docs/13-pe-sieve-detection-analysis.md Fix C.

**VAD region split:** MinGW may produce a section with `IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE` which causes the PE loader to map it as `PAGE_EXECUTE_WRITECOPY` (0x80) — a separate VAD entry that a single `NtProtectVirtualMemory` call on `ImageBase + ImageSize` may not cover. Check for this split when entropy detections appear on the last image section.

**`malformed_header` is acceptable:** Pe-sieve's `malformed_header` detection when PE header stomping (Sub-2) is active is expected and by design. Do not attempt to suppress it by re-writing valid headers — the goal is absence of the PE signature, not absence of this detection.

**`CfgAddressAdd` requires a valid PE image base — never pass NULL (ISS-008).** `CfgAddressAdd(ImageBase, Function)` reads `((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew` to locate the PE header and compute `SizeOfImage`. Passing `NULL` as `ImageBase` causes a NULL pointer dereference that immediately crashes the host process. This crash fires during `DemonInit` (before any sleep cycle) in any CFG-enforced target process (i.e., all modern Windows processes used for shellcode/DLL injection). The sleep cipher trampoline is a heap allocation with no owning PE module — do NOT register it with `CfgAddressAdd`. The cipher is called via `NtContinue` (Foliage: kernel sets RIP directly, bypasses CFG) and via a byte-scanned `jmp rax` gadget in ntdll (Timer: not a compiler-instrumented call site). Neither path triggers a CFG bitmap check, so no registration is needed or correct.

**`ExecDelaySleep()` pattern for injection dissociation (HVC-046).** Two DWORD config fields — `ExecDelay` (seconds) and `ExecDelayJitter` (%) — gate a jittered `NtDelayExecution` call inserted between injection stages. `ExecDelaySleep()` is implemented in `Win32.c` and called after `MmVirtualAlloc` and after `MmVirtualProtect` (before thread creation) in every injection function (`Inject()`, `DllInjectReflective()`, `BeaconInjectProcess()`, `BeaconInjectTemporaryProcess()`, `ThreadCreateWoW64()`). When `ExecDelay == 0` (default) the function is a single-instruction no-op — zero runtime cost. `NtDelayExecution` is used (not `Sleep`/`WaitForSingleObjectEx`) because it accepts a relative negative `LARGE_INTEGER` (1s = -10,000,000 in 100-ns units) and is not EDR-hooked. A `PRINTF` debug line fires in `--debug-dev` builds showing the computed delay in seconds before sleeping. Config blob positions: `ExecDelay` = field 25, `ExecDelayJitter` = field 26 (both appended after `InjectSpoofOffset`). `H_FUNC_NTDELAYEXECUTION = 0xf5a936aa` (DJB2 verified). UI keys: `"Exec Delay"` and `"Exec Delay Jitter"` (exact strings read by `builder.go` `b.config.Config` map). Architecture doc: `improvement-docs/HVC-046-exec-delay.md`.

### PE Stomping (ISS-037)

**`PeStomp` is opt-in and defaults to `false`.** PE header stomping (`PeProtect_Stomp()` /
`PeProtect_Restore()`) is disabled by default to prevent crashes when Demon runs as injected
shellcode in a remote process.

**Root cause of injection crash (ISS-037):** `PeProtect_Stomp()` called `NtProtectVirtualMemory`
to change the PE image region to `PAGE_READWRITE`, then called `MemSet` unconditionally. In a
remote injected process `NtProtectVirtualMemory` fails (SEC_IMAGE VAD constraint, or the
allocator used different protection), and `MemSet` to the still-non-writable page causes an
access violation. The crash occurred at the **first** `SleepObf()` call in `DemonRoutine()` -
immediately after teamserver registration, before any tasks were dispatched.

**`NT_SUCCESS` check is mandatory in `PeProtect.c`:** Both `PeProtect_Stomp()` and
`PeProtect_Restore()` must check `NT_SUCCESS(Status)` after `NtProtectVirtualMemory` and
return immediately on failure. Never call `MemSet` or `MmVirtualWrite` when the protect call
failed.

**Config blob position:** `PeStomp` is field 16 (zero-indexed), immediately after `HideModules`
in both the `builder.go` `AddInt` block and the `Demon.c` `ParserGetInt32` sequence. All
preceding field positions are unchanged.

**`PeProtect_Init()` is gated on `PeStomp` AND validates an MZ signature:** No PE header
backup is saved when stomping is disabled. Additionally, `PeProtect_Init()` checks
`((PIMAGE_DOS_HEADER)ModuleBase)->e_magic == IMAGE_DOS_SIGNATURE` before reading the backup.
If the MZ signature is absent (KaynLdr shellcode mode — sections mapped without PE header,
original blob freed by `FreeReflectiveLoader`), `PeProtect_Init()` force-sets
`Config.Implant.PeStomp = FALSE` and returns. This makes `Stomp`/`Restore` permanent no-ops
for the session, preventing code corruption. The NT_SUCCESS guard alone does NOT protect this
case: in a private (`VadPrivateMap`) allocation, `NtProtect(PAGE_READWRITE)` succeeds, but
`ModuleBase[0]` is live `.text` code, not a PE header — `MemSet` would zero 4 KB of the agent.

**`Obf.c` gating:** Both `PeProtect_Stomp()` and `PeProtect_Restore()` in the DEFAULT sleep
path are wrapped with `if ( Instance->Config.Implant.PeStomp )`. The Ekko/Zilean/Foliage
paths do not call `PeProtect_Stomp` directly and are unaffected.

**`OldProtect` must be used for the final NtProtect restore, not `PAGE_EXECUTE_READ`:** After
the `MemSet`/`MmVirtualWrite` operation in `PeProtect_Stomp()` and `PeProtect_Restore()`, the
final `NtProtectVirtualMemory` call must pass `OldProtect` (saved by the preceding first
NtProtect call) as the new protection — NOT the hardcoded constant `PAGE_EXECUTE_READ` (0x20).
The PE header page on a SEC_IMAGE mapping is typically `PAGE_READONLY` (0x02); hardcoding
`PAGE_EXECUTE_READ` permanently upgrades the page permission after the first sleep cycle, which
is both incorrect and a potential detection signal. Always reset `BaseAddr`/`StompSize` locals
before the second NtProtect call (aliasing guard — NtProtect modifies them in-place).

**DJB2 hash verification is mandatory:** Any new `H_FUNC_*` constant added to `Defines.h` MUST be verified by running the exact HashEx algorithm before committing. The algorithm: seed `5381`, `h = ((h<<5)+h) + c` (h\*33+c), uppercase (`if c >= 'a': c -= 0x20`), NULL-terminated string. Verification script:
```python
def djb2_upper(s):
    h = 5381
    for c in s.upper():
        h = (((h << 5) + h) + ord(c)) & 0xFFFFFFFF
    return h
```
The failure mode is silent: a wrong hash causes `LdrFunctionAddr` to return NULL, the function pointer is 0, and all code that writes that pointer silently writes NULL. This was the root cause of the HVC-030 Sub-3 pe-sieve fix being a complete no-op at runtime (both `RtlUserThreadStart` and `BaseThreadInitThunk` resolved to NULL, leaving frames_count=1 on every scan cycle).

### Parser and Config Blob Safety (ISS-005, ISS-006, ISS-007)

**Bounds check before every UINT32 length subtraction.** Any code that reads a length-prefixed
field from an untrusted buffer (config blob, network packet, IPC message) must verify that the
embedded length fits within the remaining buffer BEFORE performing arithmetic on the length
counter. UINT32 does not underflow loudly - it wraps silently to ~0xFFFFFFxx and every
subsequent read goes far out of bounds. Pattern: `if ( Length > parser->Length - sizeof(DWORD) ) { poison; return; }`.

**Never return NULL from a function whose return value is passed directly to MemCopy.** When a
parser or deserialisation function may fail, it must return a valid (possibly empty) pointer,
never NULL. The pattern `Buffer = Parse(...); MemCopy(dest, Buffer, size);` is unsafe when
`Buffer` can be NULL. Preferred fix: return a static safe buffer (`EmptyBuf`) with `*size = 0`
on error - any `MemCopy(dest, EmptyBuf, 0)` is a safe no-op, and no call site changes are
required. This eliminates the bug class without auditing every caller.

**MZ signature check before any PE header field access.** Any code that reads PE header fields
(`e_lfanew`, NT headers, section headers, `IMAGE_SIZE`) from a `PVOID` that may point to a
KaynLdr headerless mapping must first validate `*(PWORD)Base == IMAGE_DOS_SIGNATURE`. If the
check fails, set size/offset to 0 and return without accessing the header. This mirrors the
`PeProtect_Init()` guard from ISS-037 and applies to every macro or direct dereference that
assumes a PE header is present.

**Stability is the top priority.** All Demon code changes must prioritise runtime stability
over feature completeness. Before reporting a task complete: (1) trace every error path and
confirm no NULL pointer is passed to `MemCopy`/`MemSet`/`MmVirtualWrite`; (2) confirm every
PE field access is guarded by an MZ signature check; (3) confirm every UINT32 length
subtraction is guarded by a remaining-buffer bounds check. A crash in an injected process is
irreversible and exposes the operator.

### ntdll Unhooking (HVC-031 Sub-4)

**`NtOpenSection` and `NtMapViewOfSection` are not in `Instance->Win32`.** They are resolved
inline via `LdrFunctionAddr` using DJB2 constants `H_FUNC_NTOPENSECTION = 0x134eda0e` and
`H_FUNC_NTMAPVIEWOFSECTION = 0xd6649bca`. Use local typedefs for both. All other NT calls in
`UnhookNtdll()` (`NtUnmapViewOfSection`, `NtClose`) use `Instance->Win32.*`. The page
protection calls use `SysNtProtectVirtualMemory` (indirect syscall — see below).

**`UNICODE_STRING` init:** Never call `RtlInitUnicodeString`. Initialise the struct manually:
`.Length = sizeof(wstr) - sizeof(WCHAR)`, `.MaximumLength = sizeof(wstr)`, `.Buffer = wstr`.

**`PAGE_EXECUTE_WRITECOPY`, not `PAGE_READWRITE`, for the protection change.**
ntdll `.text` is backed by a `SEC_IMAGE` section object. The Windows memory manager
(`MiChangeImageProtection`) enforces that protection changes on `VadImageMap` pages must
remain compatible with the VAD's original execute characteristic. `PAGE_READWRITE` (0x04)
strips the execute bit — the memory manager cannot satisfy this for a CoW copy of an
execute-image page: the call may return a non-success status or the subsequent write faults.
`PAGE_EXECUTE_WRITECOPY` (0x80) retains execute and adds CoW-write. This is the same
protection the Windows loader uses when patching image pages (base relocations, IAT writes)
and is the correct, OS-sanctioned mechanism. An EDR may additionally detect and block
execute-stripping transitions as a heuristic, but the fundamental constraint is the
`SEC_IMAGE` VAD rule, which applies on all Windows versions regardless of EDR presence.

**Overwrite pattern — `SysNtProtect(PAGE_EXECUTE_WRITECOPY)` + `NtdllCopy` (custom loop) + restore:**
`NtWriteVirtualMemory` fails with `STATUS_PARTIAL_COPY` on `PAGE_EXECUTE_READ` pages (both
pseudo-handle and real handle verified at runtime). Page protection must be changed first.
`Instance->Win32.NtProtectVirtualMemory` is EDR-hooked and **crashes** — the EDR hook fires
on `.text` before the clean bytes are written. Use `SysNtProtectVirtualMemory` (indirect
syscall — calls kernel directly, bypasses the EDR hook):
```
SysNtProtectVirtualMemory(PAGE_EXECUTE_WRITECOPY, &OldProt)  // retains execute, adds CoW-write
NtdllCopy(LoadedText, CleanText, TextSize)                    // custom QWORD loop (no CRT)
SysNtProtectVirtualMemory(OldProt)                            // restore PAGE_EXECUTE_READ
```
`NtdllCopy` is a `static VOID` function in `NtdllUnhook.c` that copies 8 bytes at a time
then handles the remainder byte-by-byte. Never use `MemCopy` (`__builtin_memcpy`) — at
`-O0` with `-nostdlib` MinGW emits an external `memcpy` call which is unresolved and crashes.

**`SysInitialize()` must run before `UnhookNtdll()`.** `SysNtProtectVirtualMemory` uses the
`SYSCALL_INVOKE` macro which checks `Instance->Config.Implant.SysIndirect`,
`Instance->Syscall.SysAddress`, and `Instance->Syscall.NtProtectVirtualMemory` — all three
must be non-zero or it falls back to the hooked Win32 function and crashes. `SysInitialize`
only needs `Instance->Modules.Ntdll` and is safe to call right after `DemonConfig()`. The
ordering in `DemonInit()` is: `DemonConfig()` → `SysInitialize()` → `UnhookNtdll()`.

**`SysInitialize` must return `BOOL` correctly (ISS-004).** `SysInitialize()` is declared
`BOOL SysInitialize(IN PVOID Ntdll)`. Without a `return` statement the C standard defines the
return value as undefined behaviour. The correct final statement is
`return Instance->Syscall.SysAddress != NULL;`. The early `return FALSE` at the top (when
`Ntdll` is NULL) is unaffected. Any caller that gates on the return value (e.g. the logging
check in `DemonInit`) will see the correct value; callers that ignore it are also unaffected.

**Aliasing guard for `SysNtProtectVirtualMemory`:** NtProtect page-aligns `BaseAddress` and
`RegionSize` **in-place**. Always use separate `ProtAddr`/`ProtSize` locals, and reset them
before the second protect call:
```c
PVOID  ProtAddr = LoadedText;   /* reset after first protect modified it */
SIZE_T ProtSize = TextSize;
SysNtProtectVirtualMemory( NtCurrentProcess(), &ProtAddr, &ProtSize, OldProt, &OldProt );
```

**UnhookNtdll call site:** `DemonInit()` — after `DemonConfig()` and `SysInitialize()`.
Failure is non-fatal: log with `PUTS` and continue. Returns `Found` (TRUE only when `.text`
was successfully overwritten), not a hardcoded TRUE.

**Thread suspension around NtdllCopy is mandatory (ISS-001).** Overwriting ntdll `.text` while
host threads execute through the same region causes `#GP`/`#UD` faults on any thread that
fetches an instruction from a partially-written cache line. Before calling `NtdllCopy`,
enumerate all process threads with `SysNtGetNextThread`, query each thread's TID via
`SysNtQueryInformationThread(ThreadBasicInformation)`, skip the current thread by comparing
`ThdInfo.ClientId.UniqueThread` against `Instance->Teb->ClientId.UniqueThread`, and suspend
the rest into a fixed-size `Suspended[128]` stack array (bounded by `SuspCnt < 128`). After
`NtdllCopy` and the restore `NtProtect` call, resume and close all saved handles. Use the
`ThdSaved` flag to track whether the current `ThdHndl` was saved — handles not saved must be
closed in the loop body (to avoid leaks); saved handles must only be closed inside the resume
loop (to avoid double-close). Add an early-resume path in the `NtProtect`-failure branch so
suspended threads are never abandoned. Always use `SysNtResumeThread`/`SysNtClose` (indirect
syscall variants), not the Win32 equivalents.

**Interaction with MmGadgetFindRandom (Sub-8 fix):** `UnhookNtdll()` runs once in
`DemonInit()` before `DemonRoutine()` starts any sleep cycle. Every gadget scan sees the
already-unhooked ntdll. EDR hooks use JMP trampolines (not `FF E0`), so natural `FF E0`
gadgets in ntdll `.text` survive the overwrite. PE section headers are not touched, so the
Sub-8 `.text` section bounds (`ScanBase`/`ScanLen`) remain correct. `OldProt` is always
restored to `PAGE_EXECUTE_READ` (0x20) — gadgets picked by `MmGadgetFindRandom` are always
executable.

### Module Hiding (HVC-031 Sub-2)

**`HideModule(PVOID Base)`** is in `payloads/Demon/src/core/MemoryHide.c`. It unlinks a
module from all three PEB LDR lists (`InLoadOrderModuleList`, `InMemoryOrderModuleList`,
`InInitializationOrderModuleList`). Controlled by `Config.Implant.HideModules` (BOOL, opt-in).

**Call sites:** Both `LdrModuleLoad` call sites in `Command.c` — the ones that set
`ThreadStartAddr` and `SpoofAddr`. Called immediately after a successful load, before
`LdrFunctionAddr`. Calling `HideModule` before `LdrFunctionAddr` is safe: `LdrFunctionAddr`
walks the PE export table from the module base pointer directly and never re-queries the PEB.

**PEB walk pattern:** Walk `InLoadOrderModuleList` only (single pass). Use
`CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)` to get the struct pointer.
Advance `Entry = Entry->Flink` BEFORE the potential unlink to keep the walk cursor valid.
On match, unlink from all three lists with standard doubly-linked list removal:
`Blink->Flink = Flink` and `Flink->Blink = Blink` for each list member.

**PEB access:** Use `Instance->Teb->ProcessEnvironmentBlock`, NOT `NtCurrentTeb()` directly.
Lazy-initialise `Instance->Teb` first (same pattern as `Win32.c`):
```c
if ( !Instance->Teb )
    Instance->Teb = NtCurrentTeb();
PPEB Peb = Instance->Teb->ProcessEnvironmentBlock;
if ( !Peb || !Peb->Ldr ) return;
```

**All PEB LDR walk functions must hold `LoaderLock` (ISS-002, ISS-003).** Any function that
walks `InLoadOrderModuleList` or any other PEB LDR list — including `HideModule`,
`LdrModulePeb`, `LdrModulePebByString`, and `LdrModuleSearch` — must acquire
`PEB->LoaderLock` before starting the walk and release it at every exit point. A concurrent
`LoadLibrary`/`FreeLibrary` on another thread walks the same list; an unlink mid-walk leaves
dangling `Flink`/`Blink` pointers and causes an AV or infinite loop (ISS-011 eliminated as
side-effect). Pattern: resolve `LdrLockLoaderLock`/`LdrUnlockLoaderLock` inline via
`LdrFunctionAddr` with DJB2 constants `H_FUNC_LDRLOCKLOADERLOCK = 0xcdcd3c90` and
`H_FUNC_LDRUNLOCKLOADERLOCK = 0xfc603ed3`. Guard acquire/release with `if (pLdrLock)` so
early single-threaded calls (when `Instance->Modules.Ntdll` is NULL) safely skip locking
without crashing. DJB2 hash verified: `djb2_upper("LdrLockLoaderLock") = 0xcdcd3c90`,
`djb2_upper("LdrUnlockLoaderLock") = 0xfc603ed3`.

**`LdrModulePebByString` heap allocation must be NULL-checked (ISS-003 fix).** The function
allocates a wide-string work buffer via `MmHeapAlloc(MAX_PATH)` before acquiring the lock. If
`MmHeapAlloc` returns NULL (OOM), the subsequent `MemCopy(Name, ...)` crashes with a NULL
destination, and the loader lock is then permanently held for the process lifetime. Fix:
`if (!Name) return NULL;` immediately after the `MmHeapAlloc` call, before any lock
acquisition.

**Limitations:** Defeats usermode enumeration only. Does not affect `PsSetLoadImageNotifyRoutine`
callbacks (fire at load time, before unlink) or hypervisor-level VAD inspection.

**Config blob parse order:** `HideModules` is added to the blob AFTER `UnhookNtdll` in both
`builder.go` (`DemonConfig.AddInt(ConfigHideModules)`) and `Demon.c` (`ParserGetInt32`). Any
new bool added after this must follow the same pattern: add to the end of both sequences.

**UI key:** `ConfigHideModules->setText(0, "Hide Modules")` (with space). Must exactly match
`b.config.Config["Hide Modules"]` in `builder.go`. The YAOTL/Go struct field is `HideModules`
(no space) — two different key forms for two different paths, both correct by design.

### KaynLoader Callstack Spoofing (HVC-044 Sub-1)

**`KaynSpoofEntry` is x64 only.** The ASM function is declared `global KaynSpoofEntry` in
`payloads/Shellcode/Source/Asm/x64/Asm.s`. The `extern` declaration in `Core.h` and every
call site in `Entry.c` must be guarded by `#ifdef _WIN64`. For x86 builds, `Entry.c` falls
back to a direct `KaynDllMain(...)` call unconditionally.

**Stack layout on entry to `KaynSpoofEntry` (Windows x64 CALL semantics):**
- `[RSP+0x00]` = return address into `Entry.c` (will be overwritten)
- `[RSP+0x08..0x27]` = shadow space (32 bytes)
- `[RSP+0x28]` = FakeFrame1 (BaseThreadInitThunk) — 5th Windows x64 stack argument
- `[RSP+0x30]` = FakeFrame2 (RtlUserThreadStart) — 6th Windows x64 stack argument

**Argument shift before JMP:** `rcx`=Arg1, `rdx`=Arg2, `r8`=Arg3, `r9`=0. Target is saved
to `r10` before the shift. `[RSP+0x00]` is overwritten with FakeFrame1; FakeFrame2 and NULL
are written at `+0x08` and `+0x10`. Then `JMP r10`. Target sees FakeFrame1 as its return address.

**DemonMain never returns:** it exits via `RtlExitUserThread`. The overwritten return address is
never fetched so the fake frame write is always safe.

**Hash constants in `Core.h` (DJB2 seed 5381, uppercase, verified 2026-05-25):**
- `KERNEL32_HASH = 0x6ddb9555`
- `BASETHREADINITTHUNK_HASH = 0xe2491896`
- `RTLUSERTHREADSTART_HASH = 0x0353797c`

**Graceful degrade:** If `LdrModulePeb(KERNEL32_HASH)` or `LdrFunctionAddr(..., RTLUSERTHREADSTART_HASH)`
returns NULL, fall back to direct `KaynDllMain(...)` call. Never crash on resolution failure.

### Injection Thread Stack Spoofing (HVC-044 Sub-2 Tier 1)

**Gate:** `Config.Implant.StackSpoof == TRUE` AND `Win32.RtlUserThreadStart != NULL`. Gated by
`#ifdef _WIN64` — x86 path is unchanged.

**Mechanism (Tier 1):** Pass `Instance->Win32.RtlUserThreadStart` as `StartRoutine` and the
shellcode `Entry` as `Argument` in `SysNtCreateThreadEx`. The Windows kernel calls
`RtlUserThreadStart(Entry, NULL)` which dispatches `Entry(NULL)`. `TEB.StartAddress` records
`RtlUserThreadStart` (ntdll image) instead of the shellcode address, clearing pe-sieve `SUS_START`.

**`Arg` is discarded:** `RtlUserThreadStart(Entry, NULL)` calls `Entry(NULL)`. For KaynLoader-based
payloads this is safe — `Start()` does not read RCX. For arbitrary shellcode that requires its
argument via RCX, the operator MUST disable StackSpoof in the profile.

**UI:** The "Stack Duplication" checkbox in the Payload dialog is enabled for ALL sleep techniques
(not only Ekko/Zilean). For Ekko/Zilean it also enables sleep TIB-swap; for all techniques it
enables Tier 1 injection thread spoofing.

### Command Split Pattern (HVC-032)

**All command handler code lives in `src/commands/Command_<Group>.c`, not in `Command.c`.**
`Command.c` is a thin dispatcher: it holds only the `DemonCommands[]` dispatch table,
`CommandDispatcher`, `CommandCheckin`, `InWorkingHours`, `ReachedKillDate`, `KillDate`, and
`CommandExit`. Every handler function body must be in the appropriate split file.

**Adding a new command group:**
1. Create `src/commands/Command_<Group>.c` and `include/commands/Command_<Group>.h`
2. Add command ID constants to `include/core/Command.h`
3. Add the `.c` file to `COMMON_SOURCE` in `CMakeLists.txt`
4. Include the new header in `Command.c` with `#include <commands/Command_<Group>.h>`
5. Add a dispatch table entry `{ .ID = DEMON_COMMAND_<GROUP>, .Function = Command<Group> }` to `DemonCommands[]`
6. Add new Win32 function pointer fields to `Demon.h`, hash constants to `Defines.h`, and runtime resolution to `Runtime.c` (following the existing HideChar-scrambled pattern)
7. Add TeamServer `TaskPrepare` + `TaskDispatch` cases to `teamserver/pkg/agent/demons.go`
8. Add client parsing in `client/src/Havoc/Demon/ConsoleInput.cc` and send helpers in `CommandSend.cc`

**COM dynamic resolution rule:** All COM usage in the agent must go through function pointers resolved at
startup by `RtOle32()` in `Runtime.c` (or loaded inline via `LdrModuleLoad` for rarely-used modules like
`dbghelp.dll`). No COM import table entries. All COM interfaces are called via vtable slot indexing.
`dbghelp.dll` is loaded inline at call time (not at startup) to avoid detectable load-time artifacts.

**LdrModuleLoad is the correct module loader** for both startup-time (Runtime.c blocks) and
inline/call-time loads. It handles all proxy loading modes internally and falls back to `LdrLoadDll`
automatically. Never call raw `LdrLoadDll` from command handlers unless `LdrModuleLoad` is unavailable.

### MinGW Cross-Compile Compat Blocks

Several Vista+/Win8.1+ types are not declared by the MinGW-w64 headers shipped with Kali
(mingw-w64 ≤ v10) even when `-D_WIN32_WINNT=0x0603` is set. Whenever a `src/commands/` file
needs one of these types, add an inline compat block guarded by the Windows SDK sentinel macro:

| Type(s) | Missing header | Guard | Typedef/struct |
|---------|---------------|-------|----------------|
| `CIMTYPE` | `wbemcli.h` | `CIMTYPE_DEFINED` | `typedef LONG CIMTYPE;` |
| `SOCKADDR_INET`, `PSOCKADDR_INET` | `ws2ipdef.h` | `SOCKADDR_INET_DEFINED` | union — do NOT use `SOCKADDR_IN6` as a member type (it too may be absent); inline as `struct { USHORT sin6_family; USHORT sin6_port; ULONG sin6_flowinfo; UCHAR sin6_addr[16]; ULONG sin6_scope_id; } Ipv6;` |
| `MIB_IPNET_ROW2`, `MIB_IPNET_TABLE2`, `NL_NEIGHBOR_STATE` | `netioapi.h` | `MIB_IPNET_TABLE2_DEFINED` | minimal structs from MSDN; `Table[1]` flexible-array |
| `PSS_CAPTURE_FLAGS`, `HPSS` | `processsnapshot.h` | `_PROCESSSNAPSHOT_H_` | `typedef DWORD PSS_CAPTURE_FLAGS; typedef PVOID HPSS;` |

Pattern: `#ifndef GUARD / #define GUARD / ... / #endif`. Nest inner guards (`IF_MAX_PHYS_ADDRESS_LENGTH`, `NL_NEIGHBOR_STATE_DEFINED`) inside the outer one. The Windows SDK uses the same guards so future MinGW versions that include these headers will skip the compat block automatically.

**Function pointer typedef return types must match Win32 exactly.** `CreateFileW` returns `HANDLE`
(not `BOOL`). `RegOpenKeyExW` returns `LONG` (not `DWORD`). A wrong return type compiles on macOS
(where the typedef is never used in a cross-compile context) but fails on MinGW with
"assignment to 'HANDLE' from 'BOOL' makes pointer from integer" at every call site.

**`WIN_FUNC(x)` cannot reference Vista+/Win8.1+ APIs** without `-D_WIN32_WINNT=0x0603` in CFlags
AND `src/commands` in builder.go `SourceDirs`. For APIs that are still problematic (because
`processsnapshot.h` or `netioapi.h` may not exist at all), use `PVOID FieldName;` in the
`WIN32_FUNC_LIST` struct and cast at the call site with a local typedef.

### Command Handler Stability Checklist

Before any `src/commands/Command_<Group>.c` file is considered complete, verify all of these:

1. **Every `MmHeapAlloc`/`LocalAlloc` result is checked for NULL before `MemCopy`/`MemSet`/field write.**
   OOM crashes the agent silently in a remote-injected process. Pattern: `ptr = MmHeapAlloc(n); if (!ptr) break;`

2. **No `return` from inside a switch case without transmitting a response.**
   A bare `return` in a case block leaks the `Package` allocation, leaks any open handles, and
   sends no response to the operator. Use `PackageAddInt32(Package, FALSE); break;` instead, or
   `PackageTransmitError(...)` + `return` if the command function owns that path exclusively.

3. **Token handles from `TokenCurrentHandle()` must be closed on every exit path.**
   The `hToken` pattern: open at the top of the function, null-set it in each case that closes
   it, then add a final `if (hToken) { SysNtClose(hToken); hToken = NULL; }` just before
   `PackageTransmit` to catch all remaining cases.

4. **Switch fallthrough is a critical bug.** Every `case` block that does not `return` or
   `goto` must end with `break;`. Verify this especially when the success path uses `return`
   and the failure path falls through — the `break;` must be in the failure path, not only
   in the success path.

5. **Pseudo-handles must not be closed.** `NtCurrentProcess()` returns `(HANDLE)-1`. Calling
   `SysNtClose` on it is harmless on current Windows but semantically wrong. Track whether a
   real handle was opened with a `BOOL OpenedHandle = FALSE` flag and only close when TRUE.

6. **Duplicate field writes corrupt the client parser.** Each `PackageAddWString`/`PackageAddInt32`
   call advances the client's read pointer. A duplicate write (e.g., `sesi10_username` twice)
   means all subsequent fields are read at the wrong offset. Audit every `for` loop that builds
   per-entry fields for correct field order and uniqueness.

### Debug Output String Formatting

**Never use an em dash (—) in any string literal in code.** Use a plain hyphen (-) instead.
Em dash (U+2014) does not render correctly in the Demon debug console terminal and produces
garbage characters or is silently dropped. This applies to all `PRINTF`/`PUTS` format strings,
log prefixes, and any other string that appears in terminal output, across all components
(Demon C, teamserver Go, client C++).

### Code Style and Review

**Always add comments to code.** Every new function must have a brief comment explaining its purpose and parameters. Non-obvious inline logic must have a one-line comment explaining the why. No multi-paragraph docstrings or comment blocks — one concise line per item. Exception: trivial getters or one-liners whose name already describes the operation fully.

**Match the existing coding style exactly.** In Demon C code: use `PVOID Var = { 0 };` style declarations, `PRINTF`/`PUTS` macros for all debug output (not printf), uppercase Windows type names (`PVOID`, `BOOL`, `ULONG`), spaces around operators and after commas. In Go: match builder.go field-naming and error-handling patterns exactly. In C++/Qt: match Payload.cc widget creation patterns exactly.

**Re-read every modified file after editing.** Before reporting a task complete, re-read each file that was changed and verify the edit is correct and in the right location. Report verified line numbers. This catches off-by-one insertions, missed edits, and merge-order mistakes before they reach the QA stage.

### File and Directory Deletion

**Never delete a file or directory without explicit permission from the user.** This applies to:
- Source files, headers, test files, documentation
- Configuration files, build system files
- Any file added or modified in the current session

If a file needs to be replaced or superseded, create the new version alongside the old one and note it in the PR description. Always ask the user before deleting anything.

## Versioning Rule (HVC-045)

Both teamserver and client use **3-part semver** (major.minor.patch):

- **Patch bump** (major.minor.patch+1): moderate changes, new features within a subsystem, no wire-protocol break. Update `CHANGES.md` only.
- **Minor bump** (major.minor+1.0): large codebase changes, new subsystems, breaking wire changes. Update `CHANGES.md` **and** `README.md`.
- Codename stays the same for a minor series (e.g. Eclipse Anchor for all 0.9.x / 1.9.x builds).
- Both teamserver and client version strings must be updated together for every change that adds new config blob fields (wire-format break = minor bump for both).
- Teamserver version is in `teamserver/cmd/cmd.go` (`VersionNumber`). Client version is in `client/src/global.cc` (`HavocNamespace::Version`).

## QA Rule (HVC-045)

After writing any new `.c`/`.cc`/`.go` source files:

1. Dispatch **QA Agent 1** (code quality): check NULL deref, missing return, handle leaks, stack overflow risk, USTRING aliasing, ROP chain register layout, shellcode-safe constraints.
2. Dispatch **QA Agent 2** (code correctness / tester): verify algorithm correctness against known test vectors, check compile-flag combinations, verify config blob field order matches between Go and C, verify UI key/label match against builder switch-case strings.
3. Fix all issues found before proceeding to integration.
4. Document fixes in `CHANGES.md`.

Both QA agents may be dispatched in parallel. Do not proceed to the next phase until both approve.

## Contributing

- Branch off `main`, submit PRs back to `main`
- Separate PRs for separate features/fixes (no monolithic PRs)

## Improvement Documentation

All improvement proposals, feature specifications, and enhancement plans for new capabilities must be written to the **`improvement-docs/`** directory at the repository root. This is the canonical location for:
- New feature specs (transport additions, evasion techniques, new commands)
- Refactoring proposals (module extraction, architecture changes)
- Traffic encoding / protocol improvement designs

See `improvement-docs/00-index.md` for the master index and item status. Each file follows the standard template (Status, Problem, Scope, Design, File Map, Tests, Notes). Do **not** place improvement specs in root-level markdown files or in memory files — `improvement-docs/` is the only correct location.
