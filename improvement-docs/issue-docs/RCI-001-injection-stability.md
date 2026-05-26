# RCI-001 — Demon Shellcode Injection Stability Analysis

## Status
Open — PRIMARY CRASH (ISS-037) identified, fix pending; secondary issues pending

## Update — Re-evaluation After New Evidence

New facts established by operator testing:

- Shellcode injection succeeds
- Transport initialisation, DemonInit, and first registration packet all succeed (teamserver
  shows the agent connected)
- Crash occurs **immediately after registration** — within the first sleep cycle, before any
  operator tasks are sent
- Crash happens with **UnhookNtdll=false** (ISS-001 is not the primary cause)
- Crash happens with **HideModules=false** (ISS-002 is not the primary cause)
- The crash is directly correlated with HVC-031 Sub-2 code changes — the regression is
  present in the binary even when both features are disabled in the payload config

A second three-agent re-evaluation was performed, focused on the post-registration code path.

**Findings of re-evaluation:**

1. Config blob field ordering is **verified correct** — exhaustive side-by-side comparison of
   builder.go `AddInt`/`AddWString` calls vs Demon.c `ParserGetInt32`/`ParserGetBytes` calls
   shows all 15+ fields in identical order. No mismatch.

2. `Config.Implant` struct layout change (adding `BOOL HideModules` at the END) does **not**
   shift the offsets of any preceding or sibling struct — `HideModules` is appended after
   `UnhookNtdll`, and `Config.Transport` precedes `Config.Implant` in the outer struct, so
   no adjacent field is displaced.

3. **The primary crash cause is ISS-037** (see new entry): `PeProtect_Stomp()` called
   unconditionally in the DEFAULT sleep path on every first sleep after registration, without
   error checking on `NtProtectVirtualMemory`. In an injected process, this `NtProtect` call
   frequently fails; the subsequent `MemSet` to non-writable memory is an immediate AV.

4. The execution path is: `DemonRoutine()` → `CommandDispatcher()` → **`SleepObf()` is the
   first call** (before any task request) → DEFAULT case → `PeProtect_Stomp()` → AV → crash.
   The teamserver sends no automatic post-registration commands; the crash happens during the
   first sleep, which is why it appears to be "immediately after registration."

5. `PeProtect.c` was added by a prior HVC-030 sub-step and is linked unconditionally.
   `PeProtect_Stomp`/`PeProtect_Restore` were inserted into the `SLEEPOBF_NO_OBF` DEFAULT
   case, making them run for every payload that does not use sleep obfuscation — including
   all injected shellcode payloads where the operator chose no obfuscation technique.

**ISS-001 and ISS-002 remain valid issues** but are NOT the cause of the reported crash.
They are stability risks that must be fixed separately.

---

## Background

Analysis performed by four parallel red team developer agents inspecting the full Demon agent
codebase for stability issues that occur when the agent is injected into a remote process as
shellcode. The original symptom reported: any configuration variant of a Demon injected into a
remote process crashes the host process regardless of what that process is.

The agents covered four domains: (A) entry point and initialisation, (B) memory and PEB
operations, (C) config blob and syscall subsystem, (D) transport, HWBP, sleep obfuscation, and
runtime. Findings were deduplicated and contradictions resolved. Issues marked as "cleared" were
verified as non-bugs and excluded from the table.

**Cleared non-bugs:**
- `AgentConfig` zeroed by `RtlSecureZeroMemory` before parser reads it — `ParserNew` copies
  the blob to a heap allocation first; the wipe only affects the in-.data copy. Not a bug.
- `NtdllCopy` bounds overrun — bounds are correct; `ProtAddr`/`ProtSize` aliasing guard is
  implemented correctly. Not a bug.
- `ConvertFiberToThread` called outside success guard — the call is inside the `if(Param.Master)`
  block. Not a bug.
- `CONFIG_BYTES` size mismatch — `sizeof(AgentConfig)` exactly matches the blob size. Not a bug.

---

## Issue Table

| ID | Severity | Area | File | Lines | Root Cause (short) | HVC |
|----|----------|------|------|-------|--------------------|-----|
| ISS-001 | CRITICAL | PEB/Memory | `NtdllUnhook.c` | 153-165 | `NtdllCopy` runs unsynchronised while host process threads execute ntdll .text — torn writes crash concurrent threads | HVC-031 Sub-4 |
| ISS-002 | CRITICAL | PEB/Memory | `MemoryHide.c` | 24-62 | `HideModule()` splices PEB LDR lists without holding `PEB->LoaderLock` — concurrent loader walker gets dangling pointer | HVC-031 Sub-2 |
| ISS-003 | CRITICAL | PEB/Memory | `Win32.c` | 65-201 | `LdrModulePeb` and `LdrModuleSearch` walk PEB LDR lists without `PEB->LoaderLock` — concurrent modification produces AV | Pre-existing |
| ISS-004 | CRITICAL | Syscalls | `Syscalls.c` | ~79 | `SysInitialize` has no `return` statement — undefined behaviour; EDR environments may cause it to return FALSE leaving `SysAddress=NULL` while `SysIndirect=TRUE` | Pre-existing |
| ISS-005 | CRITICAL | Config | `Parser.c` | 135-156 | `ParserGetBytes` does not guard against embedded `Length` exceeding remaining buffer — UINT32 underflow wraps `parser->Length` to ~0xFFFFFFxx; subsequent reads go far out of bounds | Pre-existing |
| ISS-006 | CRITICAL | Config | `Demon.c` | 729-935 | 15 `ParserGetBytes` call sites in `DemonConfig` do not check for NULL return before passing to `MemCopy` — NULL-source `memcpy` on first garbled/truncated blob field crashes immediately | Pre-existing |
| ISS-007 | CRITICAL | Init | `Demon.c` | 601-613 | `KArgs==NULL` fallback calls `IMAGE_SIZE(ModuleBase)` on a headerless KaynLdr mapping — reads `e_lfanew` from code bytes, producing a garbage RVA and an AV on the NT headers read | Pre-existing |
| ISS-008 | HIGH | Transport | `MainDll.c` | 40-42 | SHELLCODE mode calls `DemonMain` directly from `DllMain` without spawning a new thread — `DemonRoutine` (and WinHTTP) run on the loader-context thread; WinHTTP fails with `ERROR_INVALID_STATE` on some host configurations; for non-KaynLdr injectors that hold the real loader lock this causes permanent deadlock | Pre-existing |
| ISS-009 | HIGH | Architecture | `Demon.c` | 51-54 | `INSTANCE Inst = { 0 }` is stack-allocated in `DemonMain` — the entire agent state lives in one thread's frame; sleep-obf context manipulation (FoliageObf `NtSetContextThread`, TimerObf NtTib swap) operates on the frame that holds the struct; any stack corruption kills the entire agent state with no recovery | Pre-existing |
| ISS-010 | HIGH | Init | `Demon.c` | 576-579 | `RtModules` loop returns from `DemonInit` on first Rt* failure without setting a flag — `DemonMetaData` then dereferences `Instance->Win32.*` and `Instance->Session.*` fields that were never set, causing NULL pointer dereferences | Pre-existing |
| ISS-011 | HIGH | PEB/Memory | `Win32.c` | 191-198 | `LdrModuleSearch` do-while advances cursor after reading `BaseDllName.Buffer`; a concurrent `HideModule()` unlink between the compare and the `Flink` read leaves the cursor pointing to an unlinked entry — infinite loop or AV | HVC-031 Sub-2 (interaction) |
| ISS-012 | HIGH | Evasion | `Win32.c` | 955-1004 | `BypassPatchAMSI()` uses `PAGE_EXECUTE_READWRITE` and writes the forbidden `0xB8 0x57 0x00 0x07 0x80 0xC3` byte sequence over `AmsiScanBuffer` — two simultaneous CLAUDE.md constraint violations; function is dead code but its presence is a static binary signature | Pre-existing |
| ISS-013 | HIGH | Sleep Obf | `ObfFoliage.c` | 159,179,221,243 | Foliage ROP chain's four protect steps (`RopSetMemRw`, `RopSetMemNA`, `RopSetMemRw2`, `RopSetMemRx`) use `Instance->Win32.NtProtectVirtualMemory` — the EDR-hookable Win32 pointer; if `UnhookNtdll` failed or is disabled, the EDR hook fires during the sleep ROP chain and may terminate the process | Pre-existing; interaction with HVC-031 Sub-4 |
| ISS-014 | HIGH | Sleep Obf | `ObfTimer.c` | 261-286 | TimerObf `StackSpoof=TRUE` path swaps `NtTib.StackBase/StackLimit` between two thread TIBs; an asynchronous exception (APC, debugger attach, hardware fault) during the swap window causes `RtlDispatchException` to use wrong stack bounds for SEH unwind — `STATUS_STACK_OVERFLOW` or unhandled exception terminates the process | HVC-030 |
| ISS-015 | HIGH | Config | `builder.go` | ~1109 | No validation in `PatchConfig()` that `UnhookNtdll=true` requires `IndirectSyscall=true` — a profile that sets only `UnhookNtdll` silently gets `UnhookNtdll` disabled at runtime (guard at `NtdllUnhook.c:59-62`); no teamserver-side warning is emitted | HVC-031 Sub-4 |
| ISS-016 | HIGH | Config | `Demon.c` | 730 | `ParserNew` calls `Instance->Win32.LocalAlloc(LPTR, size)`; OOM in the injected process returns NULL; `parser->Buffer = NULL`; the first `ParserGetInt32` call does `MemCopy(intBytes, NULL, 4)` — NULL-source dereference crash | Pre-existing |
| ISS-017 | HIGH | Sleep Obf | `Thread.c` | ~61 | `ThreadQueryTib` suspends all non-current threads via `SysNtSuspendThread` to read their RSP/TEB for stack-spoof construction; suspending a host thread that holds a `CriticalSection` or the heap allocator lock causes priority-inversion deadlock in the host process | HVC-030 |
| ISS-018 | MEDIUM | Metadata | `Demon.c` | 297-298 | `Instance->Session.PPID` is declared and transmitted in registration metadata but is never queried — `NtQueryInformationProcess(ProcessBasicInformation)` is never called; teamserver always receives PPID=0; visible opsec anomaly in all injected sessions | Pre-existing |
| ISS-019 | MEDIUM | Module Load | `Win32.c` | 280-342 | `ProxyLoading` timer path (`RtlCreateTimer`) fires `LoadLibraryW` on a thread-pool thread; if the injector framework holds the real loader lock, the pool thread deadlocks waiting for it; the 5-retry PEB poll (500ms) times out, falls back to `LdrLoadDll`, which also tries the lock — second deadlock | Pre-existing |
| ISS-020 | MEDIUM | Init | `Win32.c` | 1423-1425 | `___chkstk_ms` replaced with a NOP — suppresses Windows stack-growth probing; any future function added to the `DemonInit` call chain with a local buffer >4KB will silently skip guard pages and crash with an unprobed AV | Pre-existing |
| ISS-021 | MEDIUM | Sleep Obf | `ObfFoliage.c` | 289 | Fake callstack frames written at `StackBase - 0x50`; if the injected thread was created with a minimal-commit stack where `StackBase - 0x50` is a guard page, the write produces an AV | HVC-030 |
| ISS-022 | MEDIUM | Config | `Demon.c` | 847,863 | HTTP headers and URI arrays are allocated with `(J+1)*2` slots but the NULL sentinel is written at index `J+1` instead of `J` — off-by-one leaves the last populated slot unterminated for any code that scans for the sentinel | Pre-existing |
| ISS-023 | MEDIUM | Init | `Demon.c` | 786,920 | Kill-date `RtlExitUserThread` path exits without zeroing `Instance->Config`, freeing heap allocations (`Spawn64`, `Spawn86`), or zeroing the partial config stack frame — config material remains readable in process memory until stack page recycled | Pre-existing |
| ISS-024 | MEDIUM | Config | `builder.go` | 866,1120 | `DemonConfig.AddInt` calls are split into two blocks separated by ~250 lines of option-parsing code; a developer inserting a new field in either block without updating both and the corresponding Demon.c parse sequence silently misaligns all subsequent fields | Pre-existing; maintainability |
| ISS-025 | MEDIUM | Syscalls | `Demon.c` | 548-554 | `SysInitialize` return value is logged but execution continues regardless; when `SysAddress=NULL` with `SysIndirect=TRUE`, `SYSCALL_INVOKE` silently falls back to the hookable Win32 stub for all subsequent syscall wrappers — defeats the indirect syscall design without any runtime indicator | Pre-existing |
| ISS-026 | MEDIUM | Memory | `Memory.c` | 94-99 | `MmVirtualAlloc` passes the caller-supplied `Protect` argument directly to `SysNtAllocateVirtualMemory` with no guard against `PAGE_EXECUTE_READWRITE` (0x40) — call sites in `Command.c` / `Inject.c` could violate the CLAUDE.md constraint silently | Pre-existing |
| ISS-027 | MEDIUM | Sleep Obf | `ObfFoliage.c` | 289 | `Instance->Teb->NtTib.StackBase` is fixed at `DemonInit` time (the KaynLdr entry thread's TEB); if `SleepObf` is ever called from a different thread or after a fiber switch, `StackBase` describes the wrong stack — fake frame write lands outside the current stack and produces an AV | HVC-030 |
| ISS-028 | MEDIUM | Init | `Demon.c` | ~730 | `DemonConfig` uses `Instance->Win32.LocalAlloc` without first confirming it is non-NULL (kernel32 resolution could have failed silently earlier in `DemonInit`) — NULL function-pointer call crashes immediately | Pre-existing |
| ISS-029 | MEDIUM | HWBP | `HwBpEngine.c` | 37-44 | `HwBpEngineInit` registers a new VEH handler each time it is called without checking whether one is already registered; repeated `inline-execute dotnet` commands accumulate unreleased VEH entries in the process-wide VEH chain; each leaked VEH adds overhead to every exception dispatch | Pre-existing |
| ISS-030 | MEDIUM | Syscalls | `Syscalls.c` | 22-34 | `SysInitialize` resolves `SysAddress` only from `NtAddBootEntry`; if `LdrFunctionAddr` returns NULL for that export (EDR hiding it), `SysAddress` remains NULL and all 35 SSN extractions are wasted — no fallback to try another NT function to locate the `syscall` gadget | Pre-existing |
| ISS-031 | LOW | Init | `Demon.c` | 346 | `Instance->Teb = NtCurrentTeb()` is set inside `DemonInit`, not immediately after `Instance = &Inst` in `DemonMain`; code inserted between those two points that calls `NtProcessHeap()` or `NtSetLastError` would dereference NULL `Instance->Teb` | Pre-existing |
| ISS-032 | LOW | Evasion | `Command.c` | 1948,2045 | `HideModule()` is called before `LdrFunctionAddr` at both call sites — this is correct (LdrFunctionAddr walks the PE export table directly, never re-queries PEB) but is not documented; future code inserting a PEB-walk call between the two will miss the unlinked module | HVC-031 Sub-2 |
| ISS-033 | LOW | Loader | `Shellcode/Entry.c` | 80-91 | KaynLoader protection cascade uses if-fall-through; a section with `IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE` (which MinGW may produce) is mapped `PAGE_EXECUTE_READWRITE` — RWX region is a CLAUDE.md violation and a pe-sieve / EDR detection point | Pre-existing |
| ISS-034 | LOW | Sleep Obf | `ObfFoliage.c` | 400-403 | `SysNtTerminateThread(hThread, STATUS_SUCCESS)` is called unconditionally in the cleanup block even after `hThread` has already exited cleanly via `RopExitThd`; the redundant kernel transition shows as an anomalous post-exit terminate in ETW `ProcessTelemetryId` traces | HVC-030 |
| ISS-035 | LOW | Module Load | `Win32.c` | 318-342 | `ProxyLoading` PEB poll uses `SharedSleep(100)` — a 100ms CPU-bound busy-wait with no yield; with 10+ modules in the `RtModules` array at worst-case this burns ~5 seconds at 100% CPU on the agent thread before falling back, visible to any CPU monitoring on the host | Pre-existing |
| ISS-036 | LOW | Evasion | `Win32.c` | 989-998 | `BypassPatchAMSI` second `SysNtProtectVirtualMemory` call reuses the page-aligned `lpBaseAddress`/`uSize` from the first call without resetting — violates the aliasing pattern documented in CLAUDE.md; dead code so no runtime impact currently | Pre-existing |
| **ISS-037** | **CRITICAL** | **Sleep Obf** | **`PeProtect.c` / `Obf.c`** | **Obf.c DEFAULT case; PeProtect.c:20-35** | **`PeProtect_Stomp()` called unconditionally in `SLEEPOBF_NO_OBF` DEFAULT path without error checking on `NtProtectVirtualMemory` — in an injected process the NtProtect call fails; `MemSet` then writes to non-writable memory producing an immediate AV on the first sleep after registration. PRIMARY CRASH CAUSE.** | **HVC-030 Sub-2** |

---

## Detailed Analysis

### ISS-001 — CRITICAL — Unsynchronised ntdll .text overwrite races host process threads
**File:** `payloads/Demon/src/core/NtdllUnhook.c` lines 153-165  
**HVC:** HVC-031 Sub-4

`UnhookNtdll()` changes ntdll `.text` to `PAGE_EXECUTE_WRITECOPY` then runs `NtdllCopy()` — a
QWORD-store loop writing up to ~1.5 MB of bytes. The host process is multi-threaded. Any thread
currently executing or about to return through ntdll `.text` will read a cache line that is mid-
overwrite. Intel processors can fetch a partially-written cache line, decode a garbage instruction
sequence, and take a #GP or #UD fault. No VEH is registered to handle this; the result is an
unhandled exception and process termination.

There is zero synchronisation: no `NtSuspendProcess`, no `NtGetNextThread`+`NtSuspendThread`
loop, no check that other threads are idle. This is the most likely root cause of the reported
"crashes regardless of configuration" symptom when `UnhookNtdll=true`.

**Fix:** Freeze all non-Demon threads before `NtdllCopy` using `NtGetNextThread` +
`SysNtSuspendThread`, then resume them after the protection restore. Alternatively, detect
injection context (Demon PID != host PID) and skip `UnhookNtdll` when injected into a foreign
process.

```c
HANDLE hThread = NULL;
while ( NT_SUCCESS( Instance->Win32.NtGetNextThread(
        NtCurrentProcess(), hThread, THREAD_SUSPEND_RESUME, 0, 0, &hThread ) ) ) {
    if ( hThread != NtCurrentThread() )
        SysNtSuspendThread( hThread, NULL );
}
/* ... SysNtProtect / NtdllCopy / SysNtProtect ... */
/* resume all threads: same NtGetNextThread walk with NtResumeThread */
```

---

### ISS-002 — CRITICAL — HideModule() modifies PEB LDR lists without loader lock
**File:** `payloads/Demon/src/core/MemoryHide.c` lines 24-62  
**HVC:** HVC-031 Sub-2

All three PEB LDR lists (`InLoadOrderModuleList`, `InMemoryOrderModuleList`,
`InInitializationOrderModuleList`) are protected by `PEB->LoaderLock` (an
`RTL_CRITICAL_SECTION`). Any thread calling `LoadLibrary`, `GetModuleHandle`, `FreeLibrary`,
`CreateToolhelp32Snapshot`, or any loader-path function holds this lock during the walk.
`HideModule()` directly splices list pointers with no lock held. If a host thread is mid-walk
and its cursor points to the entry being unlinked, `cursor->Flink` becomes a dangling pointer
after the unlink — access violation on the next iteration.

**Fix:** Acquire the loader lock before any list modification:

```c
ULONG Cookie = 0;
Instance->Win32.LdrLockLoaderLock( 0, NULL, &Cookie );
/* ... walk and unlink ... */
Instance->Win32.LdrUnlockLoaderLock( 0, Cookie );
```

`LdrLockLoaderLock` / `LdrUnlockLoaderLock` are stable ntdll exports. Alternatively use
`RtlEnterCriticalSection( Peb->LoaderLock )` / `RtlLeaveCriticalSection` directly.

---

### ISS-003 — CRITICAL — LdrModulePeb / LdrModuleSearch walk PEB LDR lists without loader lock
**File:** `payloads/Demon/src/core/Win32.c` lines 65-201  
**HVC:** Pre-existing; interaction with HVC-031 Sub-2

Same root cause as ISS-002. `LdrModulePeb()` (lines 79-90) and `LdrModuleSearch()` (lines
179-198) both iterate `InLoadOrderModuleList` without holding `PEB->LoaderLock`. In a host
process where other threads are actively loading or unloading modules, the list can be modified
between the cursor read and the `Flink` dereference, producing a dangling-pointer AV.

Compounded by ISS-002: `HideModule()` now also modifies the list without the lock, creating a
new concurrent modification hazard that did not exist before HVC-031 Sub-2.

**Fix:** Both functions must acquire `PEB->LoaderLock` on entry and release on exit. Early
bootstrap calls (before `LdrLockLoaderLock` is resolved) can use
`RtlEnterCriticalSection(Peb->LoaderLock)` directly.

---

### ISS-004 — CRITICAL — Missing `return` at end of SysInitialize
**File:** `payloads/Demon/src/core/Syscalls.c` ~line 79  
**HVC:** Pre-existing

`SysInitialize` is declared `BOOL SysInitialize(IN PVOID Ntdll)` but has no `return` statement.
Under C11 (the project standard), falling off a non-void function is undefined behaviour. Under
MinGW `-Os`, the accidental return value is whatever happens to be in `rax` from the last macro
expansion — typically the return value of the final `SysExtract` call. In an EDR environment
where `SysExtract` calls `FindSsnOfHookedSyscall` for a hidden export, this returns FALSE,
causing the caller at `Demon.c:550` to log "Failed to Initialize syscalls" and continue with
`SysAddress=NULL`. All subsequent `SYSCALL_INVOKE` calls silently fall back to the hookable
Win32 stub.

**Fix:** Add `return Instance->Syscall.SysAddress != NULL;` as the final statement.

---

### ISS-005 — CRITICAL — ParserGetBytes UINT32 underflow on malformed config blob
**File:** `payloads/Demon/src/core/Parser.c` lines 135-156  
**HVC:** Pre-existing

`ParserGetBytes` checks `if (parser->Length < 4) return NULL;` but does not verify that the
embedded `Length` field fits within the remaining buffer. After reading the 4-byte length prefix:

```c
parser->Length -= 4;
parser->Length -= Length;   /* UINT32 underflow if Length > remaining */
parser->Buffer += Length;   /* out-of-bounds pointer advance */
```

If the AES-CTR decryption in HVC-014 uses a mismatched key/IV (wrong profile, stale build
cache), the plaintext is garbage. The first `ParserGetBytes` call reads a huge `Length` value,
wraps `parser->Length` to ~0xFFFFFFxx, and every subsequent read goes far beyond the heap
allocation — heap-read crash or silent misparse cascading into NULL dereferences.

**Fix:**
```c
if ( parser->Length < 4 + Length ) {
    parser->Buffer += 4;
    if ( size ) *size = 0;
    return NULL;
}
```

---

### ISS-006 — CRITICAL — No NULL check on ParserGetBytes return before MemCopy
**File:** `payloads/Demon/src/Demon.c` lines 729-935 (15 call sites)  
**HVC:** Pre-existing

Every `ParserGetBytes` call in `DemonConfig` is followed immediately by `MemCopy(dest, Buffer, Length)` without checking whether `Buffer` is NULL. When `ParserGetBytes` returns NULL (truncated blob, parser underflow from ISS-005, OOM from ISS-016), the first occurrence is:

```c
Buffer = ParserGetBytes( &Parser, &Length );
Instance->Config.Process.Spawn64 = Instance->Win32.LocalAlloc( LPTR, Length );
MemCopy( Instance->Config.Process.Spawn64, Buffer, Length ); /* NULL-source crash */
```

On Windows with DEP enabled, `memcpy` from a NULL source faults immediately.

**Fix:** Add a NULL guard at every `ParserGetBytes` call site, or add the check inside `ParserGetBytes` itself and return a pointer to a zero-length static buffer instead of NULL.

---

### ISS-007 — CRITICAL — KArgs==NULL fallback reads IMAGE_SIZE from non-PE mapping
**File:** `payloads/Demon/src/Demon.c` lines 601-613  
**HVC:** Pre-existing

When `KArgs == NULL` (injection framework that does not pass KaynArgs), the else branch at
line 612 executes:

```c
Instance->Session.ModuleSize = IMAGE_SIZE( Instance->Session.ModuleBase );
```

`IMAGE_SIZE` reads `((PIMAGE_DOS_HEADER)IM)->e_lfanew` then dereferences that RVA to reach
the NT headers' `SizeOfImage`. KaynLdr produces a headerless mapping — `ModuleBase` points
to the first byte of executable code, not a DOS header. Reading `e_lfanew` from code bytes
produces a garbage RVA, and the NT headers read accesses an arbitrary address — AV.

**Fix:** Validate the MZ signature before calling `IMAGE_SIZE`:

```c
if ( *(PWORD)Instance->Session.ModuleBase == IMAGE_DOS_SIGNATURE )
    Instance->Session.ModuleSize = IMAGE_SIZE( Instance->Session.ModuleBase );
else
    Instance->Session.ModuleSize = 0;
```

---

### ISS-008 — HIGH — SHELLCODE mode runs DemonRoutine on the loader/entry thread
**File:** `payloads/Demon/src/main/MainDll.c` lines 40-42  
**HVC:** Pre-existing; comment at lines 44-47 acknowledges WinHTTP restriction

In SHELLCODE mode, `DllMain` calls `DemonMain` directly without creating a new thread. The
code's own comment (lines 44-47) documents that WinHTTP cannot send requests from a DllMain-
context thread. `DemonRoutine` (which calls `TransportInit` and all subsequent HTTP operations)
runs on this same thread forever since `DemonRoutine` is `_Noreturn`.

For KaynLdr delivery, the Windows loader lock is not held (KaynLdr calls DllMain directly
without going through `LdrpCallInitRoutine`), so loader-lock deadlock is not the issue. The
WinHTTP restriction is: WinHTTP internal worker threads fail to initialise on certain Windows
versions and host configurations when the calling thread is in the DllMain execution context,
producing `ERROR_INVALID_STATE` on the first `WinHttpSendRequest`. For non-KaynLdr injectors
that do go through the Windows loader, the lock IS held for the lifetime of `DemonRoutine`,
deadlocking any host thread that calls `LoadLibrary`.

**Fix:** Mirror the non-SHELLCODE path — even in SHELLCODE mode, create a new thread for
`DemonMain` after initial module resolution and return from DllMain immediately:

```c
#ifdef SHELLCODE
    HANDLE hThread = NULL;
    SysNtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
                         C_PTR( DemonMain ), hDllBase, FALSE, 0, 0, 0, NULL );
    /* Return TRUE immediately without calling DemonMain here */
#endif
```

---

### ISS-009 — HIGH — INSTANCE struct stack-allocated in DemonMain
**File:** `payloads/Demon/src/Demon.c` lines 51-54  
**HVC:** Pre-existing

`INSTANCE Inst = { 0 }` is a local variable in `DemonMain`. The global `Instance = &Inst`
makes the entire agent state reside in one thread's stack frame. `DemonRoutine` is `_Noreturn`
so the frame is valid indefinitely — but only as long as that exact thread is alive and its
stack is uncorrupted.

Sleep obfuscation techniques (FoliageObf's `NtSetContextThread`, TimerObf's NtTib swap) operate
on the context of the thread whose stack contains the INSTANCE struct. A bug in context
restoration corrupts the struct directly. Any stack overflow (command handler recursion, injected
BOF with a large local array) corrupts the struct with no recovery path.

**Fix:** Allocate INSTANCE on the heap using bootstrap PEB resolution before the Win32 table is
populated. Use `RtlAllocateHeap(PEB->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(INSTANCE))` in
`DemonMain` before `DemonInit`.

---

### ISS-010 — HIGH — Rt* failure causes early DemonInit return, then DemonMetaData dereferences uninitialised pointers
**File:** `payloads/Demon/src/Demon.c` lines 576-579  
**HVC:** Pre-existing

```c
if ( ! ( ( BOOL (*)() ) RtModules[ i ] ) () ) {
    PUTS( "Failed to load a module" )
    return;
}
```

The bare `return` exits `DemonInit` without marking a failure flag. `DemonMain` then calls
`DemonMetaData()` on a partially-initialised INSTANCE. `DemonMetaData` accesses
`Instance->Win32.*` and `Instance->Session.*` fields that were never set, producing NULL
function-pointer calls and NULL-pointer dereferences.

**Fix:** Set `Instance->Session.InitFailed = TRUE` on failure and check it in `DemonMain` before
calling `DemonMetaData`. Or skip straight to `RtlExitUserThread` on mandatory module failure.

---

### ISS-011 — HIGH — LdrModuleSearch infinite loop on concurrent HideModule unlink
**File:** `payloads/Demon/src/core/Win32.c` lines 191-198  
**HVC:** HVC-031 Sub-2 (interaction)

`LdrModuleSearch` advances its cursor **after** reading `BaseDllName.Buffer`:

```c
do {
    if ( !StringCompareIW( Name, Entry->BaseDllName.Buffer ) ) { ... }
    Entry = (PLDR_DATA_TABLE_ENTRY) Entry->InLoadOrderLinks.Flink;
} while ( Entry != FirstEntry );
```

A concurrent `HideModule()` call that unlinks `Entry` between the compare and the `Flink` read
leaves `Entry` pointing to a removed node. If list corruption causes `Entry->InLoadOrderLinks.Flink`
to cycle back to itself, `while (Entry != FirstEntry)` never terminates — the agent thread hangs
forever. The fix for ISS-003 (loader lock in all PEB walks) also resolves this issue.

---

### ISS-012 — HIGH — BypassPatchAMSI violates two CLAUDE.md constraints (dead code)
**File:** `payloads/Demon/src/core/Win32.c` lines 955-1004  
**HVC:** Pre-existing

`BypassPatchAMSI()` uses `PAGE_EXECUTE_READWRITE` (explicitly forbidden) and writes
`0xB8 0x57 0x00 0x07 0x80 0xC3` over `AmsiScanBuffer` (explicitly forbidden). The function is
dead code — no call site exists in the current codebase — but its presence produces a binary
signature (the patch bytes and function name survive in the object).

**Fix:** Delete `BypassPatchAMSI()` from `Win32.c` and its declaration from `Win32.h`. If AMSI
patching for .NET inline execute is required, route it through `HwBpEngine` (the HWBP path at
`Dotnet.c:87`).

---

### ISS-013 — HIGH — FoliageObf ROP protect steps use hookable Win32 NtProtectVirtualMemory
**File:** `payloads/Demon/src/core/ObfFoliage.c` lines 159, 179, 221, 243  
**HVC:** Pre-existing; interaction with HVC-031 Sub-4

All four Foliage protect ROP steps set `Rip = Instance->Win32.NtProtectVirtualMemory` — the
Win32 table entry, which resolves to the in-process ntdll `.text` copy and may be EDR-hooked.
`UnhookNtdll` (HVC-031 Sub-4) is designed to remove these inline hooks before the first sleep
cycle. If `UnhookNtdll` fails or is disabled, the hooked pointer remains and the EDR fires
on the protect transitions during sleep, potentially terminating the process.

CLAUDE.md forbids using `Instance->Win32.NtProtectVirtualMemory` for EDR-sensitive paths and
requires `SysNtProtectVirtualMemory` instead.

**Fix:** Replace all four ROP `Rip` assignments with the indirect syscall trampoline address.
This requires that `SysInitialize` has run and `SysAddress` / `NtProtectVirtualMemory` SSN are
populated — both of which are guaranteed if `SysIndirect=TRUE` (which must be true for
`UnhookNtdll` anyway, so the dependency is already established).

---

### ISS-014 — HIGH — TimerObf NtTib swap has no recovery from async exception during swap window
**File:** `payloads/Demon/src/core/ObfTimer.c` lines 261-286  
**HVC:** HVC-030

When `StackSpoof=TRUE`, TimerObf overwrites `Instance->Teb->NtTib` with the timer thread's
NtTib (swapping `StackBase`/`StackLimit`). If an asynchronous exception fires during the window
between the swap and the restore, `RtlDispatchException` reads the wrong `StackBase`/`StackLimit`
for SEH unwinding — the unwind fails with `STATUS_STACK_OVERFLOW` or terminates the process.

**Fix:** Narrow the swap window by moving the NtTib restore to be the very first operation after
wake (before `SystemFunction032` decrypt). Add a VEH handler that restores NtTib from `BkpTib`
if an exception fires while the swap is active (detectable via a thread-local flag or a magic
value in a scratch register).

---

### ISS-015 — HIGH — No builder validation that UnhookNtdll requires IndirectSyscall
**File:** `teamserver/pkg/common/builder/builder.go` ~line 1109  
**HVC:** HVC-031 Sub-4

A profile with `UnhookNtdll=true` and `IndirectSyscall=false` compiles and deploys without
warning. At runtime, `UnhookNtdll.c:59-62` checks `SysIndirect` and returns FALSE silently
(only logged in DEBUG builds). The operator has no visibility that ntdll unhooking is disabled.

**Fix:** Add a builder-side validation in `PatchConfig()`:

```go
if ConfigUnhookNtdll == win32.TRUE && ConfigSyscall == win32.FALSE {
    b.SendConsoleMessage("Warning",
        "UnhookNtdll requires IndirectSyscall=true - UnhookNtdll will be disabled at runtime")
}
```

---

### ISS-016 — HIGH — ParserNew LocalAlloc OOM leaves Parser.Buffer = NULL
**File:** `payloads/Demon/src/Demon.c` line 730  
**HVC:** Pre-existing

`ParserNew` calls `Instance->Win32.LocalAlloc(LPTR, sizeof(AgentConfig))` to copy the config
blob to a heap buffer before `RtlSecureZeroMemory` wipes the original. If `LocalAlloc` fails
(OOM in a large-heap host process like a browser), `parser->Original` and `parser->Buffer` are
NULL. The next `ParserGetInt32` call does `MemCopy(intBytes, NULL, 4)` — immediate crash.

**Fix:** Check `parser->Original` after `ParserNew` and bail if NULL.

---

### ISS-017 — HIGH — ThreadQueryTib suspends host process threads — deadlock risk
**File:** `payloads/Demon/src/core/Thread.c` ~line 61  
**HVC:** HVC-030

The StackSpoof thread-TIB scan calls `SysNtSuspendThread` on every non-current thread in the
host process. Suspending a thread that holds a `CRITICAL_SECTION`, the heap allocator lock, or
is inside a COM STA message pump causes priority-inversion deadlock. In host processes with
complex thread synchronisation (browsers, JVMs, .NET runtimes), this manifests as a hang that
kills the agent session (timeout disconnect from teamserver).

**Fix:** Before suspending, query `THREAD_BASIC_INFORMATION.WaitReason`. Skip threads with
`WrUserRequest` (COM pump), `WrAlerted`, `WrSuspended`. Only scan threads in
`WrExecutive` / alertable wait states. Alternatively, limit the TIB scan to a single attempt
with a timeout and skip StackSpoof if the scan cannot complete safely.

---

### ISS-018 — MEDIUM — PPID never queried; all injected sessions report PPID=0
**File:** `payloads/Demon/src/Demon.c` lines 297-298  
**HVC:** Pre-existing

`Instance->Session.PPID` is transmitted in registration metadata but is never assigned.
`INSTANCE Inst = { 0 }` zero-initialises it. The teamserver always receives PPID=0. This is a
visible opsec anomaly in the session table for all injected sessions.

**Fix:** In `DemonInit`, after the ntdll function table is populated, query the parent PID:

```c
PROCESS_BASIC_INFORMATION Pbi = { 0 };
if ( NT_SUCCESS( Instance->Win32.NtQueryInformationProcess(
        NtCurrentProcess(), ProcessBasicInformation, &Pbi, sizeof(Pbi), NULL ) ) )
    Instance->Session.PPID = (DWORD)(ULONG_PTR)Pbi.InheritedFromUniqueProcessId;
```

---

### ISS-037 — CRITICAL — PRIMARY CRASH CAUSE — PeProtect_Stomp() in DEFAULT sleep path
**File:** `payloads/Demon/src/core/PeProtect.c` lines 20-35; `payloads/Demon/src/core/Obf.c` DEFAULT case  
**HVC:** HVC-030 Sub-2

`PeProtect_Stomp()` is called unconditionally in `SleepObf()`'s DEFAULT/`SLEEPOBF_NO_OBF` case.
This code path runs on the **first sleep after registration** for any payload that does not use a
sleep obfuscation technique.

`PeProtect_Stomp()` does:
```c
NtProtectVirtualMemory( NtCurrentProcess(), &BaseAddr, &StompSize, PAGE_READWRITE, &OldProtect );
MemSet( BaseAddr, 0, 0x1000 );
NtProtectVirtualMemory( NtCurrentProcess(), &BaseAddr, &StompSize, PAGE_EXECUTE_READ, &OldProtect );
```

There is **no error check** on the first `NtProtectVirtualMemory` call. In a remote injected
process, this call can fail for multiple reasons:

- The Demon image may be backed by a `SEC_IMAGE` section object — the Windows memory manager
  (`MiChangeImageProtection`) rejects a `PAGE_READWRITE` (0x04) transition that strips the
  execute bit from an execute-image VAD page (exactly the SEC_IMAGE constraint documented in
  CLAUDE.md for ntdll unhooking)
- The allocation may have been created by KaynLdr with protection flags that the NT kernel will
  not further reduce without a specific `PAGE_EXECUTE_WRITECOPY` transition
- An EDR may intercept and block `PAGE_READWRITE` transitions on the Demon image region

When `NtProtectVirtualMemory` fails, `BaseAddr` is still the original (non-writable) address.
`MemSet(BaseAddr, 0, 0x1000)` then attempts to write to that address — **ACCESS VIOLATION**.
The host process terminates. This happens on the very first `SleepObf()` call, which is the
first thing `CommandDispatcher()` does after the session connects — explaining why the crash
occurs "immediately after registration" with no further activity.

**Why HVC-031 Sub-2 is correlated:** `PeProtect.c` was added to `CMakeLists.txt` as part of the
same batch of sleep-obf/evasion changes (HVC-030 Sub-2 PE header stomp). The `HideModules` flag
from HVC-031 Sub-2 was the most recent addition and so was blamed, but it is not the root cause.
The config blob ordering and struct layout changes from HVC-031 Sub-2 are correct and harmless.

**Fix options — in order of preference:**

Option A (recommended — minimal, surgical): Add an `NT_SUCCESS` guard in `PeProtect_Stomp()`:
```c
VOID PeProtect_Stomp( VOID ) {
    PVOID    BaseAddr  = Instance->Session.ModuleBase;
    SIZE_T   StompSize = 0x1000;
    NTSTATUS Status;
    ULONG    OldProtect = 0;

    Status = Instance->Win32.NtProtectVirtualMemory(
                 NtCurrentProcess(), &BaseAddr, &StompSize, PAGE_READWRITE, &OldProtect );
    if ( !NT_SUCCESS( Status ) ) {
        PRINTF( "PeProtect_Stomp: NtProtect failed 0x%X - skipping\n", Status )
        return;
    }
    MemSet( BaseAddr, 0, 0x1000 );
    Instance->Win32.NtProtectVirtualMemory(
        NtCurrentProcess(), &BaseAddr, &StompSize, PAGE_EXECUTE_READ, &OldProtect );
}
```

Option B: Use `SysNtProtectVirtualMemory` (indirect syscall) instead of
`Instance->Win32.NtProtectVirtualMemory` — same as the ntdll unhook fix. This also bypasses EDR
hooks on the protect call. Still requires the `NT_SUCCESS` guard.

Option C: Remove `PeProtect_Stomp`/`PeProtect_Restore` from the DEFAULT/`SLEEPOBF_NO_OBF` path.
PE header stomping during unobfuscated sleep provides negligible evasion benefit — a plaintext
in-memory agent is already trivially detectable. The stomp is meaningful only when combined with
memory encryption (Foliage, Ekko, Zilean) where the PE header is not visible anyway.

---

### ISS-019 through ISS-036 — MEDIUM / LOW

These issues are documented in the table above. They represent hardening opportunities,
maintainability risks, and minor policy violations but are not direct crash causes.
Detailed fix guidance for each is available from the agent analysis reports.

---

## Priority Order for Fixes

### P0 — Immediate (the reported crash — fix now)

1. **ISS-037** — Add `NT_SUCCESS` guard to `PeProtect_Stomp()` before the `MemSet` call, or
   use `SysNtProtectVirtualMemory` + `NT_SUCCESS` guard, or remove `PeProtect_Stomp`/`Restore`
   from the `SLEEPOBF_NO_OBF` DEFAULT case. This is the sole root cause of the reported
   "crashes immediately after registration" symptom. Fix in `PeProtect.c` and/or `Obf.c`.

### P1 — Critical stability (crash in specific scenarios — fix before enabling those features)

2. **ISS-001** — Suspend host threads before `NtdllCopy` in `UnhookNtdll()`. Required before
   `UnhookNtdll=true` can be safely used in injected processes.
3. **ISS-002 + ISS-003** — Acquire `PEB->LoaderLock` in `HideModule()`, `LdrModulePeb()`, and
   `LdrModuleSearch()`. Required before `HideModules=true` can be safely used in multi-threaded
   host processes.
4. **ISS-005 + ISS-006** — `ParserGetBytes` bounds check and NULL guards at all call sites.
   Prevents crash on malformed/garbled config blob (AES-CTR key/IV mismatch in custom profiles).
5. **ISS-007** — Guard the `KArgs==NULL` `IMAGE_SIZE` call with an MZ signature check. Prevents
   crash for non-KaynLdr injection frameworks.

### P2 — Short-term stability hardening

6. **ISS-004** — Add `return` to `SysInitialize` (UB, currently returns accidental value).
7. **ISS-008** — Create a new thread in SHELLCODE mode rather than running on the loader thread.
8. **ISS-010** — Set failure flag in Rt* loop rather than bare `return` from `DemonInit`.
9. **ISS-011** — Loader lock fix (from ISS-003) also resolves this.
10. **ISS-013** — Replace hookable `NtProtectVirtualMemory` in FoliageObf ROP steps with
    `SysNtProtectVirtualMemory` indirect syscall address.
11. **ISS-016** — Add OOM guard after `ParserNew` LocalAlloc call.

### P3 — Policy compliance and evasion quality

12. **ISS-012** — Delete `BypassPatchAMSI()` from `Win32.c` (dead code, two CLAUDE.md violations).
13. **ISS-014** — Narrow the TimerObf NtTib swap window; add VEH recovery.
14. **ISS-015** — Add builder-side validation for `UnhookNtdll` + `IndirectSyscall` dependency.
15. **ISS-017** — Add `WaitReason` filter to `ThreadQueryTib` to avoid suspending locked threads.
16. **ISS-018** — Query and populate `PPID` via `NtQueryInformationProcess` in `DemonInit`.
17. **ISS-025 + ISS-029 + ISS-030** — Syscall init hardening.

### P4 — Low priority (defensive hardening)

18. ISS-009, ISS-019 through ISS-028, ISS-031 through ISS-036.

---

## HVC Correlation Summary

| HVC | Issues introduced or implicated |
|-----|--------------------------------|
| HVC-030 Sub-2 (PE header stomp) | **ISS-037 (PRIMARY CRASH)**, ISS-009, ISS-013, ISS-014, ISS-017, ISS-021, ISS-027, ISS-034 |
| HVC-031 Sub-2 (module hide) | ISS-002, ISS-011, ISS-032 — **not the crash cause; feature is correctly gated** |
| HVC-031 Sub-4 (ntdll unhook) | ISS-001, ISS-013 (interaction), ISS-015 — **not the crash cause when UnhookNtdll=false** |
| Pre-existing | ISS-003 through ISS-010, ISS-012, ISS-016, ISS-018 through ISS-036 |

*Note: The crash was initially correlated with HVC-031 Sub-2 (the most recent change) but
re-evaluation confirmed the root cause is in `PeProtect.c` added by HVC-030 Sub-2. The
HVC-031 Sub-2 config blob ordering and struct layout changes are correct and harmless.*
