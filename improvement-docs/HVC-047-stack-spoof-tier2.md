# HVC-047 — Configurable Injection Thread Callstack Spoofing (Tier 2)

## Status

`Planned`

## Problem

HVC-044 Sub-2 Tier 1 implemented a minimal injection thread start-address swap: `RtlUserThreadStart` is passed as `StartRoutine` to `SysNtCreateThreadEx`, making `TEB.Win32StartAddress` show an ntdll address. However, no fake return-address frames are written to the injected thread's stack. The callstack is either empty or a single frame — flagged by pe-sieve as `SUS_CALLSTACK_CORRUPT` and caught by equivalent EDR callstack integrity checks.

## Goal

Full Tier 2 stack spoofing: while the newly created injection thread is suspended, write a configurable fake callstack into its initial stack and overwrite `TEB.Win32StartAddress` with a configurable address. Both the start address and all four fake return-address frames are fully configurable per-build via YAOTL profile and Payload builder UI.

## Default callstack (mimics Windows thread-pool worker)

```
ntdll!TppWorkerThread                         ← TEB.Win32StartAddress
ntdll!NtWaitForWorkViaWorkerFactory+0x14      ← frame 0 (written at [RSP+0])
ntdll!TppWorkerThread+0x37e                   ← frame 1 (written at [RSP+8])
kernel32!BaseThreadInitThunk+0x17             ← frame 2 (written at [RSP+16])
ntdll!RtlUserThreadStart+0x2c                 ← frame 3 (written at [RSP+24])
NULL                                          ← stack terminator ([RSP+32])
```

## Mechanism — Suspend-Modify-Resume (SMR)

Explain the three-step process:

1. Thread is created SUSPENDED by passing `CreateSuspended=TRUE` to `SysNtCreateThreadEx`. The Tier 1 pointer swap (`StartRoutine=RtlUserThreadStart, StartArg=Entry`) is preserved unchanged so execution flows correctly.

2. While suspended: `NtGetContextThread` reads the initial RSP; `SysNtWriteVirtualMemory` writes 5 QWORDs (4 frames + NULL) at the thread's initial RSP in the target process; `NtSetInformationThread(Thread, 9 /*ThreadQuerySetWin32StartAddress*/, &SpoofStart, sizeof(PVOID))` overwrites `TEB.Win32StartAddress`.

3. `SysNtResumeThread` resumes the thread.

Note that arguments (Entry) are passed in registers (RCX), not on the stack, so overwriting [RSP+0..+32] does not corrupt execution.

## Why arguments are safe to overwrite

On x64, the first argument to `RtlUserThreadStart` (which is `Entry`) is in RCX. The kernel sets RCX = StartArg = Entry when setting up the thread context. The stack at RSP only contains the initial return address (which `RtlUserThreadStart` never uses — it calls `RtlExitUserThread` and never returns). Overwriting [RSP..RSP+32] is safe.

## Graceful degradation

If `InjSpoofStartAddr` is NULL after resolution (function not found in the target DLL), the fake frame write and TEB patch are skipped, but the thread is still resumed. Tier 1 (start-address swap) continues operating. If `StackSpoof=false`, the thread is not created suspended and the entire SMR path is skipped.

## Config pipeline

```
YAOTL profile (5 optional blocks: StackSpoofStartAddr, StackSpoofFrame0–3)
  → teamserver/pkg/profile/config.go (5 *AddrResolveBlock fields in Demon struct)
  → teamserver/pkg/common/builder/builder.go SetDemonProfileDefaults() (hardcoded fallbacks when absent)
  → builder.go PatchConfig(): 15 AddString/AddInt calls, blob fields 28–42
  → payloads/Demon/src/Demon.c DemonConfig(): 15 ParserGetString/GetInt32 calls
  → DemonInit(): LdrModuleLoad + LdrFunctionAddr + HashStringA(func) + offset → PVOID
  → Config.Implant.InjSpoofStartAddr, Config.Implant.InjSpoofFrame[4]
  → payloads/Demon/src/core/Thread.c ThreadCreate(): SMR writes
```

## Config blob field table

| Field index | Name | Type | Default value |
|---|---|---|---|
| 28 | StackSpoofStartLib | string | "ntdll.dll" |
| 29 | StackSpoofStartFunc | string | "TppWorkerThread" |
| 30 | StackSpoofStartOffset | int32 | 0 |
| 31 | StackSpoofFrame0Lib | string | "ntdll.dll" |
| 32 | StackSpoofFrame0Func | string | "NtWaitForWorkViaWorkerFactory" |
| 33 | StackSpoofFrame0Offset | int32 | 20 (0x14) |
| 34 | StackSpoofFrame1Lib | string | "ntdll.dll" |
| 35 | StackSpoofFrame1Func | string | "TppWorkerThread" |
| 36 | StackSpoofFrame1Offset | int32 | 894 (0x37e) |
| 37 | StackSpoofFrame2Lib | string | "kernel32.dll" |
| 38 | StackSpoofFrame2Func | string | "BaseThreadInitThunk" |
| 39 | StackSpoofFrame2Offset | int32 | 23 (0x17) |
| 40 | StackSpoofFrame3Lib | string | "ntdll.dll" |
| 41 | StackSpoofFrame3Func | string | "RtlUserThreadStart" |
| 42 | StackSpoofFrame3Offset | int32 | 44 (0x2c) |

Total blob fields: 43 (0–42). Fields 28–42 are new; all are appended after ExecDelayJitter (field 27).

## Address resolution

`HashStringA()` computes the DJB2 hash of the function name string at runtime — no pre-computed `H_FUNC_*` constants are required for `TppWorkerThread` or `NtWaitForWorkViaWorkerFactory`. `LdrModuleLoad()` handles all proxy-loading modes. The resolution pattern mirrors the existing `InjectSpoofAddr` resolution in Demon.c lines 1124–1133.

## Existing Win32 table entries reused (no new entries needed)

| Function | Demon.h line | Used for |
|---|---|---|
| NtGetContextThread | 239 | read initial thread RSP |
| NtSetInformationThread | 224 | set TEB.Win32StartAddress via ThreadQuerySetWin32StartAddress=9 |
| NtResumeThread (SysNtResumeThread) | 235 | resume suspended thread |
| NtWriteVirtualMemory (SysNtWriteVirtualMemory) | 246 | write fake frames to remote stack |

## YAOTL profile blocks (optional, all default to TppWorkerThread chain when absent)

```
StackSpoofStartAddr { Library = "ntdll.dll";    Function = "TppWorkerThread";               Offset = 0   }
StackSpoofFrame0    { Library = "ntdll.dll";    Function = "NtWaitForWorkViaWorkerFactory"; Offset = 20  }
StackSpoofFrame1    { Library = "ntdll.dll";    Function = "TppWorkerThread";               Offset = 894 }
StackSpoofFrame2    { Library = "kernel32.dll"; Function = "BaseThreadInitThunk";           Offset = 23  }
StackSpoofFrame3    { Library = "ntdll.dll";    Function = "RtlUserThreadStart";            Offset = 44  }
```

## Files changed

- payloads/Demon/include/Demon.h — PVOID InjSpoofStartAddr; PVOID InjSpoofFrame[4] in Config.Implant
- payloads/Demon/src/Demon.c — parse 15 new fields; resolve 5 addresses in DemonInit()
- payloads/Demon/src/core/Thread.c — SMR Tier 2 in ThreadCreate() NTCREATETHREADEX case
- teamserver/pkg/profile/config.go — 5 new *AddrResolveBlock fields
- teamserver/pkg/common/builder/builder.go — demonProfile + SetDemonProfileDefaults() + PatchConfig()
- client/src/UserInterface/Dialogs/Payload.cc — 15 new QLineEdit fields
- profiles/havoc.yaotl — 5 commented-out default blocks
- scripts/check_profile.py — 5 sub-block schemas + _validate_demon() loops

## Version

Wire-format change (15 new blob fields) = minor bump: teamserver 0.9.6→0.9.7, client 1.9.2→1.9.3.
