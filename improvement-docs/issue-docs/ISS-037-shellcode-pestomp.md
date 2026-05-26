# ISS-037-shell — PE Stomping Corrupts Code in KaynLdr Shellcode Deployments

## Status
Applied — 2026-05-25

## Problem

When Demon is deployed as shellcode via KaynLdr (e.g., injected by the "shellcode inject"
command from another Demon agent), enabling `PeStomp = true` causes the injected Demon to
crash on its first sleep cycle. The crash is silent: the agent registers with the teamserver,
then the host process terminates within seconds with no error output.

The ISS-037 fix (NT_SUCCESS guard + opt-in default=false) does **not** prevent this crash.
The guard is bypassed because `NtProtect` succeeds in the shellcode context.

## Root Cause

### KaynLdr header-stripping allocation

KaynLdr's load sequence (`payloads/Shellcode/Source/Entry.c`):

1. Reads `FirstSection->VirtualAddress` (`KHdrSize`, typically `0x1000`) to determine the PE
   header size.
2. Allocates `KVirtualMemory` sized for sections only — the PE header region is excluded.
3. Copies each section to `KVirtualMemory + Section.VirtualAddress - KHdrSize`.
4. Sets `KArgs->Demon = KVirtualMemory` — offset 0 is the start of `.text`, **not**
   `IMAGE_DOS_HEADER`.
5. Calls `FreeReflectiveLoader(KArgs->KaynLdr)` — frees the original shellcode blob (which
   contained the PE header) before returning.

In `DemonInit()` (`Demon.c:591-598`):

```c
if ( KArgs ) {
#if SHELLCODE
    Instance->Session.ModuleBase = KArgs->Demon;   // no MZ at offset 0
    ...
    FreeReflectiveLoader( KArgs->KaynLdr );         // PE header region freed here
#endif
}
// PeProtect_Init() called at line 676 — after FreeReflectiveLoader
```

By the time `PeProtect_Init()` runs, `ModuleBase` points to Demon's mapped sections with
no `IMAGE_DOS_HEADER` at offset 0, and the original PE-header-containing blob is already freed.

### Why NT_SUCCESS guard does not protect this case

In EXE/DLL mode, `ModuleBase` is a `SEC_IMAGE` `VadImageMap` entry. `NtProtect(PAGE_READWRITE)`
may fail because the VAD's execute characteristic is incompatible with stripping execute — the
NT_SUCCESS guard prevents the subsequent `MemSet`.

In KaynLdr shellcode mode, the sections are mapped into a **private** `VadPrivateMap` region
(not SEC_IMAGE). `NtProtect(PAGE_READWRITE)` succeeds unconditionally. The NT_SUCCESS guard
passes. `MemSet(ModuleBase, 0, 0x1000)` then zeroes 4 KB of live `.text` code.

The next instruction fetch from the zeroed page causes either:
- `STATUS_ACCESS_VIOLATION` if DEP/NX is active on the zeroed page, or
- A series of `ADD [rax], al` decodes from 0x00 bytes, crashing on the first NULL dereference.

Either way: host process termination, indistinguishable from a configuration-agnostic crash.

## OldProtect Restoration Bug (co-fix)

Independent of the shellcode issue, both `PeProtect_Stomp()` and `PeProtect_Restore()` had a
secondary bug: after their `MemSet`/`MmVirtualWrite` operation, they called
`NtProtectVirtualMemory` with the hardcoded constant `PAGE_EXECUTE_READ` (0x20) as the new
protection, discarding the `OldProtect` value saved by the preceding NtProtect call.

The PE header page on a `SEC_IMAGE` mapping is typically `PAGE_READONLY` (0x02). After one
stomp/restore cycle the page protection is permanently upgraded to `PAGE_EXECUTE_READ`:
- An incorrect execute permission on a data page (the zeroed-then-restored PE header)
- A potential memory-scanner detection signal (PE header page executable?)
- Persists across all subsequent sleep cycles

## Fix

**File:** `payloads/Demon/src/core/PeProtect.c`

### Fix 1 — MZ signature validation in `PeProtect_Init()`

After the `PeStomp` opt-in gate, validate `IMAGE_DOS_SIGNATURE` (0x5A4D) at `ModuleBase`
before reading the PE header backup. If absent, force-set `Config.Implant.PeStomp = FALSE` and
return. Because `PeProtect_Stomp()` and `PeProtect_Restore()` both gate on `PeStomp` at entry,
this force-disable makes them permanent no-ops for the session.

```c
PIMAGE_DOS_HEADER DosHdr = ( PIMAGE_DOS_HEADER ) Instance->Session.ModuleBase;
if ( DosHdr->e_magic != IMAGE_DOS_SIGNATURE ) {
    PUTS( "PeProtect_Init: no PE header at ModuleBase - disabling PeStomp (shellcode mode)" )
    Instance->Config.Implant.PeStomp = FALSE;
    return;
}
```

**Behaviour by deployment mode:**

| Mode | ModuleBase | MZ present? | Outcome |
|------|-----------|-------------|---------|
| EXE (`WinMain`) | PE image base from loader | Yes | PeStomp works normally |
| DLL (`DllMain`) | `hDllBase` from DllMain | Yes | PeStomp works normally |
| KaynLdr shellcode | `KArgs->Demon` (sections only) | **No** | PeStomp force-disabled, no crash |

### Fix 2 — Correct OldProtect restoration

In `PeProtect_Stomp()` and `PeProtect_Restore()`, replace the hardcoded `PAGE_EXECUTE_READ`
in the final `NtProtectVirtualMemory` call with the local `OldProtect` variable (already
populated by the preceding first NtProtect call). Also reset `BaseAddr`/`StompSize` before
the second call (aliasing guard — NtProtect page-aligns locals in-place).

```c
// After MemSet / MmVirtualWrite:
BaseAddr  = Instance->Session.ModuleBase;  // reset aliased local
StompSize = 0x1000;
Instance->Win32.NtProtectVirtualMemory(
    NtCurrentProcess(), &BaseAddr, &StompSize,
    OldProtect, &OldProtect );             // restore to original (e.g. PAGE_READONLY)
```

## Affected Files

| File | Change |
|------|--------|
| `payloads/Demon/src/core/PeProtect.c` | MZ check in Init; OldProtect restore in Stomp + Restore |

No wire format, builder, client, or profile changes required.

## Verification

### Shellcode path (Fix 1)
1. Build a shellcode payload with `PeStomp = true` in the profile.
2. Inject into a remote process via the "shellcode inject" command from a live Demon.
3. Debug output from the injected agent must include:
   ```
   PeProtect_Init: no PE header at ModuleBase - disabling PeStomp (shellcode mode)
   ```
4. The injected Demon must complete its first sleep cycle without the host process crashing.
5. Agent continues checking in normally over multiple sleep cycles.

### EXE/DLL path (Fix 2)
1. Build an EXE or DLL payload with `PeStomp = true`.
2. The "no PE header" log line must NOT appear.
3. Stomp/restore log lines must appear on each sleep cycle.
4. After a full stomp+restore cycle, add a temporary debug print of OldProtect in both Stomp
   and Restore — the restore protection must match the stomp's OldProtect (typically 0x02).

## Relationship to ISS-037

| Fix | ISS ID | Root cause | Guard that was missing |
|-----|--------|-----------|----------------------|
| ISS-037 (original) | SEC_IMAGE NtProtect failure | `NT_SUCCESS` check before `MemSet` | Added in HVC-030 Sub-2 fix |
| ISS-037-shell (this) | Private alloc — NtProtect succeeds but ModuleBase is code | MZ validity check before backup | **This fix** |

The original ISS-037 NT_SUCCESS guard covers the fail-case. This fix covers the succeed-case
where the target region happens to be a private allocation containing live code, not a PE header.

## Notes

- `PAGE_EXECUTE_READ` hardcoded in the original restore calls was almost certainly a copy-paste
  from ntdll unhook restore logic; it is incorrect for a PE header page whose original
  protection is `PAGE_READONLY`.
- `PeStomp` remains opt-in (default=false) in the profile. The fix allows operators who
  explicitly enable it to do so safely across all deployment modes — EXE/DLL get the intended
  evasion; shellcode deployments silently skip it since KaynLdr already strips the PE header.
- No new config fields, wire format fields, or UI checkboxes are needed.
