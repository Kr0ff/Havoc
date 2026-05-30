# HVC-048 — Foliage Sleep Thread Callstack Fix

## Status
Planned

## Problem

The Foliage sleep obfuscation (ObfFoliage.c) builds a 12-step APC ROP chain. One step,
`RopWaitObj`, is responsible for the actual sleep period. It sets the worker thread's context
to execute `WaitForSingleObjectEx` (kernel32.dll) and writes fake callstack frames at the
adjusted RSP:

```
RSP+0x00 = NtTestAlert           (APC delivery trigger — required)
RSP+0x08 = BaseThreadInitThunk   (fake frame)
RSP+0x10 = RtlUserThreadStart    (fake frame)
RSP+0x18 = NULL                  (terminator)
```

**The bug:** `WaitForSingleObjectEx` is a high-level kernel32 wrapper. Before it reaches the
actual kernel wait it calls several internal functions (e.g. `BasepWaitForSingleObject`,
argument validation, etc.), each of which pushes a return address onto the stack via `CALL`.
By the time the thread actually blocks inside `NtWaitForSingleObject` (the syscall), RSP has
moved ~0x100–0x200 bytes below where we placed the fake frames. A callstack walker starting
at the CURRENT RSP (where the thread blocked) sees the WaitForSingleObjectEx-internal frames
first. On the target Windows build those internal frames resolve to:

```
0 - kernel32!WaitForSingleObjectEx
1 - kernel32!InitiliazeRegTermsvrFpns+0x1af     ← internal WFSO frame
2 - ntdll!RtlpHpEnvFlsCleanup+0x87             ← internal WFSO frame
```

Our intended fake frames (NtTestAlert / BaseThreadInitThunk / RtlUserThreadStart) are on the
stack but unreachable — the frame walk terminates at frame 2 because there is no valid
frame-pointer chain connecting the WaitForSingleObjectEx internals to our fake-frame area.

The same problem affects `RopSpoof` (the main fiber's apparent sleeping context), which also
sets `Rip = WaitForSingleObjectEx` for visual consistency but is not the primary concern.

## Root-Cause Trace

```
RopWaitObj->Rip = WaitForSingleObjectEx         ; thread starts executing here
RopWaitObj->Rsp = original_rsp - 0x7000         ; new stack area
fake frames written at Rsp+0/8/16/24

WaitForSingleObjectEx prologue:
  push rbp, sub rsp, ...                         ; RSP -= N (saved regs, locals)
  call BasepWaitForSingleObject                  ; RSP -= 8 (return addr inside WFSO pushed)
    ... internal calls ...                        ; RSP decreases further
    call NtWaitForSingleObject                   ; RSP -= 8 again
      syscall                                    ; BLOCKS HERE
                                                 ; RSP is now ~0x100-0x200 below original fake-frame RSP
```

Callstack walker starting at syscall RSP:
```
[RSP+0] → return addr INSIDE WaitForSingleObjectEx → InitiliazeRegTermsvrFpns+0x1af
[RSP+8] → another WFSO-internal frame            → RtlpHpEnvFlsCleanup+0x87
...
[RSP+N] → NtTestAlert (our fake frame, unreachable due to broken chain)
```

## Fix

Replace `WaitForSingleObjectEx` (kernel32) with `NtWaitForSingleObject` (ntdll) in `RopWaitObj`.

`NtWaitForSingleObject` is a pure syscall stub:
```asm
mov r10, rcx      ; 3 bytes
mov eax, <SSN>    ; 5 bytes
syscall           ; 2 bytes  ← thread blocks here; RSP UNCHANGED
ret               ; 1 byte
```

No internal `CALL` instructions. RSP remains exactly where `RopWaitObj` set it. Our fake frames
at `Rsp+0/8/16/24` are **directly visible** to any callstack walker. `Instance->Win32.NtWaitForSingleObject`
is already in the Win32 function table (Demon.h line 243) and resolved at startup.

Resulting callstack:
```
0 - ntdll!NtWaitForSingleObject   (from thread CONTEXT.RIP)
1 - ntdll!NtTestAlert             (from [RSP+0] — also functional for APC delivery)
2 - kernel32!BaseThreadInitThunk  (from [RSP+8])
3 - ntdll!RtlUserThreadStart      (from [RSP+16])
    NULL                          (walk terminates)
```

No suspicious functions. APC delivery mechanism unchanged — NtTestAlert at [RSP+0] fires
when NtWaitForSingleObject's `ret` executes, exactly as before.

## Argument Mapping

`WaitForSingleObjectEx(Handle, dwMilliseconds, bAlertable)` vs
`NtWaitForSingleObject(Handle, Alertable, Timeout*)`:

| Register | WaitForSingleObjectEx (current) | NtWaitForSingleObject (new) |
|---|---|---|
| RCX | hDupObj | hDupObj (unchanged) |
| RDX | Param->TimeOut (ms, DWORD) | FALSE (alertable = same behavior) |
| R8 | FALSE (alertable) | pointer to LARGE_INTEGER timeout |

The LARGE_INTEGER timeout value (in 100-ns units, negative = relative) is stored at
`RopWaitObj->Rsp + 0x28` (after the four fake-frame slots at +0/+8/+16/+24). This uses
the same 0x7000-byte stack area that is already allocated:

```c
/* timeout: convert ms to 100-ns units (negative = relative wait) */
LONGLONG TimeoutNs = ( Param->TimeOut == INFINITE )
                     ? 0LL
                     : -(LONGLONG)Param->TimeOut * 10000LL;
*(LONGLONG*)( RopWaitObj->Rsp + 0x28 ) = TimeoutNs;

RopWaitObj->Rip = U_PTR( Instance->Win32.NtWaitForSingleObject );
RopWaitObj->Rcx = U_PTR( hDupObj );
RopWaitObj->Rdx = U_PTR( FALSE );          /* Alertable */
RopWaitObj->R8  = U_PTR( ( Param->TimeOut == INFINITE )
                          ? NULL
                          : RopWaitObj->Rsp + 0x28 );  /* &LARGE_INTEGER */
```

`INFINITE` (0xFFFFFFFF) maps to NULL timeout (NtWaitForSingleObject waits indefinitely).

## RopSpoof Consistency Fix

`RopSpoof->Rip` (the main fiber's apparent IP) is also set to `WaitForSingleObjectEx`.
Change it to `NtWaitForSingleObject` so both the worker thread and the main fiber appear
to be in the same (expected) NT wait function.

The `RopSpoof` fake frame area (`StackBase - 0x50`) is unchanged:
```
FakeFrames+0x00 = BaseThreadInitThunk   (main fiber appears to have returned from here)
FakeFrames+0x08 = RtlUserThreadStart    (thread entry)
FakeFrames+0x10 = NULL                  (terminator)
```

This is fine because the main fiber's spoofed context doesn't need NtTestAlert at +0x00
(it is not the APC-delivery thread; it is the fiber that was swapped out).

## Files Changed

| File | Change |
|---|---|
| `payloads/Demon/src/core/ObfFoliage.c` | RopWaitObj: change Rip, adjust Rdx/R8, write timeout LARGE_INTEGER at Rsp+0x28; RopSpoof: change Rip |

No other files require changes. `NtWaitForSingleObject` is already in the Win32 table.

## LARGE_INTEGER note

`INFINITE` check: `Param->TimeOut` is a `DWORD`. If the calling code passes `INFINITE`
(0xFFFFFFFF), the resulting negative LARGE_INTEGER would be `-42949672950000000LL` (~5 years).
Clamping to NULL avoids this — NtWaitForSingleObject with NULL Timeout waits indefinitely,
which is the semantic intent of INFINITE.

## Verification

1. Compile with `--debug-dev`. Inject shellcode with Foliage sleep enabled.
2. While Demon is sleeping, observe the worker thread's callstack in a debugger or pe-sieve.
3. Expected: `NtWaitForSingleObject → NtTestAlert → BaseThreadInitThunk → RtlUserThreadStart → NULL`
4. Expected NOT seen: `InitiliazeRegTermsvrFpns`, `RtlpHpEnvFlsCleanup`, or any other
   WaitForSingleObjectEx-internal frames.
5. Verify the Demon wakes up correctly after the sleep duration (APC chain completes).
6. Run pe-sieve against the target process. `SUS_CALLSTACK_CORRUPT` and `SUS_CALLS_INTEGRITY`
   should not be triggered on the sleeping Foliage worker thread.
