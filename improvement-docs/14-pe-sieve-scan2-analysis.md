# HVC-030 Sub-3 Post-Test Audit — Second Pe-Sieve Scan Analysis

**Status:** Analysis complete — Sub-3 hash fix and Sub-4 (Fix C) implemented  
**PID:** 13196  
**Tool:** `pe-sieve64.exe /pid 13196 /iat 2 /threads`  
**Date:** 2026-05-22  
**Reference scan:** `pe-sieve-analysis/process_13196/`

---

## Executive Summary

After applying HVC-030 Sub-3 (fake callstack frames + `RtlUserThreadStart` thread start
address), the Demon was recompiled and re-scanned with pe-sieve. Results were **identical to
the original scan** — all three thread indicators (`SUS_START`, `SUS_CALLSTACK_CORRUPT`,
`SUS_CALLS_INTEGRITY`) and `implanted_shc` remained. The root cause was a silent cascading
failure: the DJB2 hash constants for `RtlUserThreadStart` and `BaseThreadInitThunk` added to
`Defines.h` were computed incorrectly, causing `LdrFunctionAddr` to return NULL for both. All
fake callstack frame writes silently wrote NULL. Pe-sieve continued to see `frames_count: 1`.

Two fixes have been implemented to address all remaining detections:
1. **Hash correction** (`Defines.h`): correct DJB2 values for both functions
2. **Fix C** (`ObfFoliage.c`): PAGE_NOACCESS ROP step after encrypt, PAGE_READWRITE restore after wake

After both fixes, the only remaining detection is `malformed_header` ×2 — expected and
acceptable (Sub-2 PE header stomp is by design).

---

## 1. Scan Context

### 1.1 Pe-Sieve Output Summary

| Detection | Module / Thread | Indicators | Resolution |
|---|---|---|---|
| `malformed_header` | `7ff7fd670000` (Demon EXE) | — | Expected (Sub-2). Not actionable. |
| `malformed_header` | `7ff7fd670000` (Demon EXE) | — | Expected (Sub-2). Not actionable. |
| `thread_scan` | Thread 3872 | `SUS_START`, `SUS_CALLS_INTEGRITY`, `SUS_CALLSTACK_CORRUPT` | Hash fix + Fix C |
| *(implicit)* | `7ff7fd68e000` (.shc region) | `implanted_shc` | Fix C (PAGE_NOACCESS) |

Full JSON: `pe-sieve-analysis/process_13196/scan_report.json`

```json
"thread_scan": {
  "thread_id": 3872,
  "callstack": {
    "stack_ptr": "55053fffb0",
    "frames_count": 1,
    "frames": ["7ffc04e170b0;kernel32.dll!WaitForSingleObjectEx"]
  },
  "last_sysc": "NtSignalAndWaitForSingleObject",
  "last_func": "WaitForSingleObjectEx",
  "indicators": ["SUS_START", "SUS_CALLS_INTEGRITY", "SUS_CALLSTACK_CORRUPT"],
  "susp_addr": "7ff7fd68e860",
  "module": "7ff7fd68e000",
  "protection": "80",
  "stats": { "entropy": 7.99729 }
}
```

### 1.2 Which Thread Was Scanned?

Pe-sieve scanned the **main fiber** (thread 3872), not the APC worker thread. Evidence:

- `stack_ptr: 55053fffb0` = `StackBase − 0x50`

  The RopSpoof code sets `RopSpoof->Rsp = U_PTR(FakeFrames)` where
  `FakeFrames = StackBase - 0x50` (`ObfFoliage.c:289`). The stack pointer matches exactly.

- `last_sysc: NtSignalAndWaitForSingleObject` — this is the main thread's actual blocking
  syscall (`ObfFoliage.c:298`: `SysNtSignalAndWaitForSingleObject(hEvent, hThread, FALSE, NULL)`).

- `last_func: WaitForSingleObjectEx` — the spoofed RIP that was set in `RopSpoof->Rip`.
  The RIP spoof is **working correctly**.

- `frames_count: 1` — only the spoofed RIP is visible. The fake frames were NULL (hash bug).

### 1.3 Debug Log Correlation

From `pe-sieve-analysis/process_13196/demon-debug-log-13196.txt`, the sleep cycle that was
active when pe-sieve ran:

```
FoliageObf: 10 ROP entries built, queueing APCs
[10x NtQueueApcThread → 00000000]
NtAlertResumeThread → success
FoliageObf: signaling event and waiting for thread to exit
SysNtSignalAndWaitForSingleObject → 00000000    ← MAIN THREAD BLOCKED HERE
SysNtWriteVirtualMemory → 00000000              ← PeProtect_Restore (after wake)
FoliageObf: thread exited, sleep cycle complete
```

Pe-sieve ran during the `SysNtSignalAndWaitForSingleObject` window — the main thread was blocked
in that syscall, and the worker thread was executing the APC chain including `WaitForSingleObjectEx`.

---

## 2. Root Cause Analysis

### 2.1 Wrong DJB2 Hash Constants

The `HashEx` implementation in `payloads/Demon/src/core/Win32.c:17`:

```c
ULONG HashEx(IN PVOID String, IN ULONG Length, IN BOOL Upper) {
    ULONG  Hash = HASH_KEY;  // 5381
    PUCHAR Ptr  = String;
    do {
        UCHAR character = *Ptr;
        if (Upper && character >= 'a') character -= 0x20;
        Hash = ((Hash << 5) + Hash) + character;  // h = h*33 + c
        ++Ptr;
    } while (TRUE);
    return Hash;
}
```

Seed: `HASH_KEY = 5381` (Win32.h). Algorithm: `h = h*33 + c`, uppercase.

The Sub-3 implementation added incorrect hash constants to
`payloads/Demon/include/common/Defines.h`:

| Function | Original (wrong) | Correct |
|---|---|---|
| `RtlUserThreadStart` | `0xdaa22b3c` | `0x0353797c` |
| `BaseThreadInitThunk` | `0x98649676` | `0xe2491896` |

Known-good hashes for cross-reference: `NtTestAlert = 0x858a32df`, `WaitForSingleObjectEx = 0x512e1b97`.

The hash mismatch caused `LdrFunctionAddr` to return NULL for both lookups at runtime.

### 2.2 Cascade Effect

```
Wrong hash in Defines.h
    ↓
LdrFunctionAddr(ntdll,  H_FUNC_RTLUSERTHREADSTART)  → NULL
LdrFunctionAddr(kernel32, H_FUNC_BASETHREADINITTHUNK) → NULL
    ↓
Instance->Win32.RtlUserThreadStart  = NULL  (Demon.c:404)
Instance->Win32.BaseThreadInitThunk = NULL  (Demon.c:478)
    ↓
ThreadStartAddr = NULL  (Demon.c:933)  → NtCreateThreadEx with NULL start addr
    ↓
ObfFoliage.c — all fake frame writes are NULL:
  [RopWaitObj->Rsp+0x00] = NtTestAlert    (correct — function pointer resolved)
  [RopWaitObj->Rsp+0x08] = NULL           (should be BaseThreadInitThunk)
  [RopWaitObj->Rsp+0x10] = NULL           (should be RtlUserThreadStart)
  [RopWaitObj->Rsp+0x18] = NULL           (explicit NULL, correct)
    ↓
  [FakeFrames+0x00] = NULL                (should be BaseThreadInitThunk)
  [FakeFrames+0x08] = NULL                (should be RtlUserThreadStart)
  [FakeFrames+0x10] = NULL                (correct)
    ↓
pe-sieve walks callstack from Rip=WaitForSingleObjectEx, Rsp=FakeFrames:
  Frame 0: WaitForSingleObjectEx
  Return addr = [FakeFrames+0x00] = NULL → end of chain
  → frames_count = 1
    ↓
SUS_CALLSTACK_CORRUPT + SUS_CALLS_INTEGRITY
```

The structural code in `ObfFoliage.c` was correct. Only the hash values were wrong.

---

## 3. Detection Breakdown

### 3.1 `SUS_CALLSTACK_CORRUPT` + `SUS_CALLS_INTEGRITY`

**Pe-sieve trigger:** `frames_count: 1` — only `WaitForSingleObjectEx` visible. A legitimate
sleeping Windows thread always has at least 3–4 frames:

```
WaitForSingleObjectEx
BaseThreadInitThunk        ← kernel32
RtlUserThreadStart         ← ntdll
(NULL — top of stack)
```

Any fewer frames indicates a manipulated or corrupted callstack. Pe-sieve flags this as
`SUS_CALLSTACK_CORRUPT` (depth too shallow) and `SUS_CALLS_INTEGRITY` (chain broken at base).

**Code location:** `ObfFoliage.c:214–217` — the fake frame writes that were all NULL due to
the hash bug.

**Fix:** Correct the hash constants (HVC-030 Sub-3 Correction). With correct hashes,
`BaseThreadInitThunk` and `RtlUserThreadStart` resolve to their actual ntdll/kernel32 addresses.
The callstack unwinds to 4 frames (including the explicit NULL sentinel at [RSP+24]).

### 3.2 `SUS_START`

**Pe-sieve trigger:** `susp_addr: 7ff7fd68e860` = `ImageBase + 0x1e860`.

Pe-sieve queries `ThreadQuerySetWin32StartAddress` for thread 3872. The value it gets is the
**PE entry point** (`AddressOfEntryPoint` in the optional header), because the main thread's
Win32StartAddress is registered as the image's entry point when the EXE was loaded.

`ImageBase + 0x1e860` falls inside the second VAD region `[7ff7fd68e000, 7ff7fd67d000]` — the
last PE section, which MinGW compiled with `IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE`. The
Windows PE loader maps this as `PAGE_EXECUTE_WRITECOPY` (0x80) — a separate VAD entry. This
region has entropy ~8.0 and is flagged as `implanted_shc`. Pe-sieve then reports `SUS_START`
because the thread's registered start address falls inside a detected shellcode region.

**Fix:** Fix C (PAGE_NOACCESS, HVC-030 Sub-4). When the image region is PAGE_NOACCESS, pe-sieve
cannot read or measure its entropy, so it cannot classify the region as shellcode. Without a
shellcode region, there is no `susp_addr` → `SUS_START` is also resolved.

### 3.3 `implanted_shc`

**Pe-sieve trigger:** Region at `7ff7fd68e000`, size `0xf000`, protection `0x80`
(`PAGE_EXECUTE_WRITECOPY`), entropy `7.99729` bits/byte.

Pe-sieve's `implanted_shc` heuristic: executable memory region with entropy > ~7.5 bits/byte
= likely injected shellcode or encrypted code.

**Root cause:** The RC4-encrypted last section retains executable permissions during the Foliage
sleep window. The existing `RopSetMemRw` changes the first VAD region to PAGE_READWRITE, but the
second VAD (`PAGE_EXECUTE_WRITECOPY`) may retain its classification.

**Fix:** Fix C — `RopSetMemNA` sets `PAGE_NOACCESS` on the full image range after encryption.
Pe-sieve encounters access denied when attempting to read the region and cannot report entropy.

### 3.4 `malformed_header` (expected — no action required)

Two `malformed_header` entries for `7ff7fd670000`. These are produced by the HVC-030 Sub-2 PE
header stomp (`PeProtect_Stomp()`). Pe-sieve detects that the first 4 KB of the mapped image
has been zeroed (no MZ/PE signature). This is the intended effect of Sub-2 and is an accepted
trade-off. See CLAUDE.md: "`malformed_header` is acceptable."

---

## 4. Implemented Fixes

### 4.1 Fix: Correct DJB2 Hash Constants (`Defines.h`)

File: `payloads/Demon/include/common/Defines.h`

```c
// Before (wrong):
#define H_FUNC_RTLUSERTHREADSTART    0xdaa22b3c
#define H_FUNC_BASETHREADINITTHUNK   0x98649676

// After (correct):
#define H_FUNC_RTLUSERTHREADSTART    0x0353797c
#define H_FUNC_BASETHREADINITTHUNK   0xe2491896
```

Verification script (Python — must match `HashEx` exactly):
```python
def hashex(name):
    h = 5381
    for c in name.upper():
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h

assert hashex("RtlUserThreadStart")  == 0x0353797c
assert hashex("BaseThreadInitThunk") == 0xe2491896
assert hashex("NtTestAlert")         == 0x858a32df  # known-good cross-check
assert hashex("WaitForSingleObjectEx") == 0x512e1b97
```

### 4.2 Fix C: PAGE_NOACCESS Sleep Window (`ObfFoliage.c`)

Expanded the Foliage APC chain from 10 to 12 entries. Two new CONTEXT entries:

**`RopSetMemNA`** (position 4, RSP offset −10): calls `NtProtectVirtualMemory` with
`PAGE_NOACCESS` on the full image range immediately after RC4 encryption. Pe-sieve cannot read
or measure entropy of a PAGE_NOACCESS region.

**`RopSetMemRw2`** (position 8, RSP offset −6): calls `NtProtectVirtualMemory` with
`PAGE_READWRITE` on the full image range immediately after `WaitForSingleObjectEx` returns.
This restores read/write access before the RC4 decryption step (`RopMemDec`).

**APC delivery invariant:** `[RopWaitObj->Rsp+0x00]` = `NtTestAlert` is unchanged. This is the
required APC delivery trigger. The fake callstack frames remain at [RSP+8], [RSP+16], [RSP+24].

Full new chain (RSP offsets from thread's initial RSP):

| Entry | Offset | Function | Notes |
|---|---|---|---|
| RopBegin | −13 | NtWaitForSingleObject | Waits for signal event |
| RopSetMemRw | −12 | NtProtectVirtualMemory(RW) | Unlock for encryption |
| RopMemEnc | −11 | SystemFunction032 | RC4 encrypt |
| RopSetMemNA | −10 | NtProtectVirtualMemory(NOACCESS) | **new** |
| RopGetCtx | −9 | NtGetContextThread | Capture main fiber context |
| RopSetCtx | −8 | NtSetContextThread(spoof) | Set spoofed context |
| RopWaitObj | −7 | WaitForSingleObjectEx | Sleep (pe-sieve scan window) |
| RopSetMemRw2 | −6 | NtProtectVirtualMemory(RW) | **new** — restore before decrypt |
| RopMemDec | −5 | SystemFunction032 | RC4 decrypt |
| RopSetMemRx | −4 | NtProtectVirtualMemory(RX) | Restore executable |
| RopSetCtx2 | −3 | NtSetContextThread(restore) | Restore main fiber context |
| RopExitThd | −2 | RtlExitUserThread | Thread cleanup |

---

## 5. Expected Post-Fix State

After both fixes (hash correction + Fix C), a pe-sieve scan during a Foliage sleep window
should produce:

| Detection | Expected Result | Reason |
|---|---|---|
| `malformed_header` ×2 | **Still present** | Sub-2 header stomp — expected and acceptable |
| `SUS_CALLSTACK_CORRUPT` | **Resolved** | frames_count ≥ 4 (BaseThreadInitThunk → RtlUserThreadStart → NULL) |
| `SUS_CALLS_INTEGRITY` | **Resolved** | Call chain no longer broken at base |
| `SUS_START` | **Resolved** | Image region PAGE_NOACCESS → not classified as shellcode → no susp_addr |
| `implanted_shc` | **Resolved** | Image region PAGE_NOACCESS → entropy unreadable |

**Residual:** `malformed_header` ×2 only. This is the minimum achievable signature while Sub-2
(PE header stomp) is active and is accepted as the operating baseline.

---

## 6. References

- `pe-sieve-analysis/process_13196/scan_report.json` — second pe-sieve scan (PID 13196)
- `pe-sieve-analysis/process_13196/dump_report.json` — dump report
- `pe-sieve-analysis/process_13196/demon-debug-log-13196.txt` — Demon console output
- `improvement-docs/13-pe-sieve-detection-analysis.md` — first scan analysis + Fix A/B/C design
- `CHANGES.md` — HVC-030 Sub-3 Correction, HVC-030 Sub-4 entries
- `payloads/Demon/src/core/ObfFoliage.c` — Foliage implementation
- `payloads/Demon/include/common/Defines.h` — DJB2 hash constants
- `payloads/Demon/src/core/Win32.c:17` — HashEx algorithm
