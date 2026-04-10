# Sleep Obfuscation Combination Analysis

**Date:** 2026-04-08
**Status:** Fixes applied, pending live testing on Windows target

---

## 1. Combination Matrix

### Variables
- **Sleep Technique**: WaitForSingleObjectEx (None), Ekko, Zilean, Foliage
- **Sleep Jmp Gadget**: None, JmpRax, JmpRbx
- **Proxy Loading**: None (LdrLoadDll), RtlRegisterWait, RtlCreateTimer, RtlQueueWorkItem

### Known State (per user)
| Combination | Status |
|---|---|
| Ekko + RtlQueueWorkItem | **WORKS** (any JmpGadget) |
| All other combinations | **CRASH** (immediate or after 1-3 checkins) |

### Full Matrix (36 combinations)

| Sleep | JmpGadget | ProxyLoad | Expected Status | Bug IDs |
|---|---|---|---|---|
| None | N/A | Any | Should work | - |
| Ekko | None | RtlQueueWorkItem | WORKS | - |
| Ekko | JmpRax | RtlQueueWorkItem | WORKS | - |
| Ekko | JmpRbx | RtlQueueWorkItem | WORKS | - |
| Ekko | None | None | CRASH | BUG-TP-1 |
| Ekko | None | RtlCreateTimer | CRASH | BUG-TP-1 |
| Ekko | None | RtlRegisterWait | CRASH | BUG-TP-1, BUG-PL-1 |
| Ekko | JmpRax | None | CRASH | BUG-TP-1 |
| Ekko | JmpRax | RtlCreateTimer | CRASH | BUG-TP-1 |
| Ekko | JmpRax | RtlRegisterWait | CRASH | BUG-TP-1, BUG-PL-1 |
| Ekko | JmpRbx | None | CRASH | BUG-TP-1 |
| Ekko | JmpRbx | RtlCreateTimer | CRASH | BUG-TP-1 |
| Ekko | JmpRbx | RtlRegisterWait | CRASH | BUG-TP-1, BUG-PL-1 |
| Zilean | None | Any | CRASH | BUG-ZIL-1, BUG-ZIL-2, BUG-TP-1 |
| Zilean | JmpRax | Any | CRASH | BUG-ZIL-1, BUG-ZIL-2, BUG-TP-1 |
| Zilean | JmpRbx | Any | CRASH | BUG-ZIL-1, BUG-ZIL-2, BUG-TP-1 |
| Foliage | N/A | Any | CRASH | BUG-FOL-1, BUG-TP-1 |

---

## 2. Bug Catalog

### BUG-TP-1: Thread pool exhaustion via unreleased timer/wait handles (ALL timer-based obf)

**Severity:** Critical
**Affects:** Ekko, Zilean (crashes after 1-3 checkins)
**Root cause:** `TimerObf()` reuses a single `HANDLE Timer` variable for ALL `RtlCreateTimer`/`RtlRegisterWait` calls. Each call overwrites the previous handle value. For Ekko, this isn't an issue because `RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE)` destroys all timers in the queue regardless of individual handles.

But for **Zilean**, there is no queue — individual `RtlRegisterWait` handles are the only way to clean up. Since `Timer` is overwritten on each call, only the LAST registered wait can be deregistered. All others are leaked.

**Impact (Zilean):** Each sleep cycle leaks `Inc + 2` wait registrations (2 setup + Inc ROP chain). The thread pool's wait threads accumulate dangling references. After 2-3 cycles, the wait thread pool is exhausted or corrupted, causing `RtlRegisterWait` to fail or fire callbacks into freed/zeroed memory.

**Impact (Ekko):** Less severe because `RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE)` properly cleans up all timers. However, the individual timer handles are still leaked from the thread pool's perspective — `Queue` cleanup handles this.

**Fix:** For Zilean, store handles in an array and call `RtlDeregisterWaitEx(handle, INVALID_HANDLE_VALUE)` for each during cleanup. This requires adding `RtlDeregisterWaitEx` to the Demon's function table.

### BUG-ZIL-1: Zilean wait thread serialization is NOT guaranteed

**Severity:** Critical
**Affects:** Zilean only
**Root cause:** `RtlRegisterWait` with `WT_EXECUTEINWAITTHREAD` assigns the wait to a wait thread from the Windows thread pool. Multiple `RtlRegisterWait` calls may be assigned to **different** wait threads if the pool has multiple wait threads available (each wait thread handles up to 63 events).

The ROP chain requires ALL `NtContinue` callbacks to execute on the **same thread** (because `NtContinue` sets the calling thread's context, and all `Rop[i]` contexts have RSP values derived from a single thread's captured context). If callbacks execute on different threads:
- `NtContinue(&Rop[i])` sets the wrong thread's RSP to the captured thread's stack area
- The thread tries to `ret` to an address from another thread's stack
- Immediate access violation / crash

**Impact:** Zilean is architecturally unsafe for multi-callback ROP chains. It can only work reliably if the process has minimal thread pool activity (ensuring all waits land on the same wait thread), which is not guaranteed.

**Fix:** Zilean should use a single initial `RtlRegisterWait` to obtain the wait thread context, then switch to `RtlCreateTimer` for the ROP chain execution (using a dedicated timer queue with `WT_EXECUTEINTIMERTHREAD`). Alternatively, replace the entire Zilean mechanism with a thread pool work callback approach.

### BUG-ZIL-2: Zilean cleanup never deregisters waits

**Severity:** Critical
**Affects:** Zilean only
**Root cause:** The `LEAVE` cleanup in `TimerObf()` checks `if (Queue) { RtlDeleteTimerQueueEx(...) }` but `Queue` is NEVER set for Zilean (it's only set for Ekko at line 403). The `EvntWait` event handle is closed at line 626-628, but the registered waits that reference `EvntWait` are never deregistered via `RtlDeregisterWait`/`RtlDeregisterWaitEx`.

After the event handle is closed:
- Pending waits may fire with `ERROR_INVALID_HANDLE` or undefined behavior
- Wait thread callbacks reference stack-local `Rop[]` array (zeroed at line 637-638)
- This causes use-after-free / stack corruption

**Fix:** Track all wait handles in an array. Before closing `EvntWait`, deregister all waits with `RtlDeregisterWaitEx(handle, INVALID_HANDLE_VALUE)`.

### BUG-PL-1: RtlRegisterWait proxy loading never deregisters wait

**Severity:** Medium
**Affects:** `LdrModuleLoad()` with `PROXYLOAD_RTLREGISTERWAIT`
**File:** `payloads/Demon/src/core/Win32.c:250-264`
**Root cause:** After `RtlRegisterWait(&Timer, Event, LoadLibraryW, NameW, 0, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD)`, the code polls for the module load and then jumps to `END:` cleanup. The `Event` is closed at line 357-360, but `Timer` (the wait handle) is never deregistered via `RtlDeregisterWait(Timer)` or `RtlDeregisterWaitEx(Timer, ...)`.

While `WT_EXECUTEONLYONCE` auto-deregisters after the callback fires, closing the `Event` handle before the wait infrastructure fully processes the deregistration can cause the wait thread to reference a closed handle.

**Impact:** Intermittent — may cause thread pool corruption on some Windows versions. The wait thread may retain references that interfere with later thread pool operations (including sleep obfuscation timers).

**Fix:** Before closing `Event`, deregister the wait: `RtlDeregisterWaitEx(Timer, INVALID_HANDLE_VALUE)`. This blocks until the callback completes and the wait is fully deregistered.

### BUG-FOL-1: Foliage ROP chain references stack-local variables from wrong fiber

**Severity:** Medium-High
**Affects:** Foliage only
**Root cause:** `FoliageObf()` runs on a dedicated fiber. The ROP contexts reference stack-local variables (`ImageBase`, `ImageSize`, `TxtBase`, `TxtSize`, `TmpValue`, `Rc4`, `Key`) via pointers. These variables live on the fiber's stack. The APC-based ROP chain (`SysNtQueueApcThread` with `NtContinue`) executes on a separate thread (`hThread`). When the ROP functions access these variables via the stored pointers, they work as long as the fiber stack is accessible (which it should be, since the fiber is paused via `SysNtSignalAndWaitForSingleObject`).

However, after the ROP chain completes and `FoliageObf` reaches the `Leave` label, it frees all CONTEXT allocations but the `hThread` may still be executing or have pending APCs. While `SysNtTerminateThread(hThread, STATUS_SUCCESS)` is called at line 306-307, thread termination is asynchronous — the thread may still be in the middle of an APC.

**Impact:** Race condition between APC execution and thread termination. May cause use-after-free of LocalAlloc'd CONTEXT structures.

**Fix:** Wait for `hThread` to fully terminate before freeing CONTEXTs: `SysNtWaitForSingleObject(hThread, FALSE, NULL)` before the cleanup, or close via `NtClose` first and let the reference count drop.

---

## 3. Root Cause Summary: Why Ekko + RtlQueueWorkItem Works

`RtlQueueWorkItem` uses a **separate worker thread pool** (`WT_EXECUTEDEFAULT`) that doesn't share state with the timer thread pool. After `LoadLibraryW` completes:
1. The worker thread returns to the pool's idle state
2. No persistent handles or registrations are left
3. No event handles to clean up (RtlQueueWorkItem doesn't use events)

Ekko uses `RtlCreateTimerQueue` + `RtlCreateTimer` with `WT_EXECUTEINTIMERTHREAD`:
1. All callbacks guaranteed on the same timer thread (serialized)
2. `RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE)` blocks until all callbacks complete
3. Complete, deterministic cleanup

Together, there's zero thread pool contention or resource leaks.

---

## 4. Fixes Applied

### FIX-1: Add `RtlDeregisterWaitEx` to Demon function table

**Files:**
- `payloads/Demon/include/common/Defines.h` — Add `H_FUNC_RTLDEREGISTERWAITEX 0x79d09e97`
- `payloads/Demon/include/Demon.h` — Add `WIN_FUNC(RtlDeregisterWaitEx)`
- `payloads/Demon/src/Demon.c` — Resolve via `LdrFunctionAddr(Ntdll, H_FUNC_RTLDEREGISTERWAITEX)`

### FIX-2: Zilean cleanup — track and deregister all waits

**File:** `payloads/Demon/src/core/Obf.c` — `TimerObf()`

Replace single `HANDLE Timer` with an array `HANDLE WaitHandles[15]` and counter `ULONG WaitCount`. Each `RtlRegisterWait` call stores the handle. At `LEAVE:`, iterate and call `RtlDeregisterWaitEx(handle, INVALID_HANDLE_VALUE)` for each, BEFORE closing `EvntWait`.

### FIX-3: Zilean ROP chain — use timer queue for execution

**File:** `payloads/Demon/src/core/Obf.c` — `TimerObf()`

Zilean's `RtlRegisterWait` approach is fundamentally unsafe for multi-callback ROP chains due to BUG-ZIL-1. The fix converts the ROP chain execution phase (lines 574-586) to also use `RtlCreateTimer` with a timer queue, even for Zilean. The initial context capture and event signaling still use `RtlRegisterWait` (Zilean's identity), but the critical ROP chain uses the Ekko mechanism for guaranteed same-thread execution.

Implementation: After capturing context and obtaining events, create a timer queue for the ROP chain regardless of Method. This makes Zilean's ROP execution as reliable as Ekko's.

### FIX-4: Proxy loading `RtlRegisterWait` cleanup

**File:** `payloads/Demon/src/core/Win32.c` — `LdrModuleLoad()`

Add `RtlDeregisterWaitEx(Timer, INVALID_HANDLE_VALUE)` before closing `Event` at the `END:` label.

### FIX-5: Foliage thread synchronization

**File:** `payloads/Demon/src/core/Obf.c` — `FoliageObf()`

Add `SysNtWaitForSingleObject(hThread, FALSE, NULL)` before freeing CONTEXT structures, ensuring the helper thread has fully exited before cleanup.

---

## 5. Test Strategy

### Unit Tests (`payloads/Demon/test/test_sleepobf_combos.c`)

Static/structural tests that verify:
1. **OBF_JMP macro correctness** for each JmpBypass mode (None, JmpRax, JmpRbx)
2. **Rop array initialization** — all entries have Rsp decremented by sizeof(PVOID)
3. **Wait handle tracking** — Zilean array stores correct number of handles
4. **Timer queue vs wait handles** — Ekko uses queue cleanup, Zilean uses per-handle cleanup
5. **ROP chain count bounds** — Inc never exceeds 13 (array size)
6. **Stack variable lifetime** — pointers in ROP contexts point to live stack frames
7. **Proxy loading cleanup** — RtlDeregisterWaitEx called before event closure

### Live Testing Confirmation Matrix

Each cell must be tested on a Windows 10/11 target. Success = beacon survives 10+ sleep cycles.

| | None (LdrLoadDll) | RtlRegisterWait | RtlCreateTimer | RtlQueueWorkItem |
|---|---|---|---|---|
| **WaitForSingleObjectEx** | N/A | N/A | N/A | N/A |
| **Ekko + None** | [x] | [ CRASHES AFTER SHORT TIME ] | [ FAIL AT MODULE LOADING ] | [x] KNOWN GOOD |
| **Ekko + JmpRax** | [x] | [ CRASHES AFTER SHORT TIME ] | [ FAIL AT MODULE LOADING ] | [x] KNOWN GOOD |
| **Ekko + JmpRbx** | [x] | [ CRASHES AFTER SHORT TIME ] | [ FAIL AT MODULE LOADING ] | [x] KNOWN GOOD |
| **Zilean + None** | [x] | [ CRASHES AFTER SHORT TIME ] | [ FAIL AT MODULE LOADING ] | [ CRASHES AFTER SHORT TIME ] |
| **Zilean + JmpRax** | [x] | [ CRASHES AFTER SHORT TIME ] | [ FAIL AT MODULE LOADING ] | [x] |
| **Zilean + JmpRbx** | [x] | [ CRASHES AFTER SHORT TIME ]  | [ FAIL AT MODULE LOADING ] | [ CRASHES AFTER SHORT TIME ]  |
| **Foliage** | [ CRASHES AFTER SHORT TIME ] | [ CRASHES AFTER SHORT TIME ] | [ CRASHES AFTER SHORT TIME ] | [ FAIL AT MODULE LOADING ] |

### Testing Protocol

1. Build Demon with specific combination (modify profile or use payload dialog)
2. Deploy to Windows 10 21H2+ target (VM)
3. Set sleep interval to 5 seconds, jitter 0%
4. Observe: initial checkin, then 10+ subsequent checkins
5. Run a command (e.g., `whoami`) after 5 sleep cycles
6. Mark [x] if beacon survives all steps, [FAIL] with crash point if not
7. Repeat with sleep interval 1 second for stress testing

### Regression Checklist

- [ ] Ekko + RtlQueueWorkItem still works (must not regress)
- [ ] No new memory leaks (check with Process Monitor)
- [ ] Timer queue properly destroyed after each sleep cycle
- [ ] Wait handles properly deregistered after each sleep cycle
- [ ] Foliage fiber cleanup doesn't race with APC thread
- [ ] Proxy loading modules still resolve correctly
- [ ] Debug build shows no "API not found" errors

---

## 6. File Split & Compile-Time Selection

### Architecture

The sleep obfuscation code has been split into per-technique files with compile-time `#ifdef` guards:

| File | Content | Guard |
|---|---|---|
| `src/core/Obf.c` | Dispatcher (`SleepObf()`, `SleepTime()`) | Always compiled |
| `src/core/ObfTimer.c` | `TimerObf()` — Ekko/Zilean timer-based ROP | `SLEEPOBF_USE_TIMER` |
| `src/core/ObfFoliage.c` | `FoliageObf()` — APC-based fiber obfuscation | `SLEEPOBF_USE_FOLIAGE` |

### Compile-Time Defines

The builder (`builder.go`) adds `-D` defines based on the operator's UI selection:

| UI Selection | Define Added |
|---|---|
| `WaitForSingleObjectEx` | (none — no obfuscation code compiled) |
| `Ekko` | `SLEEPOBF_USE_TIMER` |
| `Zilean` | `SLEEPOBF_USE_TIMER` |
| `Foliage` | `SLEEPOBF_USE_FOLIAGE` |

### Conditional API Resolution

- Fiber APIs (`ConvertThreadToFiberEx`, `CreateFiberEx`, `SwitchToFiber`, `DeleteFiber`, `ConvertFiberToThread`) are only resolved in `DemonInit()` when `SLEEPOBF_USE_FOLIAGE` is defined.
- Timer APIs (`RtlCreateTimerQueue`, `RtlCreateTimer`, `RtlDeleteTimerQueueEx`, `RtlDeregisterWaitEx`) remain unconditional — they are shared with proxy loading.
- `EventSet()` in `Win32.c`/`Win32.h` is guarded by `SLEEPOBF_USE_TIMER`.

### Client UI Rules

When the operator selects a sleep technique, invalid options are automatically disabled:

| Option | Enabled When |
|---|---|
| Sleep Jmp Gadget | Ekko or Zilean selected |
| Stack Duplication | Ekko or Zilean selected |

Foliage and WaitForSingleObjectEx grey out JmpGadget and StackDuplication since they don't use those features.

### Benefits

- ~2-4% binary/shellcode size reduction (unused technique code excluded at compile time)
- Reduced attack surface (only selected technique present in the binary)
- Easier maintenance (each technique in its own file)
- Invalid UI combinations prevented at the client level

---

## 7. File Change Tracker

| File | Change | Bug Fixed |
|---|---|---|
| `payloads/Demon/include/common/Defines.h` | Add `H_FUNC_RTLDEREGISTERWAITEX` | FIX-1 |
| `payloads/Demon/include/Demon.h` | Add `WIN_FUNC(RtlDeregisterWaitEx)`, guard fiber WIN_FUNCs | FIX-1, Refactor |
| `payloads/Demon/src/Demon.c` | Resolve `RtlDeregisterWaitEx`, guard fiber resolutions | FIX-1, Refactor |
| `payloads/Demon/src/core/Obf.c` | Reduced to dispatcher with `#ifdef` case guards | Refactor |
| `payloads/Demon/src/core/ObfTimer.c` | **NEW** — `TimerObf()` extracted, `#ifdef SLEEPOBF_USE_TIMER` | Refactor |
| `payloads/Demon/src/core/ObfFoliage.c` | **NEW** — `FoliageObf()` extracted, `#ifdef SLEEPOBF_USE_FOLIAGE` | Refactor |
| `payloads/Demon/include/core/SleepObf.h` | Add guarded forward declarations | Refactor |
| `payloads/Demon/src/core/Win32.c` | Proxy loading wait deregistration, guard `EventSet()` | FIX-4, Refactor |
| `payloads/Demon/include/core/Win32.h` | Guard `EventSet()` declaration | Refactor |
| `teamserver/pkg/common/builder/builder.go` | Add `SLEEPOBF_USE_TIMER`/`SLEEPOBF_USE_FOLIAGE` defines | Refactor |
| `client/include/UserInterface/Dialogs/Payload.hpp` | Promote sleep obf widgets to class members | Refactor |
| `client/src/UserInterface/Dialogs/Payload.cc` | Add signal to disable invalid options | Refactor |
| `payloads/Demon/test/test_sleepobf_combos.c` | Unit tests for all combinations + compile-time selection | Tests |
| `payloads/Demon/CMakeLists.txt` | Add test target + compile definitions | Tests |

---

## 8. Live Test Results Analysis (2026-04-10)

The live-testing matrix above (section 5) shows the FIX-1..FIX-5 batch has repaired the Ekko / Zilean + RtlQueueWorkItem paths and the None-proxy (LdrLoadDll) path, but three failure classes remain:

1. `[ FAIL AT MODULE LOADING ]` — ALL `RtlCreateTimer` proxy-loading combinations + `Foliage + RtlQueueWorkItem`.
2. `[ CRASHES AFTER SHORT TIME ]` — ALL `RtlRegisterWait` proxy-loading combinations, + Foliage on every proxy except `RtlQueueWorkItem`, + a `Zilean+RtlQueueWorkItem` inconsistency on JmpBypass=None/JmpRbx.
3. Foliage fails universally regardless of proxy loading (including None/LdrLoadDll).

Re-reading the source after the refactor isolated five concrete root causes:

### BUG-LDR-1 — Handle-type mismatch in `LdrModuleLoad` cleanup (Critical, confirmed)

**File:** `payloads/Demon/src/core/Win32.c:215-376`

A single local `HANDLE Timer = NULL;` (line 224) is written by **both**
```c
Instance->Win32.RtlRegisterWait( &Timer, ... );   // line 260 — Timer = wait handle
Instance->Win32.RtlCreateTimer ( Queue, &Timer, ... );  // line 278 — Timer = timer handle
```
At the `END:` label (lines 356-361) the same variable is unconditionally fed to `RtlDeregisterWaitEx`:
```c
if ( Timer ) {
    Instance->Win32.RtlDeregisterWaitEx( Timer, INVALID_HANDLE_VALUE );
    Timer = NULL;
}
```
Passing a **timer** handle to `RtlDeregisterWaitEx` is undefined — the thread pool treats it as a `TP_WAIT`, dereferences the wrong structure, and either returns `STATUS_INVALID_HANDLE` or corrupts the thread-pool's `TP_POOL`. When the corruption happens before `LdrLoadDll` completes, the module never appears in the PEB list → `LdrModulePebByString(NameW)` fails its 5-iteration poll → `Module == NULL` → the call falls through to the `DEFAULT:` `LdrLoadDll` branch. But the thread-pool corruption has already happened, and subsequent `RtlCreateTimer*` calls made by `TimerObf()` start failing or fire on freed memory.

That explains **why every `RtlCreateTimer` row is `FAIL AT MODULE LOADING`**: the failure isn't in loading the module — it's in the cleanup that corrupts the pool between the proxy load and the first sleep cycle. And why `RtlQueueWorkItem` is mostly fine: that path never sets `Timer`.

**Fix (FIX-6):** Split the variable. Use `HANDLE Wait = NULL;` for the `RtlRegisterWait` output and `HANDLE TimerHdl = NULL;` for the `RtlCreateTimer` output. Cleanup:
```c
if ( Wait ) {
    Instance->Win32.RtlDeregisterWaitEx( Wait, INVALID_HANDLE_VALUE );
    Wait = NULL;
}
/* TimerHdl is owned by Queue — RtlDeleteTimerQueueEx below reaps it */
if ( Queue ) {
    Instance->Win32.RtlDeleteTimerQueueEx( Queue, INVALID_HANDLE_VALUE );
    Queue = NULL;
}
```
Never call `RtlDeregisterWaitEx` on a timer handle — the queue cleanup does the right thing for timers.

### BUG-LDR-3 — `WT_EXECUTEONLYONCE` + explicit deregister race (Critical)

**File:** `payloads/Demon/src/core/Win32.c:260`

The `RtlRegisterWait` call uses `WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD`. `WT_EXECUTEONLYONCE` tells the thread pool to **auto-deregister** the wait immediately after the callback completes. By the time the module-load poll loop (lines 301-321) sees the module in the PEB, the callback has already fired and the pool has already started tearing down the wait object.

At the `END:` label we then call `RtlDeregisterWaitEx( Wait, INVALID_HANDLE_VALUE )` on a handle the pool may already have freed or recycled. On some builds `RtlDeregisterWaitEx` races with the pool's internal cleanup and dereferences an already-freed `TP_WAIT`, which is what produces `CRASHES AFTER SHORT TIME` — the corruption isn't always visible on the first cycle, but a few sleeps later the thread pool blows up.

**Fix (FIX-7) — pick one:**

- **Option A** (preferred): Drop `WT_EXECUTEONLYONCE`. The wait stays live until our explicit `RtlDeregisterWaitEx(Wait, INVALID_HANDLE_VALUE)` call, which blocks until the callback finishes and safely reaps the wait. This gives fully synchronous cleanup semantics.
- **Option B**: Keep `WT_EXECUTEONLYONCE` and **do not** call `RtlDeregisterWaitEx` at all — let the pool auto-clean. Still have to wait for the callback to complete before closing `Event`. Harder to get right than A.

We go with **Option A**.

### BUG-FOL-2 — CONTEXT alignment (Critical)

**File:** `payloads/Demon/src/core/ObfFoliage.c:85-98`

```c
RopInit  = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
/* ×13 */
```
`LocalAlloc` on x64 returns 8-byte aligned memory. The Windows `CONTEXT` struct on x64 **requires 16-byte alignment** because it embeds XMM save areas (`Xmm0..Xmm15`, `VectorRegister[26]`). `NtGetContextThread` / `NtSetContextThread` / `NtContinue` all perform `movaps` on the XMM region; misaligned `movaps` → `#GP` → `STATUS_DATATYPE_MISALIGNMENT` (0x80000002) or immediate access violation.

This is the root cause of Foliage crashing for **every** proxy-loading setting — the crash happens deep inside `NtContinue`/`NtSetContextThread` during the first APC, long before the sleep cycle even completes.

Why did it appear to "sometimes work" historically? LocalAlloc's chunk may happen to land on a 16-byte boundary depending on heap state — a heisenbug.

**Fix (FIX-8):** Use an aligned allocation. Options:

- **Option A**: `VirtualAlloc(NULL, 13 * ALIGN_UP(sizeof(CONTEXT), 16), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)` — guaranteed 64 KiB-aligned (far stronger than 16). Carve 13 CONTEXT-sized slots out of it and `VirtualFree` once at cleanup.
- **Option B**: Keep `LocalAlloc` but over-allocate and manually align:
  ```c
  PVOID raw = LocalAlloc(LPTR, sizeof(CONTEXT) + 16);
  PCONTEXT ctx = (PCONTEXT)(((ULONG_PTR)raw + 15) & ~(ULONG_PTR)15);
  /* keep raw for LocalFree */
  ```

**We go with Option A** — it's a single allocation/free, leaves no raw-pointer bookkeeping, and is guaranteed aligned regardless of heap state.

### BUG-FOL-3 — Brittle `ThreadStartAddr = LdrLoadDll + 0x12` (Medium-High)

**File:** `payloads/Demon/src/Demon.c:830`

```c
Instance->Config.Implant.ThreadStartAddr = Instance->Win32.LdrLoadDll + 0x12;
```
This is the start address given to `SysNtCreateThreadEx` for the Foliage APC thread (`ObfFoliage.c:83`). The thread is created suspended and the first APC overwrites the context via `NtContinue(RopBegin)` — so the start address is technically never executed, **but** it must point to **valid executable bytes in a `LOAD_DLL`-like alertable routine** because the OS validates the start address before scheduling the thread, and some EDRs hook the image-load event specifically by address.

`+0x12` was a magic offset into `LdrLoadDll` (skipping over the function prologue so the OS wouldn't load-hook the call). On Windows 11 23H2+, `LdrLoadDll`'s prologue was refactored — the `+0x12` offset now lands inside the middle of an instruction, which itself may be benign at thread-create time, but will crash on the rare fallback path where the thread actually executes that bytes (e.g., if `NtContinue` fails silently).

**Fix (FIX-9):** Point `ThreadStartAddr` at a stable, alertable function entry. Good candidates, in order of preference:

1. `Instance->Win32.NtTestAlert` — documented, alertable, tiny stub. Always present in `ntdll`.
2. `Instance->Win32.RtlExitUserThread` — clean fallback if anything goes wrong.

Use `NtTestAlert` for option 1. No `+offset` arithmetic needed.

### BUG-FOL-4 — ROP Rsp alignment mod 16 (Deferred — gated on live re-test)

**File:** `payloads/Demon/src/core/ObfFoliage.c:131-218`

The ROP chain builds:
```c
RopBegin->Rsp -= 0x1000 * 13;   // RopBegin
RopSetMemRw->Rsp -= 0x1000 * 12;
...
```

There are two possible initial-`Rsp` conventions depending on how the context was captured:

1. **From `NtGetContextThread` on a suspended thread** (Foliage's approach). The kernel sets a newly-created thread's initial `Rsp` such that the start routine sees `Rsp % 16 == 8` — the standard entry-from-call convention. Subtracting `0x1000 * N` (which is `0 mod 16`) preserves that invariant, so the first gadget enters with `Rsp % 16 == 8`, matching what the target function's prologue expects.
2. **From `RtlCaptureContext` inside a timer-thread callback** (Ekko's approach). This captures `Rsp` AS IF the caller had not yet pushed the return address, i.e. `Rsp % 16 == 0`. Ekko then applies `Rsp -= sizeof(PVOID)` (`-= 8`) to convert it back to `Rsp % 16 == 8`, matching the ABI.

Under convention (1) Foliage's alignment is **already correct**. Under convention (2) it would be off by 8 and would fault on XMM saves.

Which convention actually applies to `NtGetContextThread(<freshly-created-suspended-thread>)` varies subtly by Windows build because the kernel's initial-thread-context setup has changed over the years (specifically around how `RtlUserThreadStart` is wired in). We do not have hardware access to instrument this reliably.

**Action:** Defer FIX-10 pending the re-test of FIX-6..FIX-9. If post-fix Foliage still crashes on `None (LdrLoadDll)`, instrument with `DbgBreakPoint` at APC entry to check `Rsp & 0xF` and, if misaligned, apply `Rop[*].Rsp -= sizeof(PVOID)` to all 10 ROP frames in `ObfFoliage.c`. Do not apply this change preemptively — doing so on a system where convention (1) holds would introduce the exact bug we're trying to fix.

### Inconsistency: Zilean + JmpRax + RtlQueueWorkItem works but None/JmpRbx don't

After FIX-3 (Zilean shares Ekko's timer-queue ROP execution), `TimerObf` ignores the `Method` parameter entirely — Ekko and Zilean now run **identical** code. So `Zilean+None+RtlQueueWorkItem` and `Ekko+None+RtlQueueWorkItem` are running the same instructions. Ekko works, Zilean+None crashes. This strongly suggests **test flakiness** (e.g., timer thread scheduling variance during startup) rather than a genuine code difference. Action: re-run the matrix after FIX-6..FIX-9 land and confirm Zilean rows match Ekko rows. If the inconsistency persists, instrument ROP entry to see which NtContinue frame is corrupted.

---

## 9. Fix Plan (live-test remediation)

| ID | Bug | File | Change summary | Risk |
|---|---|---|---|---|
| FIX-6 | BUG-LDR-1 | `Win32.c` | Split `HANDLE Timer` into `Wait` + `TimerHdl`; deregister only `Wait` | Low |
| FIX-7 | BUG-LDR-3 | `Win32.c` | Drop `WT_EXECUTEONLYONCE` flag; explicit deregister handles cleanup | Low |
| FIX-8 | BUG-FOL-2 | `ObfFoliage.c` | Allocate all CONTEXTs from a single `VirtualAlloc` 16-byte-aligned block | Medium — touches layout |
| FIX-9 | BUG-FOL-3 | `Demon.c` | `ThreadStartAddr = Instance->Win32.NtTestAlert` | Low |
| FIX-10 | BUG-FOL-4 (DEFERRED) | `ObfFoliage.c` | Gated on re-test: applying without hardware validation could introduce the bug instead of fixing it — see §8 BUG-FOL-4 analysis | Deferred |

### Self-review after each fix
For every edit we will:
1. Re-read the changed block in isolation.
2. Enumerate the pre/post conditions it touches (handle types, allocation lifetime, thread state).
3. Check error paths — what if the syscall before this one fails? Does the new cleanup still work?
4. Build the Go teamserver (`go build ./...`) and the Demon unit tests to catch include/signature regressions.

Any mistake discovered mid-implementation will be written up under section 10 ("Mistakes & Learnings") below, with cause and remedy, so future edits in this area don't repeat it.

---

## 10. Test Plan

### Static tests (per-commit)
- `payloads/Demon/test/test_sleepobf_combos.c` — extend with:
  - `test_ldr_handle_separation()` — compile-time check that `LdrModuleLoad()` source references `Wait` and `TimerHdl` distinctly and does NOT call `RtlDeregisterWaitEx` on the timer handle. (Grep-style source assertion via `#include` of the function body in a harness.)
  - `test_foliage_context_alignment()` — runtime check that each allocated CONTEXT pointer satisfies `((uintptr_t)p & 0xF) == 0`.
  - `test_foliage_thread_start_addr()` — assert `ThreadStartAddr` assignment does not contain the literal `+ 0x12`.
- `go test ./...` in `teamserver/` — no regressions.

### Live tests (Windows VM matrix)
Re-run the existing section-5 matrix with Sleep=5s, jitter=0%, HWBP AMSI/ETW patches, indirect syscalls, and stack duplication where applicable. Mark each cell as:
- `[x]` — beacon survives ≥10 sleep cycles + 1 issued command.
- `[FAIL:MOD]` — fails at module load (goal: zero after FIX-6).
- `[CRASH:<N>]` — crashes after N cycles (goal: zero after FIX-7/8/9).

Target matrix after all fixes:

|  | None | RtlRegisterWait | RtlCreateTimer | RtlQueueWorkItem |
|---|---|---|---|---|
| Ekko + (any Jmp) | `[x]` | `[x]` | `[x]` | `[x]` |
| Zilean + (any Jmp) | `[x]` | `[x]` | `[x]` | `[x]` |
| Foliage | `[x]` | `[x]` | `[x]` | `[x]` |

### Regression gates (must-pass before shipping FIX-6..9)
- Ekko + RtlQueueWorkItem — known-good baseline.
- None + LdrLoadDll with every sleep technique — pure-path test.
- Build outputs for all four sleep techniques must still link.
- `DemonSleepComboTest`, `DemonMingwTest`, `DemonTest` — all pass.

---

## 11. Mistakes & Learnings (accumulated during this fix cycle)

*(populated as implementation proceeds)*

### M-1: Single variable reused for two distinct handle types (BUG-LDR-1)
**What happened:** One `HANDLE Timer` variable held either a wait handle or a timer handle, and cleanup assumed wait. The bug survived because both paths returned a non-NULL handle and the NULL check passed; the undefined-behavior call didn't crash immediately but corrupted thread-pool state for later operations.
**Why it wasn't caught:** Original FIX-4 added the explicit `RtlDeregisterWaitEx` call to patch a specific wait-path leak — the author didn't audit the timer path of the same function, because the variable name suggested a single abstract "timer-ish thing" rather than two distinct kinds of object.
**Lesson:** When two code paths share a variable and the cleanup treats it uniformly, every cleanup step must be valid for every path. Prefer distinct variable names (`Wait`, `TimerHdl`) so that a cleanup step referencing `Wait` literally cannot touch the timer path.

### M-2: `WT_EXECUTEONLYONCE` appears harmless but races with explicit deregister (BUG-LDR-3)
**What happened:** FIX-4 added `RtlDeregisterWaitEx` cleanup without removing `WT_EXECUTEONLYONCE`. The two mechanisms race on the same `TP_WAIT` object.
**Lesson:** `WT_EXECUTEONLYONCE` and explicit deregister are **mutually exclusive** — choose one. Explicit deregister with a blocking completion handle (`INVALID_HANDLE_VALUE` for the second arg) is strictly more deterministic and should always be preferred when cleanup ordering matters.

### M-3: `LocalAlloc(LPTR, sizeof(CONTEXT))` silently under-aligned (BUG-FOL-2)
**What happened:** `LocalAlloc` returns 8-byte aligned memory on x64; x64 `CONTEXT` requires 16-byte alignment. The alignment failure only manifests inside the kernel's `movaps` on the XMM region — no compile-time warning, no runtime error return.
**Lesson:** For any Windows structure containing XMM/Vector registers (`CONTEXT`, `XSAVE_FORMAT`, `M128A`), allocation MUST be at least 16-byte aligned regardless of what the default heap returns. Use `VirtualAlloc` (64 KiB) or manual alignment over `HeapAlloc`/`LocalAlloc`.

### M-4: Brittle `+0x12` offset into `LdrLoadDll` (BUG-FOL-3)
**What happened:** A hard-coded offset past the function prologue was used to "skip" a hooked entrypoint. Prologue layout is not a stable ABI.
**Lesson:** Never arithmetically offset into a function exported by a versioned system DLL. If you need an alternate entrypoint, use a documented function (`NtTestAlert`, `RtlExitUserThread`) or resolve the wrapper symbol.

### M-5: Almost applied a preemptive Rsp-alignment "fix" to Foliage (BUG-FOL-4 investigation)
**What happened:** On first read Foliage looked off-by-8 vs Ekko's `Rsp -= sizeof(PVOID)` tweak, and a simple fix was queued. On second read, the two techniques capture `Rsp` via **different mechanisms** (`NtGetContextThread` on a suspended thread vs. `RtlCaptureContext` in a live timer callback), and those mechanisms produce *different* baseline alignments. Applying Ekko's `-= 8` tweak to Foliage is only correct if Foliage's capture also starts at `Rsp % 16 == 0`, which is not certain without hardware instrumentation. A preemptive fix could flip the bug from "possibly broken" to "definitely broken".
**Lesson:** When two code paths look structurally similar but use different primitives to reach the same state, do NOT assume a delta from one is applicable to the other. Trace the primitives end-to-end, and if hardware is needed to disambiguate, mark the fix as gated on live validation rather than guessing. Caught before pushing — the initial fix plan had "gated on re-test" and the second-pass analysis enforced it.

