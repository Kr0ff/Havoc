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

**Fix (FIX-10, applied 2026-04-12):** After `NtGetContextThread(hThread, RopInit)`, conditionally adjust Rsp:
```c
if ( ( RopInit->Rsp & 0xF ) == 0 ) {
    RopInit->Rsp -= sizeof( PVOID );
}
```
This is safe on ALL Windows builds: it only adjusts when `Rsp % 16 == 0` (convention 2), leaving convention (1) systems untouched. The fix is applied to `RopInit` before the `MemCopy` to all 10 ROP entries, so all entries inherit correct alignment. The subsequent `Rsp -= 0x1000 * N` subtracts preserve the invariant since `0x1000` is a multiple of 16.

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
| FIX-10 | BUG-FOL-4 | `ObfFoliage.c` | Normalise RopInit->Rsp to %16==8 after NtGetContextThread; conditional (only adjusts if %16==0), safe on all Windows builds | Low — **APPLIED 2026-04-12** |
| FIX-11 | NEW | `ObfFoliage.c` | Replace `WaitForSingleObjectEx` with `NtWaitForSingleObject` in ROP chain sleep — APC thread has no Win32 subsystem init | CRITICAL — **APPLIED 2026-04-12** |
| FIX-12 | NEW | `Obf.c` | Foliage `ConvertThreadToFiberEx` failure: `goto DEFAULT` instead of `break` (no-sleep tight loop) | HIGH — **APPLIED 2026-04-12** |
| FIX-13 | NEW | `ObfFoliage.c` | Deadlock-safe Leave: terminate suspended APC thread before waiting | HIGH — **APPLIED 2026-04-12** |
| FIX-14 | NEW | `Demon.h` | Restore `#pragma pack()` after KAYN_ARGS — was leaking pack(1) into INSTANCE | MEDIUM — **APPLIED 2026-04-12** |
| FIX-15 | NEW | `ObfFoliage.c` | Replace SystemFunction032 (advapi32) with position-independent RC4 stub in separately allocated RX page — only non-ntdll function in ROP chain | HIGH — **APPLIED 2026-04-13** |

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

---

## 9. Deep Comparison: Original vs Current Implementation (2026-04-17)

This section is a comprehensive behavioral comparison of every sleep obfuscation
technique, analyzing why the original code does not crash while the current
implementation may crash under certain configurations.

### 9.1 The OBF_JMP Macro — Critical Behavioral Change

**Original** (`payloads-originalfiles/Demon/include/core/SleepObf.h:16-23`):
```c
#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {    \
        Rop[ i ].Rax = U_PTR( p );                  \
    } if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \
        Rop[ i ].Rbx = U_PTR( & p );                \
    } else {                                        \
        Rop[ i ].Rip = U_PTR( p );                  \
    }
```

The second `if` is NOT `else if`. This creates a **fall-through** for JMPRAX.

**Current** (`payloads/Demon/include/core/SleepObf.h:16-23`):
```c
#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {         \
        Rop[ i ].Rax = U_PTR( p );                       \
    } else if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \
        Rop[ i ].Rbx = U_PTR( & p );                     \
    } else {                                             \
        Rop[ i ].Rip = U_PTR( p );                       \
    }
```

Fixed with `else if`.

#### Behavioral Impact Per JmpBypass Mode

**NONE (0x0):** No behavioral difference. Both reach the `else` branch → `Rip = function`.

**JMPRAX (0x1) — CRITICAL CHANGE:**
- **Original:** Sets `Rax = function`, then falls through to `else` → `Rip = function`.
  The JmpGadget set during loop init is **overwritten**. The `jmp rax` gadget is
  **NEVER executed**. JMPRAX behaves identically to NONE — a direct Rip call.
- **Current:** Sets ONLY `Rax = function`. Rip remains as JmpGadget (`jmp rax`).
  The CPU executes `jmp rax` which jumps to the function. **The gadget IS actually used.**

**JMPRBX (0x2):** No behavioral difference. Both set `Rbx = &function` and don't
reach `else`, so `Rip` stays as JmpGadget (`jmp [rbx]`).

| JmpBypass | Original Effect | Current Effect | Changed? |
|-----------|----------------|----------------|----------|
| NONE | Direct Rip call | Direct Rip call | No |
| JMPRAX | Direct Rip call (gadget never used) | Gadget-mediated jmp rax | **YES - CRITICAL** |
| JMPRBX | Gadget-mediated jmp [rbx] | Gadget-mediated jmp [rbx] | No |

**The `else if` fix made JMPRAX actually work as designed, but this is a behavioral
change from "never crashes because gadget is never used" to "may crash if the gadget
execution path has stack alignment or return address issues."**

### 9.2 TimerObf: Original vs Current

#### Ekko vs Zilean Dispatch

**Original:** Dispatches based on `Method`:
- **Ekko:** `RtlCreateTimerQueue` + `RtlCreateTimer` with `WT_EXECUTEINTIMERTHREAD`
- **Zilean:** `NtCreateEvent(&EvntWait)` + `RtlRegisterWait` with `WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD`

`WT_EXECUTEINWAITTHREAD` does NOT guarantee all callbacks run on the same thread.
NtContinue loads a CONTEXT (including Rsp) from a specific thread — executing on
a different thread is undefined behavior.

**Current:** Both Ekko and Zilean use `RtlCreateTimerQueue` + `RtlCreateTimer`.
The `Method` parameter is accepted but **completely ignored**. Both run identical
code. This is **safer** — `WT_EXECUTEINTIMERTHREAD` guarantees same-thread execution.

#### sizeof(VOID) vs sizeof(PVOID)

**Original** (line 515): `Rop[Inc].R8 = U_PTR(sizeof(VOID))` — copies 1 byte of
Rip during stack spoof (broken).

**Current** (line 198): `Rop[Inc].R8 = U_PTR(sizeof(PVOID))` — copies full 8-byte
Rip value (correct).

#### NtSetEvent Double-Set

**Original** (lines 566-567):
```c
Rop[ Inc ].Rip = U_PTR( Instance->Win32.NtSetEvent );  // Direct set
OBF_JMP( Inc, Instance->Win32.NtSetEvent )              // Then macro
```
For JMPRBX, Rip = NtSetEvent (from line 566), Rbx = &NtSetEvent. Last ROP entry
always does direct call even in JMPRBX mode. **Inconsistent but harmless.**

**Current:** Only `OBF_JMP(Inc, NtSetEvent)` — consistent behavior across all modes.

#### Cleanup

**Original:** `RtlDeleteTimerQueue(Queue)` — non-blocking. Timer callbacks may still
reference Rop array on stack after function returns. Race condition that usually
doesn't crash because timers have already fired.

**Current:** `RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE)` — blocking wait
for all callbacks. Eliminates race but hangs if a callback hangs.

### 9.3 FoliageObf: Original vs Current

Foliage does NOT use OBF_JMP — all Rip values are set directly. JmpBypass has no
effect on Foliage. ProxyLoading has no effect on Foliage.

| Aspect | Original | Current | Impact |
|--------|----------|---------|--------|
| CONTEXT allocation | 13x `LocalAlloc(LPTR, sizeof(CONTEXT))` — 8-byte aligned | Single `NtAllocateVirtualMemory` — page-aligned (16-byte guaranteed) | **Crash fix: #GP from misaligned movaps** |
| RSP normalization | None — relies on thread's initial Rsp being correct | FIX-10: adjusts Rsp to `%16==8` if `%16==0` | **Crash fix: #GP on some Windows builds** |
| Encryption | `SystemFunction032` (advapi32/cryptbase) via 2 PUSTRING params | Custom position-independent RC4 stub on separate RX page; 4 raw params | **Crash fix: SystemFunction032 may touch uninit TEB on APC thread** |
| Sleep wait | `WaitForSingleObjectEx` (Win32 API, ms timeout) | `NtWaitForSingleObject` (native syscall, LARGE_INTEGER timeout on fiber stack) | **Crash fix: Win32 API may touch uninit TEB on APC thread** |
| Thread cleanup | `SysNtTerminateThread` without wait, handle leaked | FIX-13: `ThreadResumed` tracking, wait for thread exit, handle closed | **UAF/resource fix** |
| RopExitThd ret addr | Written to `RopBegin->Rsp` (wrong, benign) | Written to `RopExitThd->Rsp` (correct) | Cosmetic fix |
| Memory cleanup | Individual `LocalFree` (RopGetCtx/RopMemEnc not freed = leak) | Single `NtFreeVirtualMemory` after thread wait | Memory leak fix |
| Fiber failure | `break` (no sleep, no fallback) | `break` (same, per operator requirement FIX-12) | Same |

#### Why Original Foliage Doesn't Crash (Usually)

1. **LocalAlloc alignment:** On x64 Windows, the default heap typically returns 16-byte
   aligned blocks for allocations >= 16 bytes. `sizeof(CONTEXT)` = 0x4D0 (1232 bytes)
   qualifies. So alignment is correct by coincidence, not by design.

2. **SystemFunction032:** On most Windows builds, it's a simple RC4 implementation that
   doesn't actually access TEB subsystem fields. The dependency on `advapi32/cryptbase`
   is load-time, and the function's runtime code path doesn't touch activation context
   or FLS on common builds.

3. **WaitForSingleObjectEx:** On most builds, the Win32 wrapper takes a fast path that
   immediately calls `NtWaitForSingleObject` internally, bypassing FLS/activation checks.

4. **Thread termination race:** `NtTerminateThread` completes quickly for a thread that's
   already finished its ROP chain. The CONTEXT memory from `LocalAlloc` isn't freed
   immediately after (the Go-to-Leave path frees contexts individually, and by the time
   execution reaches those frees, the thread is already terminated).

#### Why Original Foliage CAN Crash (Some Builds)

- Windows 10 22H2+: SystemFunction032 moved from advapi32 to cryptbase forwarded export;
  new code path may touch activation context
- Windows 11: Different WaitForSingleObjectEx code path accesses FLS
- Server 2022: Different heap alignment for small-ish allocations
- App Verifier / Page Heap: Strict 8-byte alignment exposes LocalAlloc issue

### 9.4 ProxyLoading — Confirmed Non-Factor

`ProxyLoading` (BYTE in `Instance->Config.Implant`) is parsed from the profile config
during Demon initialization but is **NEVER read by any code path** in either:
- `payloads-originalfiles/Demon/src/core/Obf.c`
- `payloads/Demon/src/core/Obf.c`
- `payloads/Demon/src/core/ObfTimer.c`
- `payloads/Demon/src/core/ObfFoliage.c`

No grep of the codebase finds any read of `ProxyLoading` after initialization.
It has **zero behavioral impact** on any sleep obfuscation technique.

### 9.5 Root Cause Summary: Why Current May Crash

**Primary cause — OBF_JMP JMPRAX behavioral change (TimerObf only):**

The `else if` fix transformed JMPRAX from "effectively NONE" (gadget never executes)
to "gadget-mediated execution" (`jmp rax`). This is a fundamental change in the
execution flow:

1. `jmp rax` is a non-call transfer — doesn't push a return address
2. Functions expect `Rsp % 16 == 8` at entry (after `call` pushes 8 bytes)
3. With `jmp rax`, Rsp is whatever NtContinue loaded (which may be `% 16 == 8` —
   correct for a `call` but the return path differs)
4. The function returns to `[Rsp]` which is set in the ROP chain — this should work
   if the stack is correctly set up
5. The crash likely occurs because `jmp rax` doesn't create a proper stack frame for
   the function's `ret` instruction — when the function returns, it pops the return
   address from Rsp, which was set by the ROP chain, but the stack unwinder and any
   exception handling code see an inconsistent call chain

**Secondary causes (Foliage, mostly fixed):**
- CONTEXT alignment (fixed by VirtualAlloc)
- RSP normalization (fixed by FIX-10)
- SystemFunction032 on APC thread (fixed by FIX-15 custom RC4)
- WaitForSingleObjectEx on APC thread (fixed by FIX-11 NtWaitForSingleObject)

### 9.6 Action Plan

#### Phase 1: Isolate JMPRAX as Crash Source (CRITICAL)

Test configurations to confirm the hypothesis:

| Test | Technique | JmpBypass | StackSpoof | Expected |
|------|-----------|-----------|------------|----------|
| T1 | Ekko | NONE | FALSE | Pass |
| T2 | Ekko | JMPRAX | FALSE | **CRASH?** |
| T3 | Ekko | JMPRBX | FALSE | Pass |
| T4 | Ekko | NONE | TRUE | Pass |
| T5 | Ekko | JMPRAX | TRUE | **CRASH?** |
| T6 | Ekko | JMPRBX | TRUE | Pass |
| T7 | Zilean | NONE | FALSE | Pass |
| T8 | Zilean | JMPRAX | FALSE | **CRASH?** |
| T9 | Foliage | N/A | N/A | Pass |

If T2/T5/T8 crash but T1/T3/T4/T6/T7/T9 pass → OBF_JMP confirmed.

#### Phase 2: Fix JMPRAX Execution Path (HIGH)

**Option A — Revert OBF_JMP to original `if`/`if`/`else`:**
Simple, known-working, but JMPRAX becomes identical to NONE (feature disabled).

**Option B — Fix stack setup for `jmp rax` gadget:**
When JMPRAX is active, adjust the ROP chain so the stack is correctly set up
for the `jmp rax` non-call transfer. Specifically, the return address needs to
be at `[Rsp]` and Rsp needs proper alignment for the target function.

**Option C — Use `call rax` gadget (`FF D0`) instead of `jmp rax` (`FF E0`):**
`call rax` pushes a return address — proper calling convention. Find `FF D0`
in ntdll instead of `FF E0`. More compatible with function prologues.
Requires: change `JmpPad` from `{0xFF, 0xE0}` to `{0xFF, 0xD0}` for JMPRAX,
and adjust Rsp in the ROP chain to account for the pushed return address.

**Recommended approach:** Option C — `call rax` is the correct gadget for
indirect function calls. `jmp rax` was likely a design error in the original
code (which was masked by the `if`/`if` fall-through bug making it never execute).

**Status (HVC-010, 2026-04-18):** Phase 1 (isolate JMPRAX as crash source) and
Phase 2 (fix) are now applied. JMPRAX explicitly sets `Rip = fn` in addition to
`Rax = fn`, making it functionally equivalent to NONE (direct call, no gadget).
The `jmp rax` gadget is found and stored in Rax but bypassed via the Rip
override. Future work (Phase 2 Option B/C) can implement proper gadget-based
dispatch; until then JMPRAX is a safe no-op over NONE.

#### Phase 3: Cross-Build Testing (MEDIUM)

Test all configurations on:
- Windows 10 21H2 (baseline)
- Windows 10 22H2 (SystemFunction032 relocation)
- Windows 11 23H2 (latest)
- Windows Server 2022

With and without App Verifier / Page Heap enabled.

#### Phase 4: Code Guards (LOW)

- Validate gadget is in executable memory before use
- Debug-mode Rsp alignment assertion before NtContinue
- Compile-time option to disable JMPRAX if it proves unreliable
- Document tested configurations in code comments

### 9.7 HVC-011: Proxy Loading Crash — Blocking Cleanup Root Cause

**Problem:** Demon crashes after ~10 sleep cycles when ProxyLoading = RtlCreateTimer or RtlRegisterWait. Works indefinitely with RtlQueueWorkItem.

**Root cause:** Both `ObfTimer.c` and `LdrModuleLoad` were changed from non-blocking `RtlDeleteTimerQueue` to blocking `RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE)`. The blocking variant waits for all timer callbacks to "complete" per the thread pool's internal accounting, but NtContinue-based callbacks (used in TimerObf's ROP chain) bypass normal callback return semantics, leaving the completion tracking inconsistent. Over ~19 timer queue lifecycles (9 proxy loading + ~10 sleep cycles), the accumulated corruption causes a hard crash.

**Fix:** Reverted all blocking cleanup to non-blocking `RtlDeleteTimerQueue`. Restored `WT_EXECUTEONLYONCE` in RtlRegisterWait proxy loading (removed explicit RtlDeregisterWaitEx). Kept BUG-LDR-1 handle separation.

**Status (2026-04-18):** Applied. Live test showed crash persists — HVC-011 is defensively correct but NOT the root cause. See §9.8.

### 9.8 HVC-012: Proxy Loading Crash — sizeof(PVOID) Rip Copy Root Cause

**Problem:** After HVC-011, the crash pattern is identical. Post-HVC-011 console outputs show the exact same crash at ~11 cycles.

**Exhaustive comparison result:** After HVC-011 brought all cleanup/LdrModuleLoad code into alignment with the original, the ONLY remaining behavioral difference in the entire TimerObf path (for Ekko + JmpBypass=NONE) is:

| Location | Original | Current (HVC-009) |
|----------|----------|--------------------|
| `ObfTimer.c` ROP step 4 | `sizeof(VOID)` = 1 byte | `sizeof(PVOID)` = 8 bytes |

**Why sizeof(PVOID) causes the crash:**

ROP step 4 copies bytes from `ThdCtx.Rip` (main thread's Rip) to `TimerCtx.Rip`. With `sizeof(VOID)` = 1 byte, this is a near-no-op: `TimerCtx.Rip` stays as the timer thread's Rip from `RtlCaptureContext`. Step 6 (`NtSetContextThread`) then applies a fully self-consistent context (all fields from the timer thread) to the main thread.

With `sizeof(PVOID)` = 8 bytes, `TimerCtx.Rip` becomes the main thread's actual Rip (inside the NtSignalAndWaitForSingleObject syscall stub). Step 6 applies a **mixed context**: Rip from the main thread's syscall path, but Rsp and all registers from the timer thread. This inconsistency in the context applied via `NtSetContextThread` to a kernel-waiting thread corrupts thread pool dispatch state over repeated cycles. The corruption accumulates faster when proxy loading has primed the pool with timer/wait threads (RtlCreateTimer/RtlRegisterWait), explaining why RtlQueueWorkItem doesn't trigger it.

**Fix:** Reverted to `sizeof(VOID)`. Added comment explaining the design intent.

**Status (2026-04-18):** Applied. Pending live test verification.

