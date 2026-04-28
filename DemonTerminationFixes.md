# Demon Agent Termination Fixes

After profile settings fixes (BUGFIX-001--006) correctly propagated values like
HWBP, SleepJmpGadget, ProxyLoading to the builder and agent config, the Demon
agent began exercising code paths that had latent bugs. Five bugs were found and
fixed. Four false positives were identified and ruled out.

## Analysis Method

Three specialized agents analyzed the codebase in parallel:
1. **Low-level dev** (ASM+C+Windows Internals): Sleep obfuscation ROP chains,
   HwBpEngine, proxy loading, type safety
2. **Code QA**: Config packing/parsing alignment audit (builder.go <-> Demon.c)
3. **Tester**: Configuration combination crash matrix

QA audit confirmed: config packing order, key names, value ranges, and packer
format all match correctly between builder.go and Demon.c. The bugs are in the
Demon C code itself.

---

## BUG-HWBP-1 (HIGH) -- Thread handle leak in HwBpEngineSetBp

**File:** `payloads/Demon/src/core/HwBpEngine.c` line 131

**Problem:** Thread handle opened at line 81 via `SysNtOpenThread(&Thread, ...)`
is only closed in the FAILED label (line 134-137). The success path at line 131
does `return Status;` without closing the handle. Every HWBP set, remove, and
exception-handler restore operation leaks one kernel handle. Over repeated .NET
assembly executions, handle count grows unbounded until the OS terminates the
process.

**Fix:** Added `SysNtClose(Thread)` before `return Status` on the success path,
mirroring the cleanup already present in the FAILED label.

**Impact:** Prevents gradual handle exhaustion that causes agent termination
after multiple .NET assembly invocations with HWBP enabled.

---

## BUG-HWBP-2 (MEDIUM) -- HwBpEngineRemove ignores Engine parameter

**File:** `payloads/Demon/src/core/HwBpEngine.c` lines 214, 222

**Problem:** Line 214 declares `PHWBP_ENGINE HwBpEngine = NULL;` (local
initialized to NULL). Line 222 checks `if ( ! HwBpEngine )` which is always
true because the local is always NULL. This means the `Engine` parameter is
completely ignored and `Instance->HwBpEngine` is always used.

Compare with `HwBpEngineAdd` (line 159) which correctly does
`PHWBP_ENGINE HwBpEngine = Engine;` and falls back to the global only when
Engine is NULL.

**Fix:** Changed line 214 to `PHWBP_ENGINE HwBpEngine = Engine;` to match the
pattern used in HwBpEngineAdd.

**Impact:** HwBpEngineRemove now correctly uses the Engine parameter when
provided, and falls back to Instance->HwBpEngine when Engine is NULL.

---

## BUG-HWBP-3 (HIGH) -- ExceptionHandler NULL pointer dereference

**File:** `payloads/Demon/src/core/HwBpEngine.c` line 330

**Problem:** The ExceptionHandler function accesses
`Instance->HwBpEngine->Breakpoints` at line 330 without checking if
`Instance->HwBpEngine` is NULL. This crashes if:
- The engine was destroyed but the VEH handler wasn't yet removed (race)
- An exception fires during the init/destroy window
- A STATUS_SINGLE_STEP exception occurs from an unrelated source

Since the VEH handler is registered globally for all threads, any single-step
exception on ANY thread will invoke this handler. A NULL dereference here
crashes the entire agent.

**Fix:** Added a NULL guard at the top of ExceptionHandler:
```c
if ( ! Instance->HwBpEngine ) {
    return EXCEPTION_CONTINUE_SEARCH;
}
```

**Impact:** Prevents immediate agent termination from NULL dereference. The
handler safely passes unhandled exceptions to the next handler in the chain.

---

## BUG-TIMER-1 (MEDIUM) -- sizeof(VOID) copies 1 byte instead of 8

**File:** `payloads/Demon/src/core/ObfTimer.c` line 198

**Problem:** `Rop[ Inc ].R8 = U_PTR( sizeof( VOID ) );` is used as the size
argument for RtlCopyMappedMemory during stack spoofing. On GCC/MinGW (which
compiles the Demon payload), `sizeof(void)` is a GCC extension that evaluates
to 1. This means only 1 byte of the instruction pointer (Rip) is copied during
the stack spoof operation.

The intended behavior is to copy the full 8-byte pointer (`sizeof(PVOID)` on
x64) from the source thread's Rip into the timer context, making the sleeping
thread appear to be at a legitimate call site.

**Fix:** Changed `sizeof( VOID )` to `sizeof( PVOID )`.

**Impact:** Stack spoofing now correctly copies all 8 bytes of the instruction
pointer. Previously, only 1 byte was copied, making the spoof completely
ineffective and leaving a partially corrupted address in the timer context.

---

## BUG-TIMER-2 (LOW) -- Timer cleanup blocking (documented)

**File:** `payloads/Demon/src/core/ObfTimer.c` line 285

**Problem:** `RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE)` is a blocking
call that waits for all outstanding timer callbacks to complete. If a timer
callback crashes or hangs, the cleanup blocks indefinitely, hanging the agent.

**Resolution:** Added documentation comment. No code change. The blocking
behavior is correct -- the image must not be used until all timers complete.
Changing to a non-blocking delete would introduce use-after-free if timers are
still touching the encrypted image region.

---

## Filtered False Positives

| Claim | Why it's wrong |
|-------|---------------|
| OBF_JMP `& p` for JMPRBX takes address of stack temporary | Macro expands to `& Instance->Win32.X` which is a valid address of a persistent struct field in the Instance on the main stack |
| ObfTimer NULL Rip when JmpGadget search fails | When MmGadgetFind fails, JmpBypass is reset to NONE. OBF_JMP then overwrites Rip with the actual function pointer for BYPASS_NONE |
| MmVirtualAlloc DX_MEM_DEFAULT infinite recursion | Memory.c:82 falls back to DX_MEM_SYSCALL when Config.Memory.Alloc == DX_MEM_DEFAULT, preventing recursion |
| VEH handler left active after DotnetExecute failure | Command.c:1803 calls DotnetClose() on failure path, which calls HwBpEngineDestroy to remove the VEH handler |

---

## Config Packing/Parsing Alignment (Verified Correct)

Builder packing order (builder.go:684-919):
```
1. Sleep (int)          -> Demon.c: ParserGetInt32 -> Config.Sleeping
2. Jitter (int)         -> Demon.c: ParserGetInt32 -> Config.Jitter
3. Alloc (int)          -> Demon.c: ParserGetInt32 -> Config.Memory.Alloc
4. Execute (int)        -> Demon.c: ParserGetInt32 -> Config.Memory.Execute
5. Spawn64 (wstring)    -> Demon.c: ParserGetBytes -> Config.Process.Spawn64
6. Spawn32 (wstring)    -> Demon.c: ParserGetBytes -> Config.Process.Spawn86
7. ObfTechnique (int)   -> Demon.c: ParserGetInt32 -> Config.Implant.SleepMaskTechnique
8. ObfBypass (int)      -> Demon.c: ParserGetInt32 -> Config.Implant.SleepJmpBypass
9. StackSpoof (int)     -> Demon.c: ParserGetInt32 -> Config.Implant.StackSpoof
10. ProxyLoading (int)  -> Demon.c: ParserGetInt32 -> Config.Implant.ProxyLoading
11. Syscall (int)       -> Demon.c: ParserGetInt32 -> Config.Implant.SysIndirect
12. AmsiPatch (int)     -> Demon.c: ParserGetInt32 -> Config.Implant.AmsiEtwPatch
```

All key names, numeric values, and packer format (AddInt = 4-byte LE int,
AddWString = 4-byte length prefix + UTF-16 data) match between builder and
Demon parser.

---

## QA Test Matrix

| # | SleepObf | JmpGadget | StackSpoof | HWBP | ProxyLoad | Result |
|---|----------|-----------|------------|------|-----------|--------|
| 1 | NONE(0) | NONE(0) | FALSE | NONE(0) | NONE(0) | Baseline - must work |
| 2 | EKKO(1) | NONE(0) | FALSE | NONE(0) | NONE(0) | Timer sleep, no spoof |
| 3 | EKKO(1) | JMPRAX(1) | FALSE | NONE(0) | NONE(0) | Timer + JMP RAX |
| 4 | EKKO(1) | JMPRBX(2) | FALSE | NONE(0) | NONE(0) | Timer + JMP RBX |
| 5 | EKKO(1) | JMPRAX(1) | TRUE | NONE(0) | NONE(0) | Tests BUG-TIMER-1 fix |
| 6 | EKKO(1) | JMPRAX(1) | TRUE | HWBP(1) | NONE(0) | Full combo |
| 7 | FOLIAGE(3) | NONE(0) | FALSE | HWBP(1) | NONE(0) | Foliage + HWBP |
| 8 | EKKO(1) | NONE(0) | FALSE | HWBP(1) | RtlCreateTimer(2) | Timer conflicts |
| 9 | ZILEAN(2) | NONE(0) | TRUE | HWBP(1) | NONE(0) | Zilean full |

Each test: agent must survive 5+ sleep cycles, handle count must not grow,
.NET assembly output captured, agent responds to commands after sleep.

---

## Files Changed

| File | Changes |
|------|---------|
| `payloads/Demon/src/core/HwBpEngine.c` | Handle leak fix (line 131), wrong variable fix (line 214), NULL guard (line 326) |
| `payloads/Demon/src/core/ObfTimer.c` | sizeof(VOID)->sizeof(PVOID) (line 198), cleanup documentation (line 285) |
| `teamserver/cmd/cmd.go` | Version bump 0.8 -> 0.8.1 |
