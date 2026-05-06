# SKILL.md -- Lessons Learned from Havoc C2 Code Changes

This file captures mistakes made and lessons learned during code analysis
and modification of the Havoc C2 framework. It serves as a training reference
for future work to avoid repeating the same errors.

---

## Lesson 1: Profile Fixes Can Unmask Latent Agent Bugs

**What happened:** Fixed profile settings to actually propagate to the builder
and Demon agent (BUGFIX-001--006). The fixes were correct -- settings like HWBP,
SleepJmpGadget, ProxyLoading were now applied. But agents started terminating.

**Root cause:** The features themselves had bugs (handle leaks, NULL dereferences,
wrong sizeof). These bugs always existed but were never triggered because the
profile settings were silently ignored.

**Lesson:** When fixing configuration propagation, always audit the downstream
code that USES the configuration values. Enabling a feature is only correct if
the feature itself works. The proper workflow is:

1. Fix config propagation
2. Audit the feature implementation for bugs
3. Fix feature bugs
4. Test with the feature actually enabled

**Rule:** After any change that enables previously-disabled code paths, trace
those code paths for latent bugs before declaring the fix complete.

---

## Lesson 2: sizeof(void) Is Not Zero -- It's 1 on GCC

**What happened:** `sizeof( VOID )` was used as a copy size for
RtlCopyMappedMemory in the sleep obfuscation ROP chain. The intent was to copy
a full pointer (8 bytes on x64). On MSVC, `sizeof(void)` is a compile error.
On GCC/MinGW (which compiles the Demon), it's a GCC extension that evaluates
to 1.

**Root cause:** The original developer likely meant `sizeof(PVOID)` but wrote
`sizeof(VOID)`. Since the Demon is compiled with MinGW (GCC), this compiled
without warning and silently copied only 1 byte.

**Lesson:** Never use `sizeof(void)` or `sizeof(VOID)`. For pointer-sized
copies, always use `sizeof(PVOID)` or `sizeof(ULONG_PTR)`.

**Rule:** When reviewing C code compiled with MinGW/GCC, grep for
`sizeof.*VOID` and verify each instance is intentional.

---

## Lesson 3: Handle Leaks Are Silent Killers

**What happened:** `HwBpEngineSetBp` opened a thread handle via
`SysNtOpenThread` but only closed it on the FAILED path. The success path
returned without closing. Each breakpoint set/remove/restore leaked one handle.

**Root cause:** Classic copy-paste or oversight. The FAILED label had proper
cleanup, but the success path was forgotten. The function is called from the
VEH exception handler (on every breakpoint hit), so the leak is rapid.

**Lesson:** For any function that opens handles or allocates resources:
1. List ALL exit points (return statements, gotos)
2. Verify EACH exit point closes/frees resources
3. Prefer a single cleanup label with goto (RAII pattern in C)

**Rule:** After writing or modifying a function that opens handles, audit ALL
return paths -- not just the error paths.

---

## Lesson 4: Initialize Local Variables From Parameters, Not NULL

**What happened:** `HwBpEngineRemove` declared `PHWBP_ENGINE HwBpEngine = NULL`
then checked `if (!HwBpEngine)` to decide whether to use the global engine.
Since the local was always NULL, the Engine parameter was always ignored.

**Root cause:** The function was likely copied from `HwBpEngineDestroy` which
has the same pattern but different semantics. `HwBpEngineAdd` correctly does
`PHWBP_ENGINE HwBpEngine = Engine;`.

**Lesson:** When a function takes a parameter that can be NULL (with a fallback
to a global), initialize the local variable FROM the parameter, then check:
```c
PHWBP_ENGINE HwBpEngine = Engine;  // from parameter
if (!HwBpEngine) {
    HwBpEngine = Instance->HwBpEngine;  // fallback to global
}
```

**Rule:** When auditing functions with "use parameter or fall back to global"
patterns, verify the local is initialized from the parameter, not from NULL.

---

## Lesson 5: VEH Handlers Need NULL Guards

**What happened:** The ExceptionHandler for hardware breakpoints accessed
`Instance->HwBpEngine->Breakpoints` without checking if `HwBpEngine` was NULL.
If HwBpEngine was destroyed (or never initialized), this NULL-dereferenced and
crashed the agent.

**Root cause:** VEH handlers are registered globally for all threads. They can
fire at any time, including during initialization/destruction windows. The
handler assumed the engine was always initialized when called.

**Lesson:** Exception handlers (VEH, SEH, signal handlers) must be defensive:
1. Always NULL-check global state before accessing it
2. Return the appropriate "not handled" value if state is invalid
3. Never assume the handler's setup/teardown is atomic

**Rule:** Any exception/signal handler should start with NULL checks on all
global state it accesses.

---

## Lesson 6: Agent Findings Need Manual Verification

**What happened:** Three analysis agents reported 8 bugs. After manual
verification, 4 were false positives:
- "OBF_JMP takes address of stack temp" -- actually takes address of struct field
- "NULL Rip when gadget search fails" -- OBF_JMP overrides Rip for BYPASS_NONE
- "MmVirtualAlloc infinite recursion" -- fallback to DX_MEM_SYSCALL prevents it
- "VEH handler left active after failure" -- Command.c calls DotnetClose on error

**Root cause:** Agents analyze code statically and can miss:
- Macro expansion context (what `p` actually expands to)
- Fallback logic in subsequent code
- Error handling in the caller (not the callee)

**Lesson:** Always verify agent findings by:
1. Reading the actual code at the reported line
2. Tracing macro expansions manually
3. Checking the calling code for error handling
4. Testing with actual compiler behavior

**Rule:** Treat agent findings as hypotheses to verify, not confirmed facts.
A 50% false positive rate is normal for static analysis.

---

## Lesson 7: Compile-Time Guards vs Runtime Values

**What happened:** Sleep obfuscation techniques are selected at both compile
time (via #ifdef) and runtime (via config value). The builder correctly sets
compile-time defines to match the runtime technique. But if mismatched, the
runtime switch statement falls through to DEFAULT safely.

**Lesson:** The Demon's design has a correct defense-in-depth pattern:
- Compile-time: only include code for the chosen technique (reduces binary size)
- Runtime: switch statement has DEFAULT fallback to unobfuscated sleep
- This means even if values are wrong, the agent survives (just loses obfuscation)

**Rule:** When modifying the builder or config, always verify that compile-time
defines match the runtime config values. Test what happens on mismatch.

---

## Lesson 8: x64 Rsp Alignment Is Per-Windows-Build

**What happened:** Foliage sleep obfuscation crashed within a few sleep cycles.
The ROP chain's CONTEXT entries had `Rsp % 16 == 0` instead of the x64 ABI
requirement of `Rsp % 16 == 8` at function entry.

**Root cause:** `NtGetContextThread` on a freshly-created suspended thread returns
different Rsp alignment depending on the Windows build (kernel version). Some
return `% 16 == 0`, others `% 16 == 8`. The Foliage code used the captured Rsp
directly without normalizing. The Ekko/Zilean code already had the fix
(`Rop[i].Rsp -= sizeof(PVOID)`) because it uses `RtlCaptureContext` which
always returns `% 16 == 0`.

**Lesson:** When building ROP chains from captured thread contexts:
1. Never assume the captured Rsp has correct ABI alignment
2. Always normalize: `if ((Rsp & 0xF) == 0) Rsp -= sizeof(PVOID);`
3. Check that existing similar code (e.g., Ekko/Zilean) already has the fix
   — if it does, the new code path probably needs it too
4. The crash manifests as `#GP` from `movaps` in NtContinue target functions
   (SystemFunction032, WaitForSingleObjectEx, etc.) — not from NtContinue itself

**Rule:** When one code path has an alignment fix and a parallel code path
doesn't, that's a bug. Always check sibling implementations for fixes that
should be shared.

---

## Lesson 9: Never Call Win32 APIs on Manually-Created NT Threads

**What happened:** The Foliage ROP chain called `WaitForSingleObjectEx` (a
Win32 API from kernelbase.dll) on the APC thread. This thread was created via
`NtCreateThreadEx` with `NtTestAlert` as start address + `CREATE_SUSPENDED` —
it never ran through `BaseThreadInitThunk` / `RtlUserThreadStart`, so its TEB
Win32 subsystem state (activation context, FLS, loader lock, CRT) was
uninitialised. The Win32 wrapper accessed these fields and crashed.

**Root cause:** Win32 APIs (kernelbase/kernel32) are wrappers around NT
syscalls that assume standard thread initialisation has occurred. Threads
created directly with `NtCreateThreadEx` bypass this initialisation entirely.

**Lesson:** On threads created directly via `NtCreateThreadEx` (especially
with `CREATE_SUSPENDED` for APC/ROP chains):
1. Only use NT-native syscalls (`NtWaitForSingleObject`, not `WaitForSingleObjectEx`)
2. Only use ntdll functions (they have no Win32 subsystem dependency)
3. Avoid kernelbase.dll / kernel32.dll wrappers entirely
4. `SystemFunction032` (advapi32) works because it's a thin wrapper that
   doesn't touch TEB Win32 state — but this is the exception, not the rule

**Rule:** If the thread was created with `NtCreateThreadEx`, restrict the ROP
chain to ntdll functions and direct syscalls only.

---

## Lesson 10: Audit ALL Non-ntdll Functions in ROP Chains on Manual Threads

**What happened:** After FIX-11 replaced `WaitForSingleObjectEx` with
`NtWaitForSingleObject`, the Foliage agent survived much longer but still
crashed intermittently. `SystemFunction032` (advapi32 → cryptbase.dll) was
the only remaining non-ntdll function in the ROP chain. It intermittently
accessed uninitialised TEB state on the APC thread.

**Root cause:** The same bug class as Lesson 9. SystemFunction032 is a
"usually safe" advapi32 function (simple RC4), but on some Windows versions
or under certain conditions, its implementation touches TEB fields that only
exist on properly initialised threads.

**Lesson:** When building ROP chains on manually-created threads
(`NtCreateThreadEx` + `CREATE_SUSPENDED`):
1. Audit EVERY function in the chain — not just the obvious Win32 wrappers
2. Only ntdll functions and direct syscalls are guaranteed safe
3. Even "simple" functions from other DLLs (advapi32, kernel32) can have
   hidden TEB dependencies in their implementation or forwarding chain
4. If you must use a non-ntdll algorithm (RC4, etc.), implement it as a
   position-independent stub in separately allocated executable memory

**Rule:** For ANY function in a ROP chain on a manual thread, verify it comes
from ntdll. If not, replace it with an ntdll alternative or a custom stub.

---

## Meta-Lesson: The Checklist

Before declaring any Demon code change complete:

1. [ ] Traced the full data flow (profile -> builder -> agent -> runtime)
2. [ ] Audited all exit paths for resource cleanup
3. [ ] Verified type sizes match between packer and parser
4. [ ] Checked for sizeof(void) usage
5. [ ] Verified NULL checks on global state in handlers
6. [ ] Manually verified all agent findings (filter false positives)
7. [ ] Tested compilation (Go + MinGW + Qt)
8. [ ] Documented changes with IDs in CHANGES.md
9. [ ] Updated version if applicable
10. [ ] Checked Rsp alignment in ROP chains (must be %16==8 at function entry)
11. [ ] Verified ALL functions in ROP chains on manual threads are from ntdll only
