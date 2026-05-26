# HVC-030 Sub-1 — JMPRAX Gadget Analysis

**Status:** Applied — 2026-05-21
**Scope:** `payloads/Demon/include/core/SleepObf.h`, `payloads/Demon/src/core/ObfTimer.c`

---

## Simple Explanation

The Demon sleep obfuscation (Ekko/Zilean) is supposed to hide what Windows function the
agent calls during each step of its sleep cycle. It does this by routing through a "gadget"
— a tiny two-byte instruction (`jmp rax`, opcode `FF E0`) found inside Windows' own
`ntdll.dll`. This makes the call stack look like the timer thread is running code inside
ntdll, not calling `VirtualProtect` or `SystemFunction032` directly.

The JMPRAX mode was broken by a missing `else` keyword. When JMPRAX is selected, the code
correctly sets `RAX = target_function`, but then the missing `else` lets a later code block
also run, setting `RIP = target_function` directly — overwriting the gadget address. The
gadget is never executed. JMPRAX has been silently identical to the no-gadget mode since
the bypass feature was introduced.

A second minor bug exists on the final chain step: a leftover line unconditionally writes
the direct function pointer into `Rip` for the NtSetEvent entry, overwriting the gadget
address that was set by the loop initialisation. That step also bypasses the gadget.

Both fixes are single-line changes. After the fixes, JMPRAX correctly routes every ROP
chain step through the `jmp rax` gadget in ntdll. JMPRBX was unaffected by either bug
and continues to work correctly.

---

## Detailed Technical Explanation

### Background: How TimerObf's ROP chain works

`TimerObf` implements the Ekko and Zilean sleep obfuscation techniques. It builds an array
of 13 `CONTEXT` structures (`Rop[0..12]`), each pre-initialised from the captured timer
thread context (`TimerCtx`). Each entry's `Rip` field (instruction pointer) and argument
registers are then set to dispatch one step: wait for signal, change memory protection,
RC4-encrypt, sleep, RC4-decrypt, change memory protection, signal completion.

The 13 timers are queued using `RtlCreateTimer` (Ekko) or `RtlRegisterWait` (Zilean),
each firing at 100 ms intervals. Each timer callback is `NtContinue`. When `NtContinue`
fires with `Rop[i]` as its argument, it restores ALL CPU registers (including `Rax`,
`Rbx`, `Rcx`, `Rdx`, `Rip`, `Rsp`, etc.) from the CONTEXT struct and jumps to `Rip`.
This "teleports" the timer thread to run the target function.

### Gadget bypass modes

When `JmpBypass != NONE`, the intent is to avoid having `Rop[i].Rip` point directly at
Win32 API functions. Instead:
- `Rop[i].Rip` = address of a `jmp rax` (`FF E0`) or `jmp [rbx]` (`FF 23`) gadget inside
  `ntdll.dll` (found by scanning ntdll's `.text` section)
- `Rop[i].Rax` (JMPRAX) or `Rop[i].Rbx` (JMPRBX) = the actual target function

`NtContinue` restores all registers, then the CPU jumps to `Rip` (the gadget). The gadget
executes `jmp rax`, which reads the already-restored `Rax` and jumps to the target function.
The call stack now shows the timer thread at the ntdll gadget address, not at the Win32 API.

The initialization loop (`ObfTimer.c:170–174`) pre-sets `Rop[i].Rip = JmpGadget` for every
entry. Individual `OBF_JMP` calls then set `Rax`/`Rbx`/`Rip` per entry depending on the mode.

### Bug 1 — Primary: OBF_JMP control flow (SleepObf.h:19)

**File:** `payloads/Demon/include/core/SleepObf.h` lines 16–23

**Current code:**
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

The C preprocessor and compiler see THREE independent control-flow statements:
1. `if (JMPRAX) { Rax = p; }`
2. `if (JMPRBX) { Rbx = &p; } else { Rip = p; }`

Statement 2 is completely independent from statement 1. For JMPRAX (value `0x1`):
- Statement 1 fires: `Rax = p` ✓
- Statement 2 evaluates: JMPRBX is `0x2`, so `0x1 == 0x2` is FALSE → the `else` runs
- `Rip = p` — **the gadget address set at line 172 is overwritten with the direct function pointer** ✗

**Control flow table:**

| Mode   | Value | Statement 1 result  | Statement 2 result      | Rax  | Rbx  | Rip            |
|--------|-------|---------------------|-------------------------|------|------|----------------|
| JMPRAX | 0x1   | TRUE → `Rax = fn`   | FALSE → else: `Rip = fn`  | fn   | —    | fn (**BUG**)   |
| JMPRBX | 0x2   | FALSE → skip        | TRUE → `Rbx = &fn`      | —    | &fn  | JmpGadget ✓   |
| NONE   | 0x0   | FALSE → skip        | FALSE → else: `Rip = fn`  | —    | —    | fn ✓           |

JMPRAX is functionally identical to NONE. The gadget is never used.

**Fix:** Change `} if (` to `} else if (` on line 19.

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

After fix:

| Mode   | Rax  | Rbx  | Rip       | Behaviour                       |
|--------|------|------|-----------|---------------------------------|
| JMPRAX | fn   | —    | JmpGadget | `jmp rax` → fn ✓               |
| JMPRBX | —    | &fn  | JmpGadget | `jmp [rbx]` → fn ✓             |
| NONE   | —    | —    | fn        | direct call ✓                   |

### Bug 2 — Secondary: Redundant Rip assignment on final entry (ObfTimer.c:258)

**File:** `payloads/Demon/src/core/ObfTimer.c` line 258

The initialization loop (lines 170–174) correctly sets `Rop[i].Rip = JmpGadget` for all
13 entries. However, immediately before the `OBF_JMP` call for the final NtSetEvent step,
there is a stray unconditional assignment:

```c
/* End of Ropchain */
Rop[ Inc ].Rip = U_PTR( Instance->Win32.NtSetEvent );   // line 258 — OVERWRITES JmpGadget
OBF_JMP( Inc, Instance->Win32.NtSetEvent )              // line 259
```

After the `else if` fix, `OBF_JMP` for JMPRAX correctly sets only `Rax = NtSetEvent` and
leaves `Rip` alone. But line 258 already wrote `NtSetEvent` into `Rip`, discarding the
gadget address from line 172. The final step silently bypasses the gadget.

**Fix:** Remove line 258. The initialization loop already set `Rip = JmpGadget` for this
entry. `OBF_JMP` on line 259 handles all necessary field assignments.

---

## What is NOT a bug

### Return address at `[Rsp]` (analysis agent "Bug 2")

The initialization loop sets `Rop[i].Rsp = TimerCtx.Rsp - 8` for every entry. No explicit
return address is written to `[Rsp]`. This was flagged as a potential crash vector.

**This is the existing design, not a new bug.** NONE mode uses the exact same `Rsp` value.
If NONE mode is stable in practice (it is), then JMPRAX mode will be equally stable after
the `else if` fix: `jmp rax` does not modify RSP, so the return-address situation when the
dispatched function executes its `ret` is identical between NONE and JMPRAX. Sub-1 does
not change this aspect of the design.

### Gadget byte patterns

- JMPRAX: `{ 0xFF, 0xE0 }` = `jmp rax` — **correct** x64 opcode
- JMPRBX: `{ 0xFF, 0x23 }` = `jmp [rbx]` — **correct** x64 opcode

The scan correctly uses `jmp rax` (`FF E0`) and not `call rax` (`FF D0`). `call rax` would
push a return address before jumping, corrupting the pre-arranged stack layout. `jmp rax`
transfers control directly without touching RSP. No change needed.

### NtContinue register restoration

`NtContinue(PCONTEXT, BOOLEAN)` is a full context-restore system call. It restores ALL
general-purpose registers from the CONTEXT struct — including `Rax` — before jumping to
`Rip`. When the `jmp rax` gadget executes, `Rax` is already set to the target function.
No additional setup needed.

### JMPRBX `&p` stability

`OBF_JMP` sets `Rbx = U_PTR(&p)` where `p` is e.g. `Instance->Win32.VirtualProtect`.
`&Instance->Win32.VirtualProtect` is the address of a field in the persistent `INSTANCE`
struct, not a stack temporary. The address is valid for the agent's lifetime. `jmp [rbx]`
correctly dereferences it to obtain the function pointer.

### JMPRBX mode unaffected by Bug 1

With the original `} if (` code:
- JMPRBX (0x2): first `if` is FALSE → skip; second `if` is TRUE → `Rbx = &fn`; `else` NOT
  reached → `Rip` stays as `JmpGadget` ✓

JMPRBX already works correctly. The `else if` fix preserves this.

---

## Bug Summary

| # | File | Line | Severity | Current | Fixed |
|---|------|------|----------|---------|-------|
| 1 | `SleepObf.h` | 19 | Critical | `} if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \` | `} else if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \` |
| 2 | `ObfTimer.c` | 258 | Minor | `Rop[ Inc ].Rip = U_PTR( Instance->Win32.NtSetEvent );` | *(line removed)* |

---

## Verification Steps

1. Cross-compile Demon with `OBF_JMPRAX` selected in the build profile
2. Deploy on a test Windows target; run 10+ sleep cycles; confirm no crash and normal checkin
3. Repeat with `OBF_JMPRBX` and no-gadget (`NONE`) to confirm no regression
4. Confirm at step entry (via debug logging) that `Rip` is an ntdll address, not a Win32 API
   address, when a gadget mode is active
