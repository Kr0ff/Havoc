# HVC-030 — Sleep Obfuscation Enhancements

**Status:** Pending

---

## Problem

The Demon agent's three sleep obfuscation techniques (EKKO, Zilean, Foliage) are well-documented
in public research and recognized by modern EDR products. Specific issues:

- **Static gadget address per build.** The `OBF_JMP` macro resolves a gadget address once at
  startup and reuses it every sleep cycle. EDRs that monitor ROP call stacks or scan for
  characteristic gadget targets will see the same address repeatedly across a campaign.
- **JMPRAX logic defect.** A missing `else` keyword in the `OBF_JMP` macro means the JMPRAX
  branch is not mutually exclusive with JMPRBX. The target register is written and then
  immediately overwritten, defeating the intended gadget selection entirely.
- **PE headers visible during sleep.** When the agent is sleeping its `MZ`/`PE` headers remain
  readable in memory. Scanner tools and EDR kernel callbacks that enumerate loaded images during
  idle periods can match these headers against known Demon build signatures.
- **x86 has no obfuscation.** The 32-bit code path falls through to a plain
  `WaitForSingleObjectEx`, providing zero concealment on WoW64 or older 32-bit targets.
- **Heap allocations are unencrypted.** All working buffers (command queues, output staging,
  string tables) remain plaintext in heap memory while the agent sleeps, giving scanners easy
  access to C2 artifacts.

---

## Scope

Five independent sub-items. Each can be implemented and merged separately. Recommended order:
Sub-1 (bug fix, no risk) → Sub-2 (high impact, moderate effort) → Sub-3 (optional hardening) →
Sub-4 (x86 parity) → Sub-5 (lower priority, complex).

---

## Design

### Sub-1: JMPRAX Gadget Fix

**Files:** `payloads/Demon/include/core/SleepObf.h`

**Current issue:** The `OBF_JMP` macro uses `} if (` between the JMPRAX and JMPRBX branches
instead of `} else if (`. When `OBF_TECHNIQUE == OBF_JMPRAX` the macro writes `Rax` to the
target address and then the next unconditional `if` block also runs (or the fall-through
logic executes), causing the register to be overwritten. The effective dispatch is always
the JMPRBX path regardless of the compile-time selection, and the `jmp rax` (`FF E0`) gadget
is never actually used.

**Fix:** Change every `} if (` separator between gadget branches inside `OBF_JMP` to
`} else if (` so each branch is mutually exclusive.

**Opcode clarification:** The intended dispatch semantics for JMPRAX require `FF E0`
(`jmp rax`), not `FF D0` (`call rax`). The difference is critical:

- `call rax` pushes a return address onto the stack before transferring control, inserting
  an extra frame into the ROP chain that breaks the carefully constructed stack layout.
- `jmp rax` transfers control without modifying the stack, which is what the ROP chain
  expects — the stack is already arranged so that the value at RSP is the intended return
  address for the called function.

After applying the `else if` fix, verify that the gadget scan in `ObfTimer.c` searches for
the byte pattern `FF E0` (not `FF D0`) when `OBF_JMPRAX` is selected.

**Regression requirement:** The JMPRAX crash previously observed (agent crashes after one
or more sleep cycles) is directly caused by this defect. After the fix, test all three
gadget modes (JMPRAX, JMPRBX, and the default/no-gadget path) for a minimum of ten
consecutive sleep cycles on a live test target before merging.

---

### Sub-2: PE Header Stomping During Sleep

**New files:**
- `payloads/Demon/src/core/PeProtect.c`
- `payloads/Demon/include/core/PeProtect.h`

**Modified files:**
- `payloads/Demon/src/core/ObfTimer.c` — call stomp before sleep, restore after wake
- `payloads/Demon/src/core/ObfFoliage.c` — same
- `payloads/Demon/src/core/Obf.c` — same

**Goal:** Zero the first 4 KB of the Demon image (DOS header, NT headers, section table)
before each sleep interval and restore from a saved backup on wake. This prevents signature
scans of the loaded image during the idle window.

**Backup strategy:** Allocate a static 4 KB buffer inside the Demon BSS section
(`BYTE PeBackup[0x1000]`) and copy the first page during `DemonInit()`, before any stomp
occurs. The buffer lives in already-encrypted memory during sleep so it is not scannable.
Heap allocation is not used for the backup because the heap itself may be a scan target
(Sub-5), and stack allocation is not used because the buffer must outlive any single
function call.

**Implementation:**

```c
// payloads/Demon/src/core/PeProtect.c

#include "core/PeProtect.h"
#include "common/Macros.h"   // MemSet, MemCopy
#include "core/Instance.h"   // Instance->Win32, Instance->Modules.Self

static BYTE PeBackup[ 0x1000 ];
static BOOL PeBackupSaved = FALSE;

VOID PeProtect_Init( VOID )
{
    if ( PeBackupSaved ) return;
    MemCopy( PeBackup, Instance->Modules.Self, 0x1000 );
    PeBackupSaved = TRUE;
}

VOID PeProtect_Stomp( VOID )
{
    PVOID  BaseAddr   = Instance->Modules.Self;
    DWORD  OldProtect = 0;
    SIZE_T StompSize  = 0x1000;

    Instance->Win32.NtProtectVirtualMemory(
        NtCurrentProcess(), &BaseAddr, &StompSize,
        PAGE_READWRITE, &OldProtect );

    MemSet( BaseAddr, 0, StompSize );

    Instance->Win32.NtProtectVirtualMemory(
        NtCurrentProcess(), &BaseAddr, &StompSize,
        PAGE_EXECUTE_READ, &OldProtect );
}

VOID PeProtect_Restore( VOID )
{
    if ( ! PeBackupSaved ) return;

    PVOID  BaseAddr   = Instance->Modules.Self;
    DWORD  OldProtect = 0;
    SIZE_T RestoreSize = 0x1000;

    Instance->Win32.NtProtectVirtualMemory(
        NtCurrentProcess(), &BaseAddr, &RestoreSize,
        PAGE_READWRITE, &OldProtect );

    MemCopy( BaseAddr, PeBackup, RestoreSize );

    Instance->Win32.NtProtectVirtualMemory(
        NtCurrentProcess(), &BaseAddr, &RestoreSize,
        PAGE_EXECUTE_READ, &OldProtect );
}
```

**Call sites:** In each `SleepObf*()` function, call `PeProtect_Stomp()` immediately before
the wait primitive (timer wait, event wait, fiber switch) and `PeProtect_Restore()`
immediately after control returns. Both calls must be inside the same encryption window as
the main memory encryption so headers are never plaintext while the region is also
unencrypted.

**Constraints:**
- `NtProtectVirtualMemory` is already resolved via indirect syscalls — no new resolution needed.
- `Instance->Modules.Self` holds the Demon base address — already populated in `DemonInit()`.
- Never use `PAGE_EXECUTE_READWRITE`. Use `PAGE_READWRITE` for the stomp/restore write, then
  immediately flip to `PAGE_EXECUTE_READ`.

---

### Sub-3: Runtime Gadget Randomization

**New function:** `MmGadgetFind()` in `payloads/Demon/src/core/Memory.c`
(or a dedicated `payloads/Demon/src/core/Gadget.c` if the Memory.c file is already large)

**Compile flag:** `-DRANDGADGET` — feature is opt-in, not enabled by default on all builds.

**Goal:** Instead of resolving one gadget address at startup, scan the ntdll `.text` section
at runtime for all occurrences of the target byte pattern and select one at random each
sleep cycle. This ensures no single gadget address appears in two consecutive ROP chains
for the same process, defeating EDR heuristics that track reused gadget pointers.

**Implementation:**

```c
// Scan ntdll .text section for all instances of a 2-byte gadget pattern.
// Returns a randomly selected matching address, or NULL if none found.
// Pattern: e.g. 0xFFE0 for "jmp rax", 0xFF23 for "jmp [rbx]"
PVOID MmGadgetFind( WORD Pattern )
{
    // 1. Locate ntdll .text section boundaries using the PEB or
    //    Instance->Modules.Ntdll + PE section table walk.
    // 2. Walk every byte in .text; collect PVOID addresses where
    //    *(PWORD)addr == Pattern into a local stack array (max 256 hits).
    // 3. Select index: Instance->Win32.RtlRandomEx( &Seed ) % count.
    // 4. Return selected address.
}
```

The random selection uses `RtlRandomEx` (already resolved) rather than any user32 or
bcrypt dependency. The collection array is stack-allocated (256 pointers = 2 KB on x64)
to avoid heap allocation during the sensitive pre-sleep window.

Call `MmGadgetFind()` once per sleep cycle, replacing the startup-resolved static gadget
pointer used by the existing `OBF_JMP` macro.

---

### Sub-4: x86 Sleep Obfuscation (Zilean Variant)

**Files:** `payloads/Demon/src/core/ObfTimer.c` (x86 `#ifdef` block)

**Goal:** Provide a 32-bit-compatible sleep obfuscation for WoW64 and older 32-bit target
hosts. The current x86 fallback calls `WaitForSingleObjectEx` directly with no memory
encryption, leaving all Demon allocations plaintext during sleep.

**Approach:** Implement a stripped-down Zilean variant for x86. `RtlCreateTimerQueue` and
`RtlCreateTimer` are available in 32-bit ntdll. The encryption step uses the same
`SystemFunction032` / RC4 path as the 64-bit Zilean implementation. The ROP chain is
simpler on x86 because the calling convention uses the stack rather than registers, so
gadget requirements are less strict.

**Priority:** Lower than Sub-1 through Sub-3. x86 targets are uncommon in modern engagements
but the capability matters for legacy environments. Implement after the x64 fixes are stable.

---

### Sub-5: Heap Encryption During Sleep

**Priority:** Low — complex, high risk of instability.

**Goal:** Walk the Demon process heap and encrypt all allocated blocks before sleep, then
decrypt them on wake, using the same per-request AES key that encrypts the `.text` section.

**Challenges:**
- `HeapWalk` enumerates allocated blocks but requires the heap to not be locked by another
  thread at the point of the call. Thread suspension (already done for memory encryption)
  must complete before the walk begins.
- Re-encrypting individual heap blocks with AES-256-CTR requires a separate IV per block or
  a single pass over a contiguous range — neither is straightforward given heap fragmentation.
- Any heap allocation inside the encryption loop itself (e.g., from CRT or indirect Win32
  calls) would encrypt a live allocation and cause corruption on decrypt.

**Approach if implemented:** Use `RtlWalkHeap` (ntdll internal) instead of the Win32
`HeapWalk` to avoid CRT involvement. Pre-allocate all loop temporaries on the stack.
Restrict encryption to blocks over a minimum size threshold (e.g., 256 bytes) to avoid
corrupting small internal heap metadata allocations.

Mark as experimental; gate behind `-DHEAP_ENC` compile flag with prominent warning that
stability is not guaranteed.

---

## File Map

| File | Change |
|------|--------|
| `payloads/Demon/include/core/SleepObf.h` | Fix `OBF_JMP` macro: `} if (` → `} else if (` (Sub-1) |
| `payloads/Demon/src/core/PeProtect.c` | New — PE header stomp and restore (Sub-2) |
| `payloads/Demon/include/core/PeProtect.h` | New — `PeProtect_Init`, `PeProtect_Stomp`, `PeProtect_Restore` declarations |
| `payloads/Demon/src/core/ObfTimer.c` | Call `PeProtect_Stomp`/`Restore` around wait primitives (Sub-2) |
| `payloads/Demon/src/core/ObfFoliage.c` | Call `PeProtect_Stomp`/`Restore` around fiber switch (Sub-2) |
| `payloads/Demon/src/core/Obf.c` | Call `PeProtect_Stomp`/`Restore` around fallback wait (Sub-2) |
| `payloads/Demon/src/core/Memory.c` or new `Gadget.c` | Add `MmGadgetFind()` (Sub-3) |
| `payloads/Demon/CMakeLists.txt` | Add `PeProtect.c` and optionally `Gadget.c` to source list |

---

## Tests

1. **Sub-1 regression:** Build Demon with `OBF_JMPRAX`, `OBF_JMPRBX`, and the default gadget
   mode. Run each for a minimum of ten sleep cycles on a test target. Confirm no crash occurs.
   The prior JMPRAX crash (seen after the `else if` defect was first introduced) must not
   reappear.

2. **Sub-2 verification:** Attach a monitoring process that reads the Demon image base at a
   1-second polling interval. During a sleep window the first 4 KB must read as all zeros.
   After wake the `MZ` signature (`4D 5A`) must be present at offset 0 again.

3. **Sub-3 distribution check:** With `-DRANDGADGET` enabled, log the selected gadget address
   for 50 consecutive sleep cycles and verify that at least three distinct addresses appear
   (confirming random selection rather than a fixed index).

4. **Sub-4 smoke test:** Cross-compile a 32-bit Demon build with Zilean obfuscation enabled.
   Run under WoW64 for ten sleep cycles; confirm the process survives and checks in normally.

---

## Notes

- The `PeProtect_Init()` call must happen in `DemonInit()` before the first sleep. If the
  first sleep occurs before `PeProtect_Init()` the backup buffer will be empty and
  `PeProtect_Restore()` will zero the PE headers permanently, crashing the agent on next
  execution.
- The static `PeBackup` buffer adds 4 KB to the Demon BSS. This is acceptable.
- Sub-3 gadget randomization is a compile-time optional feature (`-DRANDGADGET`) and must not
  be forced on all builds. The default build continues to use the startup-resolved static
  gadget address after the Sub-1 `else if` fix is applied.
- `PAGE_EXECUTE_READWRITE` must never appear in any new or modified code. The pattern is
  always: allocate or protect as `PAGE_READWRITE`, perform the write, then flip to
  `PAGE_EXECUTE_READ`.
