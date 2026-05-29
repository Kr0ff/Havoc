# AGENTS.md — Havoc C2 Framework Agent Role Definitions

This file defines specialised agent personas used when implementing improvements to the Havoc
C2 framework. Agents are spawned via the Claude Code Agent tool and assigned work based on
their domain. All agents treat `CLAUDE.md` as the authoritative constraint document — when
this file and `CLAUDE.md` conflict on any rule, `CLAUDE.md` wins.

**Read `CLAUDE.md` in full before starting any task.**

---

## Agent Roles

### red-team-developer

**Specialties:** C2 development, C/C++, NASM/x64 ASM, Golang, Qt5, COFF/BOF, Windows
internals, syscall engineering, EDR evasion, PE manipulation, sleep obfuscation

**Responsibilities:** Implement new features, bug fixes, and protocol changes across all three
components (Demon C agent, Go teamserver, Qt5 C++ client). Write correct, minimal,
production-quality code that fits the existing style. No new abstractions beyond what the
task requires.

---

#### Mandatory Reading Before Any Code Change

| Component | Reference Document |
|-----------|--------------------|
| Demon agent (`payloads/Demon/`) | `Demon.md` (repo root) |
| Teamserver (`teamserver/`) | `Teamserver.md` (repo root) |
| Client (`client/`) | `Client.md` (repo root) |
| Improvement index | `improvement-docs/00-index.md` |
| Open issue docs | `improvement-docs/issue-docs/` |
| Applied changes | `CHANGES.md` |

Do not write a single line of code before reading the relevant reference document. These
documents contain invariants that cannot be inferred from code inspection alone.

---

#### Architecture Overview

```
Client (Qt5 C++) <─ WebSocket ─> Teamserver (Go) <─ HTTP/HTTPS/SMB ─> Demon Agent (C/ASM)
```

**Deployment modes (Demon entry points):**
- `src/main/MainExe.c` — Standalone EXE; `ModuleBase` = PE image base from loader
- `src/main/MainDll.c` — DLL injection or KaynLdr shellcode; `ModuleBase` = `hDllBase`
  (DLL) or `KArgs->Demon` (shellcode — sections only, no PE header at offset 0)
- `src/main/MainSvc.c` — Windows service

---

#### Build Commands

```bash
# Teamserver
cd teamserver
go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go

# Go tests
cd teamserver && go test ./...

# Client
cd client && mkdir -p Build && cd Build
cmake .. -DCMAKE_BUILD_TYPE=Release && make -j4

# Full build
make all

# Dependencies (MinGW cross-compilers, NASM)
cd teamserver && bash Install.sh
```

**IDE diagnostics in Demon C files are always false positives.** Clang's IDE checker runs
without MinGW-w64 include paths. Errors like `'Demon.h' file not found`, `Unknown type name
'VOID'`, or `Use of undeclared identifier 'Instance'` are not real build failures. Only
MinGW compilation output matters.

---

#### Hard Constraints — Never Violate

##### 1. No stdlib in Demon C Code

`printf`, `malloc`, `free`, `memset`, `memcpy` are forbidden in Demon C. Substitutes:

| Forbidden | Demon replacement |
|-----------|-------------------|
| `printf` | `PRINTF(...)` / `PUTS(...)` macros |
| `memset` | `MemSet(dst, byte, size)` |
| `memcpy` | `MemCopy(dst, src, size)` |
| `malloc` | `Instance->Win32.LocalAlloc(LPTR, size)` |
| `free` | `Instance->Win32.LocalFree(ptr)` |

**Exception:** In `NtdllCopy` (the static QWORD loop in `NtdllUnhook.c`), even `MemCopy`
is forbidden because at `-O0 -nostdlib` MinGW emits an external `memcpy` call that is
unresolved at link time. Use only the manual QWORD loop.

##### 2. No PAGE_EXECUTE_READWRITE

Never allocate or set `PAGE_EXECUTE_READWRITE` (0x40). Correct pattern:
1. Allocate `PAGE_READWRITE` — write payload
2. `NtProtect(PAGE_EXECUTE_READ)` — flip to executable

The only exception: `PAGE_EXECUTE_WRITECOPY` (0x80) is permitted exclusively for CoW-patching
SEC_IMAGE execute pages (ntdll `.text`). See SEC_IMAGE VAD constraint below.

##### 3. NT_SUCCESS Guard — Mandatory Before Any Write to Protected Memory

Every `NtProtectVirtualMemory` call preceding a `MemSet`, `MemCopy`, or `MmVirtualWrite`
MUST be guarded:

```c
Status = Instance->Win32.NtProtectVirtualMemory(
    NtCurrentProcess(), &BaseAddr, &Size, PAGE_READWRITE, &OldProtect );
if ( ! NT_SUCCESS( Status ) ) {
    PRINTF( "FuncName: NtProtect failed 0x%X\n", Status )
    return;
}
// safe to write here
```

No write path may be reachable when `NtProtect` failed. The NT_SUCCESS guard protects the
SEC_IMAGE VAD failure case (where NtProtect returns an error). Note: it does NOT protect the
case where NtProtect succeeds but the target region is wrong — that requires separate
validation (e.g., the MZ signature check for PE stomping).

##### 4. OldProtect Restoration — Never Hardcode Protection Constants

After making a region writable and writing, restore to `OldProtect` (the value retrieved by
the preceding NtProtect call), not to a hardcoded constant:

```c
DWORD OldProtect = 0;
NtProtect( PAGE_READWRITE, &OldProtect );  // OldProtect = original protection
// ... write ...
BaseAddr = OriginalBase;                   // reset aliased locals first (see below)
Size     = OriginalSize;
NtProtect( OldProtect, &OldProtect );      // restore to original — NOT PAGE_EXECUTE_READ
```

The original PE header page is `PAGE_READONLY` (0x02), not `PAGE_EXECUTE_READ` (0x20).
Hardcoding `PAGE_EXECUTE_READ` permanently upgrades the page — incorrect and detectable.

##### 5. NtProtect Aliasing Guard — Reset Locals Before Second Call

`NtProtectVirtualMemory` page-aligns `*BaseAddress` and `*RegionSize` **in-place** through
the pointer arguments. Always reset them before the second call:

```c
PVOID  ProtAddr = Target;
SIZE_T ProtSize = Size;
NtProtect( NtCurrentProcess(), &ProtAddr, &ProtSize, PAGE_READWRITE, &OldProtect );
// ... write ...
ProtAddr = Target;       // reset — first call modified these in-place
ProtSize = Size;
NtProtect( NtCurrentProcess(), &ProtAddr, &ProtSize, OldProtect, &OldProtect );
```

##### 6. SEC_IMAGE VAD — PAGE_EXECUTE_WRITECOPY for Execute Pages

When patching pages with original protection `PAGE_EXECUTE_READ` (ntdll `.text`):
- Use `PAGE_EXECUTE_WRITECOPY` (0x80) — retains execute, adds CoW-write
- Do NOT use `PAGE_READWRITE` (0x04) — strips the execute bit; `MiChangeImageProtection`
  cannot satisfy this for a `VadImageMap` VAD and the call fails or the write faults

For non-execute SEC_IMAGE pages (PE header, original `PAGE_READONLY`), `PAGE_READWRITE` is
acceptable because no execute bit is being stripped.

Always use `SysNtProtectVirtualMemory` (indirect syscall) when patching ntdll `.text` — the
Win32 table entry goes through the EDR-hooked stub; that hook fires before clean bytes are
written and crashes the agent.

##### 7. DJB2 Hash Verification — Mandatory for Every New H_FUNC_* Constant

Every new `H_FUNC_*` in `payloads/Demon/include/common/Defines.h` MUST be verified:

```python
def djb2_upper(s):
    h = 5381
    for c in s.upper():
        h = (((h << 5) + h) + ord(c)) & 0xFFFFFFFF
    return h

# Verify before committing:
assert hex(djb2_upper("NtOpenSection"))      == "0x134eda0e"
assert hex(djb2_upper("NtMapViewOfSection")) == "0xd6649bca"
```

A wrong hash causes `LdrFunctionAddr` to return NULL silently. All code using that pointer
becomes a no-op with no runtime error — the failure mode is invisible.

##### 8. No Em Dash in Any String Literal

Never use `—` (U+2014) in `PRINTF`/`PUTS` format strings, Go log messages, or any terminal
output string. Use a plain hyphen `-` instead. Em dash renders as garbage in the Demon debug
console.

##### 9. Optional Improvements Must Not Affect Core Agent Behaviour

Gate optional features inside their own module — never in callers:

```c
// CORRECT — gate inside the optional module
VOID PeProtect_Stomp( VOID ) {
    if ( ! Instance->Config.Implant.PeStomp ) return;
    ...
}

// WRONG — gate in the caller (Obf.c, Demon.c)
if ( Instance->Config.Implant.PeStomp ) PeProtect_Stomp();
```

The core sleep path (DEFAULT case in `Obf.c`) must always call `WaitForSingleObjectEx`
directly when optional features are disabled or unavailable. A disabled `StackSpoof`,
`PeStomp`, or `HideModules` must leave the core agent behaviour completely unchanged.

##### 10. AMSI / ETW — HWBP Engine Only

Never patch AMSI or ETW functions with raw bytes. Do not write `0xC3`,
`0xB8 0x57 0x00 0x07 0x80 0xC3`, or any byte sequence over `AmsiScanBuffer`,
`NtTraceEvent`, or any AMSI/ETW export. All AMSI/ETW suppression goes through
`HwBpEngine` (`src/core/HwBpEngine.c`) via `HwBpEngineAdd()`.

---

#### Config Blob Pattern — 12-File Lockstep

Adding any new boolean or string config field to Demon requires changes in all of:

| # | File | Change |
|---|------|--------|
| 1 | `teamserver/pkg/profile/config.go` | Field in `Demon` struct, `yaotl:"...,optional"` tag |
| 2 | `teamserver/pkg/common/builder/builder.go` | Local var; parse from `b.config.Config["Label"]`; `AddInt`/`AddString` at END of blob sequence |
| 3 | `teamserver/cmd/server/dispatch.go` | Call `SetDemonProfileDefaults()` if field bypasses UI |
| 4 | `payloads/Demon/include/Demon.h` | Add field to `Config.Implant` struct |
| 5 | `payloads/Demon/src/Demon.c` | `ParserGetInt32`/`ParserGetString` at the matching position in `DemonConfig()` |
| 6 | `client/src/UserInterface/Dialogs/Payload.cc` | `QCheckBox` + `QTreeWidgetItem`; read JSON default; bind widget |
| 7 | `profiles/havoc.yaotl` | New field with default value |
| 8 | `scripts/check_profile.py` | `FieldSpec` entry in `SCHEMA["Demon"]` |
| 9 | `scripts/create_profile.py` | CLI argument + emitter line |
| 10 | `CHANGES.md` | New entry |
| 11 | `improvement-docs/00-index.md` | Status row update |
| 12 | `CLAUDE.md` / memory | Constraint section update |

**Wire format invariant:** The `AddInt`/`AddString` sequence in `builder.go:PatchConfig()`
and the `ParserGetInt32`/`ParserGetString` sequence in `Demon.c:DemonConfig()` must be in
identical order. A single mismatch silently misaligns every field from that point onward.

**Current field ordering (zero-indexed at the tail of the sequence):**

| Field | Type | Position |
|-------|------|----------|
| ConfigRandGadget | Int | 13 |
| ConfigUnhookNtdll | Int | 14 |
| ConfigHideModules | Int | 15 |
| ConfigPeStomp | Int | 16 |
| ConfigVerbose | Int | 17 |
| ConfigCoffeeVeh | Int | 18 |
| ConfigCoffeeThreaded | Int | 19 |
| ConfigSleepObfLib | String | 20 |
| ConfigSleepObfFunc | String | 21 |
| ConfigSleepObfOffset | Int | 22 |
| ConfigInjectSpoofLib | String | 23 |
| ConfigInjectSpoofFunc | String | 24 |
| ConfigInjectSpoofOffset | Int | 25 |

New fields are always appended after position 25. Never insert in the middle.

**UI label == builder.go config key.** `item->setText(0, "Label Text")` in `Payload.cc`
is the exact key used in `b.config.Config["Label Text"]` in `builder.go`. Must match
character-for-character including spaces. The YAOTL profile field name is different (no spaces,
Go struct naming) — both key forms are correct by design for their respective paths.

---

#### Key Patterns Quick Reference

**PE Stomping — MZ check mandatory:**
```c
// PeProtect_Init() — before reading PE header backup
PIMAGE_DOS_HEADER DosHdr = ( PIMAGE_DOS_HEADER ) Instance->Session.ModuleBase;
if ( DosHdr->e_magic != IMAGE_DOS_SIGNATURE ) {
    // KaynLdr shellcode mode: sections mapped without PE header;
    // NtProtect on private alloc succeeds but MemSet would zero live code
    Instance->Config.Implant.PeStomp = FALSE;
    return;
}
```

**ntdll unhooking — required ordering in DemonInit():**
```
DemonConfig()     // sets Config.Implant.SysIndirect
SysInitialize()   // populates Syscall.SysAddress + all SSNs
UnhookNtdll()     // SysNtProtect now has valid SSN → indirect syscall → bypasses EDR hook
PeProtect_Init()  // gates on PeStomp; validates MZ signature
```

**ntdll .text overwrite pattern:**
```c
PVOID  ProtAddr = LoadedText;
SIZE_T ProtSize = TextSize;
DWORD  OldProt  = 0;
SysNtProtectVirtualMemory( NtCurrentProcess(), &ProtAddr, &ProtSize,
                           PAGE_EXECUTE_WRITECOPY, &OldProt );
NtdllCopy( LoadedText, CleanText, TextSize );   // static QWORD loop — no CRT
ProtAddr = LoadedText;                          // reset aliased locals
ProtSize = TextSize;
SysNtProtectVirtualMemory( NtCurrentProcess(), &ProtAddr, &ProtSize, OldProt, &OldProt );
```

**Inline function resolution (NtOpenSection, NtMapViewOfSection):**
These two are NOT in `Instance->Win32`. Resolve inline via `LdrFunctionAddr`:
```c
typedef NTSTATUS (WINAPI* _NtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
_NtOpenSection pNtOpenSection = LdrFunctionAddr(Instance->Modules.Ntdll, H_FUNC_NTOPENSECTION);
// H_FUNC_NTOPENSECTION      = 0x134eda0e
// H_FUNC_NTMAPVIEWOFSECTION = 0xd6649bca
```

**UNICODE_STRING manual init (never call RtlInitUnicodeString):**
```c
WCHAR          SectionPath[] = L"\\KnownDlls\\ntdll.dll";
UNICODE_STRING SectionName   = { 0 };
SectionName.Length        = sizeof(SectionPath) - sizeof(WCHAR);
SectionName.MaximumLength = sizeof(SectionPath);
SectionName.Buffer        = SectionPath;
```

**Pe-sieve — fake callstack frames for APC ROP sleeping thread:**
```
[RSP+ 0] = NtTestAlert           // required: APC delivery return address — DO NOT REPLACE
[RSP+ 8] = BaseThreadInitThunk   // pe-sieve evasion frame 1
[RSP+16] = RtlUserThreadStart    // pe-sieve evasion frame 2
[RSP+24] = NULL                  // sentinel
```

**Module hiding — PEB cursor advance before unlink:**
```c
PLIST_ENTRY Flink = Entry->Flink;   // advance cursor BEFORE potential unlink
Entry = Flink;
// unlink the previous entry from all three LDR lists
```

---

#### Coding Style

**Demon C:**
- Declarations: `PVOID Var = { 0 };` or `PVOID Var = NULL;`
- Debug: `PRINTF( "fmt\n", args )` and `PUTS( "msg" )` — never `printf()`
- Types: `PVOID`, `BOOL`, `ULONG`, `NTSTATUS`, `SIZE_T`, `DWORD` — always uppercase
- Spacing: spaces around binary operators and after commas
- Comments: one concise line per non-obvious block; every new function gets a brief header

**Go (teamserver):**
- Match `builder.go` field-naming and error-handling patterns exactly
- `win32.TRUE` / `win32.FALSE` for integer booleans in `AddInt` calls

**C++ (client):**
- Match `Payload.cc` widget creation and binding patterns exactly
- JSON default access: `DemonConfig["FieldName"]`

---

#### Post-Implementation Checklist

Before reporting done:
- [ ] Re-read every modified file and verify each edit is at the correct location
- [ ] Report verified line numbers for each change
- [ ] Wire format: count and order of Add*/Parser* calls match on both sides
- [ ] Any new `H_FUNC_*` constant verified with `djb2_upper()` script
- [ ] No `PAGE_EXECUTE_READWRITE` anywhere in the diff
- [ ] NT_SUCCESS guard present before every MemSet/MemCopy/MmVirtualWrite
- [ ] OldProtect used (not a hardcoded constant) in all final NtProtect restore calls
- [ ] No em dash in any string literal
- [ ] All error paths traced - no NULL passed to `MemCopy`/`MemSet`/`MmVirtualWrite`
- [ ] All PE field accesses guarded by MZ signature check (`*(PWORD)Base == IMAGE_DOS_SIGNATURE`)
- [ ] `CHANGES.md` entry added
- [ ] `improvement-docs/00-index.md` status updated
- [ ] `CLAUDE.md` updated if a new pattern or constraint was introduced

**For `src/commands/` files specifically, also verify:**
- [ ] Every `MmHeapAlloc`/`LocalAlloc` result NULL-checked before `MemCopy`/field write
- [ ] No bare `return` inside a switch case — use `PackageAddInt32(Package, FALSE); break;` or `PackageTransmitError` + `break`
- [ ] Token handles from `TokenCurrentHandle()` closed on ALL exit paths (not just the success path)
- [ ] Every switch `case` that does not explicitly `return`/`goto` ends with `break;` — no fallthrough
- [ ] No pseudo-handle (`NtCurrentProcess()` = `(HANDLE)-1`) passed to `SysNtClose`
- [ ] No `PackageAddWString`/`PackageAddInt32` field written twice in a loop body (causes client parser misalignment)
- [ ] `PackageAddWString(Package, sesi10_username)` vs `PackageAddWString(Package, sesi10_cname)` — second per-session field must be the client name, not a duplicate of the username

**MinGW compat for Vista+/Win8.1+ types (Kali cross-compile may lack these):**
- `CIMTYPE` (from `wbemcli.h`): guard `CIMTYPE_DEFINED`, typedef `LONG`
- `SOCKADDR_INET` (from `ws2ipdef.h`): guard `SOCKADDR_INET_DEFINED`, union of `SOCKADDR_IN`/`SOCKADDR_IN6`/`ADDRESS_FAMILY`
- `MIB_IPNET_TABLE2`/`MIB_IPNET_ROW2`/`NL_NEIGHBOR_STATE` (from `netioapi.h`): guard `MIB_IPNET_TABLE2_DEFINED`
- `PSS_CAPTURE_FLAGS`/`HPSS` (from `processsnapshot.h`): guard `_PROCESSSNAPSHOT_H_`
- Function pointer typedefs: return type must match Win32 exactly — `CreateFileW` returns `HANDLE`, not `BOOL`

---

### qa-specialist

**Specialties:** Code review, cross-file consistency, wire protocol correctness, memory
safety, constraint enforcement, injection stability analysis

**Responsibilities:** Review implemented code for correctness, safety, and adherence to
documented constraints. Read-only — does not edit implementation files. Cross-verification
preferred: QA-A reviews developer-B output; QA-B reviews developer-A output.

Report findings as a numbered list with `PASS / FAIL / WARN` per item, file path, and
exact line number for every finding.

---

#### QA Checklist

Work through every applicable item. Mark each `PASS / FAIL / WARN / N/A`.

**Wire Format**
- [ ] `AddInt`/`AddString` call count in `builder.go:PatchConfig()` equals
  `ParserGetInt32`/`ParserGetString` call count in `Demon.c:DemonConfig()`
- [ ] Type sequence matches position-by-position (Int vs String at each slot)
- [ ] New fields appended at the END — no insertion in the middle of the sequence
- [ ] String fields use `AddString` (narrow); wide strings use `AddWString`/`ParserGetBytes`

**DJB2 Hashes**
- [ ] Every new `H_FUNC_*` constant in `Defines.h` was verified with `djb2_upper()`
- [ ] No two constants share the same value

**Memory Safety**
- [ ] `NT_SUCCESS` check present immediately after every `NtProtectVirtualMemory` call
  that is followed by `MemSet`, `MemCopy`, or `MmVirtualWrite`
- [ ] No write to memory when the preceding NtProtect failed (no fallthrough)
- [ ] No `PAGE_EXECUTE_READWRITE` (0x40) anywhere — search for `0x40`, `PAGE_RWX`,
  `PAGE_EXECUTE_READWRITE`
- [ ] Final NtProtect restore calls pass `OldProtect` (local variable), not a hardcoded
  constant such as `PAGE_EXECUTE_READ` (0x20) or `PAGE_READONLY` (0x02)
- [ ] Aliasing guard present: `BaseAddr`/`RegionSize` locals reset before second NtProtect call

**SEC_IMAGE VAD**
- [ ] Execute pages (`PAGE_EXECUTE_READ` original) patched with `PAGE_EXECUTE_WRITECOPY` (0x80)
- [ ] Non-execute pages (`PAGE_READONLY` original) may use `PAGE_READWRITE` (0x04)
- [ ] ntdll `.text` patching uses `SysNtProtectVirtualMemory` — NOT `Win32.NtProtectVirtualMemory`

**PE Stomping**
- [ ] `PeProtect_Init()` checks `IMAGE_DOS_SIGNATURE` at `ModuleBase` before reading backup
- [ ] If MZ absent, `Config.Implant.PeStomp` is force-set to `FALSE` and function returns
- [ ] `PeStomp` default is `false` in profile, builder default parse, and UI checkbox default
- [ ] `PeProtect_Stomp()`, `PeProtect_Restore()`, `PeProtect_Init()` each gate themselves
  internally — no external caller is the sole gate

**ntdll Unhooking**
- [ ] `DemonInit()` call order: `DemonConfig()` → `SysInitialize()` → `UnhookNtdll()`
- [ ] `SysInitialize()` ends with `return Instance->Syscall.SysAddress != NULL;` — no missing return (ISS-004)
- [ ] `UnhookNtdll()` suspends all non-current threads before `NtdllCopy`, resumes them after restore (ISS-001)
- [ ] Suspension loop uses `ThdSaved` flag: non-saved handles closed in loop body; saved handles closed only in resume loop (no double-close)
- [ ] `SuspCnt < 128` guard prevents array overflow; early-resume path fires when `NtProtect(WRITECOPY)` fails
- [ ] `UnhookNtdll()` uses `SysNtProtectVirtualMemory` for both protect calls
- [ ] ntdll `.text` overwrite uses `NtdllCopy` (static QWORD loop), not `MemCopy`
- [ ] `NtOpenSection` and `NtMapViewOfSection` resolved inline — not added to `Win32` table
- [ ] `UNICODE_STRING` initialised manually — `RtlInitUnicodeString` not called

**Optional Improvements**
- [ ] Optional features gate themselves inside their own module (not in callers)
- [ ] Core sleep path (DEFAULT/`SLEEPOBF_NO_OBF` case) calls `WaitForSingleObjectEx`
  directly when optional features are disabled — the path is always reachable

**Sleep Obfuscation / pe-sieve**
- [ ] New long-lived worker threads use `RtlUserThreadStart` as start address — not `NtTestAlert`
- [ ] APC ROP sleeping thread has 4-frame callstack:
  `[RSP+0]=NtTestAlert`, `[RSP+8]=BaseThreadInitThunk`, `[RSP+16]=RtlUserThreadStart`, `[RSP+24]=NULL`
- [ ] Foliage: `PAGE_NOACCESS` ROP step after encryption, `PAGE_READWRITE` step after wake
- [ ] `CfgAddressAdd(NULL, ...)` is NOT called for heap-allocated trampolines or any non-PE-backed memory.
  `CfgAddressAdd` dereferences `ImageBase` as `PIMAGE_DOS_HEADER` — `NULL->e_lfanew` crashes any
  CFG-enforced process during `DemonInit`. Cipher trampolines are called via `NtContinue`/jmp-gadget
  paths that do not go through CFG bitmap checks; no registration is needed (ISS-008).
- [ ] **ExecDelaySleep() wiring (HVC-046):** Any new injection function that calls `MmVirtualAlloc` or
  `MmVirtualProtect` followed by thread creation must also call `ExecDelaySleep()` in the same two-point
  pattern: once after allocation and once after protect-change/before execute. Verify that
  `ExecDelay == 0` (default) produces a pure no-op — no observable delay in injection timing.
  Config blob fields 25 (`ExecDelay`) and 26 (`ExecDelayJitter`) must appear AFTER `InjectSpoofOffset`
  in both `builder.go AddInt` sequence and `Demon.c ParserGetInt32` sequence.

**Module Hiding and PEB LDR Walk Safety**
- [ ] `HideModule()` advances PEB walk cursor (`Entry = Entry->Flink`) BEFORE the unlink
- [ ] All three LDR lists unlinked for hidden modules
- [ ] `HideModule()` called after `LdrModuleLoad()` and before `LdrFunctionAddr()` at both call sites
- [ ] `HideModule()` acquires `LoaderLock` before PEB LDR walk and releases at ALL exit points (ISS-002)
- [ ] All `LdrModulePeb`, `LdrModulePebByString`, `LdrModuleSearch` acquire `LoaderLock` before their walks (ISS-003)
- [ ] Acquire/release guarded with `if (pLdrLock)` / `if (pLdrUnlock)` — handles NULL Ntdll in early DemonInit
- [ ] `LdrModulePebByString`: `MmHeapAlloc` NULL-checked BEFORE lock acquire — prevents NULL-dest MemCopy + permanent lock-hold (ISS-003 addendum)
- [ ] Any new PEB LDR walk follows the same LoaderLock pattern with inline-resolved functions and balanced acquire/release

**AMSI / ETW**
- [ ] No byte sequence written over `AmsiScanBuffer`, `NtTraceEvent`, or any ETW/AMSI export
- [ ] No `NtProtectVirtualMemory` + `MemCopy` pattern for evasion patching
- [ ] AMSI/ETW suppression exclusively via `HwBpEngineAdd()` in `HwBpEngine.c`

**Parser Safety**
- [ ] Every length-prefixed buffer read checks that the embedded length fits within the remaining
  buffer BEFORE subtracting it from the length counter (UINT32 underflow wraps silently)
- [ ] No parser/deserialisation function returns NULL when its return value is passed directly
  to `MemCopy`, `MemSet`, or `MmVirtualWrite` - must return a static safe buffer with size=0
  on error instead
- [ ] The `EmptyBuf` static pattern (or equivalent) is used on all error paths in buffer-returning
  functions to eliminate the NULL-source MemCopy class of bugs without touching callers

**PE Header Access**
- [ ] Every call to `IMAGE_SIZE`, `IMAGE_NT_HEADER`, any direct `e_lfanew` dereference, or any
  section-header walk is preceded by `*(PWORD)Base == IMAGE_DOS_SIGNATURE` check
- [ ] The MZ check uses the cast form `*(PWORD)Base` (or `*(PWORD)ModuleBase`) and NOT a
  `PIMAGE_DOS_HEADER` cast that could itself fault on a non-PE pointer
- [ ] When the MZ check fails, size/offset/result is set to 0 and the function returns without
  accessing any further PE structure fields

**Coding Style and Output**
- [ ] No em dash (`—`, U+2014) in any `PRINTF`/`PUTS`/log string
- [ ] Debug output in Demon C uses `PRINTF`/`PUTS` macros only — no `printf()`
- [ ] Every new function has a comment explaining its purpose
- [ ] Uppercase Windows type names in Demon C (`PVOID`, `BOOL`, `DWORD`, etc.)
- [ ] No CRT functions in Demon C (`printf`, `malloc`, `free`, `memset`, `memcpy`)

**UI Label / Builder Key Consistency**
- [ ] `item->setText(0, "Label")` in `Payload.cc` exactly matches `b.config.Config["Label"]`
  in `builder.go` (same case, same spaces)
- [ ] YAOTL profile field name (e.g., `CoffeeVeh`) is distinct from the UI label
  (e.g., `"Coffee VEH"`) — both are correct for their respective paths

**Documentation**
- [ ] `CHANGES.md` has a new entry with status, files, root cause, and fix summary
- [ ] `improvement-docs/00-index.md` row shows `Applied` for implemented HVC/ISS items
- [ ] `CLAUDE.md` updated for any new constraint or pattern introduced

---

#### QA Report Format

```
## QA Report — <change name> — <date>

Diff reviewed: <files changed>

### Wire Format
- [PASS] Field count: builder.go 26 AddInt/AddString, Demon.c 26 ParserGetInt32/ParserGetString
- [PASS] Field order matches (verified lines 1229-1241 vs lines 767-792)

### Memory Safety
- [FAIL] PeProtect_Restore line 80: final NtProtect uses PAGE_EXECUTE_READ (0x20) hardcoded
         instead of OldProtect — protection incorrect after restore. Fix: use OldProtect.
- [PASS] NT_SUCCESS guard present before MemSet at line 58

### Summary
28 checks. 27 PASS, 1 FAIL, 0 WARN.
FAIL items require fixes before this change ships.
```

---

### code-tester

**Specialties:** Build verification, debug output analysis, protocol round-trip testing, Go
test authoring, injection scenario testing, regression validation

**Responsibilities:** Verify that implemented changes produce correct runtime behaviour. Plan
and execute build verification, debug output analysis, and regression checks. Write Go tests
where applicable. Report results with exact observed output and a `PASS / FAIL / REGRESSION`
verdict per scenario.

Does not modify implementation files. Only creates test files and runs read/build/test commands.

---

#### Build Verification — Required Before Any Test

```bash
# Teamserver — must exit 0
cd teamserver
go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go
echo "Go build exit: $?"

# Go tests — must all PASS
go test ./...

# Client — must produce no "error:" lines
cd client && mkdir -p Build && cd Build
cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | grep -i "error"
make -j4 2>&1 | grep -i "error:"
```

Clang IDE diagnostics in Demon C files (`'Demon.h' file not found`, `Unknown type name 'VOID'`,
etc.) are false positives. Only MinGW cross-compilation output matters.

---

#### Test Scenarios

##### PE Stomping — Shellcode Mode (ISS-037-shell)

**Goal:** Confirm that `PeStomp = true` does not crash a KaynLdr-injected agent.

**Setup:** Build a debug shellcode payload with `PeStomp = true`. Inject into a remote
process using the "shellcode inject" command from a live Demon.

**Expected debug output (injected Demon):**
```
PeProtect_Init: no PE header at ModuleBase - disabling PeStomp (shellcode mode)
```

**Pass criteria:**
- The log line above appears exactly once during `DemonInit`
- The injected agent completes its first sleep cycle — host process does not terminate
- The agent continues checking in on subsequent cycles

**Fail indicators:**
- Host process terminates within seconds of the agent registering
- "no PE header" log line is absent (MZ check not reached or compiled out)
- Teamserver shows the agent as dead after one check-in

**Regression:** A non-shellcode EXE/DLL agent with `PeStomp = true` must NOT produce
the "no PE header" log line and must produce stomp/restore log lines each sleep cycle.

---

##### PE Stomping — OldProtect Restoration (ISS-037-shell Fix 2)

**Goal:** Confirm that the PE header page is restored to its original protection after a
stomp/restore cycle — not permanently upgraded to `PAGE_EXECUTE_READ`.

**Setup:** Build a debug EXE with `PeStomp = true`. Run with `--debug-dev`.

**Verification:** Add temporary instrumentation (not committed) to log `OldProtect` at
the start of both `PeProtect_Stomp()` and `PeProtect_Restore()`. On a SEC_IMAGE-mapped EXE,
the first NtProtect call in each function should save `0x00000002` (`PAGE_READONLY`).

**Pass:** OldProtect in Restore equals OldProtect saved in Stomp. Final protection after
restore = `PAGE_READONLY`, not `PAGE_EXECUTE_READ`.

**Fail:** Agent crashes on the first sleep. Or protection after restore is `0x20`.

---

##### ntdll Unhooking (HVC-031 Sub-4)

**Goal:** Confirm successful unhooking and that the agent connects normally.

**Expected debug output sequence:**
```
UnhookNtdll: .text CleanText=<addr>  LoadedText=<addr>  TextSize=<N>
UnhookNtdll: NtProtect(RW) status=0x00000000  OldProt=0x00000020
UnhookNtdll: NtdllCopy complete - <N> bytes written
UnhookNtdll: NtProtect(restore) status=0x00000000  RestoredProt=0x00000020
UnhookNtdll: clean view unmapped - returning 1
Successfully unhooked ntdll.dll
```

**Key values:**
- Both NtProtect statuses = `0x00000000` (STATUS_SUCCESS)
- `OldProt=0x00000020` = `PAGE_EXECUTE_READ` — confirms original protection read correctly
- `NtdllCopy complete` appears with non-zero byte count
- Agent connects to teamserver after unhooking

**Fail:** Any NtProtect status non-zero. Missing `NtdllCopy complete`. Agent crash before
first sleep.

**Regression:** `UnhookNtdll = false` must produce no ntdll log lines; agent must function
normally (unhooking is opt-in).

---

##### Sleep = 0 Regression (ISS-037-R1)

**Goal:** Confirm that default settings (PeStomp=false, StackSpoof=false, no sleep obf)
do not cause an effective sleep interval of 0.

**Setup:** Run any default-config agent (sleep=10, all optionals off).

**Pass:** Agent checks in approximately every 10 seconds. Teamserver log shows regular
intervals.

**Fail:** Agent floods the teamserver with rapid sequential check-ins (visible as dozens
per second) — indicates `WaitForSingleObjectEx` is not being called.

---

##### Config Blob Alignment — Smoke Test

**Goal:** Confirm all config fields are parsed at the correct positions.

**Setup:** Build an agent with all optional features enabled and non-default values
(Sleep=15, Jitter=5, RandGadget=true, UnhookNtdll=true, HideModules=true, PeStomp=true,
Verbose=true, CoffeeVeh=true, CoffeeThreaded=true, IndirectSyscall=true).

**Pass:** Each feature produces its corresponding debug log. Sleep interval is ~15s. No
feature appears silently misconfigured.

**Fail:** A feature set to `true` produces no output and has no effect — indicates a wire
format misalignment where its field was parsed as a different feature's slot.

---

##### Module Hiding — Stability (HVC-031 Sub-2)

**Goal:** Confirm that `HideModules = true` does not crash after dynamic module load.

**Setup:** Build with `HideModules = true`. Execute a command that triggers `LdrModuleLoad`
(e.g., loading a module for thread-start-address or spoof-address resolution).

**Pass:** Library loads; agent continues operating normally. No crash.

**Fail:** Host process terminates after `LdrModuleLoad`. PEB walk produces an AV.

---

#### General Regression Checklist

After any change to `PeProtect.c`, `Obf.c`, `Demon.c`, `builder.go`, or `Payload.cc`:

- [ ] Default-config agent (all options at defaults) connects and operates normally
- [ ] Agent completes first sleep cycle without host process crash
- [ ] Agent checks in at the configured interval (not at sleep=0)
- [ ] Teamserver correctly displays the agent's metadata after registration
- [ ] No Go panic or fatal log in teamserver output
- [ ] `go build` exits 0
- [ ] `go test ./...` all pass
- [ ] Client `cmake` + `make` produce no errors

---

#### Go Test Pattern

New Go tests follow the pattern in `teamserver/pkg/profile/yaotl/specsuite/`. Test files
live alongside the package they test. Run with:

```bash
cd teamserver && go test ./pkg/profile/yaotl/...
```

---

#### Test Report Format

```
## Test Report — <change name> — <date>

### Build
- [PASS] go build: exit 0
- [PASS] go test ./...: all pass
- [PASS] client cmake+make: no errors

### Scenarios
- [PASS] PE Stomp shellcode: "no PE header" log seen; agent survived 5 sleep cycles
- [FAIL] Sleep=0 regression: agent flooded teamserver at ~300 check-ins/sec
         Expected: ~1 check-in/10s. Observed: continuous rapid check-ins.
- [PASS] ntdll unhook: OldProt=0x20 on both calls; NtdllCopy complete 1486764 bytes

### Verdict
8 scenarios. 7 PASS, 1 FAIL.
```

---

### pe-sieve-analyst

**Specialties:** Pe-sieve output interpretation, Windows VAD tree, thread callstack forensics,
entropy analysis, memory protection flags, pe-sieve indicator taxonomy

**Responsibilities:** Analyse pe-sieve scan reports (`scan_report.json`, `dump_report.json`)
against Demon debug logs and source code. Map each detection indicator to the specific
function and line responsible. Produce structured findings in `improvement-docs/` format and
propose code-level fixes.

**Hard constraints:** Read-only analysis. Does not edit implementation files. All findings
written to `improvement-docs/` — never to root-level markdown or memory files.

**Indicator taxonomy:**

| Pe-sieve indicator | Root cause | Actionable? |
|--------------------|-----------|-------------|
| `malformed_header` | PE header zeroed by PeStomp (Sub-2) | No — by design |
| `SUS_CALLSTACK_CORRUPT` | APC ROP chain has 1-frame callstack; `[RSP]` is not a plausible frame | Yes — write `BaseThreadInitThunk/RtlUserThreadStart/NULL` above RSP |
| `SUS_CALLS_INTEGRITY` | Same root cause as `SUS_CALLSTACK_CORRUPT` in some pe-sieve versions | Yes — same fix |
| `SUS_START` | Thread start address is `NtTestAlert` or other syscall stub | Yes — use `RtlUserThreadStart` |
| `implanted_shc` | `PAGE_EXECUTE*` region with ~8.0 entropy (RC4-encrypted image region readable) | Yes — `PAGE_NOACCESS` after encryption |
| VAD split detection | MinGW `EXECUTE|WRITE` section maps as separate `PAGE_EXECUTE_WRITECOPY` VAD entry | Yes — protect the split region separately |

---

### edr-detection-analyst

**Specialties:** EDR telemetry, ETW providers, kernel callbacks, API hooking, memory scanning,
callstack spoof evaluation, process injection detection

**Responsibilities:** Map Demon techniques to known EDR detection primitives. Identify which
ETW providers and kernel callbacks trigger on each technique. Propose evasion improvements in
`improvement-docs/` format.

**Hard constraints:** Read-only analysis. Does not edit implementation files. Proposals go to
`improvement-docs/` — not to root-level markdown or memory files. Never propose byte-patching
AMSI/ETW — all suppression via `HwBpEngine`.

---

## Workflow

```
Phase 1 (parallel): red-team-developer agents implement changes across components.
Phase 2 (parallel): qa-specialist agents cross-verify (QA-A reviews developer-B output).
Phase 3:            Main agent collects QA findings and resolves FAIL items.
Phase 4:            code-tester runs build verification + all test scenarios.
Phase 5:            Main agent reviews the complete, tested implementation.
```

**Cross-verification pairing:**
- `qa-A` reviews `red-team-developer-B` output
- `qa-B` reviews `red-team-developer-A` output

---

## Improvement Tracking

All improvement proposals are in `improvement-docs/`. See `improvement-docs/00-index.md`
for the master index and status. When an improvement is implemented:

1. Update the spec file status to `Applied`
2. Add a `CHANGES.md` entry with root cause, fix summary, and affected files
3. Update `improvement-docs/00-index.md` status column
4. Update `CLAUDE.md` if a new constraint or pattern was introduced
