# HVC-032 New Commands Code QA Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Audit and fix all correctness, safety, and wire-format issues in the 5 new HVC-032 command files (Command_Lateral.c, Command_Persist.c, Command_Creds.c, Command_Privesc.c, Command_Netinfo.c) and their Go/C++ dispatch counterparts.

**Architecture:** Read each C file and its matching Go TaskPrepare/TaskDispatch block, verify wire layout field-by-field, then apply each fix directly. No automated test harness exists for agent C code; correctness is verified by code reading and cross-referencing Go parser calls against C PackageAdd calls.

**Tech Stack:** C (MinGW/MSVC target), Go 1.21, Qt5 C++ (client); `go build` is the only mechanically runnable check.

---

## File Map

| File | Role | Issues |
|------|------|--------|
| `payloads/Demon/src/commands/Command_Persist.c` | Persistence handlers | 5 bugs (Bug A-E) |
| `payloads/Demon/src/commands/Command_Lateral.c` | Lateral movement handlers | Already fixed (2 bugs fixed in prior session) |
| `payloads/Demon/src/commands/Command_Creds.c` | Credential access | Verified correct |
| `payloads/Demon/src/commands/Command_Privesc.c` | Privilege escalation | Verified correct |
| `payloads/Demon/src/commands/Command_Netinfo.c` | Network discovery | Verified correct |
| `teamserver/pkg/agent/demons.go` | Go TaskPrepare + TaskDispatch | Verified correct |
| `client/src/Havoc/Demon/CommandSend.cc` | C++ send helpers | Verified correct |
| `client/src/Havoc/Demon/ConsoleInput.cc` | C++ command parsing | Verified correct |

---

## Task 1: Fix `persist remove reg` wire format over-read (Bug A)

**Files:**
- Modify: `payloads/Demon/src/commands/Command_Persist.c:287-299`

**Problem:** `DEMON_PERSIST_REMOVE_REG` reads a `Hive` int32 from the parser (line 289), but
Go's TaskPrepare for `persist remove` sends only `[PERSIST_REMOVE, RemoveType, Name(wstring)]` —
no Hive field. The parser reads 0 from an empty buffer, which maps to HKCU. The key is never
removed from HKLM even if intended. More importantly, reading past end of packet is undefined
behaviour in the parser.

**Fix:** Remove the `Hive` field read and hardcode `HKEY_CURRENT_USER`. The client has no
`/system` flag for `persist remove`, so HKLM removal is not supported at the UI level anyway.

- [ ] **Step 1: Read the REMOVE_REG block to confirm the exact lines**

```bash
sed -n '280,325p' payloads/Demon/src/commands/Command_Persist.c
```

Expected: lines 287-300 show `case DEMON_PERSIST_REMOVE_REG:` with `INT32 Hive = ParserGetInt32( DataArgs );` at line 289 and `HKEY RootKey = ( Hive == 1 ) ? ... : ...;` at line 290.

- [ ] **Step 2: Apply the fix**

In `payloads/Demon/src/commands/Command_Persist.c`, replace:

```c
                case DEMON_PERSIST_REMOVE_REG: PUTS( "Persist::Remove::Reg" )
                {
                    INT32   Hive    = ParserGetInt32( DataArgs );
                    HKEY    RootKey = ( Hive == 1 ) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
                    HKEY    hKey    = NULL;
                    LONG    Res     = 0;
```

with:

```c
                case DEMON_PERSIST_REMOVE_REG: PUTS( "Persist::Remove::Reg" )
                {
                    /* Hive is not sent by the teamserver for remove-reg; always HKCU.
                     * HKLM removal is not supported at the UI level (no /system flag). */
                    HKEY    RootKey = HKEY_CURRENT_USER;
                    HKEY    hKey    = NULL;
                    LONG    Res     = 0;
```

- [ ] **Step 3: Verify the Go remove packet layout matches**

```bash
sed -n '2462,2485p' teamserver/pkg/agent/demons.go
```

Confirm: `job.Data = []interface{}{ DEMON_PERSIST_REMOVE, RemoveType, common.EncodeUTF16(Name) }` —
3 fields, no Hive. C now reads exactly: SubCommand + RemoveType + Name. Match. ✓

- [ ] **Step 4: Commit**

```bash
git add payloads/Demon/src/commands/Command_Persist.c
git commit -m "fix(persist): remove Hive over-read in PERSIST_REMOVE_REG - hardcode HKCU

Go TaskPrepare sends [PERSIST_REMOVE, RemoveType, Name] with no Hive field.
The C parser was reading a 4th int32 that does not exist in the packet.
HKCU is the only supported target for persist remove (no /system flag in UI).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 2: Add NULL guards for `ParserGetWString` results in `Command_Persist.c` (Bugs B-E)

**Files:**
- Modify: `payloads/Demon/src/commands/Command_Persist.c` (4 locations)

**Problem:** `ParserGetWString` may return NULL when the parser buffer has insufficient data.
All four persist sub-commands (reg, schtask, com, remove) use the returned pointers in
`StringLengthW`, `StringConcatW`, or Win32 registry calls without a NULL check. A NULL
dereference in `StringLengthW(NULL)` causes an immediate access violation.

Per CLAUDE.md: "All Demon code changes must prioritise runtime stability over feature
completeness. Before reporting a task complete: trace every error path and confirm no NULL
pointer is passed to MemCopy/MemSet/MmVirtualWrite." The same principle applies to string
functions.

- [ ] **Step 1: Confirm Bug B — DEMON_PERSIST_REG has no NULL guard on Name/Value**

```bash
sed -n '83,130p' payloads/Demon/src/commands/Command_Persist.c
```

Confirm: `Name` and `Value` from `ParserGetWString` at lines 87-88 have no NULL guard before
`StringLengthW( Value )` at line 115.

- [ ] **Step 2: Fix Bug B — add NULL guard after Name/Value parse in DEMON_PERSIST_REG**

In `payloads/Demon/src/commands/Command_Persist.c`, after:
```c
            PWCHAR  Name     = ParserGetWString( DataArgs, &NameLen );
            PWCHAR  Value    = ParserGetWString( DataArgs, &ValLen );
            INT32   Hive     = ParserGetInt32( DataArgs );
```
add:
```c
            if ( !Name || NameLen == 0 || !Value || ValLen == 0 ) {
                PUTS( "Persist::Reg - missing Name or Value" )
                PackageAddInt32( Package, FALSE );
                break;
            }
```

- [ ] **Step 3: Confirm Bug C — DEMON_PERSIST_SCHTASK has no NULL guard on TaskName/Command/Trigger**

```bash
sed -n '138,170p' payloads/Demon/src/commands/Command_Persist.c
```

Confirm: `TaskName`, `Command`, `Trigger` from `ParserGetWString` at lines 143-145 have no
NULL guard before `StringLengthW( Trigger )` at line 168.

- [ ] **Step 4: Fix Bug C — add NULL guard after TaskName/Command/Trigger parse in DEMON_PERSIST_SCHTASK**

After:
```c
            PWCHAR TaskName    = ParserGetWString( DataArgs, &TaskNameLen );
            PWCHAR Command     = ParserGetWString( DataArgs, &CmdLen );
            PWCHAR Trigger     = ParserGetWString( DataArgs, &TrigLen );
```
add:
```c
            if ( !TaskName || TaskNameLen == 0 || !Command || CmdLen == 0 || !Trigger || TrigLen == 0 ) {
                PUTS( "Persist::SchTask - missing required field" )
                PackageAddInt32( Package, FALSE );
                break;
            }
```

- [ ] **Step 5: Confirm Bug D — DEMON_PERSIST_COM has no NULL guard on ClsidStr/DllPath**

```bash
sed -n '218,260p' payloads/Demon/src/commands/Command_Persist.c
```

Confirm: `ClsidStr` and `DllPath` from `ParserGetWString` at lines 222-223 have no NULL guard
before `StringConcatW( KeyPath, ClsidStr )` at line 239.

- [ ] **Step 6: Fix Bug D — add NULL guard after ClsidStr/DllPath parse in DEMON_PERSIST_COM**

After:
```c
            PWCHAR ClsidStr   = ParserGetWString( DataArgs, &ClsidLen );
            PWCHAR DllPath    = ParserGetWString( DataArgs, &DllPathLen );
```
add:
```c
            if ( !ClsidStr || ClsidLen == 0 || !DllPath || DllPathLen == 0 ) {
                PUTS( "Persist::Com - missing CLSID or DllPath" )
                PackageAddInt32( Package, FALSE );
                break;
            }
```

- [ ] **Step 7: Confirm Bug E — DEMON_PERSIST_REMOVE has no NULL guard on Name**

```bash
sed -n '278,300p' payloads/Demon/src/commands/Command_Persist.c
```

Confirm: `Name` from `ParserGetWString` at line 282 has no NULL guard. `Name` is then passed
directly to `RegDeleteValueW(hKey, Name)` (line 312), `StringConcatW(CmdBuf, Name)` (line 345),
and `StringConcatW(KeyPath, Name)` (line 373).

- [ ] **Step 8: Fix Bug E — add NULL guard after Name parse in DEMON_PERSIST_REMOVE**

After:
```c
            INT32  RemoveType = ParserGetInt32( DataArgs );
            UINT32 NameLen    = 0;
            PWCHAR Name       = ParserGetWString( DataArgs, &NameLen );
```
add:
```c
            if ( !Name || NameLen == 0 ) {
                PUTS( "Persist::Remove - missing Name" )
                PackageAddInt32( Package, FALSE );
                break;
            }
```

- [ ] **Step 9: Verify all 4 guards are in place**

```bash
grep -n "missing Name\|missing required\|missing CLSID\|missing.*Value" payloads/Demon/src/commands/Command_Persist.c
```

Expected: 4 lines matching, one in each sub-case.

- [ ] **Step 10: Commit**

```bash
git add payloads/Demon/src/commands/Command_Persist.c
git commit -m "fix(persist): add NULL guards for ParserGetWString results

ParserGetWString may return NULL on malformed parser data. Without guards,
StringLengthW(NULL) / StringConcatW(buf, NULL) cause an access violation.
Added NULL checks in all four DEMON_PERSIST_* sub-cases: reg, schtask, com, remove.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 3: Verify `Command_Lateral.c` DCOM fixes are complete and correct

**Files:**
- Read: `payloads/Demon/src/commands/Command_Lateral.c` (lines 460-582)

These fixes were applied earlier in the session. This task confirms they are correct before
the final build check.

- [ ] **Step 1: Verify Fix 1 — guard failure early return sends 2 int32s**

```bash
sed -n '462,472p' payloads/Demon/src/commands/Command_Lateral.c
```

Expected output (both `PackageAddInt32` lines present):
```c
    if ( !Instance->Win32.CoInitializeEx    ||
         !Instance->Win32.CoCreateInstanceEx ||
         !Instance->Win32.CoUninitialize    )
    {
        PUTS( "LateralDcomExec - COM pointers not resolved" )
        PackageAddInt32( Package, 0 );  /* Success */
        PackageAddInt32( Package, 0 );  /* PID (none for DCOM) */
        return;
    }
```

- [ ] **Step 2: Verify Fix 2 — CoInitializeEx failure early return sends 2 int32s**

```bash
sed -n '473,482p' payloads/Demon/src/commands/Command_Lateral.c
```

Expected: two `PackageAddInt32( Package, 0 )` lines before `return`.

- [ ] **Step 3: Verify Fix 3 — Mqi.pItf released on partial CoCreateInstanceEx failure**

```bash
sed -n '509,518p' payloads/Demon/src/commands/Command_Lateral.c
```

Expected: `if ( Mqi.pItf ) { ComRelease( &Mqi.pItf ); }` before `goto DCOM_OUT`.

- [ ] **Step 4: Verify Fix 4 — bottom of LateralDcomExec sends 2 int32s**

```bash
sed -n '578,584p' payloads/Demon/src/commands/Command_Lateral.c
```

Expected:
```c
    PackageAddInt32( Package, (UINT32) Success );
    PackageAddInt32( Package, 0 );   /* PID - DCOM does not return a remote PID */
```

- [ ] **Step 5: Cross-check with Go TaskDispatch expectations**

```bash
sed -n '6910,6945p' teamserver/pkg/agent/demons.go
```

Confirm Go reads: `SubCommand` then `CanIRead(ReadInt32, ReadInt32)` → `Success + PID`. All
4 C exit paths now send both ints. ✓

---

## Task 4: Verify `Command_Creds.c` resource cleanup on all paths

**Files:**
- Read: `payloads/Demon/src/commands/Command_Creds.c` (lines 59-276)

- [ ] **Step 1: Trace all LSASS exits — confirm hLsass closed on every path**

```bash
grep -n "goto LSASS_CLEANUP\|SysNtClose.*hLsass\|break;" payloads/Demon/src/commands/Command_Creds.c | head -20
```

Confirm: `hLsass` is only opened at one point (ProcessOpen). Every `goto LSASS_CLEANUP` path
reaches the cleanup block at `LSASS_CLEANUP:` which closes hLsass when non-NULL. Direct `break`
paths (lines 85, 125, 135) occur before `hLsass` is opened, so it is NULL and no close needed. ✓

- [ ] **Step 2: Trace hFile closure — confirm closed on all paths that open it**

```bash
grep -n "hFile\|LSASS_CLEANUP" payloads/Demon/src/commands/Command_Creds.c
```

Confirm: hFile is set to NULL immediately after a CreateFileW failure (so LSASS_CLEANUP
`if ( hFile && hFile != INVALID_HANDLE_VALUE )` skips it). Success and MiniDumpWriteDump
failure paths both fall through to LSASS_CLEANUP which closes hFile. ✓

- [ ] **Step 3: Verify Snapshot freed only when PssCaptureSnapshot succeeded**

```bash
sed -n '256,275p' payloads/Demon/src/commands/Command_Creds.c
```

Confirm: `if ( UsedPss && Instance->Win32.PssFreeSnapshot )` gates the `PssFreeSnapshot`
call. `UsedPss` is only `TRUE` when `PssCaptureSnapshot` returned `ERROR_SUCCESS`. ✓

- [ ] **Step 4: Verify SAM hive handles all closed**

```bash
grep -n "hKey\|RegCloseKey\|hKey = NULL" payloads/Demon/src/commands/Command_Creds.c
```

Confirm: each of the three SAM hive blocks (SAM, SECURITY, SYSTEM) closes `hKey` immediately
after `RegSaveKeyExW` and resets to NULL before the next block. ✓

- [ ] **Step 5: Cross-check SAM wire format with Go**

```bash
sed -n '7007,7035p' teamserver/pkg/agent/demons.go
```

C sends (SAM): `SubCommand(int32) + SamPath(wstring) + SecPath(wstring) + SysPath(wstring) + Success(int32)`
Go reads: `CanIRead(ReadBytes, ReadBytes, ReadBytes, ReadInt32)` → parse 3 paths + 1 success.

Confirm C PackageAddWString is called for each of the three paths at lines 326, 355, 383,
with fallback `PackageAddWString(Package, L"")` on failure. ✓

---

## Task 5: Verify `Command_Privesc.c` wire format and handle cleanup

**Files:**
- Read: `payloads/Demon/src/commands/Command_Privesc.c` (full)

- [ ] **Step 1: Verify UAC response wire format**

```bash
grep -n "PackageAddInt32" payloads/Demon/src/commands/Command_Privesc.c
```

Expected order for PRIVESC_UAC: `SubCommand(echo) + Method(int32) + Success(int32)`.

Go reads (line 7054): `CanIRead(ReadInt32, ReadInt32)` → `UacMethod + Success`. Match. ✓

- [ ] **Step 2: Verify default method case still emits Success**

```bash
sed -n '218,228p' payloads/Demon/src/commands/Command_Privesc.c
```

Confirm: the `default:` inner switch case falls through to line 226
`PackageAddInt32( Package, Ok ? TRUE : FALSE )` with `Ok = FALSE`. Response is
`SubCommand + Method + FALSE`. Go reads `UacMethod + Success` = `Method + 0`. ✓

- [ ] **Step 3: Verify hEvt and hKey closed on all paths**

```bash
grep -n "hEvt\|hKey\|SysNtClose\|RegCloseKey" payloads/Demon/src/commands/Command_Privesc.c
```

Confirm: `SysNtClose( hEvt )` at line 140, hKey at line 107. Both reset to NULL. The
`RegDeleteTreeW` cleanup at line 146-148 runs unconditionally regardless of ShellExecuteW
result. ✓

- [ ] **Step 4: Confirm no path leaves key dirty if functions are missing**

```bash
sed -n '58,67p' payloads/Demon/src/commands/Command_Privesc.c
```

Confirm: `UacBypassViaRegistry` returns FALSE immediately (before writing any registry key)
when required function pointers are missing. No cleanup needed. ✓

---

## Task 6: Verify `Command_Netinfo.c` buffer management and sentinel format

**Files:**
- Read: `payloads/Demon/src/commands/Command_Netinfo.c` (full)

- [ ] **Step 1: Confirm AdapBuf freed on all paths**

```bash
grep -n "AdapBuf\|MmHeapFree" payloads/Demon/src/commands/Command_Netinfo.c
```

Confirm: `MmHeapFree(AdapBuf)` is called on the resize-failure path (line 83-91), on the
`GetAdaptersInfo` failure path (line 97-103), and on the success path (line 135). ✓

- [ ] **Step 2: Confirm Table freed on all ARP paths**

```bash
grep -n "Table\|FreeMibTable" payloads/Demon/src/commands/Command_Netinfo.c
```

Confirm: `FreeMibTable(Table)` at line 213 after the iteration loop. Early failures (lines
152-167) do not open a Table (Table stays NULL, FreeMibTable not called). ✓

- [ ] **Step 3: Verify ADAPTERS sentinel consistency with Go parser**

The C sentinel is `PackageAddInt32( Package, 0 )` (line 133) — 4 bytes `\x00\x00\x00\x00`.
Go parses adapters in a `for CanIRead(ReadBytes)` loop. `ReadBytes` checks for a 4-byte
length prefix. The sentinel's 4 bytes are read as length=0, data="". `ParseString()` returns
"". Name=="" → break. The sentinel bytes are consumed by the loop, not by the post-loop
`if CanIRead(ReadInt32) { ParseInt32() }` (which safely no-ops when empty). ✓

- [ ] **Step 4: Verify ARP sentinel consistency with Go parser**

```bash
sed -n '170,215p' payloads/Demon/src/commands/Command_Netinfo.c
```

C sentinel for ARP: `PackageAddInt32( Package, 0 )` (line 211) — plain int32(0).
Go ARP loop reads `CanIRead(ReadInt32)` → `IfIdx = ParseInt32()`. Sentinel is IfIdx=0 → break. ✓

---

## Task 7: Verify ConsoleInput.cc and CommandSend.cc field names match Go Optional map keys

**Files:**
- Read: `client/src/Havoc/Demon/CommandSend.cc:400-481`
- Read: `teamserver/pkg/agent/demons.go:2352-2570`

- [ ] **Step 1: Check Lateral field names**

Go TaskPrepare reads: `Optional["SubCommand"]`, `Optional["Target"]`, `Optional["Cmd"]`,
`Optional["Method"]`.

CommandSend.cc Lateral() sends: `"SubCommand"=Sub`, `"Target"=Target`, `"Cmd"=Cmd`, `"Method"=Method`.

```bash
grep -A15 "CommandExecute::Lateral" client/src/Havoc/Demon/CommandSend.cc | head -18
```

Confirm all 4 keys present and spelled identically. ✓

- [ ] **Step 2: Check Persist field names**

Go reads: `Optional["SubCommand"]`, then for each sub: `Optional["Name"]`, `Optional["Value"]`,
`Optional["Hive"]` (reg); `Optional["TaskName"]`, `Optional["Cmd"]`, `Optional["Trigger"]`
(schtask); `Optional["CLSID"]`, `Optional["DllPath"]` (com); `Optional["RemoveType"]`,
`Optional["Name"]` (remove).

ConsoleInput.cc sets: `Params["Name"]`, `Params["Value"]`, `Params["Hive"]`;
`Params["TaskName"]`, `Params["Cmd"]`, `Params["Trigger"]`; `Params["CLSID"]`,
`Params["DllPath"]`; `Params["RemoveType"]`, `Params["Name"]`.

CommandSend.cc Persist() copies all Params into Info map directly via the `for` loop.

```bash
grep -n "Params\[" client/src/Havoc/Demon/ConsoleInput.cc | grep -A1 "persist"
```

Confirm every key in ConsoleInput.cc Params matches the exact string Go reads from Optional. ✓

- [ ] **Step 3: Check Creds field names**

Go reads: `Optional["SubCommand"]`, `Optional["Filename"]`.
CommandSend.cc Creds() sends: `"SubCommand"=Sub`, `"Filename"=Filename`.

```bash
grep -A12 "CommandExecute::Creds" client/src/Havoc/Demon/CommandSend.cc | head -14
```

Confirm. ✓

- [ ] **Step 4: Check Privesc field names**

Go reads: `Optional["SubCommand"]`, `Optional["Method"]`, `Optional["Cmd"]`.
CommandSend.cc Privesc() sends: `"SubCommand"=Sub`, `"Method"=Method`, `"Cmd"=Cmd`.

```bash
grep -A12 "CommandExecute::Privesc" client/src/Havoc/Demon/CommandSend.cc | head -14
```

Confirm. ✓

- [ ] **Step 5: Check Netinfo field names**

Go reads: `Optional["SubCommand"]`.
CommandSend.cc Netinfo() sends: `"SubCommand"=Sub`.

```bash
grep -A10 "CommandExecute::Netinfo" client/src/Havoc/Demon/CommandSend.cc | head -12
```

Confirm. ✓

---

## Task 8: Go build verification

**Files:**
- Read: `teamserver/pkg/agent/demons.go` (already modified)

- [ ] **Step 1: Build the agent package**

```bash
cd /Users/kr0ff/Desktop/git/Havoc/teamserver && go build ./pkg/agent/...
```

Expected: exits 0, no output.

- [ ] **Step 2: Check for vet warnings introduced by HVC-032**

```bash
cd /Users/kr0ff/Desktop/git/Havoc/teamserver && go vet ./pkg/agent/... 2>&1 | grep -v "self-assignment"
```

Expected: empty output. The pre-existing `self-assignment` warnings on `a.Info.FirstCallIn`
and `a.Info.LastCallIn` (upstream code, not HVC-032) are excluded by the grep. If anything
else appears, it is a new issue to fix.

- [ ] **Step 3: Build the full teamserver**

```bash
cd /Users/kr0ff/Desktop/git/Havoc/teamserver && go build -o /dev/null main.go
```

Expected: exits 0.

---

## Task 9: CMakeLists.txt audit

**Files:**
- Read: `payloads/Demon/CMakeLists.txt`

- [ ] **Step 1: Verify all 5 new command files are listed**

```bash
grep -n "Command_Lateral\|Command_Persist\|Command_Creds\|Command_Privesc\|Command_Netinfo" payloads/Demon/CMakeLists.txt
```

Expected: 5 lines, one per file.

- [ ] **Step 2: Verify all 6 split files are listed**

```bash
grep -n "Command_FS\|Command_Proc\|Command_Token\|Command_Inject\|Command_Net\|Command_Config" payloads/Demon/CMakeLists.txt
```

Expected: 6 lines.

- [ ] **Step 3: Verify Command.c itself is still listed (thin dispatcher must be compiled)**

```bash
grep -n "src/core/Command.c" payloads/Demon/CMakeLists.txt
```

Expected: 1 line.

---

## Task 10: Final commit with QA summary

- [ ] **Step 1: Confirm all fixes are staged**

```bash
git status payloads/Demon/src/commands/Command_Persist.c payloads/Demon/src/commands/Command_Lateral.c
```

Expected: both files modified (already committed in Tasks 1-2 above, so should be clean here).

- [ ] **Step 2: Update improvement-docs/00-index.md status if needed**

```bash
grep "HVC-032" improvement-docs/00-index.md
```

Confirm status is `Applied`. If not:
```bash
# Edit improvement-docs/00-index.md to set HVC-032 status to Applied
```

---

## Self-Review

**Spec coverage:**
- Bug A (persist remove Hive over-read): Task 1 ✓
- Bug B (persist reg NULL guards): Task 2 ✓
- Bug C (persist schtask NULL guards): Task 2 ✓
- Bug D (persist com NULL guards): Task 2 ✓
- Bug E (persist remove NULL guards): Task 2 ✓
- DCOM fix verification: Task 3 ✓
- Creds resource audit: Task 4 ✓
- Privesc audit: Task 5 ✓
- Netinfo audit: Task 6 ✓
- Client field name audit: Task 7 ✓
- Go build: Task 8 ✓
- CMakeLists: Task 9 ✓

**Placeholder scan:** No TBD, no "handle edge cases", no "similar to Task N". Every step has exact code or exact commands. ✓

**Type consistency:** All type names, function names, and field names match the actual code. ✓
