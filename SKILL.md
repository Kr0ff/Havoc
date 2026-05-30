# SKILL.md — Havoc C2 Framework Skill Definitions

This file defines invocable skills (standard operating procedures) for the three specialist
agent roles defined in `AGENTS.md`. Each skill is a named, step-by-step procedure that an
agent invokes when it encounters a specific type of task. Skills encode proven patterns and
hard lessons from this codebase — they exist because the right approach is non-obvious.

**How to invoke:** Reference the skill name when assigning work to an agent. The agent reads
the relevant skill section and follows it exactly before writing any code or analysis.

All skills operate under the constraints in `CLAUDE.md` and `AGENTS.md`. When a skill step
contradicts those documents, the constraint in `CLAUDE.md` wins.

---

## Skills for: red-team-developer

---

### skill: implement-demon-feature

**When to invoke:** Starting any new feature, evasion improvement, or subsystem change in
the Demon C agent (`payloads/Demon/`).

#### Procedure

**Step 1 — Read before writing**
1. Read `Demon.md` in full. If the feature involves the teamserver wire protocol or builder,
   also read `Teamserver.md`.
2. Read the relevant improvement spec in `improvement-docs/` (or issue doc in
   `improvement-docs/issue-docs/`). Understand the exact problem and acceptance criteria.
3. Read `CHANGES.md` entries for the three most recent applied changes in the same subsystem.
   Understand what was already tried, what patterns were established, and what failures occurred.
4. Read the files that will be modified. Do not rely on the improvement spec's code snippets
   alone — read the actual current file state.

**Step 2 — Identify existing patterns to reuse**
1. Before writing any new function, search for existing functions that do the same thing:
   - API resolution: `LdrModuleLoad`, `LdrFunctionAddr`, `HashStringA`
   - Memory: `MemSet`, `MemCopy`, `MmVirtualAlloc`, `MmVirtualWrite`
   - Syscalls: `SysNtProtectVirtualMemory`, `SysNtSuspendThread`, etc.
   - Debug output: `PRINTF(...)`, `PUTS(...)`
2. Reuse exact patterns. Do not reimpliment what already exists.

**Step 3 — Validate any new DJB2 hash constants**
For every new `H_FUNC_*` constant added to `Defines.h`, run before writing the constant:
```python
def djb2_upper(s):
    h = 5381
    for c in s.upper():
        h = (((h << 5) + h) + ord(c)) & 0xFFFFFFFF
    return h
print(hex(djb2_upper("FunctionName")))
```
Do not commit the constant until the script output matches it exactly.
**Wrong hash = silent NULL from `LdrFunctionAddr` = complete silent no-op at runtime.**

**Step 4 — Write the implementation**
Follow the coding style rules from `AGENTS.md § Coding Style`:
- `PVOID Var = { 0 };` declarations, `PRINTF`/`PUTS` macros, uppercase types, spaces around operators
- Every new function gets one brief header comment — its purpose and key parameters
- One inline comment per non-obvious logic block (the WHY, not the WHAT)
- No em dash (`—`) anywhere in string literals or log messages — use hyphen (`-`) only

Apply the memory safety pattern without exception:
```c
/* 1. Protect */
Status = Instance->Win32.NtProtectVirtualMemory(
    NtCurrentProcess(), &BaseAddr, &Size, PAGE_READWRITE, &OldProtect );
if ( ! NT_SUCCESS( Status ) ) {          /* 2. Guard */
    PRINTF( "Name: NtProtect failed 0x%X\n", Status )
    return;
}
/* 3. Write */
MemSet( BaseAddr, 0, Size );
/* 4. Reset aliased locals, restore original protection */
BaseAddr    = OriginalBase;
Size        = OriginalSize;
Instance->Win32.NtProtectVirtualMemory(
    NtCurrentProcess(), &BaseAddr, &Size, OldProtect, &OldProtect );
```

**Step 5 — Gate optional features inside their own module**
If the feature is controlled by a config flag (e.g., `Config.Implant.PeStomp`):
```c
VOID MyFeature_Do( VOID ) {
    if ( ! Instance->Config.Implant.MyFeatureFlag ) return;  /* gate inside, not in caller */
    // ...
}
```
Never put the gate in `Obf.c`, `Demon.c`, or any other caller. The core agent code path
must remain unchanged when the feature flag is false.

**Step 5b — Choose NT stubs not Win32 wrappers for ROP sleep gadgets (HVC-048)**
When setting a thread's RIP to a sleep function in a Foliage/Timer ROP context, always use
the `NtWaitForSingleObject` (ntdll) stub directly — never `WaitForSingleObjectEx` (kernel32).
The Win32 wrapper has a ~0x100-0x200 byte internal call chain. Its intermediate return
addresses fill the stack ABOVE the fake frames, making those frames invisible to callstack
walkers. The NT stub is `mov r10,rcx / mov eax,SSN / syscall / ret` — no internal `CALL`s,
so the fake frames at `[RSP+0/8/16]` are directly visible when the thread blocks.
Remember: `NtWaitForSingleObject` takes `(Handle, Alertable, PLARGE_INTEGER Timeout)` —
convert milliseconds to 100-ns units (`-(LONGLONG)ms * 10000LL`).

**Step 5a — Wire ExecDelaySleep() at injection points (HVC-046)**
Any new injection function (`MmVirtualAlloc` -> write -> `MmVirtualProtect` -> thread create)
must call `ExecDelaySleep()` at two points: once after the alloc succeeds and once after the
protect-change/before thread creation. The function is a no-op when `ExecDelay == 0`
(the default) — no performance penalty. Pattern:
```c
if ( ! ( Memory = MmVirtualAlloc( DX_MEM_DEFAULT, Process, Size, PAGE_READWRITE ) ) )
    goto END;
ExecDelaySleep();   /* HVC-046: dissociate alloc->protect in time */
/* ... write ... */
if ( ! ( MmVirtualProtect( DX_MEM_SYSCALL, Process, Memory, Size, PAGE_EXECUTE_READ ) ) )
    goto END;
ExecDelaySleep();   /* HVC-046: dissociate protect->execute in time */
/* ... thread create ... */
```

**Step 6 — Re-read every modified file**
After each edit, re-read the full modified file. Verify:
- The edit is at the correct line and not duplicated
- No unintended surrounding code was disturbed
- Wire format sequence (if `DemonConfig` was modified) still matches `builder.go` in count and order

**Step 7 — Update documentation**
1. Add entry to `CHANGES.md` — status, files changed, root cause, fix summary
2. Update `improvement-docs/00-index.md` — set status to `Applied` for the relevant row
3. Update `CLAUDE.md` if a new pattern or constraint was introduced
4. Update memory files if a new root cause or lesson was discovered

#### Exit Criteria
- [ ] Every new `H_FUNC_*` constant verified with `djb2_upper()` before commit
- [ ] No `PAGE_EXECUTE_READWRITE` in the diff
- [ ] NT_SUCCESS guard present before every MemSet/MemCopy/MmVirtualWrite
- [ ] OldProtect (not a hardcoded constant) used in all final NtProtect restore calls
- [ ] NtProtect aliasing guards present (BaseAddr/Size reset before second call)
- [ ] No em dash in any string literal
- [ ] All modified files re-read and verified
- [ ] `CHANGES.md` updated

---

### skill: add-config-bool

**When to invoke:** Adding any new boolean or string configuration option to the Demon agent
that requires changes in the profile, builder, wire format, Demon parser, and client UI.

This skill enforces the **12-file lockstep** that prevents wire format misalignment.
A single missed file causes all subsequent config fields to be parsed from the wrong
slot with no error at runtime.

#### Procedure

**Step 1 — Determine the field position**
Read `AGENTS.md § Config Blob Pattern` to find the current last field index. The new
field goes at the END — never inserted in the middle.

Current tail: field 25 (`ConfigInjectSpoofOffset`). New field = 26.

**Step 2 — Profile config struct** (`teamserver/pkg/profile/config.go`)
Add a new field to the `Demon` struct:
```go
MyNewFlag bool `yaotl:"MyNewFlag,optional"`
```

**Step 3 — Builder** (`teamserver/pkg/common/builder/builder.go`)
Make three additions:
1. Declare a local variable near the top of `PatchConfig()`:
   ```go
   ConfigMyNewFlag := win32.FALSE
   ```
2. Parse the UI/profile value in the option-parsing block:
   ```go
   if val, ok := b.config.Config["My New Label"]; ok {
       if v, ok := val.(bool); ok && v {
           ConfigMyNewFlag = win32.TRUE
       }
   }
   ```
3. Add `AddInt` at the END of the sequence (after the last existing field):
   ```go
   DemonConfig.AddInt( ConfigMyNewFlag )   /* field 26 */
   ```

**Step 4 — Dispatch** (`teamserver/cmd/server/dispatch.go`)
If the field comes from the profile rather than the UI, call `SetDemonProfileDefaults()`
or the equivalent setter after `SetConfig(Config)`. If it's a UI-only field, no change needed.

**Step 5 — Demon struct** (`payloads/Demon/include/Demon.h`)
Add the field to `Config.Implant`:
```c
BOOL  MyNewFlag;
```
Place it after the last existing field (`CoffeeThreaded`) in the struct declaration.

**Step 6 — Demon config parser** (`payloads/Demon/src/Demon.c`)
Add the parse call in `DemonConfig()` at the matching position — immediately after the last
existing parse call (`ParserGetInt32` for `CoffeeThreaded`):
```c
Instance->Config.Implant.MyNewFlag = ParserGetInt32( &Parser );
```

**Step 7 — Client UI** (`client/src/UserInterface/Dialogs/Payload.cc`)
Add in seven places following the exact pattern of existing checkboxes:
1. `QTreeWidgetItem* ConfigMyNewFlag = nullptr;`  — declaration (with other item declarations)
2. `QCheckBox* ConfigMyNewFlagCheck = nullptr;`    — declaration (with other checkbox declarations)
3. Read profile default: `bool defaultMyNewFlag = DemonConfig.value("MyNewFlag", false).toBool();`
4. `ConfigMyNewFlag = new QTreeWidgetItem();` `ConfigMyNewFlag->setFlags(Qt::NoItemFlags);`
5. `ConfigMyNewFlagCheck = new QCheckBox(); ConfigMyNewFlagCheck->setObjectName("ConfigItem");`
6. `ConfigMyNewFlagCheck->setChecked(defaultMyNewFlag);`
7. `ConfigImplant->setItemWidget(ConfigMyNewFlag, 1, ConfigMyNewFlagCheck);`
   `ConfigMyNewFlag->setText(0, "My New Label");`

**CRITICAL:** `setText(0, "My New Label")` must exactly match the key used in
`b.config.Config["My New Label"]` in `builder.go`. Same case, same spaces.

**Step 8 — Profile example** (`profiles/havoc.yaotl`)
Add the field with its default value in the `Demon { }` block:
```
MyNewFlag = false
```

**Step 9 — Profile linter** (`scripts/check_profile.py`)
Add a `FieldSpec` entry in the `SCHEMA["Demon"]` list:
```python
FieldSpec("MyNewFlag", "bool", required=False),
```

**Step 10 — Profile generator** (`scripts/create_profile.py`)
Add a CLI argument and emitter:
```python
parser.add_argument("--demon-my-new-flag", action="store_true", default=False)
# In build_profile():
if args.demon_my_new_flag:
    demon_lines.append("    MyNewFlag = true")
```

**Step 11 — Gate the feature inside its own module**
If the feature has a dedicated implementation file, gate internally:
```c
VOID MyFeature( VOID ) {
    if ( ! Instance->Config.Implant.MyNewFlag ) return;
    ...
}
```
Do not gate in `Obf.c`, `Demon.c`, or any other caller.

**Step 12 — Update docs**
- `CHANGES.md` — new entry
- `improvement-docs/00-index.md` — status to `Applied`
- `CLAUDE.md` — add to the field ordering table in the PE Stomping / Config Blob section

#### Exit Criteria (wire format parity check)
Count the `AddInt`/`AddString` calls in `builder.go:PatchConfig()`. Count the
`ParserGetInt32`/`ParserGetString` calls in `Demon.c:DemonConfig()`. The totals must be equal.
List types at each position side-by-side and verify they match.

---

### skill: implement-bug-fix

**When to invoke:** Diagnosing and fixing a crash, incorrect behaviour, or regression in
any Demon, teamserver, or client component.

#### Procedure

**Step 1 — Reproduce and locate**
1. Identify the exact execution path to the crash: `DemonRoutine()` → which function?
   → which line? Work backwards from the symptom using the ISS pattern:
   - "Crash immediately after registration" → first `SleepObf()` call → `SleepObf()` callers
   - "Crash on first sleep" → DEFAULT case in `Obf.c`
   - "Crash after module load" → `LdrModuleLoad` call sites in `Command.c`
2. Read the relevant issue doc in `improvement-docs/issue-docs/` if one exists.
3. Read `CHANGES.md` for recently applied changes in the same subsystem — regressions are
   almost always caused by the most recent change to that code path.

**Step 2 — Identify root cause class**
Common root causes in this codebase:
- **NT_SUCCESS guard missing:** `NtProtect` failed, `MemSet` ran on non-writable memory → AV
- **Wrong target region:** NtProtect succeeded, but `BaseAddr` points to code not a header → code corruption
- **Wire format mismatch:** New field inserted mid-sequence, all subsequent fields parse from wrong slot
- **DJB2 hash wrong:** `LdrFunctionAddr` returns NULL, function pointer = 0, callers become no-ops
- **OldProtect not restored:** Hardcoded `PAGE_EXECUTE_READ` used in final NtProtect → wrong protection
- **Aliasing guard missing:** `BaseAddr`/`RegionSize` modified in-place by first NtProtect; second call uses stale page-aligned values
- **CfgAddressAdd(NULL, ...):** called for a heap trampoline or non-PE address → NULL dereference of `ImageBase->e_lfanew` → immediate crash in any CFG-enforced target process during `DemonInit`. Only call `CfgAddressAdd` with a valid PE module base (ISS-008, Lesson 16).

**Step 3 — Write the minimal fix**
Apply the fix to the narrowest possible scope. Do not refactor surrounding code.
Do not add error handling for scenarios that cannot happen.

If the fix introduces a new protection pattern, follow the template from
`skill: implement-demon-feature § Step 4`.

**Step 4 — Check for sibling code paths with the same bug**
If the bug is a pattern (missing guard, wrong constant), search for all call sites:
```bash
grep -rn "NtProtectVirtualMemory\|PAGE_EXECUTE_READ" payloads/Demon/src/
```
Fix all instances of the same bug class in the same pass — do not fix one and leave others.

**Step 5 — Verify no regression on the core path**
After the fix, trace the DEFAULT sleep path (`Obf.c`) with all optional features disabled
(PeStomp=false, StackSpoof=false, HideModules=false). The core path must reach
`WaitForSingleObjectEx` unconditionally. No optional flag may block this path.

**Step 6 — Document**
Write an issue doc in `improvement-docs/issue-docs/` if none exists. Update `CHANGES.md`.
If the root cause is a new class of bug, add a lesson to `SKILL.md § Lessons Learned`.

#### Exit Criteria
- [ ] Root cause identified and documented (not just the symptom)
- [ ] Fix is minimal — no unrelated code changed
- [ ] All sibling code paths with the same bug pattern fixed
- [ ] Core sleep path (DEFAULT case) verified reachable with all optionals disabled
- [ ] `CHANGES.md` updated; issue doc created or updated

---

### skill: verify-djb2-hash

**When to invoke:** Adding any new `H_FUNC_*` constant to `Defines.h`.

**This is mandatory before committing. Wrong hash = silent NULL. Silent NULL = complete
no-op with no error, no crash, no log output.**

#### Procedure

1. Identify the exact Windows API export name (case-sensitive, as exported from the DLL):
   - `NtOpenSection` (not `ZwOpenSection`, not `NtOpenSection_`)
   - `NtMapViewOfSection`
   - `BaseThreadInitThunk`

2. Run the exact HashEx algorithm (seed 5381, uppercase, DJB2):
   ```python
   def djb2_upper(s):
       h = 5381
       for c in s.upper():
           h = (((h << 5) + h) + ord(c)) & 0xFFFFFFFF
       return h

   name = "FunctionNameHere"
   print(f"H_FUNC_{name.upper().replace('.', '_')} = {hex(djb2_upper(name))}")
   ```

3. Compare the output to the constant you are about to write. They must match exactly.

4. Check for hash collisions — no two `H_FUNC_*` constants may share the same value.
   Search `Defines.h` for the computed hex value before adding the new constant.

5. Add to `Defines.h` with a comment showing the verified function name:
   ```c
   #define H_FUNC_NTOPENSECTION      0x134eda0e   /* NtOpenSection */
   #define H_FUNC_NTMAPVIEWOFSECTION 0xd6649bca   /* NtMapViewOfSection */
   ```

#### Known-verified constants

| Constant | Value | Function |
|----------|-------|----------|
| `H_FUNC_NTOPENSECTION` | `0x134eda0e` | `NtOpenSection` |
| `H_FUNC_NTMAPVIEWOFSECTION` | `0xd6649bca` | `NtMapViewOfSection` |
| `H_FUNC_RTLUSERTHREADSTART` | verify before use | `RtlUserThreadStart` |
| `H_FUNC_BASETHREADINITTHUNK` | verify before use | `BaseThreadInitThunk` |

---

## Skills for: qa-specialist

---

### skill: review-change

**When to invoke:** Reviewing a completed implementation from a red-team-developer agent.
This skill is the full QA procedure. Run every applicable checklist item.

#### Procedure

**Step 1 — Gather the diff**
1. Identify all modified files from the change description.
2. Read each file in full at the modified sections — do not rely on the diff alone. The diff
   shows what changed; the file shows what the change is embedded in.

**Step 2 — Wire format audit** (if `builder.go` or `Demon.c` was modified)
1. Open `builder.go:PatchConfig()`. List every `AddInt`, `AddString`, `AddWString` call in order.
2. Open `Demon.c:DemonConfig()`. List every `ParserGetInt32`, `ParserGetString`, `ParserGetBytes` call in order.
3. Compare the two lists side-by-side, position by position. The type (Int/String) and order must match.
4. Count: total Add* calls must equal total Parser* calls.
5. Verify new fields are at the END — no insertion in the middle.
6. `FAIL` if: count mismatch, type mismatch at any position, or new field inserted mid-sequence.

**Step 3 — DJB2 hash audit** (if `Defines.h` was modified)
1. Extract every new `H_FUNC_*` constant.
2. Run `djb2_upper(function_name)` for each and compare to the constant value.
3. `FAIL` if any constant does not match its verification result.
4. `FAIL` if any two constants share the same value (collision).

**Step 4 — Memory safety audit** (for all Demon C changes)
For every `NtProtectVirtualMemory` call in the diff:
1. Confirm an `if (!NT_SUCCESS(Status)) { return; }` block immediately follows.
2. Confirm no `MemSet`, `MemCopy`, or `MmVirtualWrite` is reachable when the NtProtect failed.
3. Confirm the final NtProtect restore call passes the local `OldProtect` variable — not a
   hardcoded constant like `PAGE_EXECUTE_READ` (0x20) or `PAGE_READONLY` (0x02).
4. Confirm `BaseAddr` and `RegionSize`/`Size` locals are reset to their original values
   before the second NtProtect call in any protect/write/restore sequence.
5. `FAIL` if: guard absent, write reachable after failure, hardcoded restore constant,
   or aliasing guard absent.

**Step 5 — Protection constant audit**
Search the diff for: `0x40`, `PAGE_EXECUTE_READWRITE`, `PAGE_RWX`.
`FAIL` if any appears in production code (comments are acceptable).

Search for `PAGE_EXECUTE_WRITECOPY` (0x80) usage:
- Permitted only when patching pages with original protection `PAGE_EXECUTE_READ`
  (SEC_IMAGE execute pages, e.g., ntdll `.text`)
- Not appropriate for PE header pages (original protection `PAGE_READONLY`)

**Step 6 — PE stomping audit** (if `PeProtect.c` was modified)
1. Confirm `PeProtect_Init()` checks `IMAGE_DOS_SIGNATURE` before reading the PE header backup.
2. Confirm that when MZ is absent, `Config.Implant.PeStomp` is force-set to `FALSE` and the
   function returns immediately.
3. Confirm `PeProtect_Stomp()`, `PeProtect_Restore()`, `PeProtect_Init()` each gate themselves
   with `if (!Instance->Config.Implant.PeStomp) return;` at their entry.
4. Confirm no external caller is the sole gate (gate must be inside the function).
5. `FAIL` if MZ check absent; gate absent in any of the three functions; or external-only gate.

**Step 7 — ntdll unhooking audit** (if `NtdllUnhook.c` or `Demon.c:DemonInit` was modified)
1. Confirm `DemonInit()` order: `DemonConfig()` → `SysInitialize()` → `UnhookNtdll()`.
2. Confirm `UnhookNtdll()` uses `SysNtProtectVirtualMemory` — not `Win32.NtProtectVirtualMemory`.
3. Confirm ntdll `.text` overwrite uses `NtdllCopy` (static QWORD loop) — not `MemCopy`.
4. Confirm `NtOpenSection`/`NtMapViewOfSection` are resolved inline — not added to `Win32`.

**Step 8 — Optional feature isolation audit**
1. Identify every optional config flag used in the diff.
2. For each flag, confirm the gate is inside the optional module — not in `Obf.c`, `Demon.c`,
   or another caller.
3. Trace the DEFAULT sleep path with all optionals disabled. Confirm `WaitForSingleObjectEx`
   is always reachable.
4. `FAIL` if any optional flag gates the core sleep path.

**Step 9 — String literal audit**
Search the diff for `—` (U+2014). `FAIL` if any em dash appears in a `PRINTF`, `PUTS`,
or any other string that reaches terminal output.

**Step 10 — UI label / builder key consistency audit** (if `Payload.cc` and `builder.go` both modified)
1. List every `setText(0, "Label")` call in `Payload.cc`.
2. For each, find the matching `b.config.Config["Label"]` in `builder.go`.
3. Compare character-for-character. `FAIL` if they differ.

**Step 11 — Documentation audit**
1. Confirm `CHANGES.md` has a new entry with: status, files changed, root cause, fix summary.
2. Confirm `improvement-docs/00-index.md` shows `Applied` for the relevant row.
3. Confirm `CLAUDE.md` is updated if a new pattern was introduced.

#### Report Format

```
## QA Report — <change name> — <date>

Files reviewed: [list]

### Wire Format
- [PASS/FAIL] builder.go N AddInt/AddString == Demon.c N ParserGetInt32/ParserGetString
- [PASS/FAIL] Type sequence matches at all positions
...

### Memory Safety
- [PASS/FAIL] NT_SUCCESS guard at <file>:<line>
- [PASS/FAIL] OldProtect restoration at <file>:<line>
...

### Summary
N checks. N PASS, N FAIL, N WARN.
FAIL items must be resolved before this change is merged.
```

---

### skill: audit-memory-safety

**When to invoke:** Spot-checking any Demon C file for memory safety issues, independent
of a full change review.

#### Procedure

1. **NtProtect guard scan:**
   ```bash
   grep -n "NtProtectVirtualMemory" payloads/Demon/src/core/TargetFile.c
   ```
   For each call, verify `if (!NT_SUCCESS(Status)) return;` immediately follows.

2. **Hardcoded protection scan:**
   ```bash
   grep -n "PAGE_EXECUTE_READ\|PAGE_READONLY\|0x20\|0x02" payloads/Demon/src/core/TargetFile.c
   ```
   Any hardcoded constant in a final NtProtect restore call is a bug — should be `OldProtect`.

3. **RWX scan:**
   ```bash
   grep -rn "PAGE_EXECUTE_READWRITE\|0x40" payloads/Demon/src/
   ```
   Any result in production code is a `FAIL`.

4. **Write-after-failed-protect scan:**
   Manually trace every `MemSet`/`MemCopy`/`MmVirtualWrite` call. Confirm each is guarded
   by a preceding NT_SUCCESS check that returns on failure.

5. **Aliasing scan:**
   For every function with two NtProtect calls on the same `BaseAddr`/`Size` locals, confirm
   those locals are reset between calls.

---

### skill: audit-wire-format

**When to invoke:** Verifying wire format consistency after any change to `builder.go`,
`Demon.c`, or both.

#### Procedure

1. Open `teamserver/pkg/common/builder/builder.go`. Find `PatchConfig()`. Extract the
   sequence of `AddInt`/`AddString`/`AddWString` calls in order. Format as a numbered list
   with types: `1:Int, 2:Int, 3:String, ...`

2. Open `payloads/Demon/src/Demon.c`. Find `DemonConfig()`. Extract the sequence of
   `ParserGetInt32`/`ParserGetString`/`ParserGetBytes` calls in order. Format identically.

3. Compare the two lists side-by-side. Every position must have the same type.

4. Total count must match.

5. Cross-reference with the field table in `AGENTS.md § Config Blob Pattern`. Field positions
   13-25 must not have shifted.

6. If a mismatch is found: identify which field is at the wrong position, trace its `AddInt`
   call in builder.go and its `ParserGetInt32` call in Demon.c, and report the exact lines
   where the sequences diverge.

---

## Skills for: code-tester

---

### skill: build-verify

**When to invoke:** Before any test scenario. Always run first.

#### Procedure

```bash
# 1. Teamserver Go build
cd teamserver
go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go
echo "Go build exit: $?"          # must be 0

# 2. Go tests
go test ./...                     # must be all PASS, zero failures

# 3. Client CMake + Make
cd ../client && mkdir -p Build && cd Build
cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | grep -i "error"
make -j4 2>&1 | grep -i "error:"  # must produce no output
```

**False positive suppression:** Clang IDE diagnostics in Demon C files (`'Demon.h' file
not found`, `Unknown type name 'VOID'`, etc.) are not build errors. Only MinGW output matters.
If the MinGW cross-compile is available, add: `make demon-build 2>&1 | grep -i "error:"`.

**Exit criteria:**
- `go build` exit code = 0
- `go test ./...` = all PASS
- `make -j4` output contains no `error:` lines

---

### skill: test-injection-stability

**When to invoke:** Verifying that any change involving `PeProtect.c`, `Obf.c`, `DemonInit`,
or any sleep obfuscation path does not introduce an injection crash.

#### Procedure

**Scenario A — Shellcode injection with PeStomp enabled**

1. Build a debug shellcode payload with `PeStomp = true`.
2. Start the teamserver with a configured listener.
3. Inject the shellcode into a remote process (via "shellcode inject" from a live Demon,
   or via an external injector).
4. Monitor debug output from the injected agent.

Expected log line (must appear exactly once):
```
PeProtect_Init: no PE header at ModuleBase - disabling PeStomp (shellcode mode)
```

Pass criteria:
- Log line appears
- Host process does not terminate within the first 3 sleep cycles
- Agent continues checking in at the configured sleep interval

Fail indicators:
- Host process terminates within seconds of registration
- Log line absent (MZ check not reached)
- Teamserver marks agent dead after one check-in

**Scenario B — Default-config shellcode injection (no PeStomp)**

1. Build a shellcode payload with all defaults (PeStomp=false, StackSpoof=false).
2. Inject into a remote process.
3. Monitor for 5+ sleep cycles.

Pass: Agent alive and checking in at configured interval.
Fail: Host process crash. Agent flooding teamserver (sleep=0 regression).

**Scenario C — EXE with PeStomp enabled (regression check)**

1. Build a debug EXE with `PeStomp = true`.
2. Run the EXE directly (not injected).

Pass:
- "no PE header" log line does NOT appear
- Stomp/restore log lines appear each sleep cycle
- OldProtect value in restore matches OldProtect saved in stomp (add temporary debug print)

Fail: Agent crashes on first sleep. "no PE header" appears (MZ check returns false on a real PE).

---

### skill: test-ntdll-unhook

**When to invoke:** Verifying that `UnhookNtdll = true` with `IndirectSyscall = true`
succeeds and the agent connects normally.

#### Procedure

1. Build a debug payload with `UnhookNtdll = true` and `IndirectSyscall = true`.
2. Run the payload.
3. Collect debug output.

Expected sequence (must all appear in this order):
```
UnhookNtdll: .text CleanText=<addr>  LoadedText=<addr>  TextSize=<N>
UnhookNtdll: NtProtect(RW) status=0x00000000  OldProt=0x00000020
UnhookNtdll: NtdllCopy complete - <N> bytes written
UnhookNtdll: NtProtect(restore) status=0x00000000  RestoredProt=0x00000020
UnhookNtdll: clean view unmapped - returning 1
Successfully unhooked ntdll.dll
```

Key values to verify:
- Both NtProtect status = `0x00000000` (STATUS_SUCCESS)
- `OldProt=0x00000020` = `PAGE_EXECUTE_READ` — confirms original protection correct
- `NtdllCopy complete` with non-zero byte count
- Agent connects to teamserver after unhooking completes

Fail indicators:
- Any NtProtect status non-zero
- Missing `NtdllCopy complete` line
- Agent crash before first sleep

Regression: `UnhookNtdll = false` must produce no ntdll log lines; agent must connect normally.

---

### skill: test-sleep-regression

**When to invoke:** After any change to `Obf.c`, `PeProtect.c`, `ObfTimer.c`, or `ObfFoliage.c`.
Verifies the sleep=0 regression is not present.

#### Procedure

1. Build a payload with default settings (sleep=10, StackSpoof=false, PeStomp=false,
   no sleep obfuscation technique).
2. Run the payload against a teamserver.
3. Observe the teamserver connection log for 60 seconds.

Pass: Agent checks in approximately every 10 seconds (allow ±2s variation).
The total number of check-ins in 60 seconds should be 5-7.

Fail: Agent floods the teamserver with rapid sequential check-ins — dozens per second.
This indicates `WaitForSingleObjectEx` is not being called in the DEFAULT sleep path.

**Root cause pattern if regression present:**
Trace `Obf.c:SleepObf()` DEFAULT case. Verify:
1. `PeProtect_Stomp()` is called (it gates itself internally — no crash possible)
2. `SpoofFunc` is gated on `StackSpoof=true` AND `MmGadgetFind` returns non-NULL
3. The `else` branch falls through to direct `WaitForSingleObjectEx`
4. Step 3 must be unconditionally reachable when StackSpoof=false

---

### skill: test-config-alignment

**When to invoke:** After any change to the config blob sequence (new field added or reordered).
Verifies all config fields are parsed from the correct position.

#### Procedure

1. Build a debug payload with every optional feature enabled and non-default values:
   - `Sleep = 15`, `Jitter = 5`
   - `RandGadget = true`, `UnhookNtdll = true`, `HideModules = true`, `PeStomp = true`
   - `Verbose = true`, `CoffeeVeh = true`, `CoffeeThreaded = true`
   - `IndirectSyscall = true`
2. Run the payload with `--debug-dev`.
3. Verify that each feature produces its corresponding log line.

Expected log evidence per feature (in `DemonInit` / first sleep cycle):
- `RandGadget`: gadget scan log
- `UnhookNtdll`: ntdll unhook sequence (see `skill: test-ntdll-unhook`)
- `HideModules`: hide module log on first `LdrModuleLoad` call
- `PeStomp` (EXE/DLL): stomp log on first sleep; "no PE header" must NOT appear
- `Verbose`: verbose mode log
- `IndirectSyscall`: syscall address log from `SysInitialize`

Fail: Any feature set to `true` produces no output and appears to have no effect.
This indicates a wire format misalignment where that feature's field is parsed from a
different (adjacent) field's position.

---

### skill: test-parser-safety

**When to invoke:** After any change to `Parser.c`, `Demon.c:DemonConfig()`, or any function
that reads a length-prefixed field from an untrusted buffer. Verifies the UINT32 underflow
guard and NULL-source MemCopy protections are effective.

#### Procedure

**Scenario 1 - Mismatched AES key (config blob corruption)**

1. Edit the teamserver profile to use a wrong-length AES key or mismatched IV so the
   decrypted config blob contains garbage length fields.
2. Build a debug payload and run it against the teamserver.
3. Observe behaviour.

Pass: Agent does not crash (access violation, segfault). It either exits cleanly,
re-connects, or logs a parse error and idles. No heap read past allocated buffer.

Fail: Agent crashes or produces an access violation during `DemonConfig()` - indicates
a UINT32 underflow occurred and subsequent reads went out of bounds.

**Scenario 2 - KaynLdr shellcode injection (KArgs=NULL path)**

1. Build a debug shellcode payload (KaynLdr mode is NOT used - use a non-KaynLdr injector
   that sets `KArgs = NULL`).
2. Inject the shellcode into a remote process.
3. Monitor for successful registration and first sleep cycle.

Pass: Agent registers with the teamserver without crashing in `DemonInit`. No access
violation before config parse completes.

Fail: Remote process terminates immediately after shellcode runs - indicates `IMAGE_SIZE`
or another PE field access faulted on the headerless mapping because the MZ check was absent.

**Expected log behaviour on a correctly-configured build:**
`ParserGetBytes` should not log a bounds-exceeded message during normal operation. If that
message appears on a valid build with correct profile settings, it indicates a bug elsewhere
in the config blob construction - investigate `builder.go:PatchConfig()` field ordering.

---

### skill: regression-check

**When to invoke:** After any change to the codebase, before declaring the implementation
complete. This is the full regression gate.

#### Procedure

Run all of the following in order:

1. `skill: build-verify` — must pass before continuing
2. Default-config agent: connect, survive 5 sleep cycles, check-in at correct interval
3. `skill: test-sleep-regression` — verify no sleep=0
4. If `PeProtect.c` touched: `skill: test-injection-stability` Scenario A + B + C
5. If `NtdllUnhook.c` or `DemonInit` ordering touched: `skill: test-ntdll-unhook`
6. If config blob sequence changed: `skill: test-config-alignment`

#### Report Format

```
## Test Report — <change name> — <date>

### Build
- [PASS] go build exit 0
- [PASS] go test ./... all PASS
- [PASS] client make: no errors

### Regression
- [PASS] Default-config agent: 6 check-ins in 60s (expected ~6)
- [PASS] Sleep regression: no flooding
- [PASS] Injection stability (shellcode, PeStomp=true): "no PE header" seen; survived 5 cycles
- [PASS] Injection stability (EXE, PeStomp=true): stomp/restore logs; OldProt=0x02
- [PASS] ntdll unhook: OldProt=0x20 on both calls; 1486764 bytes written
- [PASS] Config alignment: all 10 features produced expected log evidence

### Verdict
N scenarios. N PASS, N FAIL.
```

---

## Lessons Learned

These lessons are preserved from earlier codebase work. Each captures a non-obvious bug or
mistake that was made and should not be repeated.

---

### Lesson 1: Profile Fixes Can Unmask Latent Agent Bugs

**What happened:** Fixed profile settings to actually propagate to the builder and Demon agent.
Features like HWBP, SleepJmpGadget, ProxyLoading were now applied. But agents started terminating.

**Root cause:** The features themselves had bugs (handle leaks, NULL dereferences, wrong sizeof).
These bugs always existed but were never triggered because the profile settings were silently ignored.

**Rule:** After any change that enables previously-disabled code paths, trace those code paths
for latent bugs before declaring the fix complete. Fix config propagation, then audit the feature.

---

### Lesson 2: sizeof(void) Is Not Zero — It Is 1 on GCC

**What happened:** `sizeof(VOID)` was used as a copy size. On GCC/MinGW (used for Demon),
`sizeof(void)` is a GCC extension that evaluates to 1, silently copying only 1 byte.

**Rule:** Never use `sizeof(void)` or `sizeof(VOID)`. For pointer-sized copies, use
`sizeof(PVOID)` or `sizeof(ULONG_PTR)`. When reviewing, `grep -n "sizeof.*VOID"` and verify.

---

### Lesson 3: Handle Leaks From Incomplete Exit Path Audit

**What happened:** `HwBpEngineSetBp` closed a thread handle on the failed path but not the
success path. The function is called from the VEH handler — the leak is rapid.

**Rule:** For every function that opens handles or allocates resources, enumerate ALL exit
points (return, goto, fall-through). Verify each one closes/frees resources.

---

### Lesson 4: Initialize Local Variables From Parameters, Not NULL

**What happened:** `HwBpEngineRemove` declared `PHWBP_ENGINE HwBpEngine = NULL` and then
checked `if (!HwBpEngine)` to decide whether to fall back to the global. The local was always
NULL so the parameter was always ignored.

**Rule:** When a function accepts a parameter with a NULL fallback to a global, initialize
the local FROM the parameter:
```c
PHWBP_ENGINE HwBpEngine = Engine;   // from parameter
if (!HwBpEngine) HwBpEngine = Instance->HwBpEngine;  // fallback
```

---

### Lesson 5: VEH Handlers Must NULL-Guard All Global State

**What happened:** The HWBP exception handler accessed `Instance->HwBpEngine->Breakpoints`
without checking if `HwBpEngine` was NULL. VEH handlers fire from all threads at any time,
including initialization/destruction windows.

**Rule:** Every VEH/SEH handler starts with NULL checks on all global state before accessing.
Return `EXCEPTION_CONTINUE_SEARCH` if state is invalid — do not crash.

---

### Lesson 6: Agent Findings Are Hypotheses, Not Confirmed Facts

**What happened:** Three analysis agents reported 8 bugs. After manual verification, 4 were
false positives — agents missed macro expansion context, fallback logic in subsequent code,
and error handling in callers.

**Rule:** Always verify agent findings by reading the actual code at the reported line and
tracing macro expansions manually. A 50% false positive rate is normal for static analysis.

---

### Lesson 7: x64 RSP Alignment Varies By Windows Build

**What happened:** Foliage sleep crashed. The ROP chain had `Rsp % 16 == 0` instead of
`Rsp % 16 == 8` (required at x64 function entry). `NtGetContextThread` on a freshly-created
suspended thread returns different Rsp alignment depending on the Windows build.

**Rule:** Never use the captured Rsp from `NtGetContextThread` directly. Normalize:
```c
if ((Rsp & 0xF) == 0) Rsp -= sizeof(PVOID);
```
The crash manifests as `#GP` from `movaps` in the ROP chain target functions, not from
`NtContinue` itself.

---

### Lesson 8: Only ntdll Functions Are Safe on Manually-Created NT Threads

**What happened:** Foliage ROP chain called `WaitForSingleObjectEx` (kernelbase.dll) on an
APC thread created with `NtCreateThreadEx` + `NtTestAlert`. The thread never ran through
`BaseThreadInitThunk`, so its TEB Win32 subsystem state was uninitialised. The Win32 wrapper
accessed uninitialised fields and crashed.

**Rule:** On threads created directly via `NtCreateThreadEx` (with `CREATE_SUSPENDED` for
APC/ROP chains), use ONLY ntdll functions and direct syscalls — no kernelbase.dll,
kernel32.dll, or advapi32.dll wrappers. If an algorithm is needed (e.g., RC4), implement
it as a position-independent stub in separately allocated executable memory.

---

### Lesson 9: Audit ALL Functions in ROP Chains for Non-ntdll Dependencies

**What happened:** After replacing `WaitForSingleObjectEx` with `NtWaitForSingleObject`,
Foliage still crashed intermittently. `SystemFunction032` (advapi32) — the RC4 wrapper —
accessed uninitialised TEB state on the APC thread on some Windows versions.

**Rule:** For ANY function in a ROP chain on a manual thread, confirm it comes from ntdll.
If not, replace it or implement the algorithm as a custom stub. "Simple" functions from
other DLLs can have hidden TEB dependencies in their implementation or forwarding chain.

---

### Lesson 10: NT_SUCCESS Guard Covers Failure — Not Wrong Target

**What happened:** ISS-037 added `NT_SUCCESS` guards to `PeProtect_Stomp()` to prevent
writing to non-writable memory. In KaynLdr shellcode mode, NtProtect SUCCEEDS (private
allocation), but `ModuleBase` points to `.text` code, not a PE header. The guard passed.
`MemSet` zeroed 4 KB of live agent code.

**Rule:** `NT_SUCCESS` only guards the FAIL case. When NtProtect succeeds, validate that
the target region IS what you expect (e.g., check for `IMAGE_DOS_SIGNATURE` before assuming
`ModuleBase` is a PE header). Both guards are always needed independently.

---

### Lesson 11: Hardcoded Protection Constants Cause Permanent Permission Creep

**What happened:** `PeProtect_Stomp()` and `PeProtect_Restore()` restored the PE header page
with hardcoded `PAGE_EXECUTE_READ` (0x20). The original protection was `PAGE_READONLY` (0x02).
After one sleep cycle, the PE header page permanently gained the execute bit — incorrect and
a potential detection signal.

**Rule:** Always use `OldProtect` (the value saved by the preceding NtProtect call) as the
restoration protection. Never hardcode a protection constant in a restore call. The original
protection is whatever it was — do not guess.

---

### Lesson 12: DJB2 Hash Errors Are Completely Silent

**What happened:** HVC-030 Sub-3 pe-sieve fix was a complete no-op at runtime. Both
`RtlUserThreadStart` and `BaseThreadInitThunk` resolved to NULL because their `H_FUNC_*`
constants were wrong. The code ran without error — it just silently wrote NULL to every
frame that was supposed to hold those addresses.

**Rule:** DJB2 hash verification is mandatory before committing ANY new `H_FUNC_*` constant.
Wrong hash = `LdrFunctionAddr` returns NULL = all users of that pointer silently no-op.
There is no runtime error, no crash, no log. Run `djb2_upper(name)` and confirm.

---

### Lesson 13: UINT32 Length Counters on Untrusted Buffers Must Be Bounds-Checked Before Arithmetic

**What happened (ISS-005):** `ParserGetBytes` read a 4-byte `Length` field from the config
blob and subtracted it from `parser->Length` twice without checking whether `Length` fit in
the remaining buffer. When `Length > parser->Length - 4`, both subtractions underflowed, wrapping
`parser->Length` to ~0xFFFFFFxx. Every subsequent read went far out of bounds.

**Rule:** Before any `parser->Length -= N` operation, verify `N <= parser->Length`. `parser->Length`
is UINT32, not INT32 - there is no signed overflow, only silent wrap to a huge value. The
pattern: `if ( Length > parser->Length - sizeof(DWORD) ) { parser->Length = 0; *size = 0; return EmptyBuf; }`.

---

### Lesson 14: Functions Returning Buffer Pointers Used Directly in MemCopy Must Never Return NULL

**What happened (ISS-006):** All call sites in `DemonConfig` passed the return value of
`ParserGetBytes` directly into `MemCopy(dest, Buffer, Length)` without a NULL check. When
`ParserGetBytes` returned NULL (its original error path), the MemCopy faulted immediately.
Auditing every one of 15+ call sites is error-prone - one missed check is enough to crash.

**Rule:** When a parser function has many callers following the same `Buffer = Parse(); MemCopy(dest, Buffer, size);`
pattern, fix the failure path inside the parser: return a static safe zero-length buffer
(`EmptyBuf`) and set `*size = 0`. Any `MemCopy(dest, EmptyBuf, 0)` is a safe no-op. This
eliminates the entire class of bugs without touching a single call site.

---

### Lesson 15: `*(PWORD)Base == IMAGE_DOS_SIGNATURE` Is a Mandatory Guard, Not an Optional Check

**What happened (ISS-007):** When `KArgs == NULL` (non-KaynLdr injector), `DemonInit` called
`IMAGE_SIZE(Instance->Session.ModuleBase)` unconditionally. `IMAGE_SIZE` reads `e_lfanew` from
`ModuleBase` to reach the NT headers. In a KaynLdr headerless mapping, `ModuleBase[0]` is the
start of `.text` code. Reading `e_lfanew` from code bytes yields a garbage RVA; the NT header
dereference accesses an arbitrary address and faults before config parse even begins.

**Rule:** Any code that treats a `PVOID` as a PE image must validate `*(PWORD)Base == IMAGE_DOS_SIGNATURE`
first. A non-NULL pointer check is insufficient - KaynLdr mappings, fresh allocations, and
non-PE blobs all pass non-NULL but crash on `e_lfanew`. When the MZ check fails, set any
dependent size or offset to 0 and do not proceed. Apply this guard consistently across the
entire codebase wherever `IMAGE_SIZE`, `IMAGE_NT_HEADER`, or direct `e_lfanew` access appears.

---

### Lesson 16: Rewriting Shared Library Code While Threads Execute It Requires Full Thread Suspension

**What happened (ISS-001):** `UnhookNtdll()` called `NtdllCopy` to overwrite ntdll `.text`
without suspending host threads. In a multi-threaded host process, another thread fetching an
instruction from the in-progress region during the QWORD-by-QWORD copy reads a partially-written
cache line. This produces a nonsense instruction sequence that causes a `#GP` (general protection
fault) or `#UD` (undefined instruction) fault — a crash in the host process. Single-threaded
targets (e.g. freshly spawned notepad) would not trigger this, making it a rare and intermittent
failure.

**Rule:** Any code that overwrites memory containing executable code in a process that may have
more than one thread must enumerate and suspend all non-current threads before writing, and resume
them after restoring page protection. Use `SysNtGetNextThread` + `SysNtQueryInformationThread`
(ThreadBasicInformation) for TID-based filtering. Use the `ThdSaved` flag pattern to track
whether handles are saved to the resume array or need to be closed in the loop body — this
prevents both double-closes and handle leaks.

---

### Lesson 17: PEB LDR List Walks Without LoaderLock Are Racy and Crash-Prone

**What happened (ISS-002, ISS-003):** `HideModule()`, `LdrModulePeb`, `LdrModulePebByString`,
and `LdrModuleSearch` all walked `InLoadOrderModuleList` without holding `PEB->LoaderLock`. A
concurrent `LoadLibrary` or `FreeLibrary` on another thread splices the same list simultaneously.
The walking thread reads a `Flink` pointer that the other thread has already zeroed or replaced,
causing an access violation or infinite loop. `LdrModuleSearch`'s `Entry != FirstEntry`
termination condition is particularly vulnerable — if `Flink` is corrupted, the walk never
terminates (ISS-011).

**Rule:** Every PEB LDR list walk — including `HideModule`, all `LdrModule*` functions, and any
future enumeration — must acquire `LoaderLock` before the first `Flink` dereference and release
it at every exit point. Resolve `LdrLockLoaderLock`/`LdrUnlockLoaderLock` inline via
`LdrFunctionAddr` (they are not in `Instance->Win32`). Guard the acquire with `if (pLdrLock)`
for the early-init case where `Modules.Ntdll` is still NULL.

**DJB2 hashes (verified):**
- `LdrLockLoaderLock`   → `0xcdcd3c90`
- `LdrUnlockLoaderLock` → `0xfc603ed3`

---

### Lesson 18: Heap Allocation Failure Before Lock Acquire Permanently Deadlocks the Loader

**What happened (ISS-003 addendum):** `LdrModulePebByString` allocated a wide-string work buffer
with `MmHeapAlloc(MAX_PATH)` at line 135, then acquired `LoaderLock` at line 145. No NULL check
existed between them. Under OOM conditions, `MmHeapAlloc` returns NULL; the subsequent
`MemCopy(NULL, ...)` produces an access violation. At crash time the lock is already held,
leaving it permanently acquired for the process lifetime. Every future `LoadLibrary` call
deadlocks waiting for the lock that will never be released.

**Rule:** Heap allocations that are prerequisites for a critical-section operation must be NULL-
checked BEFORE the lock is acquired. Pattern: `Name = MmHeapAlloc(MAX_PATH); if (!Name) return NULL;`
then acquire the lock. This keeps the resource acquisition order clean (allocation -> check -> lock)
and eliminates the permanently-held-lock failure mode.

---

### Lesson 19: Functions Declared `BOOL` Without a `return` Statement Have Undefined Return Value

**What happened (ISS-004):** `SysInitialize()` was declared `BOOL SysInitialize(IN PVOID Ntdll)`
but had no `return` statement. The C standard defines this as undefined behaviour — on most x64
calling conventions the "return value" is whatever happens to be in `RAX` at function exit (the
last computed value, which is the NTSTATUS from the final `SYS_EXTRACT` macro or some other
expression). On EDR environments where `SysExtract(NtAddBootEntry)` fails and `SysAddress` stays
NULL, the function could return a non-zero garbage value that callers treat as TRUE, masking the
initialization failure.

**Rule:** Every non-void function must have an explicit `return` statement on all code paths.
For functions that compute a boolean result from instance state, the pattern is
`return Instance->Subsystem.Key != NULL;` or `return ConditionIsMet;` as the final statement.
Never rely on the implicit return value from the last expression or on compiler warnings to catch
missing returns — `-W` flags may not be enabled, and the bug is completely silent at runtime.

---

### Lesson 20: MinGW Compat Blocks for Vista+/Win8.1+ Types

**What happened (HVC-032):** `src/commands/` files referenced `SOCKADDR_INET`, `MIB_IPNET_TABLE2`,
`MIB_IPNET_ROW2`, `CIMTYPE`, `HPSS`, and `PSS_CAPTURE_FLAGS`. These are Vista+/Win8.1+ types
declared in `ws2ipdef.h`, `netioapi.h`, `wbemcli.h`, and `processsnapshot.h`. MinGW-w64 on Kali
does not ship these headers (or ships incomplete versions). Even with `-D_WIN32_WINNT=0x0603`,
the types are absent, producing "unknown type name" errors.

**Rule:** For every Vista+/Win8.1+ type not in core MinGW headers, add an inline compat block at
the top of the `.c` file that needs it, guarded by the same macro the Windows SDK uses:

```c
#ifndef MIB_IPNET_TABLE2_DEFINED
#define MIB_IPNET_TABLE2_DEFINED
/* ... minimal struct defs from MSDN ... */
#endif
```

Known guards: `CIMTYPE_DEFINED`, `SOCKADDR_INET_DEFINED`, `MIB_IPNET_TABLE2_DEFINED`,
`_PROCESSSNAPSHOT_H_`. If a future MinGW ships the real header it will set these guards and
the compat block is silently skipped.

Additionally: **function pointer typedef return types must match Win32 exactly.** `CreateFileW`
returns `HANDLE` (void *), not `BOOL` (int). A wrong return type in a typedef is silently cast
on macOS/MSVC but produces "makes pointer from integer" on MinGW at every call site.

---

### Lesson 21: `src/commands/` Switch Case Safety Rules

**What happened (HVC-032 QA):** Deep review of all 11 new command files found recurring patterns:

1. **Bare `return` in a switch case** leaks the `Package` allocation, leaks open handles (token,
   process, registry), and sends no response to the operator. The operator's command hangs
   indefinitely. Fix: replace with `PackageAddInt32(Package, FALSE); break;`.

2. **Missing `break` before the next case** (found in `SOCKET_COMMAND_WRITE`): the success path
   `return`s, but the failure path fell through into `SOCKET_COMMAND_CONNECT`, parsing new socket
   fields from the wrong buffer position and creating a spurious socket.

3. **Token handle from `TokenCurrentHandle()` leaked** when not all case branches close it. Pattern:
   open `hToken` once at the function top; close+NULL it in cases that use it; add a final
   `if (hToken) { SysNtClose(hToken); hToken = NULL; }` just before `PackageTransmit`.

4. **`PackageAddWString` field duplicated** in a loop body (session list: `sesi10_username` written
   twice; second should be `sesi10_cname`). Client reads fields sequentially — a duplicate shifts
   every subsequent field and corrupts the display for all remaining entries.

5. **`MmHeapAlloc` result unchecked before `MemCopy`**: OOM crashes the agent in an injected
   process with no recoverable error. Every heap allocation must be NULL-checked before use.

6. **Assembly argument length assigned to wrong variable** (`&Buffer.Length` instead of
   `&AssemblyArgs.Length`): `AssemblyArgs.Length` stays 0, so the .NET assembly always sees
   empty arguments regardless of what the operator sent.

---

### Lesson 22: `CfgAddressAdd(NULL, ...)` Crashes Any CFG-Enforced Process (ISS-008)

**What happened (HVC-045):** `SystemFunction032` (advapi32.dll) was replaced by compiled-in
RC4/ChaCha20 ciphers living in a heap trampoline. The `CfgAddressAdd` call for the old cipher
(`CfgAddressAdd(Advapi32, SystemFunction032)`) was replaced with
`CfgAddressAdd(NULL, SleepCipherFunc)`. `CfgAddressAdd` reads `((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew`
to locate the PE headers — passing `NULL` as `ImageBase` is a NULL pointer dereference.
This crash occurs during `DemonInit` (before any sleep cycle or task) in any CFG-enforced target
process (virtually all modern Windows processes). EXE mode worked because MinGW-built Demon
executables do not have CFG enabled, so `CfgQueryEnforced()` returned FALSE and the block was
skipped. DLL and shellcode modes crashed immediately on injection.

**Root cause insight:** The cipher is invoked via `NtContinue` (Foliage — kernel sets RIP
directly, bypasses all userland CFG checks) and via a byte-scanned `jmp rax` gadget in ntdll
(Timer — not a compiler-instrumented indirect call site). CFG only intercepts call sites that
were instrumented at compile time with `/guard:cf`. Neither path qualifies. The registration
was both incorrect (NULL `ImageBase`) and unnecessary (no CFG-guarded call site touches it).

**Rule:** Never call `CfgAddressAdd` for heap-allocated stubs, trampolines, or any memory that
is not backed by a loaded PE image. Pass only valid PE module handles (e.g.,
`Instance->Modules.Ntdll`, `Instance->Modules.Kernel32`) as the first argument. Before adding
a `CfgAddressAdd` call, verify: (a) the function is called through a CFG-instrumented site, and
(b) the module base is a real PE image with a valid `e_lfanew`.

---

### Lesson 23: Injection Dissociation via ExecDelaySleep (HVC-046)

**Problem:** EDRs and memory forensics tools correlate the tight temporal sequence
`VirtualAllocEx -> VirtualProtectEx -> CreateRemoteThread` occurring within milliseconds as a
high-confidence injection signature. The gap between allocation and execution in the base Demon
injection path was zero.

**Solution:** `ExecDelaySleep()` in `src/core/Win32.c` calls `NtDelayExecution` with a jittered
relative delay (`Li.QuadPart = -(Ms * 10000LL)` — negative = relative 100-ns units). It is gated
by `Instance->Config.Implant.ExecDelay == 0` as a pure no-op when disabled (default).

**Why NtDelayExecution (not Sleep or WaitForSingleObjectEx)?**
- No handle needed; accepts negative `LARGE_INTEGER` for relative time
- Not EDR-hooked; not instrumented with CFG; not in the Win32 API surface at all
- 1ms = `Li.QuadPart = -10000LL`; 1s = `-10000000LL`

**Wiring rule:** Insert `ExecDelaySleep()` at exactly two points in each injection function:
1. After `MmVirtualAlloc` (dissociates alloc->protect gap)
2. After `MmVirtualProtect` / before `NtCreateThreadEx` (dissociates protect->execute gap)

**Config blob positions:** `ExecDelay` = field 25, `ExecDelayJitter` = field 26 — both after
`InjectSpoofOffset` in both `builder.go AddInt` sequence and `Demon.c ParserGetInt32` sequence.
`H_FUNC_NTDELAYEXECUTION = 0xf5a936aa` (DJB2 verified 2026-05-28).

---

### Lesson 24: Profile-to-UI Pipeline (Payload.cc)

**Problem:** A new profile field (e.g., `ExecDelay`) was wired through the full teamserver
pipeline and stored in `HavocX::Teamserver.DemonConfig`, but the `Payload.cc` dialog
initialized the corresponding `QLineEdit` with a hardcoded `"0"` instead of reading from
the profile JSON. The operator's profile setting was silently ignored.

**Pipeline:**
```
havoc.yaotl  →  profile.Config.Demon  →  json.Marshal  →  events.SendProfile
  →  "Demon" field in InitConnection.Profile packet
  →  HavocX::Teamserver.DemonConfig (QJsonDocument, stored in Packager.cc)
  →  Payload.cc DemonConfig["FieldName"].toXxx() at dialog construction
```

**JSON key = Go struct field name.** The `Demon` struct in `config.go` has no `json:` tags,
so `json.Marshal` uses Pascal-case field names: `ExecDelay`, `ExecDelayJitter`, `RandGadget`, etc.

**Rule:** Every new field in `Payload.cc` backed by a profile value must read from `DemonConfig`
at construction — never use a hardcoded literal. Patterns:
- `new QLineEdit( QString::number( DemonConfig[ "ExecDelay" ].toInt() ) )`
- `DemonConfig[ "RandGadget" ].toBool()`
- `DemonConfig[ "SleepCipher" ].toString()`
- `DemonConfig[ "ProcessInjection" ].toObject()[ "Spawn64" ].toString()`

When `toInt()` is called on an absent JSON key, Qt returns `0` — identical to the old
hardcoded default — so there is no regression when the profile field is unset.

---

### Lesson 26: Revert and Change Discipline

**Problem:** Using `git checkout <commit> -- <file>` to revert a change replaces the entire
file with the committed version, silently discarding all working-tree improvements that were
never committed — including multi-hour UI changes, new config fields, and refactors.

**Rule 1 - Surgical changes only:** When reverting, use the `Edit` tool to replace only the
exact lines that need to change. The rest of the file is untouched.

**Rule 2 - Backup before revert:** Before touching any file for a revert, write its current
content to `/tmp/<filename>-backup`. Proceed only after the backup exists.

**Rule 3 - Never use commits as source of truth:** Commits are infrequent and predate
in-session changes. Use `Read` on the current working-tree file to understand current state.
Git history is for audit only — not for restoration.

