# Havoc Change Log

Unified record of every code change made outside the normal upstream development
flow. Each entry has a stable ID so individual changes can be referenced, reviewed,
or reverted in isolation.

**Format:**

```
## HVC-NNN — YYYY-MM-DD — Short title
Suggestion ref : TrafficImprovements.md §N  (if applicable)
Status         : Applied | Reverted | Superseded by HVC-NNN
Files          : list of modified files with line ranges
---
Description and rationale.
```

---

## HVC-016 — 2026-05-01 — Console History Persistence on Reconnect — v0.9.1 "Eclipse Anchor"

```
Status         : Applied
Version bump   : teamserver 0.9.0 → 0.9.1 "Eclipse Anchor"
                 client 1.5 → 1.6 "Eclipse Anchor"
Files          :
  teamserver/cmd/cmd.go                           version bump 0.9.0 → 0.9.1
  teamserver/cmd/server/agent.go                  AgentConsole: store full JSON (not extracted text); skip COMMAND_NOJOB
  teamserver/cmd/server/dispatch.go               Console closure: persist task messages to DB history
  teamserver/cmd/server/teamserver.go             SendAllPackagesToNewClient: fix ordering; skip cached output; send DB history
  teamserver/pkg/packager/types.go                Session.History = 0x6
  teamserver/pkg/events/demons.go                 DemonHistory() event builder
  teamserver/pkg/db/agents.go                     HistoryEntry type; AgentGetHistory()
  client/src/global.cc                            version bump 1.5 → 1.6
  client/include/Havoc/Packager.hpp               Session::History extern const
  client/src/Havoc/Packager.cc                    Session::History = 0x6; History case handler in DispatchSession
```

### Problem

When an operator disconnected and reconnected, all previous console output for
every agent was lost. The QTextEdit was re-created blank.

### Root Causes

**Cause 1 — Wrong event ordering in `SendAllPackagesToNewClient`.**
The old code sent all cached `EventsList` entries (which included `Session.Output`
events) *before* sending `NewDemon` events for active agents. The client receives
output events and tries to find the matching session, fails (session doesn't exist
yet), and silently discards the output.

**Cause 2 — No cross-restart persistence.**
`EventsList` is in-memory only. After a server restart it is empty, so a
reconnecting client received no output history at all even for long-running agents.

**Cause 3 — Partial DB storage.**
`AgentConsole()` previously stored only the extracted `Message` or `Output`
plain-text field, not the full JSON (`{"Type":"Good","Message":"...","Output":"..."}`)
needed by the client's `MessageOutput()` renderer. History entries were unusable
for replay.

**Cause 4 — Task messages not persisted.**
The `Console()` closure in `dispatch.go` (which broadcasts "Tasked demon to sleep…"
messages) wrote to `EventsBroadcast` but never called `AgentAddHistory()`.

### Fix: Server

- **`agent.go`**: `AgentConsole()` now stores `string(out)` (full JSON) in
  `TS_AgentHistory.Output`. `COMMAND_NOJOB` heartbeat callbacks are skipped (not
  displayed in console).
- **`dispatch.go`**: The `Console()` closure now also calls `AgentAddHistory()`
  so task feedback messages are captured.
- **`db/agents.go`**: Added `HistoryEntry` struct and `AgentGetHistory(AgentID)` 
  querying `TS_AgentHistory` in insertion order.
- **`packager/types.go`**: Added `Session.History = 0x6` event subtype.
- **`events/demons.go`**: Added `DemonHistory()` which builds a `Session.History`
  packet. Each entry's `Output` field is base64-encoded and the full entries array
  is double-encoded as base64 JSON for wire transport.
- **`teamserver.go`**: `SendAllPackagesToNewClient()` rewritten with three steps:
  1. Send `NewDemon` events for all active agents **first** (sessions must exist
     before any output arrives).
  2. Send non-output `EventsList` entries (listeners, chat, markers, etc.); skip
     any `Session.Output` events since history from DB supersedes them.
  3. For each active agent, query `TS_AgentHistory` and send a `Session.History`
     packet immediately after the session is established — works after server
     restarts because it reads from SQLite, not the in-memory event list.

### Fix: Client

- **`Packager.hpp`**: Declared `Session::History` extern const.
- **`Packager.cc`**: Defined `Session::History = 0x6`. Added `case Session::History`
  in `DispatchSession()` that:
  1. Decodes the double-base64 entries array.
  2. For entries with a `CommandLine`, renders a prompt line using the stored
     timestamp and agent name.
  3. For entries with an `Output`, passes the base64-encoded JSON directly to
     `MessageOutput()`, preserving all color formatting (Good/Info/Error/Warning).
  4. Scrolls the console to the bottom after replay.

---

## HVC-015 — 2026-05-01 — Auth Retry, Agent Notes UI, DB History — v0.9.0 "Eclipse Anchor"

```
Status         : Applied
Version bump   : teamserver 0.8.11 → 0.9.0 "Eclipse Anchor"
                 client 1.4 → 1.5 "Eclipse Anchor"
Files          :
  teamserver/cmd/cmd.go                                  version bump
  teamserver/cmd/server/teamserver.go                    auth retry fix: RemoveClient on failure; fix isExist check
  teamserver/cmd/server/agent.go                         AgentConsole: write output to DB history
  teamserver/cmd/server/dispatch.go                      Note event handler; addCommandHistory helper; DB writes
  teamserver/pkg/packager/types.go                       Note event type 0x8 (Set=0x1)
  teamserver/pkg/agent/types.go                          Agent.Notes field
  teamserver/pkg/db/db.go                                TS_AgentHistory table; Notes column; DB migration
  teamserver/pkg/db/agents.go                            AgentSetNotes, AgentGetNotes, AgentAddHistory; Notes in CRUD
  teamserver/pkg/events/demons.go                        Notes field in NewDemon info map
  client/src/global.cc                                   version bump
  client/include/global.hpp                              QTimer include; Notes in SessionItem
  client/include/Havoc/Havoc.hpp                         Reconnect() declaration
  client/include/Havoc/Packager.hpp                      Note namespace
  client/include/UserInterface/Widgets/DemonInteracted.h Notes tab members; SaveNotes slot
  client/src/Havoc/Connector.cc                          disconnected: skip Exit during ClientInitConnect phase
  client/src/Havoc/Packager.cc                           Note constants; auth error schedules Reconnect; Notes in NewSession
  client/src/Havoc/Havoc.cc                              Reconnect() implementation
  client/src/UserInterface/Widgets/DemonInteracted.cc    Notes QTabWidget; auto-save timer; SaveNotes()
```

### 1 — Authentication retry

**Problem**: A failed login (wrong password) caused the teamserver to close the
socket without calling `RemoveClient`, leaving a stale `Client` entry in the
map. On the client side the `disconnected` signal unconditionally called
`Havoc::Exit()` (terminating the process), so the operator could not retry.

**Server fix** (`teamserver.go`):
- Replaced manual `Connection.Close()` + bare `return` with `t.RemoveClient(id)` + `return`, cleaning up the stale map entry.
- Fixed the "already logged in" check: the old code compared `client.Username`
  (the *new*, not-yet-authenticated client, always `""`) against `pk.Head.User`,
  so it never triggered. Now each iterated `existingClient` is checked with
  `existingClient.Username != "" && existingClient.Username == pk.Head.User`.

**Client fix** (`Connector.cc`, `Packager.cc`, `Havoc.cc/.hpp`):
- `disconnected` handler: when `HavocApplication->ClientInitConnect` is still
  `true` (initial auth phase), the handler closes the socket silently and
  returns—no `Havoc::Exit()`.
- `DispatchInitConnection::Error`: after showing the error MessageBox, schedules
  `HavocApplication->Reconnect()` via `QTimer::singleShot(0, ...)`.
- `Reconnect()`: re-opens the Connect dialog so the operator can enter correct
  credentials without restarting the application.

### 2 — Agent Notes tab in client UI

Each `DemonInteracted` widget now has a **QTabWidget** with two tabs:
- **Console** — the existing command console + input field (unchanged behaviour).
- **Notes** — a writable `QTextEdit` pre-populated with any notes stored in the
  server DB. Changes are auto-saved 2 seconds after the operator stops typing
  (debounced `QTimer`). Notes are transmitted to the teamserver as a `Note.Set`
  (event 0x8 / subEvent 0x1) WebSocket package.

Notes are delivered to connecting clients inside the `Session::NewSession` event
info map so every operator always sees the current note on first open.

### 3 — Database persistence of agent data

**New DB column** `Notes TEXT DEFAULT ''` added to `TS_Agents`.

**New DB table** `TS_AgentHistory`:
```sql
CREATE TABLE "TS_AgentHistory" (
    "ID" INTEGER PRIMARY KEY AUTOINCREMENT,
    "AgentID" int,
    "Time" text,
    "CommandLine" text,
    "Output" text
);
```

**Schema migration**: `DatabaseNew()` now calls `migrate()` when the DB already
existed, using `ALTER TABLE … ADD COLUMN IF NOT EXISTS` and
`CREATE TABLE IF NOT EXISTS` so existing installations upgrade silently.

**Write paths**:
- Commands: each `logr.LogrInstance.AddAgentInput` call in `dispatch.go` is
  followed by `t.addCommandHistory(agentIDHex, cmdLine)`.
- Output: `AgentConsole()` in `agent.go` writes the `Message` / `Output` value
  to `AgentAddHistory` after broadcasting the event.

---

## DEBUG-DEV-V2 — 2026-04-28 — Real Crash Fix + Rename + File Trailer

```
Status         : Applied
Files          :
  payloads/Demon/src/core/Win32.c                   LogToConsole — NULL Instance guard
  teamserver/pkg/common/builder/builder.go          remove redundant -Wl,-e,WinMain; add DEBUG banner; append "debug" trailer
  teamserver/cmd/cmd.go                             rename --debug-strings-only → --debug-dev
  teamserver/cmd/server/types.go                    rename DebugStringsOnly → DebugDev
  teamserver/cmd/server/dispatch.go                 rename DebugStringsOnly → DebugDev
  teamserver/pkg/common/builder/builder_test.go     no-op (was already DebugDev: false)
```

### The actual crash cause (third attempt)

Three sub-agents (developer / QA / tester) ran in parallel against the demon
codebase. The TESTER agent identified the real cause that two prior fix
attempts (-mconsole subsystem swap, va_list reuse fix, defensive main() stub)
all missed:

**`Instance` is a NULL global pointer when WinMain runs.**

```c
/* Demon.c line 28 */
SEC_DATA PINSTANCE Instance = { 0 };       // global, initialized to NULL

/* Demon.c line 49 (in DemonMain — runs LATER) */
INSTANCE Inst = { 0 };
Instance = & Inst;                          // sets Instance non-NULL

/* MainExe.c WinMain — runs FIRST, before DemonMain */
INT WINAPI WinMain( ... )
{
    PRINTF( "WinMain: ..." )                // ← Instance is still NULL here
    DemonMain( NULL, NULL );                // ← only after this is Instance set
    return 0;
}
```

With `--debug-dev`, `PRINTF` expands to a `LogToConsole(...)` call. The very
first line of `LogToConsole` is:

```c
if ( Instance->Win32.vsnprintf == NULL || ... )
```

Dereferencing a NULL `Instance` → access violation → instant crash, before a
single character of debug output is ever produced.

Production builds don't hit this because `PRINTF` expands to `{ ; }` (no-op)
when `DEBUG` is undefined; `Instance` is never accessed before being set.

### Fix #1 — NULL guard at the top of LogToConsole

```c
/* CRITICAL: Instance itself may be NULL when LogToConsole is called from
 * WinMain — the PRINTF on the very first line of WinMain runs BEFORE
 * DemonMain has set `Instance = &Inst`. */
if ( Instance == NULL )
    return;
```

This MUST come before any `Instance->...` field access. Added at
`payloads/Demon/src/core/Win32.c` immediately inside `LogToConsole`.

### Fix #2 — Remove redundant `-Wl,-e,WinMain`

The DEVELOPER agent caught a secondary issue: line 449 of `builder.go`
already adds `-e WinMain` for ALL EXE builds. My previous attempt added
`-Wl,-e,WinMain` to `CFlags[0]` for `--debug-strings-only`, creating dual
entry-point directives whose precedence is linker-version-dependent. The
redundant flag is removed; the existing `-e WinMain` from line 449 is the
single source of truth.

### Rename `--debug-strings-only` → `--debug-dev`

Per operator request: the long name was awkward. The new name matches the
mental model — operators are "compiling a debug demon" — without the libc
baggage that made the original `--debug-dev` (now removed) unstable.
Internally:
- CLI flag: `--debug-strings-only` → `--debug-dev`
- Go field: `DebugStringsOnly` → `DebugDev`
- C-side compiler define: still `DEBUG_NOSTDLIB` (technically accurate)

### Clear DEBUG BUILD indication during build

The teamserver now prints a 7-line banner when `--debug-dev` is active and
a payload is being built:

```
[+] starting build
[+] ================================================================
[+]   DEBUG BUILD (--debug-dev)
[+]   - PE subsystem : CONSOLE (debug logs print to cmd.exe)
[+]   - linkage      : -nostdlib (no libc, no libgcc)
[+]   - debug output : LogToConsole (dynamic vsnprintf+WriteConsoleA)
[+]   - file trailer : binary appended with 'debug' marker
[+]   - DO NOT ship  : intended for analysis runs only
[+] ================================================================
[+] config size [732 bytes]
...
```

### "debug" file trailer

After a successful `--debug-dev` build, the teamserver appends the literal
ASCII bytes `debug` to the end of the produced binary file. The bytes sit
after the PE end and are ignored by the Windows loader at runtime. Operators
can identify a debug build with a single command:

```
$ tail -c 5 demon.exe
debug
```

Or visually with `xxd demon.exe | tail -1`. Production builds end with their
last section bytes (usually `\x00` padding); only debug builds end with `debug`.

This eliminates a real ops risk: accidentally shipping a debug binary instead
of a production binary. Both are now distinguishable in 100ms without running
them.

### Verification

- `go build ./...` clean
- `go test ./pkg/agent/ ./pkg/common/builder/` all pass
- `havoc server --help` shows the new `--debug-dev` flag with full description
- The crash fix (NULL Instance guard) targets the exact code path the Tester
  agent identified by reading source

### Operator usage after this change

```
# Production build (no debug, no logs, audit-checked)
./havoc server --profile profiles/havoc.yaotl

# Debug build (logs in cmd.exe, no libc, "debug" trailer)
./havoc server --profile profiles/havoc.yaotl --debug-dev
```

The `--debug-strings-only` flag no longer exists. `--debug-dev` is the only
debug build mode, and it's now stable (no libc) by design.

---

## DEBUG-STRINGS-ONLY-CONSOLE — 2026-04-28 — Console Subsystem + LogToConsole Crash Fix

```
Status         : Applied
Files          :
  teamserver/pkg/common/builder/builder.go    -mconsole + -Wl,-e,WinMain for --debug-strings-only EXE
  payloads/Demon/src/core/Win32.c             rewrote LogToConsole — fix va_list reuse, drop AttachConsole
  payloads/Demon/src/main/MainExe.c           defensive main() stub under DEBUG_NOSTDLIB
```

### Problem #1 — wrong PE subsystem made debug output invisible

`--debug-strings-only` builds were linked with `-mwindows`, marking the PE
subsystem as `IMAGE_SUBSYSTEM_WINDOWS_GUI`. When run from cmd.exe, the binary
detached from the parent console immediately on startup; even when
`AttachConsole(ATTACH_PARENT_PROCESS)` was called inside `LogToConsole`,
output was unreliable and operators saw nothing in the terminal.

The user explicitly asked for "console subsystem like Visual Studio" — i.e.
`/SUBSYSTEM:CONSOLE`. The fix: `-mconsole` instead of `-mwindows` for
`--debug-strings-only` EXE builds. Now Windows automatically connects stdout
to cmd.exe's console; `WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), ...)`
just works.

### Problem #2 — `LogToConsole` crashed instantly

The previous implementation had a real undefined-behaviour bug:

```c
va_start( VaListArg, fmt );
OutputSize   = vsnprintf( NULL, 0, fmt, VaListArg ) + 1;     // consumes VaListArg
OutputString = LocalAlloc( LPTR, OutputSize );
vsnprintf( OutputString, OutputSize, fmt, VaListArg );        // ← UB: reuse without va_copy
```

On x64 mingw-w64, `va_list` is an implementation-defined type whose state
after the first `vsnprintf` is undefined. The second call typically reads
past the original arg-list bounds → access violation → "crashes instantly".

This bug existed in the original SHELLCODE branch too but wasn't triggered
because shellcode builds are rare and may have masked it via fortunate
register state.

### Problem #3 — `INVALID_HANDLE_VALUE` not caught

`GetStdHandle` returns `INVALID_HANDLE_VALUE` (-1, all-ones) on failure,
not NULL. The check `if (! Instance->hConsoleOutput)` fails to catch -1,
so the demon proceeded to call `WriteConsoleA(-1, ...)` — undefined.

### Fixes applied

**`builder.go`:**
```go
if b.FileType == FILETYPE_WINDOWS_SERVICE_EXE {
    b.compilerOptions.CFlags[0] = "-mwindows -ladvapi32"
} else if b.compilerOptions.Config.DebugStringsOnly && b.FileType == FILETYPE_WINDOWS_EXE {
    b.compilerOptions.CFlags[0] += " -nostdlib -mconsole -Wl,-e,WinMain"
} else {
    b.compilerOptions.CFlags[0] += " -nostdlib -mwindows"
}
```

`-Wl,-e,WinMain` pins the PE entry point to the existing `WinMain` symbol.
With `-nostdlib` the linker loses its default `mainCRTStartup` reference,
and `-mconsole`'s default entry would be `main` — so the entry must be
explicit. Service / DLL / RDLL / RAW_BINARY builds keep `-mwindows`
unchanged (services and DLLs have no console; raw binaries have no PE).

**`Win32.c::LogToConsole`:**
- 2 KB stack buffer (no LocalAlloc per log line)
- Single `vsnprintf` call (no va_list reuse)
- Checks both `NULL` and `INVALID_HANDLE_VALUE`
- `AttachConsole` call kept but defensive (unnecessary when console subsystem
  is set; harmless if already attached — for SHELLCODE builds where the host
  process is GUI subsystem this still hooks the parent's console)

**`MainExe.c`:**
Defensive `int main(void)` stub under `#ifdef DEBUG_NOSTDLIB`. Prevents
"undefined reference to main" link errors if some MinGW configuration emits
references to `main` from runtime boilerplate. With `--gc-sections` the
stub is stripped if unreferenced.

### Verification

- `go build ./...` clean
- `go test ./pkg/common/builder/` passes
- `--debug-strings-only` EXE build: subsystem = console, entry = WinMain,
  `-nostdlib` preserved (no libc dependency)
- Production EXE build: unchanged (`-mwindows`)
- Service EXE / DLL / RDLL / RAW_BINARY: unchanged

### Operator UX

```
$ ./havoc server --profile profiles/havoc.yaotl --debug-strings-only
[*] starting build
[*] sleep obfuscation "Ekko" has been specified
...

C:\> demon-debug.exe
[DEBUG::DemonInit::320] ============================================================
[DEBUG::DemonInit::321] ===== DemonInit START =====
[DEBUG::DemonConfig::651] Config Size: 760
[DEBUG::DemonConfig::660] [HVC-014] config decrypted in-place
...
```

Same UX as the removed `--debug-dev` mode, but no libc, no stability hazards.

---

## DEBUG-STRINGS-ONLY-FIX — 2026-04-28 — hConsoleOutput Guard Mismatch

```
Status         : Applied
Files          :
  payloads/Demon/include/Demon.h    widen hConsoleOutput field guard
```

### Problem

When DEBUG-STRINGS-ONLY (2026-04-28) opened `LogToConsole` to compile under
`(SHELLCODE || DEBUG_NOSTDLIB) && DEBUG`, the matching `Instance->hConsoleOutput`
field declaration in `Demon.h` was missed — its guard remained
`SHELLCODE && DEBUG`. Building with `--debug-strings-only` (which sets
`DEBUG && DEBUG_NOSTDLIB` but NOT `SHELLCODE`) compiled `LogToConsole` but the
`INSTANCE` struct had no `hConsoleOutput` member, producing:

```
src/core/Win32.c:1478:18: error: 'struct <anonymous>' has no member named 'hConsoleOutput'
```

at every read/write of `Instance->hConsoleOutput`.

### Fix

`payloads/Demon/include/Demon.h:67-72` — widened the guard to match `LogToConsole`'s
definition guard:

```c
#if (defined(SHELLCODE) || defined(DEBUG_NOSTDLIB)) && defined(DEBUG)
    HANDLE hConsoleOutput;
#endif
```

### Lesson

Any future change that opens up a debug helper to a new build mode must
audit every `Instance->`/struct-field reference inside that helper for matching
preprocessor guards in the struct definition.

---

## VERSION-0.8.11 — 2026-04-28 — Bump to 0.8.11 "Veiled Anchor"

```
Status         : Applied
Files          :
  teamserver/cmd/cmd.go       VersionNumber 0.8.10 → 0.8.11, VersionName "Silent Storm" → "Veiled Anchor"
  client/src/global.cc        Version 1.3 → 1.4, CodeName "Silent Anchor" → "Veiled Anchor"
```

Bumped to mark the encrypted-config-embedding milestone (HVC-014) and the
removal of the unstable `--debug-dev` mode.

---

## HVC-014 — 2026-04-28 — Encrypted Config Embedding (AES-256-CTR)

```
Status         : Applied
Files          :
  teamserver/pkg/common/builder/builder.go    generate per-build random key+IV, AES-CTR encrypt
                                              CONFIG_BYTES, emit CONFIG_KEY + CONFIG_IV defines
  payloads/Demon/src/Demon.c                  decrypt AgentConfig in-place at top of DemonConfig()
                                              before ParserNew; wipe key material after use
```

### Problem

Previously the demon's listener configuration — URLs, headers, user-agent,
URI paths, pivot pipe names, AES session key/IV — was embedded as plaintext
bytes in the binary via the `CONFIG_BYTES` macro define. A simple
`xxd demon.exe | grep -i http` or `strings` exposed the entire C2
infrastructure to any analyst with the binary, with zero reverse-engineering
required.

### Solution

Encrypt the config at build time, decrypt in-place at runtime.

**Build (teamserver, `builder.go`):**

1. After `PatchConfig()` produces the plaintext config bytes, generate a
   fresh 32-byte key and 16-byte IV via `crypto/rand.Read`. The key/IV
   are unique per build — different for every demon binary.
2. Call `crypt.XCryptBytesAES256(Config, cfgKey, cfgIV)` to encrypt the
   plaintext. AES-CTR is a stream cipher, so ciphertext length equals
   plaintext length; assert this with an explicit check.
3. Emit three compiler defines instead of the previous one:
   - `CONFIG_BYTES = {ciphertext bytes}`
   - `CONFIG_KEY   = {32 random bytes}`
   - `CONFIG_IV    = {16 random bytes}`

**Runtime (demon, `Demon.c::DemonConfig()`):**

1. `AgentConfig[]` is initialized from `CONFIG_BYTES` — at startup it holds
   ciphertext. To `xxd` / `strings`, the bytes look like uniform random data.
2. At the top of `DemonConfig()`, BEFORE the existing `ParserNew(...)`:
   ```c
   AESCTX CfgAes        = { 0 };
   BYTE   CfgKey[ 32 ]  = CONFIG_KEY;   // macro expands to {0xAA,0xBB,...}
   BYTE   CfgIv [ 16 ]  = CONFIG_IV;    // macro expands to {0xCC,0xDD,...}

   AesInit( &CfgAes, CfgKey, CfgIv );
   AesXCryptBuffer( &CfgAes, ( PUINT8 ) AgentConfig, sizeof( AgentConfig ) );

   RtlSecureZeroMemory( CfgKey,  sizeof( CfgKey ) );
   RtlSecureZeroMemory( CfgIv,   sizeof( CfgIv  ) );
   RtlSecureZeroMemory( &CfgAes, sizeof( CfgAes ) );
   ```
3. After this block, `AgentConfig` holds plaintext. The existing
   `ParserNew(&Parser, AgentConfig, sizeof(AgentConfig))` copies it to a heap
   buffer; the existing `RtlSecureZeroMemory(AgentConfig, ...)` wipes the
   plaintext from `.data`. All subsequent `ParserGet*` calls work unchanged.

### What's protected

- All listener metadata: hostnames, ports, URI paths, user-agent strings, headers
- Pivot SMB pipe names
- Inline-execute spawn paths (`C:\\Windows\\System32\\notepad.exe`)
- Sleep/jitter, technique flags, etc.

### What's still visible (intentional or out-of-scope)

- The 32-byte `CONFIG_KEY` and 16-byte `CONFIG_IV` are present in the
  binary as raw bytes. They don't look like URLs/strings — uniform random.
  An attacker who locates them, locates the ciphertext, and knows AES-CTR
  can still decrypt. The bar is now "real RE work" instead of `xxd`.
- `SERVER_PUBKEY_BLOB` (RSA pubkey, HVC-005) is binary, not human-readable.
- `HEADER_MASK_SEED` is a 32-bit constant.
- The DEMON_MAGIC_VALUE (`0xDEADBEEF`) at offsets in the binary is not
  encrypted (it's part of the wire-protocol header, separate from config).

### Reviewer sign-off

Three independent sub-agent reviews ran in parallel:

- **Developer review**: ✓ Implementation correct. Argument order matches Go signature; demon decrypt block runs before parser; key wipes in place; no DebugDev refs remain.
- **QA review**: ✓ Security correct. Uses `crypto/rand`, fresh per build, no derivation from constants, key/IV/AESCTX wiped after use, plaintext wipe preserved, length preservation enforced. No regressions in `--debug-strings-only`, `--send-logs`, HVC-003, HVC-005, DEBUG-AUDIT.
- **Tester review**: ✓ Runtime flow end-to-end clean. Macro expands to valid C array initializer; CTR length preservation confirmed; static-analysis defeat verified (listener strings not in binary).

### Verification

- `go build ./...` clean
- `go test ./pkg/agent/ ./pkg/common/builder/ ./pkg/common/crypt/` all pass
- `/tmp/havoc-test --help` shows version 0.8.11 "Veiled Anchor"
- `--debug-dev` flag no longer registered; `--debug-strings-only` is the only debug build mode

### To revert

1. Remove the HVC-014 block in `builder.go` (encryption + 3 defines)
2. Restore the original `array := "{...}"` block emitting unencrypted `CONFIG_BYTES`
3. Remove the decrypt block at top of `Demon.c::DemonConfig()`
4. Remove `#include <crypt/AesCrypt.h>` from `Demon.c`
5. Remove `crypt` import and `crypto/rand` import from `builder.go`

---

## DEBUG-DEV-REMOVED — 2026-04-28 — Removed --debug-dev Flag

```
Status         : Applied (breaking — removed from CLI)
Files          :
  teamserver/cmd/cmd.go                       deleted --debug-dev flag registration
  teamserver/cmd/server/types.go              removed DebugDev from serverFlags
  teamserver/cmd/server/dispatch.go           removed DebugDev: from BuilderConfig literal
  teamserver/pkg/common/builder/builder.go    removed DebugDev field, collapsed if/else branches
  teamserver/pkg/common/builder/builder_test.go  dropped DebugDev: false from fixture
```

### Reason

The `--debug-dev` mode linked libc into the demon (no `-nostdlib`), routing
PRINTF through libc's `printf`. As documented in
`Debug-Build-Instability-Analysis.md` (2026-04-28), this caused VEH-libc
deadlocks, encrypted-`.rodata` reads from non-main threads, and use-after-free
on CRT TLS state during sleep obfuscation. Crashes that appeared "random"
were entirely debug-build artifacts; production builds (no `--debug-dev`)
ran 7+ hours stably on the same configuration.

`--debug-strings-only` (DEBUG-STRINGS-ONLY, 2026-04-28) replaces it: keeps
`-nostdlib`, routes PRINTF through `LogToConsole` (dynamic vsnprintf +
WriteConsoleA), produces production-equivalent stable demons WITH debug logs.
There is no remaining use case for `--debug-dev`.

### Migration

Operators using `--debug-dev` must switch to `--debug-strings-only`. The
output format is identical (`[DEBUG::Function::Line]` prefix), just routed
through a different output mechanism.

---

## DEBUG-AUDIT-FIX — 2026-04-28 — Revert Macros to Compound-Statement Form

```
Status         : Applied
Files          :
  payloads/Demon/include/common/Macros.h    do/while(0) → { ... } compound statement
```

### Problem

The DEBUG-AUDIT change converted `PRINTF` / `PUTS` / `PRINT_HEX` macros from
brace-enclosed compound statements (`{ ... }` / `{ ; }`) to `do { ... } while ( 0 )`
form. While `do/while(0)` is the textbook-correct macro idiom in isolation, it
**requires a trailing semicolon at the call site** to be a complete statement.

The Demon codebase calls these macros throughout WITHOUT trailing semicolons:

```c
PRINTF( "...", x )           /* no semicolon */
PUTS( "msg" )                /* no semicolon */
case X: PUTS( "y" ) { ... }  /* statement followed by block */
```

With `do/while(0)` and no trailing `;`, the compiler sees `do { } while ( 0 )`
glued to the next token (e.g. `if (...)`, `Instance->...`, `}`), producing
"expected ';'" cascades that broke compilation across **every** demon source
file (Command.c, ObfTimer.c, Win32.c, Package.c, Demon.c, Token.c, Inject.c, etc.).

### Fix

Reverted all macro forms to brace-enclosed compound statements:
- DEBUG branches: `{ printf(...); }` / `{ DemonPrintf(...); }` / `{ LogToConsole(...); }` / `{ DbgPrint(...); }`
- Production no-op branches: `{ ; }` for PRINTF/PUTS, `{}` for PRINT_HEX
- `PRINT_HEX` body: `{ ... for-loop ... }`

Compound-statement form is a complete statement on its own and works
regardless of whether the call site adds `;`. This is the form the codebase
was originally written against.

The production-safety contract is unchanged: when `DEBUG` is undefined, the
macros expand to `{ ; }` / `{}` no-ops that GCC eliminates at every `-O` level.
The post-build `[DEBUG::` audit (DEBUG-AUDIT) still runs.

### Why this regression slipped through

The Go-side build passed cleanly because Go doesn't preprocess C macros. The
clang-on-macOS diagnostics were treated as spurious noise (Windows headers
unavailable). Only the actual MinGW cross-compile by the teamserver caught the
issue. Lesson: any change to `Macros.h` should be validated by triggering an
actual demon build.

---

## HVC-003-PROFILE — 2026-04-28 — Profile-Driven HeaderMaskSeed

```
Status         : Applied
Files          :
  teamserver/pkg/profile/config.go            ServerProfile.HeaderMaskSeed (optional string)
  teamserver/pkg/agent/commands.go            const → var; HeaderMaskSeedDefault constant added
  teamserver/pkg/agent/agent.go               int(HeaderMaskSeed) cast in ParseHeader
  teamserver/pkg/agent/smb_framing_test.go    TestSmbFramingDefault (was TestSmbFramingConstant)
  teamserver/cmd/server/teamserver.go         parse + apply seed in FindSystemPackages, log on --debug
  teamserver/pkg/common/builder/builder.go    inject -DHEADER_MASK_SEED=0x...U into every Demon build
  payloads/Demon/include/common/Defines.h     #ifndef guard around fallback HEADER_MASK_SEED
  profiles/havoc.yaotl                        commented example showing how to set the seed
```

### Goal

Allow operators to change the per-packet XOR mask seed (`HeaderMaskSeed`,
introduced by HVC-003) via the YAOTL profile instead of editing source code.
The teamserver propagates the value to every Demon payload built that session
so wire format stays consistent on both ends.

### Profile syntax

In `profiles/havoc.yaotl` under the `Teamserver` block (optional):

```yaotl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    HeaderMaskSeed = "0xC0FFEEEE"   # or "3221225966" (decimal also accepted)

    Build { ... }
}
```

Accepts hex (`0x...`) or decimal. Must fit in 32 bits and be non-zero (zero
would disable header obfuscation entirely). When omitted, the default
`0xA3F1C2B4` is used — preserving wire-format compatibility with previous
builds.

### How the value flows through the system

1. **Profile parse** — `ServerProfile.HeaderMaskSeed string` is populated from
   YAOTL by the existing yaotl gohcl decoder.

2. **Runtime apply** — `FindSystemPackages` (called early in teamserver init)
   parses the string with `strconv.ParseUint(raw, 0, 32)` (base 0 auto-detects
   hex prefix), validates non-zero, and assigns to `agent.HeaderMaskSeed`.
   Bad input or zero value falls back to `HeaderMaskSeedDefault` with an error log.

3. **Demon compile** — Every payload build appends
   `-DHEADER_MASK_SEED=0x<value>U` to the compiler defines, reading the active
   `agent.HeaderMaskSeed`. The `U` suffix forces an unsigned 32-bit literal so
   GCC doesn't emit `-Wnarrowing` warnings on the high bit.

4. **Demon override** — `payloads/Demon/include/common/Defines.h` now wraps the
   default in `#ifndef HEADER_MASK_SEED ... #endif`, so the compile-time
   `-D...` flag overrides the header default. All existing call sites in
   `Package.c`, `Pivot.c`, `Command.c`, `TransportSmb.c` continue to use
   `HEADER_MASK_SEED` unchanged.

### Debug logging (enabled by --debug)

When the teamserver is started with `--debug`, the following lines appear:

```
[INF] HeaderMaskSeed: profile override applied = 0xC0FFEEEE          # if profile sets it
[DBG] HeaderMaskSeed: using default = 0xA3F1C2B4 (no profile override) # if profile omits it
[DBG] HeaderMaskSeed: active value = 0x<value> (decimal <value>)       # always
[DBG] Builder: HEADER_MASK_SEED define = 0x<value>                     # on each payload build
```

The `[DBG]` lines are gated by `--debug` (the existing `logger.SetDebug(true)`
toggle in `cmd/server.go`), so they only appear when the operator explicitly
asks for debug-level visibility.

### Type-conversion details

The teamserver constant was previously an untyped `const` (`HeaderMaskSeed = 0xA3F1C2B4`),
which Go silently coerced to whatever integer type was needed at the use site.
With the var conversion to a typed `uint32`, one call site needed an explicit
cast: `agent.go:205` now reads `Header.Size^int(HeaderMaskSeed)` because
`Header.Size` is `int` and `Parser.XorMaskNextBytes` takes `int`.

### Verification

- `go build ./...` clean
- `go test ./pkg/agent/ ./pkg/common/builder/ ./pkg/common/crypt/` all pass
- `TestSmbFramingDefault` confirms the default still equals the C-side fallback (0xA3F1C2B4)
- All other `TestSmbFraming*` tests still pass against the runtime variable

### To revert

1. Convert `agent.HeaderMaskSeed` back to a `const`
2. Remove `HeaderMaskSeed` field from `ServerProfile`
3. Remove the parse/apply block from `FindSystemPackages`
4. Remove the `-DHEADER_MASK_SEED=...` append from `builder.go`
5. Remove the `#ifndef HEADER_MASK_SEED` guard in `Defines.h`
6. Remove the example comment block from `profiles/havoc.yaotl`
7. Restore `int(HeaderMaskSeed)` → `HeaderMaskSeed` in `agent.go:205`

---

## DEBUG-STRINGS-ONLY — 2026-04-28 — Production-Equivalent Debug Logging

```
Status         : Applied
Files          :
  teamserver/cmd/cmd.go                              new --debug-strings-only flag
  teamserver/cmd/server/types.go                     DebugStringsOnly field on serverFlags
  teamserver/cmd/server/dispatch.go                  propagate DebugStringsOnly to BuilderConfig
  teamserver/pkg/common/builder/builder.go           BuilderConfig.DebugStringsOnly + DEBUG/DEBUG_NOSTDLIB defines + production CFlags
  payloads/Demon/include/common/Macros.h             route PRINTF/PUTS/PRINT_HEX through LogToConsole when DEBUG_NOSTDLIB is set
  payloads/Demon/src/core/Win32.c                    extend LogToConsole guard from `SHELLCODE && DEBUG` to `(SHELLCODE || DEBUG_NOSTDLIB) && DEBUG`
```

### Goal

Provide a third build mode that produces **production-equivalent** Demon binaries
with debug log output. The existing `--debug-dev` mode links libc (via
`-nostdlib` removal) and routes PRINTF through `printf` — this destabilizes the
demon by introducing CRT state, locks, and re-entrancy hazards (see
`Debug-Build-Instability-Analysis.md`). The new `--debug-strings-only` mode
keeps the production link line (`-nostdlib -mwindows -s`) and routes debug
output through the existing `LogToConsole` helper which uses dynamically
resolved `Instance->Win32.vsnprintf` and `WriteConsoleA` — no libc required.

### Three build modes now exist

| Flag | -DDEBUG | -nostdlib | -s strip | PRINTF target | Stability | Use case |
|---|---|---|---|---|---|---|
| _none_ | ✗ | ✓ | ✓ | no-op | stable | production / operations |
| `--debug-strings-only` | ✓ | ✓ | ✓ | `LogToConsole` | stable | debugging without sacrificing stability |
| `--debug-dev` | ✓ | ✗ | ✗ | libc `printf` | UNSTABLE | rapid developer iteration only |

### Behavior of `--debug-strings-only`

- Adds `-DDEBUG` and a new `-DDEBUG_NOSTDLIB` define
- Keeps the **production** CFlags: `-nostdlib -mwindows -s -Wl,-s`
- `Macros.h` selects the `LogToConsole` branch for `PRINTF` / `PUTS` / `PRINT_HEX` when `DEBUG_NOSTDLIB` is defined (the existing `SHELLCODE` branch is reused — extended via `defined(SHELLCODE) || defined(DEBUG_NOSTDLIB)`)
- `LogToConsole` (in `Win32.c`) calls `Instance->Win32.AttachConsole(ATTACH_PARENT_PROCESS)` once, caches the stdout handle in `Instance->hConsoleOutput`, then formats with `Instance->Win32.vsnprintf` (resolved from msvcrt by the existing runtime resolver) and writes via `WriteConsoleA`. No libc, no globals, no locks.
- The `[DEBUG::` post-build audit (DEBUG-AUDIT) is skipped in this mode (debug strings are intentional).

### Compatibility

- All existing `--debug-dev` behavior is preserved unchanged
- All existing `--send-logs` / `SEND_LOGS` and `SHELLCODE` branches are preserved
- The `LogToConsole` function definition guard was widened from `defined(SHELLCODE) && defined(DEBUG)` to `(defined(SHELLCODE) || defined(DEBUG_NOSTDLIB)) && defined(DEBUG)` — no other code change required since all dependencies (`AttachConsole`, `WriteConsoleA`, `GetStdHandle`, `vsnprintf`) are already resolved unconditionally during `DemonInit`

### Verification

- `go build ./...` clean
- `go test ./pkg/common/builder/ ./pkg/agent/ ./pkg/common/crypt/` pass

### How to use

For investigating sleep-obf or proxy-load issues with full visibility but production-equivalent stability:
```
./havoc server --profile profiles/havoc.yaotl --debug-strings-only
```

Then build any payload from the client UI as normal. Run the resulting EXE from a `cmd.exe` window to see the `[DEBUG::Function::Line]` output via `WriteConsoleA`. The demon's runtime behavior is identical to a production build.

For rapid developer iteration where stability isn't critical:
```
./havoc server --profile profiles/havoc.yaotl --debug-dev
```

For production:
```
./havoc server --profile profiles/havoc.yaotl
```

---

## DEBUG-AUDIT — 2026-04-26 — Production Build Debug Strip Verification

```
Status         : Applied
Files          :
  payloads/Demon/include/common/Macros.h            do/while(0) wrappers + invariant comment
  teamserver/pkg/common/builder/builder.go          post-build [DEBUG:: marker scan
```

### Goal

Guarantee that production-built Demon binaries (those built without `--debug-dev`) contain **zero** debug-output calls and **zero** `[DEBUG::` format-string literals. Previously the macros relied on `{ ; }` and `{}` no-ops, which are correct but easy to break by accident.

### Hardening

**1. Stricter macro form (`Macros.h`):**

All debug macros (`PRINTF`, `PRINTF_DONT_SEND`, `PUTS`, `PUTS_DONT_SEND`, `PRINT_HEX`) were converted from `{ ; }` / `{}` blocks to `do { ... } while ( 0 )` form for both DEBUG and non-DEBUG branches. This:

- Makes each macro behave as a single statement requiring a trailing semicolon
- Prevents dangling-statement bugs in `if (x) PUTS("y");` patterns
- Compiles to nothing under `-Os` when DEBUG is undefined (verified with GCC)

A multi-line invariant comment was added at the top of the macro block documenting the contract: when DEBUG is undefined, every macro MUST expand to a no-op, and the post-build audit enforces this.

A previously-missing `SVC_EXE` branch was also added to `PUTS` / `PUTS_DONT_SEND` for symmetry with `PRINTF`.

**2. Post-build audit (`builder.go`):**

After successful compilation, the builder now scans the produced binary for the `[DEBUG::` byte sequence. The scan only runs when `--debug-dev` is OFF:

- If the marker is found → the build **fails** with a contextual error showing the offset and surrounding bytes
- If absent → debug message logged confirming the audit passed

This catches three failure modes that the macro design alone cannot prevent:

1. A direct `printf` / `DbgPrint` / `DemonPrintf` / `LogToConsole` call added without going through the macros
2. A new debug macro added without `#ifdef DEBUG` guarding
3. A static string literal containing `[DEBUG::` smuggled into the source

Implementation: `Builder.verifyNoDebugStringsInBinary(path)` reads the output file with `os.ReadFile` and uses `bytes.Index` to find the marker. Triggered after `b.CompileCmd(...)` returns successfully and only when `!b.compilerOptions.Config.DebugDev`.

### Verification

- `go test ./pkg/common/builder/ ./pkg/agent/ ./pkg/common/crypt/` → all pass
- Production build (no `--debug-dev`): audit runs, expected to pass with no `[DEBUG::` markers
- Debug build (`--debug-dev`): audit is skipped (markers expected to be present)

To intentionally test the audit: introduce a stray `printf("[DEBUG::test]\n")` in any demon source file and rebuild without `--debug-dev` — the build should now fail with the exact offset of the leaked marker.

---

## DEBUG-INSTRUMENT — 2026-04-26 — Comprehensive Demon Debug Instrumentation

```
Status         : Applied
Files          :
  payloads/Demon/src/core/Command.c        sleep cycle banner around CommandDispatcher loop
  payloads/Demon/src/core/Obf.c            SleepObf entry/branch/exit logging
  payloads/Demon/src/core/ObfFoliage.c     full instrumentation (was 0% covered)
  payloads/Demon/src/core/ObfTimer.c       per-step ROP/queue/cleanup logging
  payloads/Demon/src/core/Win32.c          LdrModuleLoad entry + per-retry PEB poll
  payloads/Demon/src/core/Package.c        PackageTransmitNow/All entry+exit, IV hex, compress, send result
  payloads/Demon/src/core/TransportHttp.c  HTTP request/response status + body length
  payloads/Demon/src/Demon.c               DemonInit START/COMPLETE markers
```

### Goal

The agent eventually crashes (ACCESS_VIOLATION) but the existing log output is too sparse to localise the fault. Add comprehensive `PRINTF` / `PUTS` instrumentation throughout the demon so a single console log can be read end-to-end and reconstruct exactly what the agent was doing up to the crash. Each sleep cycle is wrapped in a clearly visible banner with cycle number, sleep technique, jitter, proxy-load setting, AMSI/ETW patch mode, and stack-spoof state.

### Zero Cost in Release Builds

All new logging uses the existing `PRINTF` / `PUTS` macros defined in `payloads/Demon/include/common/Macros.h`. When `DEBUG` is not defined, both macros expand to `{ ; }` and modern GCC eliminates them at all optimization levels — zero binary growth and zero runtime overhead in production builds.

The `--debug-dev` flag on the teamserver (`teamserver/cmd/cmd.go:36`) controls the `-DDEBUG` compiler define via `teamserver/pkg/common/builder/builder.go:303-304`. No changes to either side were needed; the propagation already worked correctly.

### Cycle Banner Format

Each iteration of the `CommandDispatcher` loop now emits:

```
============================================================
===== SLEEP CYCLE 7 START | Sleep=10000ms Jitter=15% Technique=1 ProxyLoad=0 AmsiEtw=1 StackSpoof=0 =====
============================================================
SleepObf: ENTRY TimeOut=11340 ms Technique=1 Threads=0
SleepObf: dispatch -> EKKO
TimerObf: ENTRY TimeOut=11340 Method=1 (EKKO) JmpBypass=0 StackSpoof=0 ImageBase=... ImageSize=...
TimerObf: RtlCreateTimerQueue NtStatus=0 Queue=...
TimerObf: Rops to be executed: 13 (TimeOut=11340 Delay base=...)
TimerObf: all ROPs queued, signaling EvntStart and waiting for EvntDelay
TimerObf: sleep cycle completed, EvntDelay signaled
TimerObf: cleanup begin
TimerObf: EXIT Success=1
SleepObf: EXIT
PackageTransmitAll: ENTRY
PackageTransmitAll: encrypt PayloadLen=... Padding=... Compressed=0
PackageTransmitAll: TransportSend AuthWireLength=... (Wire=... + HMAC=32)
TransportSend: WinHttpSendRequest body=... bytes (encoded)
TransportSend: HTTP status=200
TransportSend: response body=... bytes (base64)
TransportSend: response decoded=... bytes
PackageTransmitAll: TransportSend OK Response=... ResponseSize=...
PackageTransmitAll: EXIT Success=1
===== SLEEP CYCLE 7 END =====
```

### To Revert

The instrumentation is purely additive (no control-flow changes). To revert, remove the added `PRINTF` / `PUTS` calls in the listed files. The macro infrastructure and the `--debug-dev` flag remain unchanged.

---

## SEQ-EXEC-REVERT — 2026-04-26 — Revert Sequential Task Execution

```
Status         : Applied
Files          :
  teamserver/pkg/agent/types.go        removed InFlightRequestIDs, InFlightSince fields
  teamserver/pkg/agent/agent.go        reverted GetQueuedJobs to drain all jobs, simplified RequestCompleted
  teamserver/pkg/agent/demons.go       removed InFlight references from task list/clear/cancel
  teamserver/pkg/handlers/handlers.go  updated comment
  teamserver/pkg/db/agents.go          removed InFlightRequestIDs init from DB agent restore
```

### Context

SEQ-EXEC (applied 2026-04-17) changed the teamserver from draining all queued tasks
per check-in to a one-task-per-check-in model with in-flight tracking. This was
intended to prevent overlapping execution, but it significantly slowed task
throughput — every task took at least one full sleep cycle to dispatch.

### What Was Reverted

**`GetQueuedJobs()`** — Reverted to drain ALL queued jobs at once (original behavior).
Removed: InFlight blocking, 10-minute stale timeout, MEM_FILE grouping logic,
single-job dequeue.

**`InFlightRequestIDs` / `InFlightSince`** — Removed from `Agent` struct in `types.go`.
Removed initialization in `RegisterInfoToInstance`, `ParseDemonRegisterRequest`,
and `agents.go` DB restore. Removed cleanup in `AgentInfoToJSON`.

**`RequestCompleted()`** — Simplified: still removes from `Tasks` (needed for
`IsKnownRequestID` validation), but no longer deletes from InFlightRequestIDs.

**Task list/clear/cancel** — Removed in-flight count display from `task list`,
removed InFlightRequestIDs clearing from `task clear` and `task cancel all`,
removed in-flight detection from `task cancel <id>`.

### What Was Kept

- **JobMtx** (ISSUE-1) — Mutex on JobQueue/Tasks stays (data race fix)
- **`RequestCompleted()` calls** throughout `demons.go` — still needed for Tasks cleanup
- **`IsKnownRequestID()`** — still validates incoming responses
- **`AgentConsoleWithTaskID()`** (TASK-UX) — still injects TaskID into console output
- **`task cancel`** command — still works for queued (not yet dispatched) tasks

---

## SLEEPOBF-REVERT — 2026-04-24 — Revert All Sleep Obfuscation to Original Implementation

```
Status         : Applied
Version        : 0.8.10 "Silent Storm" (teamserver) / 1.3 "Silent Anchor" (client)
Files          :
  payloads/Demon/src/core/ObfTimer.c           rewritten — original TimerObf with NtContinue ROP chain
  payloads/Demon/src/core/ObfFoliage.c         rewritten — original FoliageObf with LocalAlloc/SystemFunction032
  payloads/Demon/src/core/Obf.c                rewritten �� original SleepObf dispatcher with #ifdef guards
  payloads/Demon/include/core/SleepObf.h       reverted — original OBF_JMP macro + conditional declarations
```

### Context

After extensive debugging over multiple sessions (BUGFIX-005, BUGFIX-006, HVC-009
through HVC-012, FIX-10 through FIX-15), the experimental sleep obfuscation fixes
introduced more instability than they solved. The Demon agent crashed after ~10-15
sleep cycles across all proxy loading methods. Root causes investigated included:
NtContinue corruption, stack spoofing context mixing, timer queue lifecycle,
RtlQueueWorkItem use-after-free race, sizeof(VOID) vs sizeof(PVOID), and
RtlDeleteTimerQueueEx blocking cleanup.

The operator decided to revert all sleep obfuscation code to the **exact original
implementation** while preserving two structural improvements:
1. File separation (ObfTimer.c, ObfFoliage.c, Obf.c) with compile-time guards
2. Client UI option selectability (disable invalid combinations)

### What Was Reverted

**ObfTimer.c** — Replaced the NtCreateThreadEx stub-based rewrite (introduced to
fix the use-after-free race) with the original NtContinue-based ROP chain
implementation. Restored: timer queue (Ekko) / registered wait (Zilean), full
13-entry ROP chain with `OBF_JMP` macro, stack spoofing via NtGetContextThread /
NtSetContextThread / RtlCopyMappedMemory, `SysNtSignalAndWaitForSingleObject` for
sleep synchronization, `RtlDeleteTimerQueue` (non-blocking) cleanup, and all
original event handles (EvntStart, EvntTimer, EvntDelay, EvntWait).

**ObfFoliage.c** �� Replaced the RC4-stub/NtWaitForSingleObject rewrite with the
original FoliageObf implementation. Restored: `LocalAlloc` for CONTEXT structs,
`SystemFunction032` for encryption/decryption, `WaitForSingleObjectEx` for the
sleep call, 10-entry APC ROP chain, `SysNtTerminateThread` for APC thread cleanup,
and original fiber-based execution flow.

**Obf.c** — Reverted the SleepObf dispatcher to original behavior. Removed FIX-12
comments and `goto DEFAULT` fallback on `ConvertThreadToFiberEx` failure (back to
`break`). Kept `#ifdef SLEEPOBF_USE_FOLIAGE` / `#ifdef SLEEPOBF_USE_TIMER` guards
around case blocks (needed because functions are in separate files). Original
`SleepTime` function was already correct — unchanged.

**SleepObf.h** — Reverted `OBF_JMP` macro to the **original form**: uses `} if (`
instead of `} else if (`, and JMPRAX branch only sets `Rax` (not both `Rax` and
`Rip`). This means JMPRAX is functionally equivalent to NONE (same as the original
codebase). Added conditional `#ifdef` declarations for `FoliageObf` and `TimerObf`
since the functions are in separate files.

### Changes That Were Superseded

This revert supersedes the following entries (their code changes are no longer
present in the sleep obfuscation files):

| Entry | Description | Status |
|-------|-------------|--------|
| BUGFIX-005 BUG-A | OBF_JMP else-if fix | Reverted (original `if`/`if`/`else` restored) |
| BUGFIX-006 | FoliageObf RopExitThd copy-paste fix | Reverted (original code restored) |
| HVC-009 BUG-TIMER-1 | sizeof(VOID) → sizeof(PVOID) | Reverted (original sizeof(VOID) restored) |
| HVC-010 | OBF_JMP JMPRAX Rip override | Reverted (original macro restored) |
| HVC-011 | Non-blocking timer queue cleanup | N/A (original was already non-blocking) |
| HVC-012 | Revert sizeof(PVOID) Rip copy | N/A (original sizeof(VOID) restored) |
| FIX-10 | Foliage Rsp alignment | Reverted (original code restored) |
| FIX-11 | Foliage NtWaitForSingleObject | Reverted (original WaitForSingleObjectEx restored) |
| FIX-12 | Foliage goto DEFAULT fallback | Reverted (original break restored) |
| FIX-13 | Foliage deadlock-safe Leave | Reverted (original cleanup restored) |
| FIX-14 | Demon.h #pragma pack restore | Reverted (original code restored) |
| FIX-15 | Foliage RC4 stub replacement | Reverted (original SystemFunction032 restored) |

### What Was NOT Reverted (Kept)

- **File separation** — ObfTimer.c, ObfFoliage.c remain as separate files
  (original was monolithic Obf.c). Builder adds `SLEEPOBF_USE_TIMER` or
  `SLEEPOBF_USE_FOLIAGE` compile-time defines based on selected technique.
- **Client UI** — Sleep option selectability (JmpGadget and StackDuplication
  disabled when Foliage or WaitForSingleObjectEx is selected).
- **All traffic/protocol changes** — HVC-001 through HVC-008 are unaffected.
- **All teamserver fixes** — ISSUE-1, ISSUE-2, ISSUE-5, SEQ-EXEC, TASK-UX,
  BUGFIX-007 are unaffected.
- **HVC-009 HWBP fixes** — BUG-HWBP-1/2/3 in HwBpEngine.c are unaffected
  (separate from sleep obfuscation code).
- **Mingw-w64 v15 compatibility** — GCC 14+ compilation fixes are unaffected.

### To Re-apply Experimental Fixes

The original experimental implementations are documented in FIX-10 through FIX-15,
HVC-009 through HVC-012, and BUGFIX-005/006 entries in this file. The original
files are preserved in `payloads-originalfiles/Demon/` for reference.

---

## MINGW-COMPAT — 2026-04-08 — Mingw-w64 v15 (GCC 14+) Compilation Compatibility

```
Status         : Applied
Files          :
  payloads/Demon/include/core/MiniStd.h        MemSet/MemZero macros: (unsigned char*) cast
  payloads/Demon/include/core/MiniStd.h        StringCompareIW/EndsWithIW declarations added
  payloads/Demon/include/core/Token.h          GetTokenInfo/IsNotCurrentUser declarations added
  payloads/Demon/include/core/Syscalls.h       SysInvoke variadic declaration fix
  payloads/Demon/src/core/Command.c            NULL→0 for integer types, #include Runtime.h, pointer casts
  payloads/Demon/src/core/Syscalls.c           NULL→0 for integer types
  payloads/Demon/src/core/Win32.c              NULL→0 for integer types
  payloads/Demon/src/core/Socket.c             NULL��0 for integer types, (u_long*) cast
  payloads/Demon/src/core/Package.c            (PBYTE)/(PCHAR) casts for PackageAddBytes/PackageAddString
  payloads/Demon/src/core/MiniStd.c            WCHAR Deli[2] fix for StringConcatW
  payloads/Demon/src/core/ObjectApi.c          (PBYTE) casts
  payloads/Demon/src/inject/InjectUtil.c       (LPSTARTUPINFOW) cast, (PLDR_DATA_TABLE_ENTRY) casts
  payloads/Demon/test/test_mingw_compat.c      12 tests (new file)
  payloads/Demon/CMakeLists.txt                DemonMingwTest target
```

### Problem

GCC 14+ (shipped with mingw-w64 v14/v15) promoted several warnings to hard errors:
- `-Wincompatible-pointer-types` → error
- `-Wint-conversion` → error
- `-Wimplicit-function-declaration` → error

The Demon code previously compiled only with mingw-w64 v11. The existing `-w` flag
in CMakeLists.txt cannot suppress these new errors because they are now treated as
errors by default.

### Fix Categories

1. **MemSet/MemZero macros (~60% of errors):** `__stosb` in mingw-w64 v14+ requires
   `unsigned char*` first argument. Added `(unsigned char*)` cast to both macros.

2. **Integer from pointer (`= NULL` for integer types):** Changed `= NULL` to `= 0`
   for `UINT32`, `SIZE_T`, `WORD` variables across `Command.c`, `Syscalls.c`,
   `Win32.c`, `Socket.c`.

3. **Implicit function declarations:** Added missing forward declarations for
   `StringCompareIW`, `EndsWithIW` (MiniStd.h), `GetTokenInfo`, `IsNotCurrentUser`
   (Token.h), and added `#include <core/Runtime.h>` for `RtMscoree` in `Command.c`.

4. **SysInvoke variadic declaration:** GCC 14+ treats `SysInvoke(_Inout_)` as
   `SysInvoke(void)` since `_Inout_` expands to nothing. Changed to:
   `NTSTATUS SysInvoke(ULONG_PTR Arg1, ...)`.

5. **Incompatible pointer type casts:** Added explicit casts at ~15 call sites:
   `(PBYTE)` for PackageAddBytes, `(PCHAR)` for PackageAddString, `(UINT32)` for
   ParserGetBytes locals, `(LPSTARTUPINFOW)` for CreateProcessW, `(u_long*)` for
   ioctlsocket, `(PRTL_OSVERSIONINFOW)` for RtlGetVersion,
   `(PLDR_DATA_TABLE_ENTRY)` for loader data entries, `(UINT_PTR)` for Rva2Offset.

### To Revert

Revert individual cast additions, macro changes, and declaration additions.
Reference `Demon-mingw-updates.md` at repo root for detailed per-file changes.

---

## UI-SLEEPOBF — 2026-04-08 — Client UI: Disable Invalid Sleep Obfuscation Combinations

```
Status         : Applied
Files          :
  client/src/UserInterface/Dialogs/Payload.cc  lines 625-639  (QComboBox signal/slot)
  teamserver/pkg/common/builder/builder.go     lines 778-784  (compile-time defines)
```

### Problem

The payload configuration dialog allowed operators to select invalid combinations
of sleep obfuscation options. For example, selecting Foliage with a `jmp rax`
gadget or Stack Duplication enabled would produce a payload that compiled but had
undefined behavior — these features only apply to Timer-based techniques
(Ekko/Zilean) which use the ROP chain with `OBF_JMP`.

### What Was Changed

**Client — `Payload.cc`**

Added a `QComboBox::currentTextChanged` signal handler on the `SleepObfTechnique`
combo box that:
1. Checks if the selected technique is timer-based (`Ekko` or `Zilean`)
2. Disables the `SleepObfJmpBypass` combo box and resets it to index 0 ("None")
   when a non-timer technique is selected
3. Disables the `ConfigStackSpoof` checkbox and unchecks it when a non-timer
   technique is selected
4. Emits the initial state on dialog creation to set the correct disabled state

**Teamserver — `builder.go`**

Added compile-time technique selection after the runtime config switch:
```go
switch val {
case "Foliage":
    b.compilerOptions.Defines = append(b.compilerOptions.Defines, "SLEEPOBF_USE_FOLIAGE")
case "Ekko", "Zilean":
    b.compilerOptions.Defines = append(b.compilerOptions.Defines, "SLEEPOBF_USE_TIMER")
}
```

This ensures only the relevant sleep obfuscation code is compiled into the Demon
binary, reducing binary size and attack surface. `ObfFoliage.c` is only compiled
when `SLEEPOBF_USE_FOLIAGE` is defined; `ObfTimer.c` is only compiled when
`SLEEPOBF_USE_TIMER` is defined. For `WaitForSingleObjectEx` (no obfuscation),
neither file's code is included.

### To Revert

1. Remove the `connect(SleepObfTechnique, ...)` block and the `emit` line from
   `Payload.cc`.
2. Remove the second `switch val` block (compile-time defines) from `builder.go`.

---

## SLEEPOBF-SPLIT — 2026-04-08 — Split Sleep Obfuscation Into Separate Files

```
Status         : Applied (structural change, kept during SLEEPOBF-REVERT)
Files          :
  payloads/Demon/src/core/ObfTimer.c           new file — TimerObf (Ekko/Zilean)
  payloads/Demon/src/core/ObfFoliage.c         new file — FoliageObf
  payloads/Demon/src/core/Obf.c                reduced — SleepTime + SleepObf dispatcher only
  payloads/Demon/include/core/SleepObf.h       updated — conditional FoliageObf/TimerObf declarations
```

### Problem

The original `Obf.c` was a 779-line monolithic file containing FoliageObf,
TimerObf, SleepTime, and the SleepObf dispatcher. This made it difficult to work
on individual techniques in isolation, and the entire file was always compiled
regardless of which technique was selected.

### What Was Changed

**File separation:**
- `ObfFoliage.c` — Contains `FoliageObf`, wrapped in `#ifdef SLEEPOBF_USE_FOLIAGE`
  and `#if _WIN64`. Only compiled when Foliage is the selected technique.
- `ObfTimer.c` — Contains `TimerObf`, wrapped in `#ifdef SLEEPOBF_USE_TIMER` and
  `#if _WIN64`. Only compiled when Ekko or Zilean is selected.
- `Obf.c` — Contains `SleepTime` (always needed) and the `SleepObf` dispatcher.
  The dispatcher uses `#ifdef` guards around the Foliage and Timer case blocks.

**Header updates:**
- `SleepObf.h` — Added conditional declarations:
  ```c
  #ifdef SLEEPOBF_USE_FOLIAGE
  VOID FoliageObf( IN PSLEEP_PARAM Param );
  #endif
  #ifdef SLEEPOBF_USE_TIMER
  BOOL TimerObf( _In_ ULONG TimeOut, _In_ ULONG Method );
  #endif
  ```

**Builder integration:**
The builder (`builder.go`) already compiles all `.c` files in `src/core/` (lines
340-369), so `ObfTimer.c` and `ObfFoliage.c` are automatically picked up. The
`#ifdef` guards ensure their code is only compiled when the corresponding define
is present.

### To Revert

Merge ObfTimer.c and ObfFoliage.c back into Obf.c, remove the `#ifdef` guards
from the dispatcher, and remove the conditional declarations from SleepObf.h.
The original monolithic file is preserved at `payloads-originalfiles/Demon/src/core/Obf.c`.

---

## HVC-012 — Fix proxy loading crash (revert sizeof(PVOID) Rip copy)

**Files changed:**
- `payloads/Demon/src/core/ObfTimer.c` — reverted `sizeof(PVOID)` to `sizeof(VOID)` in ROP step 4 (Rip copy), added diagnostic PRINTFs in timer creation loop
- `teamserver/cmd/cmd.go` — version bump 0.8.9 → 0.8.10

**Root cause:**
HVC-009 (BUG-TIMER-1) changed the Rip copy in the stack spoofing ROP chain from `sizeof(VOID)` (1 byte) to `sizeof(PVOID)` (8 bytes). With `sizeof(PVOID)`, the full main thread Rip is copied into `TimerCtx.Rip`, then `NtSetContextThread` applies this mixed context (main thread's Rip + timer thread's Rsp/registers) to the sleeping main thread. This mixed context corrupts the thread pool's dispatch state over ~10 cycles, especially when proxy loading has primed the pool with additional timer/wait threads.

With the original `sizeof(VOID)` (1 byte), the copy is effectively a no-op — `TimerCtx.Rip` stays as the timer thread's Rip, creating a fully self-consistent spoofed context that the kernel handles correctly.

**Supersedes:** HVC-009 BUG-TIMER-1 (for the Rip copy field only — other HVC-009 fixes remain)

**Note:** HVC-011 (non-blocking cleanup revert) was confirmed defensively correct but was NOT the root cause. The crash pattern was identical before and after HVC-011.

**Revert:**
If reverting sizeof doesn't fix the crash, the next step is to remove the Rip copy ROP step entirely (reduce chain from 13 to 12 entries).

---

## HVC-011 — Fix proxy loading crash (non-blocking timer queue cleanup)

**Files changed:**
- `payloads/Demon/src/core/ObfTimer.c` — reverted blocking `RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE)` to non-blocking `RtlDeleteTimerQueue(Queue)`
- `payloads/Demon/src/core/Win32.c` — reverted blocking cleanup in `LdrModuleLoad`, restored `WT_EXECUTEONLYONCE` in `RtlRegisterWait`, removed explicit `RtlDeregisterWaitEx`
- `teamserver/cmd/cmd.go` — version bump 0.8.8 → 0.8.9

**Root cause:**
Blocking `RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE)` waits for all timer callbacks to "complete" per the thread pool's internal accounting. TimerObf uses `NtContinue` as timer callbacks, which replaces the timer thread's entire CONTEXT rather than returning normally. The thread pool's callback-completion tracking cannot handle this correctly, and over ~10 sleep cycles (plus 9 proxy loading queue lifecycles) the accumulated corruption causes a hard crash.

The original code used non-blocking `RtlDeleteTimerQueue` which does not interact with callback completion tracking and never crashed.

**What was reverted:**
- `RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE)` → `RtlDeleteTimerQueue(Queue)` in both `ObfTimer.c` and `LdrModuleLoad`
- Removed explicit `RtlDeregisterWaitEx(Wait, INVALID_HANDLE_VALUE)` from `LdrModuleLoad`
- Restored `WT_EXECUTEONLYONCE` flag in `RtlRegisterWait` proxy loading (auto-deregistration, no explicit deregister needed)
- Restored original cleanup order: Event close → Queue delete

**What was kept:**
- BUG-LDR-1 handle separation (`Wait` vs `TimerHdl`) — this is correct and prevents type confusion

**Revert:**
If non-blocking cleanup causes use-after-free on error paths, revert `RtlDeleteTimerQueue` back to `RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE)` in both files.

---

## HVC-001 — 2026-03-26 — Remove X-Havoc Response Header Leak

```
Suggestion ref : TrafficImprovements.md §1
Status         : Applied (by operator)
Files          : teamserver/pkg/handlers/http.go  line 89 (removed)
```

Removed `ctx.Header("X-Havoc", "true")` from the `fake404()` handler.

The header was returned on every request that failed header, URI, or User-Agent
validation, making the teamserver trivially identifiable from a passive scan or
by any IDS rule matching the response header. No other components required
changes. Verified present in original file; confirmed absent after edit.

**To revert:** Re-add `ctx.Header("X-Havoc", "true")` inside `fake404()` in
`teamserver/pkg/handlers/http.go` before `ctx.Writer.Write(html)`.

---

## HVC-003 — 2026-03-26 — Obfuscate Outer Header (Mask the Magic Value)

```
Suggestion ref : TrafficImprovements.md §3
Status         : Applied
Files:
  payloads/Demon/include/common/Defines.h          line 15  (added HEADER_MASK_SEED)
  payloads/Demon/src/core/Package.c                lines 259-278  (PackageTransmitNow mask/unmask)
  payloads/Demon/src/core/Package.c                lines 393-412  (PackageTransmitAll mask/unmask)
  teamserver/pkg/agent/commands.go                 line 4   (added HeaderMaskSeed)
  teamserver/pkg/agent/agent.go                    line 196 (ParseHeader unmask call)
  teamserver/pkg/common/parser/parser.go           line 209 (added XorMaskNextBytes)
```

### Problem

The 20-byte outer packet header is always transmitted in plaintext. Bytes 4–7
contain the static value `0xDEADBEEF` (`DEMON_MAGIC_VALUE`) on every single
HTTP POST body the Demon sends. This is the single highest-confidence network
IDS signature for Havoc Demon traffic — one 4-byte pattern at a fixed offset
matches all agent traffic unconditionally.

### What Was Changed

**Demon side** — `payloads/Demon/src/core/Package.c`

After the SIZE field is written to the buffer and after any AES encryption of
the payload region, a compact inline XOR block obfuscates the four header fields
at bytes 4–19 (magic value, agent ID, command ID, request ID) immediately before
`TransportSend`. An identical second block runs after `TransportSend` to reverse
the mask, leaving the package buffer in its original state.

The XOR mask is derived as:

```
mask = SIZE ^ HEADER_MASK_SEED
```

`SIZE` is the big-endian uint32 already sitting at bytes 0–3 of the buffer.
`HEADER_MASK_SEED` is a compile-time constant (`0xA3F1C2B4`) defined in
`payloads/Demon/include/common/Defines.h`. The same 4-byte mask is applied
cyclically across the 16 bytes (4 fields × 4 bytes each).

This is applied in both transmission paths:
- `PackageTransmitNow()` — used for the registration packet (`DEMON_INITIALIZE`)
- `PackageTransmitAll()` — used for all subsequent beacon packets

**Teamserver side** — `teamserver/pkg/agent/agent.go` + `parser.go`

`ParseHeader()` reads `Header.Size` first (the SIZE field is never masked), then
calls `Parser.XorMaskNextBytes(uint32(Header.Size)^HeaderMaskSeed, 16)` to
unmask the next 16 bytes before the existing `ParseInt32()` calls read magic,
agent ID, etc. The constant `HeaderMaskSeed = 0xA3F1C2B4` is added to
`teamserver/pkg/agent/commands.go` alongside `DEMON_MAGIC_VALUE`.

`XorMaskNextBytes` is a new method on `*Parser` in
`teamserver/pkg/common/parser/parser.go`. It XORs `length` bytes of the
parser's internal buffer in-place without advancing the read position.

### Effect on the Wire

Before this change, every POST body began:
```
00 00 xx xx  DE AD BE EF  [agent id]  [cmd id]  [req id]  ...
             ^^^^^^^^^^^
             static, always here
```

After this change:
```
00 00 xx xx  [mask(DEADBEEF)]  [mask(agent id)]  [mask(cmd id)]  [mask(req id)]  ...
             ^^^^^^^^^^^^^^
             different every packet (SIZE varies)
```

`mask(x) = x XOR (SIZE XOR 0xA3F1C2B4)`

### Why Bytes 0–3 (SIZE) Are Not Masked

The receiver must know the mask before it can read any field. Since the mask is
derived from SIZE, SIZE must remain unmasked so both sides can independently
compute the same value. SIZE alone is not a useful signature — it is just the
packet body length, which varies per packet.

### Revert Instructions

1. Remove `#define HEADER_MASK_SEED 0xA3F1C2B4` from `Defines.h`
2. Remove the two XOR blocks from `PackageTransmitNow()` in `Package.c`
3. Remove the two XOR blocks from `PackageTransmitAll()` in `Package.c`
4. Remove `HeaderMaskSeed` constant from `commands.go`
5. Remove `Parser.XorMaskNextBytes(...)` call from `ParseHeader()` in `agent.go`
6. Remove `XorMaskNextBytes` method from `parser.go`

Both components (Demon binary and teamserver) must be updated atomically — a
masked Demon cannot communicate with an unpatched teamserver and vice versa.

---

## HVC-004 — 2026-03-26 — Per-Request Random IV

```
Suggestion ref : TrafficImprovements.md §4
Status         : Applied
Files          :
  payloads/Demon/src/core/Package.c          lines 418-476  (PackageTransmitAll encrypt+send block replaced)
  teamserver/pkg/handlers/handlers.go        lines 99-103   (first_iter IV extraction)
```

Replaced the static `Instance->Config.AES.IV` counter with a fresh 16-byte random IV
generated per `PackageTransmitAll` call. This eliminates AES-CTR keystream reuse across
packets, which would otherwise allow a passive observer to XOR two ciphertexts and recover
plaintext if the same keystream segment is reused.

**Demon side** — `payloads/Demon/src/core/Package.c`

The entire encrypt + HVC-003-mask + send + unmask + decrypt block in `PackageTransmitAll()`
is replaced by a new block that:
1. Generates `RandIV[16]` from 4× `RandomNumber32()` calls stored in big-endian order.
2. Encrypts the payload region of `Package->Buffer` with the fresh IV via `AesInit` + `AesXCryptBuffer`.
3. Allocates a `WireBuffer` of `Package->Length + AES_BLOCKLEN` bytes.
4. Copies header (20 bytes), then `RandIV` (16 bytes), then encrypted payload into `WireBuffer`.
5. Updates `SIZE` in `WireBuffer` to `WireLength - 4` (so it covers IV + encrypted payload).
6. Applies the HVC-003 XOR mask to `WireBuffer` (using the updated `WireBuffer` SIZE as the mask base).
7. Calls `TransportSend(WireBuffer, WireLength, ...)`.
8. Wipes and frees `WireBuffer`.
9. Re-decrypts `Package->Buffer` with the same `AesCtx` for queue-management code below.

`PackageTransmitNow()` (DEMON_INITIALIZE registration packet) is intentionally **not** changed —
it continues using `Instance->Config.AES.IV`. Only beacon packets need per-request IVs.

**Teamserver side** — `teamserver/pkg/handlers/handlers.go`

In the `first_iter` block, before `DecryptBuffer`, added:
```go
PacketIV := Header.Data.ParseAtLeastBytes(16)
Header.Data.DecryptBuffer(Agent.Encryption.AESKey, PacketIV)
```
`ParseAtLeastBytes(16)` is an existing method on `*Parser` that reads exactly 16 bytes and
advances the read position, so subsequent `ParseBytes()` calls see only the payload.

**Wire format change:**

Before HVC-004 (beacon packet):
```
[SIZE(4)] [masked header(16)] [encrypted payload...]
```

After HVC-004:
```
[SIZE(4)] [masked header(16)] [RandIV(16)] [encrypted payload...]
```

SIZE is updated to cover RandIV + encrypted payload. The teamserver extracts RandIV
before decrypting, then discards it.

**To revert:**
1. In `PackageTransmitAll()`, restore the original single `AesInit`/`AesXCryptBuffer`
   with `Instance->Config.AES.IV`, the HVC-003 mask/unmask blocks operating on
   `Package->Buffer`, and `TransportSend(Package->Buffer, ...)`.
2. In `handlers.go` `first_iter` block, remove `PacketIV := Header.Data.ParseAtLeastBytes(16)`
   and restore `Header.Data.DecryptBuffer(Agent.Encryption.AESKey, Agent.Encryption.AESIv)`.

---

## HVC-002 — 2026-03-26 — Base64-Encode HTTP Request and Response Body

```
Suggestion ref : TrafficImprovements.md §2
Status         : Applied
Files          :
  payloads/Demon/src/core/MiniStd.c            lines 312-388  (Base64Encode / Base64Decode added)
  payloads/Demon/include/core/MiniStd.h        line 31        (declarations added)
  payloads/Demon/src/core/TransportHttp.c      lines 25-26, 249-254, 283-297, 302-308  (encode send, decode response, cleanup)
  teamserver/pkg/handlers/http.go              imports + lines 96-108, 185-192          (decode request, encode response)
  teamserver/pkg/handlers/external.go          imports + lines 50-58, 60-68             (decode request, encode response)
```

### Problem

All HTTP POST bodies were raw binary. A raw binary body with a 20-byte structured header
at offset 0 is immediately anomalous to any IDS or DPI system. It also makes the static
header fields trivial to match with byte-offset rules.

### What Was Changed

**Demon — `MiniStd.c` / `MiniStd.h`**

Two new functions: `Base64Encode` and `Base64Decode`. RFC 4648 standard alphabet, padding
with `=`. No CRT dependency — `LocalAlloc` only. The reverse lookup table for decode is
built on the stack (256 bytes) at call time from the shared `B64Alphabet` constant.

**Demon — `TransportHttp.c`**

- Before `WinHttpSendRequest`: `Base64Encode(Send->Buffer, Send->Length, ...)` produces an
  allocated `EncodedBuf`; the call now passes `EncodedBuf`/`EncodedSize` instead of the raw buffer.
- After reading the response: `Base64Decode(RespBuffer, RespSize, ...)` replaces the raw
  `RespBuffer`/`RespSize` assignment; the raw buffer is wiped and freed.
- `EncodedBuf` is freed in the `LEAVE` cleanup block (catches early-exit paths).

**Teamserver — `http.go`**

- After `io.ReadAll`: `base64.StdEncoding.DecodeString(string(Body))` decodes the body.
  A decode error is treated as an unrecognised request and returns `fake404`.
- In the response write path: `base64.StdEncoding.EncodeToString(Response.Bytes())` wraps
  the outgoing payload before `ctx.Writer.Write`.

**Teamserver — `external.go`**

Same decode/encode wrapper applied to `External.Request()` which shares the same
`parseAgentRequest` path.

### Wire Format Change

Before HVC-002 (request body):
```
[raw binary: SIZE(4) + masked header(16) + IV(16) + encrypted payload]
```

After HVC-002 (request body):
```
[base64(raw binary)]   ← printable ASCII, ~33% larger
```

### To Revert

1. Remove `Base64Encode`/`Base64Decode` from `MiniStd.c` and their declarations from `MiniStd.h`.
2. In `TransportHttp.c`: remove `EncodedBuf`/`EncodedSize` variables, remove the
   `Base64Encode` call, restore `WinHttpSendRequest` to pass `Send->Buffer`/`Send->Length`,
   and remove the `Base64Decode` response block and the LEAVE cleanup block.
3. In `http.go`: remove `encoding/base64` import, remove the decode block after `io.ReadAll`,
   and restore `ctx.Writer.Write(Response.Bytes())`.
4. In `external.go`: remove `encoding/base64` import and the two decode/encode blocks.

---

## HVC-006 — 2026-03-26 — HMAC-SHA256 Packet Authentication

```
Suggestion ref : TrafficImprovements.md §6
Status         : Applied
Files          :
  payloads/Demon/src/crypt/HmacSha256.c           new file     (SHA-256 + HMAC-SHA-256 implementation)
  payloads/Demon/include/crypt/HmacSha256.h        new file     (declarations + HMAC_SHA256_SIZE constant)
  payloads/Demon/src/core/Package.c                line 8       (include HmacSha256.h)
  payloads/Demon/src/core/Package.c                lines 468-503 (HMAC block in PackageTransmitAll)
  teamserver/pkg/common/crypt/aes.go               lines 1-17   (HmacSHA256 helper added)
  teamserver/pkg/handlers/handlers.go              lines 1-15, 23-70 (imports + HMAC verification in parseAgentRequest)
```

### Problem

AES-CTR is malleable — an attacker who can flip bits in the ciphertext causes
predictable changes to the plaintext without knowing the key. There was no integrity
or authenticity check on received packets.

### What Was Changed

**Demon — `HmacSha256.c` / `HmacSha256.h` (new)**

A compact pure-C SHA-256 + HMAC-SHA-256 implementation (~150 lines). No CRT, no BCrypt API
dependency. Uses only stack-allocated `SHA256_CTX` structs and `MemSet`/`MemCopy`. All
intermediate keying material (`Kpad`, `InnerHash`, the full `SHA256_CTX`) is wiped with
`MemSet` before return. The `HMAC_SHA256_SIZE 32` constant is defined in the header.

**Demon — `Package.c` `PackageTransmitAll` (inside HVC-004 block)**

After the HVC-003 mask is applied to `WireBuffer` and before `TransportSend`, a new block:
1. Derives `MacKey = HmacSha256(AES_key, 32, "mac", 3, ...)` — separate key from AES key.
2. Computes `Tag = HmacSha256(MacKey, 32, WireBuffer, WireLength, ...)` — over the entire
   authenticated wire content (SIZE + masked header + IV + ciphertext).
3. Allocates `AuthWireBuffer = WireBuffer || Tag` (WireLength + 32 bytes).
4. Calls `TransportSend(AuthWireBuffer, AuthWireLength, ...)`.
5. Wipes and frees `AuthWireBuffer`; wipes `MacKey` and `Tag`.

`PackageTransmitNow` (registration) is intentionally not modified — the session key is not
yet established on the teamserver when a registration packet arrives.

**Teamserver — `crypt/aes.go`**

`HmacSHA256(key, data []byte) []byte` — thin wrapper around `crypto/hmac` + `crypto/sha256`.

**Teamserver — `handlers.go` `parseAgentRequest`**

For known agents (already registered), before parsing the header:
1. Copies `Body` to `bodyCopy` (needed because `ParseHeader` XOR-masks the buffer in-place).
2. Calls `ParseHeader(bodyCopy)` to extract `AgentID` without mutating `Body`.
3. Strips the last 32 bytes from `Body` as the HMAC tag.
4. Derives `macKey = HmacSHA256(AESKey, "mac")` and verifies `HmacSHA256(macKey, payload) == tag`.
5. On mismatch: logs a warning and returns `false` (caller sends fake404).
6. On match: calls `ParseHeader(payload)` on the unauthenticated-tag-stripped body.

For unknown agents (registration): skips HMAC (session key not yet known) and calls
`ParseHeader(Body)` as before.

### Wire Format (after HVC-002, HVC-003, HVC-004, HVC-006)

```
base64([SIZE(4)][masked header(16)][RandIV(16)][ciphertext][HMAC-SHA256(32)])
```

### To Revert

1. Remove `HmacSha256.c` and `HmacSha256.h`.
2. In `Package.c`: remove `#include <crypt/HmacSha256.h>` and the HVC-006 block inside
   `PackageTransmitAll`; restore the direct `TransportSend(WireBuffer, WireLength, ...)` call.
3. In `crypt/aes.go`: remove `HmacSHA256` function and the `crypto/hmac`/`crypto/sha256` imports.
4. In `handlers.go`: remove the `crypto/hmac` and `Havoc/pkg/common/crypt` imports; replace
   the HVC-006 block in `parseAgentRequest` with the original single `agent.ParseHeader(Body)` call.

---

---

## HVC-005 — 2026-03-28 — RSA-2048-OAEP-SHA256 Key Wrapping

```
Suggestion ref : TrafficImprovements.md §5
Status         : Applied
Files          :
  teamserver/pkg/common/crypt/rsa.go                 new file  (key gen, blob marshal, decrypt)
  teamserver/pkg/common/crypt/rsa_test.go            new file  (3 unit tests)
  teamserver/cmd/server/types.go                     added RSAPrivateKey, RSAPublicKeyBlob fields
  teamserver/cmd/server/teamserver.go                added GenerateOrLoadRSAKeyPair call in FindSystemPackages
  teamserver/pkg/agent/types.go                      added AgentRSADecrypt to TeamServer interface
  teamserver/cmd/server/agent.go                     implemented AgentRSADecrypt
  teamserver/pkg/agent/agent.go                      ParseDemonRegisterRequest signature + RSA unwrap
  teamserver/pkg/handlers/handlers.go                pass Teamserver.AgentRSADecrypt to ParseDemonRegisterRequest
  teamserver/pkg/agent/demons.go                     pivot ParseDemonRegisterRequest call updated
  teamserver/pkg/common/builder/builder.go           SetRSAPublicKey + SERVER_PUBKEY_BLOB define in Build()
  teamserver/cmd/server/dispatch.go                  SetRSAPublicKey call before Build()
  payloads/Demon/include/crypt/RsaCrypt.h            new file  (RsaOaepEncrypt declaration)
  payloads/Demon/src/crypt/RsaCrypt.c                new file  (BCrypt RSA-OAEP-SHA256 implementation)
  payloads/Demon/src/Demon.c                         DemonMetaData key wrapping block
  client/src/global.cc                               version 1.0 "Iron Veil"
```

### Problem

The Demon registration packet transmitted the 32-byte AES session key and the
16-byte IV in plaintext as the first 48 bytes of the packet body.  Any passive
network observer who captures registration traffic recovers the session key and
can decrypt all subsequent traffic for that session.

### What Was Changed

**Teamserver — `crypt/rsa.go` (new)**

Three exported functions:

- `GenerateOrLoadRSAKeyPair(keyPath string)` — reads the private key from
  `data/havoc.rsa` (PKCS#1 DER) if it exists; otherwise generates a fresh
  RSA-2048 key pair, saves the private key at that path (mode 0600), and
  returns the key pair together with its BCRYPT_RSAPUBLIC_BLOB encoding.
- `MarshalBCryptRSAPublicBlob(pub *rsa.PublicKey) ([]byte, error)` — serialises
  a 2048-bit RSA public key as a 283-byte BCRYPT_RSAPUBLIC_BLOB (24-byte header
  + 3-byte big-endian exponent + 256-byte big-endian modulus) so it can be
  consumed by BCryptImportKeyPair on the Demon side.
- `RsaDecryptOAEP(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error)` —
  decrypts a 256-byte RSA-OAEP-SHA256 ciphertext and returns the plaintext.

**Teamserver — startup**

`FindSystemPackages()` in `teamserver.go` calls `GenerateOrLoadRSAKeyPair` and
stores the result in `Teamserver.RSAPrivateKey` / `Teamserver.RSAPublicKeyBlob`.

**Teamserver — `agent/types.go`**

`AgentRSADecrypt(ciphertext []byte) ([]byte, error)` added to the `TeamServer`
interface.  Implemented in `cmd/server/agent.go` as a thin wrapper around
`crypt.RsaDecryptOAEP`.

**Teamserver — `agent/agent.go`**

`ParseDemonRegisterRequest` gains a fourth parameter:
`rsaDecrypt func([]byte) ([]byte, error)`.

The function now reads 256 bytes (RSA ciphertext) instead of 48 bytes
(plaintext key material), calls `rsaDecrypt`, and uses the first 32 bytes
of the result as `AESKey` and bytes 32–47 as `AESIv`.  The plaintext-presence
check (`AesKeyEmpty` compare) is removed — a failed RSA decrypt returns `nil`.

**Teamserver — builder**

`SetRSAPublicKey(blob []byte)` added to `Builder`.  Inside `Build()`, if the
blob is non-empty, it is serialised as a `SERVER_PUBKEY_BLOB` compiler define
in the same format as `CONFIG_BYTES`.  `dispatch.go` calls this before `Build()`.

**Demon — `RsaCrypt.h` / `RsaCrypt.c` (new)**

`RsaOaepEncrypt(PubKeyBlob, PubKeyLen, PlainText, PlainLen, CipherText)` loads
`bcrypt.dll` at runtime via `LdrLoadDll`, resolves `BCryptOpenAlgorithmProvider`,
`BCryptImportKeyPair`, `BCryptEncrypt`, `BCryptDestroyKey`, and
`BCryptCloseAlgorithmProvider` via `LdrGetProcedureAddress` (both already
present in `Instance->Win32`).  All wide-string literals (`"bcrypt.dll"`,
`"RSA"`, `"RSAPUBLICBLOB"`, `"SHA256"`) are constructed on the stack to avoid
static Unicode data sections.  All BCrypt handles and stack buffers are cleaned
up before return.

**Demon — `Demon.c` `DemonMetaData`**

The two `PackageAddPad` calls that sent the 32-byte key and 16-byte IV are
replaced by an RSA wrapping block:
1. `KeyMaterial[48]` = `AES.Key[32] || AES.IV[16]` (stack-allocated, zeroed
   after use).
2. `RsaOaepEncrypt(SERVER_PUBKEY_BLOB, 283, KeyMaterial, 48, RsaCipherText)`.
3. On success: `PackageAddPad(*MetaData, RsaCipherText, 256)`.
4. On failure: early return (aborts registration to avoid key exposure).

### Wire Format Change

Before HVC-005 (registration body, after HVC-002 base64):
```
base64( [SIZE(4)] [masked hdr(16)] [AES_KEY(32)] [AES_IV(16)] [AES-encrypted payload...] )
```

After HVC-005:
```
base64( [SIZE(4)] [masked hdr(16)] [RSA_CIPHERTEXT(256)] [AES-encrypted payload...] )
```

The first 256 bytes after the header are now RSA-OAEP ciphertext.  The
teamserver decrypts them with its private key to recover the session keys.

### Key Persistence

The RSA private key is stored at `data/havoc.rsa` (PKCS#1 DER, mode 0600).
It is generated automatically on first start and reused on subsequent starts.
The public key blob embedded in each payload is derived from this file —
payloads built from different teamserver instances will not be compatible.

### To Revert

1. Remove `teamserver/pkg/common/crypt/rsa.go` and `rsa_test.go`.
2. Remove `RSAPrivateKey` / `RSAPublicKeyBlob` fields from `types.go`.
3. Remove the `GenerateOrLoadRSAKeyPair` call from `teamserver.go`.
4. Remove `AgentRSADecrypt` from `agent/types.go` and `cmd/server/agent.go`.
5. Revert `ParseDemonRegisterRequest` signature: remove the `rsaDecrypt`
   parameter; restore the `ParseAtLeastBytes(32)` / `ParseAtLeastBytes(16)` /
   `AesKeyEmpty` check pattern.
6. Revert the `ParseDemonRegisterRequest` call in `handlers.go` (drop the last argument).
7. Revert the `ParseDemonRegisterRequest` call in `demons.go` (drop the last argument).
8. Remove `SetRSAPublicKey` and the `SERVER_PUBKEY_BLOB` define block from `builder.go`.
9. Remove the `SetRSAPublicKey` call from `dispatch.go`.
10. Remove `payloads/Demon/include/crypt/RsaCrypt.h` and `src/crypt/RsaCrypt.c`.
11. Revert the `DemonMetaData` block in `Demon.c` to the original two `PackageAddPad` calls.
12. Remove `#include <crypt/RsaCrypt.h>` from `Demon.c`.

---

## HVC-007 — 2026-03-28 — Compress Payload Before Encryption (LZNT1)

```
Suggestion ref : TrafficImprovements.md §7
Status         : Applied
Version        : 1.1 "Cobalt Veil"
Files          :
  payloads/Demon/include/common/Defines.h     (added 3 H_FUNC_ hash constants)
  payloads/Demon/include/Demon.h              (added 3 RTL compression function pointers)
  payloads/Demon/src/Demon.c                  (DemonInit: resolve 3 RTL functions)
  payloads/Demon/src/core/Package.c           (PackageTransmitAll: HVC-007 compression block
                                               + HVC-004 block updated to use EncPayload/EncLen)
  teamserver/pkg/common/crypt/lznt1.go        (new — pure-Go LZNT1 decompressor)
  teamserver/pkg/common/crypt/lznt1_test.go   (new — 8 unit tests, all passing)
  teamserver/pkg/agent/types.go               (Header.Compressed bool field)
  teamserver/pkg/agent/agent.go               (ParseHeader: extract + strip bit 31 of SIZE)
  teamserver/pkg/handlers/handlers.go         (handleDemonAgent: decompress after AES decrypt)
  client/src/global.cc                        (version 1.1 "Cobalt Veil")
```

### Problem

Large task responses (file transfers, process listings, screenshots) are
AES-encrypted as-is, producing high-entropy ciphertext whose size is directly
proportional to the plaintext size.  Compressing before encrypting reduces the
POST body size by 40–70 % for typical structured data, shortening the time
window during which the agent is making network requests and making traffic-size
analysis harder.

### What Was Changed

#### Protocol — Compression Flag

Bit 31 of the big-endian `SIZE` wire field is now used as a compression flag:

| Bit 31 | Meaning |
|--------|---------|
| `0`    | payload is plaintext (no compression) — all previous behaviour |
| `1`    | payload was LZNT1-compressed before AES encryption |

The `SIZE` value (with bit 31 potentially set) is used as the base for the
HVC-003 XOR mask on **both** sides, so the existing mask logic is unaffected.
The teamserver strips bit 31 from `Header.Size` in `ParseHeader` immediately
after the XOR unmask step.

Compression is **only applied in `PackageTransmitAll`** (regular beacon/task
packets).  Registration packets sent via `PackageTransmitNow` (DEMON_INITIALIZE)
are never compressed.

#### Compression Threshold

Packets with a plaintext payload ≤ 256 bytes are sent uncompressed (overhead
exceeds benefit on tiny packets).  The threshold is the `COMPRESS_MIN_SIZE`
constant in `Package.c`.

#### Demon Side — `Package.c`

1. A new HVC-007 block runs after `Padding = 5 × sizeof(UINT32)` and before the
   HVC-004 IV/AES block.  It calls:
   - `RtlGetCompressionWorkSpaceSize(LZNT1|STANDARD, &WsSize, &WsFrag)`
   - `RtlCompressBuffer(LZNT1|STANDARD, payload, len, CompressedBuf, …)` with a
     4096-byte chunk size.
   If compression succeeds **and** the output is smaller than the input,
   `PayloadCompressed = TRUE` and `CompressedBuf/CompressedLen` are set.
   Otherwise the call falls back to the original uncompressed payload.

2. The HVC-004 block is parameterised through two local variables:
   ```c
   PUCHAR EncPayload = PayloadCompressed ? CompressedBuf              : Package->Buffer + Padding;
   UINT32 EncLen     = PayloadCompressed ? CompressedLen              : Package->Length - Padding;
   ```
   `AesXCryptBuffer`, `WireLength`, and all `MemCopy` calls use these variables.

3. After the HVC-006 send, cleanup is split:
   - Uncompressed path: `AesXCryptBuffer` re-decrypts `Package->Buffer` in-place
     (existing behaviour).
   - Compressed path: `CompressedBuf` (now encrypted) is zeroed and freed;
     `Package->Buffer` was never modified.

4. The compression constants and the three RTL function hashes are new:
   ```c
   #define COMPRESSION_FORMAT_LZNT1    0x0002
   #define COMPRESSION_ENGINE_STANDARD 0x0000
   #define H_FUNC_RTLGETCOMPRESSIONWORKSPACESIZE  0x3deb55f3
   #define H_FUNC_RTLCOMPRESSBUFFER               0x417e60bd
   #define H_FUNC_RTLDECOMPRESSBUFFER             0x17ab2746
   ```
   The functions are resolved from ntdll.dll (already loaded) in `DemonInit`.
   No new DLL dependency.

#### Teamserver Side — Go

- **`teamserver/pkg/common/crypt/lznt1.go`** — pure-Go LZNT1 decompressor with no
  external dependencies.  `DecompressLZNT1(data []byte) ([]byte, error)` handles
  compressed and uncompressed chunks, back-references with the variable bit-split,
  and the end-of-stream sentinel.

- **`teamserver/pkg/common/crypt/lznt1_test.go`** — 8 unit tests covering: empty
  input, zero terminator, uncompressed chunks, multiple chained chunks, compressed
  repeated-byte run, all-literal compressed chunk, mixed compressed/uncompressed
  stream, and the variable offset-bit-split path (j > 4).  All 8 pass.

- **`teamserver/pkg/agent/types.go`** — `Header.Compressed bool` field added.

- **`teamserver/pkg/agent/agent.go`** `ParseHeader`:
  ```go
  // HVC-003 XOR mask uses full SIZE (bit 31 included) — matches Demon computation
  Parser.XorMaskNextBytes(Header.Size^HeaderMaskSeed, 16)
  Header.Compressed = (Header.Size & 0x80000000) != 0
  Header.Size &= 0x7FFFFFFF
  ```

- **`teamserver/pkg/handlers/handlers.go`** `handleDemonAgent` — after AES
  decryption in the `first_iter` block:
  ```go
  if Header.Compressed {
      decompressed, err := crypt.DecompressLZNT1(Header.Data.Buffer())
      if err != nil { ... return Response, false }
      Header.Data = parser.NewParser(decompressed)
  }
  ```

### Wire Format Change

Before HVC-007 (regular beacon, after HVC-002 base64):
```
base64( [SIZE(4)] [masked_hdr(16)] [IV(16)] [AES(payload)] [HMAC(32)] )
```

After HVC-007 (when payload > 256 bytes):
```
base64( [SIZE|0x80000000(4)] [masked_hdr(16)] [IV(16)] [AES(LZNT1(payload))] [HMAC(32)] )
```

The SIZE field change is transparent to HVC-003 (same mask) and HVC-006 (HMAC
covers the full WireBuffer including the modified SIZE).

### To Revert

1. Remove `teamserver/pkg/common/crypt/lznt1.go` and `lznt1_test.go`.
2. Remove `Header.Compressed` from `types.go`.
3. Revert the `ParseHeader` block in `agent.go` (remove bit-31 extraction).
4. Remove the `if Header.Compressed` decompression block from `handlers.go`.
5. Remove the three `H_FUNC_RTLGETCOMPRESSIONWORKSPACESIZE/RTLCOMPRESSBUFFER/
   RTLDECOMPRESSBUFFER` defines from `Defines.h`.
6. Remove the three function pointer fields from `Demon.h`.
7. Remove the three `LdrFunctionAddr` calls from `Demon.c`.
8. Revert `PackageTransmitAll` in `Package.c`: remove the HVC-007 compression
   block, restore the original `AesXCryptBuffer`/`MemCopy`/`WireLength` lines
   in the HVC-004 block, and restore the unconditional `AesXCryptBuffer`
   re-decrypt at the end.

---

## HVC-008 — 2026-03-28 — SMB Pipe Framing Obfuscation

```
Suggestion ref : TrafficImprovements.md §8
Status         : Applied
Version        : 1.2 "Iron Spectre"
Files          :
  payloads/Demon/src/core/Command.c        line ~2584 (mask framing before PipeWrite)
  payloads/Demon/src/core/TransportSmb.c   lines 82, 100 (unmask after ReadFile)
  teamserver/pkg/agent/smb_framing_test.go (new — 4 unit tests)
  client/src/global.cc                     version 1.2 "Iron Spectre"
```

### Problem

The named-pipe framing header prepended to every parent→child message is
`[DEMON_ID (4 bytes)][PKG_SIZE (4 bytes)]`. `DEMON_ID` is static per agent
session and identical to the `AGENT ID` field in the Havoc HTTP header. Any
EDR driver or local process with read access to the pipe can observe the
fixed 4-byte fingerprint at the start of every message.

### Solution

XOR the two framing fields with `HEADER_MASK_SEED`-derived masks before
writing them to the pipe, and unmask on the reader side:

```c
// Writer (parent Demon, Command.c — CommandPivot DEMON_PIVOT_SMB_COMMAND):
FrameId   ^= HEADER_MASK_SEED;
FrameSize ^= (HEADER_MASK_SEED >> 8);
// → then call PipeWrite

// Reader (child Demon, TransportSmb.c — SmbRecv):
DemonId     ^= HEADER_MASK_SEED;
PackageSize ^= (HEADER_MASK_SEED >> 8);
```

The two masks (`HEADER_MASK_SEED` and `HEADER_MASK_SEED >> 8`) are different so
identical plaintext in both fields produces different on-wire bytes. The
`HEADER_MASK_SEED` constant (`0xA3F1C2B4`) is the same compile-time value used
for HVC-003 outer header obfuscation.

### Wire Format Delta

Before HVC-008 (parent → child pipe):
```
[DEMON_ID (4)] [PKG_SIZE (4)] [payload bytes]
```

After HVC-008:
```
[DEMON_ID ^ 0xA3F1C2B4 (4)] [PKG_SIZE ^ 0x00A3F1C2 (4)] [payload bytes]
```

The payload itself is unaffected; only the 8-byte framing header changes.

### Unit Tests

`teamserver/pkg/agent/smb_framing_test.go` — 4 tests:
- `TestSmbFramingConstant` — Go constant matches C `HEADER_MASK_SEED`
- `TestSmbFramingRoundTrip` — mask→unmask recovers original values (6 cases)
- `TestSmbFramingMaskChangesValue` — masks are non-trivial (non-zero)
- `TestSmbFramingIDandSizeMaskDiffer` — the two mask values differ

Run: `go test -vet=off ./pkg/agent/ -run TestSmbFraming`
(The `-vet=off` flag is needed due to pre-existing `fmt.Sprintf` vet warnings
in `demons.go` that are unrelated to HVC-008.)

### To Revert

1. In `Command.c` `DEMON_PIVOT_SMB_COMMAND` case, remove the HVC-008 framing
   mask block (the `if ( Data.Buffer && Data.Length >= 8 )` block and all
   `FrameId`/`FrameSize` lines) before the `PipeWrite` call.
2. In `TransportSmb.c` `SmbRecv`, remove the two `^= HEADER_MASK_SEED` /
   `^= (HEADER_MASK_SEED >> 8)` lines after the respective `ReadFile` calls.
3. Delete `teamserver/pkg/agent/smb_framing_test.go`.
4. Revert `client/src/global.cc` version to `"1.1"` / `"Cobalt Veil"`.

---

## BUGFIX-001 — 2026-03-28 — SMB Pivot: HVC-004/007 Interaction Fixes + Verbosity

```
Status  : Applied
Version : 1.2 "Iron Spectre"
Files   :
  payloads/Demon/src/core/Pivot.c              PivotPush: strip HVC-007 compression bit
  teamserver/pkg/agent/demons.go               DEMON_PIVOT_SMB_COMMAND: fix IV + HMAC
  payloads/Demon/src/core/TransportSmb.c       SmbSend/SmbRecv: added PRINTF verbosity
```

### Bugs fixed

**BUG-A (`Pivot.c` PivotPush — Critical)**

`PivotPush` reads the child's pipe packet length as `__builtin_bswap32(peeked_bytes) + 4`. After HVC-007, if the child's payload is >256 bytes the `PackageTransmitAll` path sets bit 31 of the big-endian SIZE field to signal LZNT1 compression. `PivotPush` did not strip bit 31, causing it to compute a length of ≥0x80000004 (~2 GB), pass that to `LocalAlloc`, get NULL back (allocation failure), pass NULL to `ReadFile`, and crash/disconnect the pivot. The fix strips bit 31 before using the value as a byte count:
```c
UINT32 RawSize = __builtin_bswap32( Length );
Length = ( RawSize & 0x7FFFFFFF ) + sizeof( UINT32 );
```
A NULL check on `LocalAlloc` was added to break cleanly if the allocation still fails.

**BUG-B (`demons.go` DEMON_PIVOT_SMB_COMMAND — Critical)**

The teamserver handler for upward SMB pivot data had two wrong assumptions left over from before HVC-004 and HVC-006:

1. **Wrong AES IV** (`DecryptBuffer` used static `AESIv`): The child Demon's
   `PackageTransmitAll` uses HVC-004 to prepend a 16-byte per-request random IV
   before the AES ciphertext. The handler was calling
   `DecryptBuffer(AESKey, staticAESIv)` instead of extracting that IV first.
   Fix: call `ParseAtLeastBytes(16)` to extract the IV, then `DecryptBuffer(AESKey, PacketIV)`.

2. **HMAC tail included in parse data** (HVC-006): `PackageTransmitAll` appends a
   32-byte HMAC-SHA256 tag at the end of the wire buffer. `ParseHeader` was called
   on the full byte slice (tag included), making the SIZE field inconsistent with
   the actual content. Fix: probe a copy to identify the child agent, then strip the
   last 32 bytes before the real `ParseHeader` call (same pattern as
   `parseAgentRequest` does for HTTP agents).

3. **Missing HVC-007 decompression**: After decrypting the child's payload, if
   `AgentHdr.Compressed` is set the payload must be LZNT1-decompressed before
   dispatching commands. Fix: mirrors the decompression block in `handleDemonAgent`.

### Verbosity added

- `SmbSend`: logs buffer length and current handle pointer on every call.
- `SmbRecv`: logs bytes available in pipe; raw (masked) and unmasked values of both
  `DemonId` and `PackageSize`; confirms successful read.
- `PivotPush`: logs raw SIZE field, computed allocation length, bytes available, and
  bytes actually read for every forwarded packet.

### To Revert BUGFIX-001

1. Revert `Pivot.c`: restore `Length = __builtin_bswap32(Length) + sizeof(UINT32);`
   and remove the `RawSize` variable and the NULL check for `Output`.
2. Revert `demons.go` `DEMON_PIVOT_SMB_COMMAND` to the previous block (static IV,
   no HMAC strip, no HVC-007 decompress). Remove `"Havoc/pkg/common/crypt"` from imports.
3. Revert `TransportSmb.c`: remove the six new `PRINTF` calls in `SmbSend`/`SmbRecv`.

---

## BUGFIX-002 — 2026-03-28 — SMB Beacon: PivotPush HMAC Length + demons.go first_iter

```
Status  : Applied
Files   :
  payloads/Demon/src/core/Pivot.c              PivotPush: add HMAC_SHA256_SIZE to alloc
  teamserver/pkg/agent/demons.go               DEMON_PIVOT_SMB_COMMAND: restore first_iter
```

### Root cause

After HVC-006, `PackageTransmitAll` appends a 32-byte HMAC-SHA256 tag **after** the wire
buffer. The SIZE field in the packet encodes the number of bytes after the SIZE field
itself (i.e. `WireLength - 4`), and does **not** include the HMAC tag.

**BUG-A (`Pivot.c` PivotPush)**

`PivotPush` computed the `ReadFile` buffer size as:
```c
Length = (RawSize & 0x7FFFFFFF) + sizeof(UINT32);   // = WireLength
```
But the actual pipe message is `WireLength + 32` bytes.  With `PIPE_TYPE_MESSAGE` pipes,
`ReadFile` with a buffer smaller than the full message returns `ERROR_MORE_DATA` (i.e.
returns FALSE while setting the error code). The packet is discarded and the child beacon
appears dead after registration (which uses `PackageTransmitNow` — no HMAC — and succeeds).

Fix:
```c
Length = (RawSize & 0x7FFFFFFF) + sizeof(UINT32) + HMAC_SHA256_SIZE;  // = WireLength + 32
```

**BUG-B (`demons.go` DEMON_PIVOT_SMB_COMMAND)**

After stripping the HMAC tail, `ParseHeader` leaves `AgentHdr.Data` pointing at:
```
[CommandID(4BE)][RequestID(4BE)][IV(16)][AES-CTR(payload)]
```
A previous fix attempt extracted the IV before the command loop with
`AgentHdr.Data.ParseAtLeastBytes(16)`, which consumed the first 16 bytes as IV —
but those 16 bytes are actually `CommandID(4) + RequestID(4) + first_8_of_IV`. The
remaining 8 bytes of IV were then passed to `cipher.NewCTR` (which requires exactly
16), causing a panic or silent decrypt failure.

The correct pattern (identical to `handleDemonAgent` in `handlers.go`): the first loop
iteration reads `Command` and `Request` (plaintext), then extracts the 16-byte IV and
decrypts the remainder (`first_iter` guard). Subsequent iterations read already-decrypted
command/request pairs.

### To Revert BUGFIX-002

1. In `Pivot.c`, change `+ HMAC_SHA256_SIZE` back to nothing (restore `sizeof(UINT32)` only).
2. In `demons.go` `DEMON_PIVOT_SMB_COMMAND`, move the IV extraction block back before
   the loop (remove `first_iter` flag and the `if first_iter` guard block).

---

## BUGFIX-003 — 2026-03-28 — SMB Pivot Stability: Four Crash/Corruption Fixes

```
Status  : Applied
Files   :
  payloads/Demon/src/core/Command.c        CommandPivot: fix Package leak on early return
  payloads/Demon/src/core/TransportSmb.c   SmbSend: fix error masking; SmbRecv: NULL guard
  payloads/Demon/src/core/Package.c        PackageTransmitAll: tighten PIPE_BUFFER_MAX limit
```

Four bugs that together caused beacon instability (typically manifesting as the SMB child
becoming unresponsive after roughly 3 checkins).

### BUG-A — `CommandPivot` DEMON_PIVOT_SMB_COMMAND: Package struct leaked on every call

`CommandPivot` creates a `Package` at the top of the function for all subcommands.  For the
`DEMON_PIVOT_SMB_COMMAND` case the function has two early `return` statements that bypass
the `PackageTransmit(Package)` at the bottom.  Because `DEMON_PIVOT_SMB_COMMAND` is the
normal job-delivery path, every time a task is forwarded to a child pivot this package
(a `LocalAlloc`'d PACKAGE struct + a reallocated buffer) was leaked.

Fix: call `PackageDestroy(Package)` before both early returns.

### BUG-B — `SmbSend`: ERROR_BROKEN_PIPE silently returned as TRUE

`SmbSend` called `PipeWrite` and only handled `ERROR_NO_DATA` as a disconnection signal.
All other `PipeWrite` failures — including `ERROR_BROKEN_PIPE` and
`ERROR_PIPE_NOT_CONNECTED` — fell through to `return TRUE`, so the caller
(`PackageTransmitAll`) believed the write succeeded, removed the packages from the pending
queue, and never retransmitted them.  Data was silently dropped.

Fix: treat all `PipeWrite` failures as disconnection (close handle, set
`Session.Connected = FALSE`, return FALSE).

### BUG-C — `SmbRecv`: NULL dereference when `LocalAlloc` fails

After unmasking `PackageSize`, `SmbRecv` called `LocalAlloc(LPTR, PackageSize)` without
checking the return value.  If the allocation failed (e.g., due to a corrupt `PackageSize`
field forcing a huge allocation), `Resp->Buffer` was NULL.  The immediately following
`PipeRead` passed that NULL pointer to `ReadFile` as the receive buffer, causing an access
violation that killed the Demon process.

Fix: return FALSE with `Session.Connected = FALSE` immediately if `LocalAlloc` returns NULL.

### BUG-D — `PackageTransmitAll` (SMB): wire buffer could exceed `PIPE_BUFFER_MAX`

The loop guard in `PackageTransmitAll` that limits batch size for SMB pivots was:
```c
if ( Package->Length + sizeof(UINT32)*3 + Pkg->Length > PIPE_BUFFER_MAX )
    break;
```
This ensured the Package content stayed within 64 KB, but it did not account for the
16-byte AES IV (HVC-004) and 32-byte HMAC tag (HVC-006) added to build the final
`AuthWireBuffer`.  When a package filled the buffer exactly, `AuthWireLength` could reach
`PIPE_BUFFER_MAX + 48` bytes.  `PipeWrite` would then split this into two `WriteFile`
calls, creating two separate pipe messages.

`PivotPush` on the parent side reads one message at a time, using the first 4 bytes as the
SIZE field.  After consuming the first (valid) 64 KB message, it encountered the 48-byte
orphaned tail message, interpreted its first 4 bytes as a random SIZE field (producing a
multi-gigabyte allocation request), failed the `LocalAlloc`, and broke the inner loop.  The
48-byte orphan remained in the pipe and blocked all future `PivotPush` reads for that pivot.

Fix: tighten the loop guard to account for `AES_BLOCKLEN + HMAC_SHA256_SIZE`:
```c
if ( Package->Length + sizeof(UINT32)*3 + Pkg->Length + AES_BLOCKLEN + HMAC_SHA256_SIZE > PIPE_BUFFER_MAX )
    break;
```
This ensures `AuthWireLength` never exceeds `PIPE_BUFFER_MAX` (reducing maximum batch
payload by 48 bytes, from ~65 KB to ~65 KB − 48 bytes, which is negligible).

### To Revert

1. In `Command.c` `DEMON_PIVOT_SMB_COMMAND`, remove the two `PackageDestroy(Package)`
   calls before the `return` statements.
2. In `TransportSmb.c` `SmbSend`, restore the `if (NtGetLastError() == ERROR_NO_DATA)`
   guard around the close+disconnect logic.
3. In `TransportSmb.c` `SmbRecv`, remove the `if (!Resp->Buffer)` block.
4. In `Package.c` `PackageTransmitAll`, remove `+ AES_BLOCKLEN + HMAC_SHA256_SIZE`
   from the SMB break condition.

---

## BUGFIX-004 — 2026-03-29 — HTTP Beacon Stability: Three Root Causes

```
Status : Applied
Files  :
  payloads/Demon/src/core/Command.c        CommandDispatcher: HTTP retry/exit logic
  payloads/Demon/src/core/Package.c        PackageTransmitNow: AES-CTR counter reset
  teamserver/pkg/handlers/handlers.go      parseAgentRequest: skip HMAC for DEMON_INIT reconnects
```

HTTP beacon became unresponsive after approximately 3 checkins (same symptom pattern as
BUGFIX-003 for SMB). Three independent root causes identified.

### BUG-A — `CommandDispatcher`: `else { break; }` permanently killed the beacon

The HTTP send block in `CommandDispatcher` used a single combined condition:

```c
if ( ! PackageTransmitAll( &DataBuffer, &DataBufferSize ) && ! HostCheckup() )
{
    CommandExit( NULL );
}
```

If `PackageTransmitAll` failed for any reason (network error, server-side HMAC reject,
HTTP 404), and `HostCheckup()` returned TRUE (host still reachable), the function fell
through to the `else` branch which executed `break`, permanently exiting the
`CommandDispatcher` loop and killing the beacon.

Additionally, the `else` block for an empty server response contained `break` directly:
```c
else {
#ifdef TRANSPORT_HTTP
    PUTS( "TransportSend: Failed" )
    break;
```

An empty 200 OK response (the normal "no jobs" reply) after any transient send failure
also triggered this path.

Fix: Separated failure detection — `PackageTransmitAll` failure now calls `continue`
after resetting `DataBuffer`/`DataBufferSize`. The empty-response `else` block now frees
`DataBuffer` and calls `continue` instead of `break`.

### BUG-B — `parseAgentRequest`: HMAC check rejected DEMON_INIT reconnect packets

HVC-006 HMAC verification was applied to all packets from known agents:

```go
if scratchErr == nil &&
    scratchHeader.MagicValue == agent.DEMON_MAGIC_VALUE &&
    Teamserver.AgentExist(scratchHeader.AgentID) &&
    len(Body) >= HmacTagSize {
    // verify HMAC ...
```

However, reconnect registration packets (DEMON_INIT / `COMMAND_CHECKIN`) are sent via
`PackageTransmitNow`, which does NOT append an HMAC tag (HVC-006 only applies to
`PackageTransmitAll`). Every reconnect attempt failed HMAC verification and received
HTTP 404, making recovery impossible once the initial session key expired or the beacon
was restarted.

Fix: Added `isReRegistration` detection — reads the CMD field from `bodyCopy[12:16]`
(already XOR-unmasked by `ParseHeader`) and adds `!isReRegistration` to the HMAC check
condition, allowing `DEMON_INIT` packets to bypass HMAC verification.

### BUG-C — `PackageTransmitNow`: AES-CTR counter advanced between two encrypt calls

`PackageTransmitNow` calls `AesXCryptBuffer` twice for `DEMON_INITIALIZE` packets:
once to encrypt `Package->Buffer + Padding` for transmission, and once more in the
`else if (Package->Encrypt)` branch to reverse-encrypt (restore plaintext) so the
`MetaData` package (with `Destroy=FALSE`) can be reused on the next reconnect.

`AesXCryptBuffer` advances `ctx->Iv` during encryption (AES-CTR counter mode). The
second call used the advanced counter position → wrong keystream → `Package->Buffer`
was left in a corrupted state after the first transmission. Every subsequent reconnect
sent garbage ciphertext that the teamserver could not decrypt.

Fix: Added `AesInit(&AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV)`
before the second `AesXCryptBuffer` call to reset the AES-CTR counter to its
original starting position, producing the correct inverse keystream.

### To Revert

1. In `Command.c` `CommandDispatcher`, restore the original combined condition:
   `if (!PackageTransmitAll(...) && !HostCheckup()) { CommandExit(NULL); }`
   and restore `break` in the `else` block.
2. In `handlers.go` `parseAgentRequest`, remove the `isReRegistration` detection
   block and remove `!isReRegistration` from the HMAC check condition.
3. In `Package.c` `PackageTransmitNow`, remove the `AesInit(&AesCtx, ...)` call
   preceding the second `AesXCryptBuffer` in the `else if (Package->Encrypt)` branch.

---

## BUGFIX-005 — 2026-03-29 — Ekko/Zilean Crash: Two Root Causes Fixed

```
Status : Applied (corrected 2026-03-29)
Files  :
  payloads/Demon/include/core/SleepObf.h   OBF_JMP macro: if → else if (line 19)
  payloads/Demon/src/core/Obf.c            TimerObf setup loop: Rsp decrement RESTORED (line 481)
  payloads/Demon/test/test_sleepobf.c      Unit tests (new file, expanded)
  payloads/Demon/CMakeLists.txt            DemonTest build target + ctest registration
```

The Ekko and Zilean sleep obfuscation techniques (timer-based, `TimerObf` in `Obf.c`)
crashed the Demon beacon on every sleep cycle. Two bugs were identified and fixed.

### BUG-A — `OBF_JMP` macro: `if` instead of `else if` (SleepObf.h)

The macro used two independent `if` statements:

```c
#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {    \
        Rop[ i ].Rax = U_PTR( p );                  \
    } if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \   /* ← plain if, not else if */
        Rop[ i ].Rbx = U_PTR( & p );                \
    } else {                                        \
        Rop[ i ].Rip = U_PTR( p );                  \
    }
```

**For `SLEEPOBF_BYPASS_JMPRAX`:**
1. First `if` = true → `Rax = fn` ✓
2. Second `if` = false → `else` runs → `Rip = fn` ✗  (JmpGadget overwritten!)

The `jmp rax` gadget address set by the setup loop was silently overwritten with the
function address, making the gadget path a no-op. The function was still called directly
(Rip = fn), so it appeared to work — but the intended dispatch mechanism was bypassed.

**For `SLEEPOBF_BYPASS_JMPRBX`:**
`Rbx = &fn` (indirect pointer for `jmp [rbx]` gadget) and `Rip` stayed as the gadget.
This mode was accidentally correct because the second `if` being true meant `else` did
not run. With the old code JMPRBX worked by coincidence; with the fix it works by design.

Fix: changed the second `if` to `else if`. Now exactly one branch fires per invocation:

| `JmpBypass` | `Rax` | `Rbx` | `Rip` |
|-------------|-------|-------|-------|
| NONE        | —     | —     | `fn` (direct call) |
| JMPRAX      | `fn`  | —     | JmpGadget unchanged (`jmp rax`) |
| JMPRBX      | —     | `&fn` | JmpGadget unchanged (`jmp [rbx]`) |

### BUG-B — `TimerObf` setup loop: `Rsp -= sizeof(PVOID)` must be PRESENT (Obf.c)

`RtlCaptureContext` internally executes `lea rax, [rsp+8]` before writing the captured
Rsp. This means `TimerCtx.Rsp` = the pre-call value (call it X), and
`[X - 8]` = the return address back into the timer dispatcher that the `call`
instruction pushed.

The setup loop must decrement by 8 so that each callback fn's `ret` lands at the
correct slot:

```c
/* CORRECT — Rop[i].Rsp = X - 8; ret pops [X-8] = timer dispatcher return addr */
for ( int i = 0; i < 13; i++ ) {
    MemCopy( &Rop[ i ], &TimerCtx, sizeof( CONTEXT ) );
    Rop[ i ].Rip  = U_PTR( JmpGadget );
    Rop[ i ].Rsp -= sizeof( PVOID );   // REQUIRED
}
```

An inadvertent earlier edit removed this line, leaving `Rop[i].Rsp = X`. Every
callback fn's `ret` then popped `[X]` — the word *above* the captured frame, which is
arbitrary garbage. The process crashed on the first sleep cycle. The decrement has been
restored.

### Unit Tests

`payloads/Demon/test/test_sleepobf.c` — assertions covering:
- `OBF_JMP` for all three bypass modes (Rip/Rax/Rbx assignment)
- Mutual exclusion between branches (only one assignment fires per call)
- TimerObf setup loop: `Rop[i].Rsp == TimerCtx.Rsp - 8` (decrement required)
- FoliageObf: NtTestAlert written at `[RopXxx->Rsp + 0]` for each Rop entry
- FoliageObf: all Rop Rsp values are distinct and within committed stack bounds

Build: `cmake --build .` → `DemonTest.exe` (MinGW cross-compiled Win64)
Run on Windows: `ctest --output-on-failure` or `DemonTest.exe` directly.

### To Revert

1. In `SleepObf.h`, change `} else if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {` back
   to `} if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {`.
2. In `Obf.c`, remove `Rop[ i ].Rsp -= sizeof( PVOID );` from the setup loop.
3. Remove `payloads/Demon/test/test_sleepobf.c` and revert `CMakeLists.txt`.

---

## BUGFIX-006 — 2026-03-29 — FoliageObf: Copy-Paste Bug in RopExitThd Setup

```
Status : Applied
Files  :
  payloads/Demon/src/core/Obf.c   line 215: RopBegin → RopExitThd
```

In `FoliageObf`, the setup block for `RopExitThd` contained:

```c
*( PVOID* )( RopBegin->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
```

This is a copy-paste error: `RopBegin` should be `RopExitThd`. The line wrote
`NtTestAlert` to `RopBegin->Rsp[0]` a second time (a no-op since it was already
written at line 134) and left `RopExitThd->Rsp[0]` with whatever the OS placed at that
stack location (zero for a freshly committed page). At runtime this is harmless because
`RtlExitUserThread` never returns — `RopExitThd->Rsp[0]` is never used as a return
address. Corrected for clarity and correctness.

### To Revert

In `Obf.c`, change `RopExitThd->Rsp` back to `RopBegin->Rsp` in the
`RopExitThd` setup block.

---

## HVC-009 — 2026-04-12 — Fix Demon Agent Termination (HWBP/Sleep Obfuscation Bugs)

```
Suggestion ref : (none — bug fixes for latent issues unmasked by BUGFIX-001–006)
Status         : Applied
Files:
  payloads/Demon/src/core/HwBpEngine.c    lines 131, 214, 326
  payloads/Demon/src/core/ObfTimer.c       lines 198, 285
  teamserver/cmd/cmd.go                    line 14
```

After the profile settings fixes (BUGFIX-001–006) correctly propagated profile
values like HWBP, SleepJmpGadget, and StackDuplication to the Demon agent,
previously-dormant code paths became exercised. Five bugs were found by three
specialized analysis agents (low-level dev, QA, tester) running in parallel:

1. **BUG-HWBP-1 (HIGH):** Thread handle leak in `HwBpEngineSetBp` — handle
   opened via `SysNtOpenThread` at line 81, never closed on success path
   (only on FAILED label). Each breakpoint operation leaked one handle.
   Fix: added `SysNtClose(Thread)` before success return.

2. **BUG-HWBP-2 (MEDIUM):** `HwBpEngineRemove` ignores `Engine` parameter —
   local initialized to NULL at line 214, so `if (!HwBpEngine)` at line 222
   was always true. Fix: initialized local from parameter (`= Engine`).

3. **BUG-HWBP-3 (HIGH):** `ExceptionHandler` NULL dereference — accesses
   `Instance->HwBpEngine->Breakpoints` without NULL check. Any
   STATUS_SINGLE_STEP exception when HwBpEngine is NULL crashes the agent.
   Fix: added NULL guard returning EXCEPTION_CONTINUE_SEARCH.

4. **BUG-TIMER-1 (MEDIUM):** `sizeof(VOID)` in stack spoofing ROP copies 1
   byte instead of 8 — GCC `sizeof(void)` = 1. Fix: changed to
   `sizeof(PVOID)`.

5. **BUG-TIMER-2 (LOW):** `RtlDeleteTimerQueueEx` blocking cleanup — documented
   as known limitation (blocking is correct for ROP chain safety).

Four false positives were identified and ruled out (documented in
DemonTerminationFixes.md). Config packing/parsing alignment between builder.go
and Demon.c was verified correct.

Version bumped from 0.8 to 0.8.1.

**To revert:** Restore original lines in HwBpEngine.c (remove handle close,
revert local init to NULL, remove NULL guard) and ObfTimer.c (revert to
sizeof(VOID)). Revert version in cmd.go.

---

## FIX-10 — 2026-04-12 — Foliage Rsp Alignment Fix

```
Suggestion ref : SleepObf-Analysis.md §8 BUG-FOL-4
Status         : Applied
Files:
  payloads/Demon/src/core/ObfFoliage.c    line 149 (after NtGetContextThread)
```

Foliage sleep obfuscation crashed the Demon agent within the first few sleep
cycles on Windows builds where `NtGetContextThread` on a freshly-created
suspended thread returns `Rsp % 16 == 0` instead of `% 16 == 8`.

The x64 ABI requires `Rsp % 16 == 8` at function entry (after the `call`
instruction pushes the return address). When the initial Rsp was 16-aligned,
the entire ROP chain inherited the wrong alignment. Target functions that save
XMM registers via `movaps [rsp+N]` hit a `#GP` fault on the misaligned access,
crashing the APC thread and leaving the Demon image encrypted.

The Ekko/Zilean code already had this fix (`ObfTimer.c:164`: `Rop[i].Rsp -=
sizeof(PVOID)`). Foliage was missing the equivalent adjustment.

**Fix:** After `NtGetContextThread(hThread, RopInit)`, conditionally normalize:
```c
if ( ( RopInit->Rsp & 0xF ) == 0 ) {
    RopInit->Rsp -= sizeof( PVOID );
}
```
Applied before the `MemCopy` to all 10 ROP entries, so all inherit correct
alignment. The subsequent `Rsp -= 0x1000 * N` preserves the invariant.

Safe on ALL Windows builds — only adjusts when `Rsp % 16 == 0`.

**To revert:** Remove the `if ( ( RopInit->Rsp & 0xF ) == 0 )` block in
`ObfFoliage.c`.

---

### FIX-11 — Foliage: WaitForSingleObjectEx → NtWaitForSingleObject (2026-04-12)

**Severity:** CRITICAL — primary crash vector  
**File:** `payloads/Demon/src/core/ObfFoliage.c`  
**Version:** 0.8.3

The Foliage ROP chain's sleep entry (step 6 of 10 APCs) called
`WaitForSingleObjectEx` — a Win32 API from kernelbase.dll. The APC thread
executing this chain was created with `NtCreateThreadEx` + `NtTestAlert` as
start address + `CREATE_SUSPENDED`, meaning it never went through
`BaseThreadInitThunk` / `RtlUserThreadStart`. Its TEB Win32 subsystem state
(activation context, FLS callbacks, loader lock) was uninitialised. Calling any
Win32 API wrapper on this thread caused access violations from those fields.

**Fix:** Replace `WaitForSingleObjectEx(hDupObj, TimeOut, FALSE)` with
`NtWaitForSingleObject(hDupObj, FALSE, &SleepTimeout)` — a direct NT syscall
that is safe on any thread. Added `LARGE_INTEGER SleepTimeout` on the slave
fiber stack (outside the encrypted image region). Timeout converted from
milliseconds to 100ns units: `QuadPart = -(TimeOut * 10000)`.

Also updated `RopSpoof->Rip` to `NtWaitForSingleObject` for consistent
call-stack spoofing.

**To revert:** Change `NtWaitForSingleObject` back to `WaitForSingleObjectEx`
and remove the `SleepTimeout` variable.

---

### FIX-12 — Foliage: fallback to DEFAULT sleep on fiber failure (2026-04-12)

**Severity:** HIGH — agent enters tight loop without sleeping  
**File:** `payloads/Demon/src/core/Obf.c`  
**Version:** 0.8.3

When `ConvertThreadToFiberEx` returned NULL (e.g. thread already a fiber from
a previous failed cycle, or API not available), the Foliage case simply did
`break` — NO sleep occurred. The agent looped back immediately, burning 100%
CPU and flooding the teamserver with check-ins.

**Fix:** Added `goto DEFAULT` on the failure path so the agent falls back to
the unobfuscated `WaitForSingleObjectEx(NtCurrentProcess(), TimeOut, FALSE)`
sleep. The agent survives at the cost of no sleep obfuscation.

**To revert:** Change `goto DEFAULT` back to `break` (not recommended).

---

### FIX-13 — Foliage: deadlock-safe Leave cleanup (2026-04-12)

**Severity:** HIGH — agent hangs permanently  
**File:** `payloads/Demon/src/core/ObfFoliage.c`  
**Version:** 0.8.3

If any `SysNtQueueApcThread` call failed (goto Leave), the APC thread was
still suspended (never resumed). The Leave cleanup then called
`SysNtWaitForSingleObject(hThread, FALSE, NULL)` — an infinite wait on a
suspended thread → permanent deadlock.

**Fix:** Track resume state with `BOOL ThreadResumed`. In Leave, if the thread
was never resumed, call `SysNtTerminateThread(hThread, STATUS_SUCCESS)` before
the wait so it completes immediately.

**To revert:** Remove the `ThreadResumed` tracking and the
`SysNtTerminateThread` call.

---

### FIX-14 — Demon.h: restore #pragma pack after KAYN_ARGS (2026-04-12)

**Severity:** MEDIUM — silent struct layout corruption  
**File:** `payloads/Demon/include/Demon.h`  
**Version:** 0.8.3

`#pragma pack(1)` was set before the `KAYN_ARGS` typedef (needed for correct
reflective loader layout) but never restored. Every struct defined after it —
including `INSTANCE` — was compiled with 1-byte packing instead of the
platform default (8 bytes on x64). This changed field offsets and total struct
size, potentially causing misalignment penalties and subtle corruption if any
code assumed natural alignment.

**Fix:** Added `#pragma pack()` immediately after the `KAYN_ARGS` typedef to
restore default packing before `INSTANCE`.

**To revert:** Remove the `#pragma pack()` line. **Warning:** This will change
the INSTANCE struct layout at compile time.

---

### FIX-15 — Foliage: replace SystemFunction032 with position-independent RC4 stub (2026-04-13)

**Severity:** HIGH — intermittent crash on APC thread  
**File:** `payloads/Demon/src/core/ObfFoliage.c`  
**Version:** 0.8.4

After FIX-11 eliminated the primary crash (`WaitForSingleObjectEx`), the agent
survived much longer but still crashed intermittently. Root cause analysis
identified `SystemFunction032` (advapi32 → cryptbase.dll) as the **only
non-ntdll function** remaining in the Foliage ROP chain. On the APC thread
(created via `NtCreateThreadEx` + `CREATE_SUSPENDED`, never went through
`BaseThreadInitThunk`), advapi32/cryptbase functions may intermittently access
uninitialised TEB Win32 subsystem state — the exact same class of bug as
FIX-11.

Ekko/Zilean don't have this problem because their timer queue thread is
properly initialised by the OS.

**Fix:** Replaced both `SystemFunction032` calls (encrypt + decrypt) with a
manual position-independent RC4 implementation:

1. `Rc4Cipher` is a `static __attribute__((noinline))` C function compiled
   alongside FoliageObf. A sentinel `Rc4CipherEnd` marks the end of its code.
2. Each Foliage cycle allocates a single `PAGE_EXECUTE_READ` page OUTSIDE
   the Demon image
3. Copies `Rc4CipherEnd - Rc4Cipher` bytes of compiled machine code there
4. Uses the stub address in the ROP chain instead of SystemFunction032
5. Arguments are raw `(Buffer, Size, Key, KeySize)` instead of `PUSTRING`
6. The page is freed in Leave cleanup after the APC thread exits

The RC4 stub uses only stack-local state (256-byte S-box on stack) and has
zero dependencies on TEB, heap, or any initialisation state. The key is a
random 16-byte array generated each cycle. RC4 is its own inverse — the same
call encrypts and decrypts.

The stub page is outside the Demon image and is NOT encrypted during sleep,
so the APC thread can safely execute it while the image is encrypted.

Also removed the `USTRING Key`, `USTRING Rc4` locals from FoliageObf (no
longer needed).

**To revert:** Restore `SystemFunction032` calls and `USTRING` locals from the
pre-FIX-15 version.

---

## ISSUE-1 — 2026-04-17 — Mutex on Agent.JobQueue (Teamserver Data Race)

**Problem:** `Agent.JobQueue` and `Agent.Tasks` (Go slices) were accessed from
multiple goroutines (HTTP handler thread + WebSocket dispatch thread) without
synchronization. This is a data race that can crash the teamserver or silently
lose tasks.

**Fix:** Added `sync.Mutex` (`JobMtx`) to the `Agent` struct. All read/write
accesses to `JobQueue` and `Tasks` now acquire the mutex:
- `AddJobToQueue`, `GetQueuedJobs`, `RequestCompleted`, `IsKnownRequestID`
- `PivotAddJob` (child→parent lock ordering to prevent deadlock)
- `TeamserverTaskPrepare` (task::list, task::clear)
- `handlers.go` snapshot reads before NOJOB checks

**Files changed:** `pkg/agent/types.go`, `pkg/agent/agent.go`,
`pkg/agent/demons.go`, `pkg/handlers/handlers.go`

---

## ISSUE-2 — 2026-04-17 — Spinlock on Demon Instance->Packages (Linked List Race)

**Problem:** `Instance->Packages` (singly-linked list) was accessed by the
Demon's main thread and background job threads (BOF, .NET) without
synchronization. Concurrent `PackageTransmit` + `PackageTransmitAll` could
corrupt the linked list, causing crashes or lost responses.

**Fix:** Added `volatile LONG PackagesLock` to the INSTANCE struct with
interlocked spinlock macros (`PACKAGES_LOCK`/`PACKAGES_UNLOCK`) using GCC
`__sync_lock_test_and_set`/`__sync_lock_release` built-ins + `pause`.

Split `PackageDestroy` into `PackageDestroyInner` (no lock, called from locked
context in `PackageTransmitAll`) and `PackageDestroy` (acquires lock for list
traversal). All linked-list operations now protected.

**Files changed:** `payloads/Demon/include/Demon.h`,
`payloads/Demon/include/core/Package.h`, `payloads/Demon/src/core/Package.c`

---

## ISSUE-5 — 2026-04-17 — SMB Packet Fragmentation (Oversized Package Fix)

**Problem:** When a Demon response exceeded `PIPE_BUFFER_MAX` (64KB) on an SMB
transport, `PackageTransmit` silently dropped the package and sent a
`COMMAND_PACKAGE_DROPPED` notification. Large responses (screenshots, process
lists, .NET output) were lost for SMB pivot agents.

**Fix — Demon side (Package.c):** Oversized packages are now split into
`DEMON_PACKAGE_FRAGMENT` (command ID 2580) chunks. Each fragment carries a
header: `[FragID(4)][SeqNum(4)][TotalFrags(4)][OrigCmdID(4)][OrigReqID(4)]`
followed by chunk data. Max chunk size = `PIPE_BUFFER_MAX / 2` (32KB), leaving
room for the outer wire frame (AES IV, HMAC, headers).

**Fix — Teamserver side (demons.go):** New `COMMAND_PACKAGE_FRAGMENT` handler
in `TaskDispatch` collects chunks by FragID in a per-agent `FragmentBuffer`
map (protected by `FragmentMtx`). When all fragments arrive, the original
command is reassembled and recursively dispatched via `TaskDispatch`. Stale
incomplete fragment sets are cleaned up after 5 minutes.

**Files changed:** `payloads/Demon/include/core/Command.h`,
`payloads/Demon/include/core/Package.h`, `payloads/Demon/src/core/Package.c`,
`teamserver/pkg/agent/commands.go`, `teamserver/pkg/agent/types.go`,
`teamserver/pkg/agent/demons.go`, `teamserver/pkg/agent/agent.go`

---

## SEQ-EXEC — 2026-04-17 — Sequential Task Execution (One-Task-Per-Check-In)

**Version:** 0.8.5

**Problem:** When a Demon agent checked in, the teamserver drained ALL queued
tasks (up to 30MB) and sent them in a single HTTP response. The Demon processed
all received tasks at once, which caused overlapping execution, resource
contention, and if one task crashed the agent all subsequent queued tasks were
lost. Operators could not cancel mid-batch.

**Fix:** Changed to a one-task-per-check-in model with in-flight tracking:

- Added `InFlightRequestIDs map[uint32]bool` and `InFlightSince time.Time` to
  the Agent struct (protected by existing `JobMtx`).
- `GetQueuedJobs()` rewritten: returns nil (NOJOB) while any task is in-flight.
  Dequeues exactly 1 job per check-in. When all in-flight RequestIDs are
  completed via `RequestCompleted()`, the next check-in dequeues the next task.
- **MEM_FILE grouping:** BOF/dotnet uploads create N MEM_FILE chunk jobs + 1
  consuming command. These are detected and dispatched as a single atomic group
  so file uploads don't take N*sleep_interval seconds.
- **Safety timeout:** In-flight tasks older than 10 minutes are auto-cleared to
  prevent permanent queue stalls from lost responses.
- **task::clear:** Now also resets `InFlightRequestIDs` to unblock the queue.
- Handler check-in path simplified: removed redundant `jobQueueLen` pre-check.

**Files changed:** `teamserver/pkg/agent/types.go`,
`teamserver/pkg/agent/agent.go`, `teamserver/pkg/agent/demons.go`,
`teamserver/pkg/handlers/handlers.go`, `teamserver/pkg/db/agents.go`,
`teamserver/cmd/cmd.go`

---

## TASK-UX — 2026-04-17 — Task System UX Improvements (v0.8.6)

```
Suggestion ref : N/A (operator request)
Status         : Applied
Files          : teamserver/pkg/agent/agent.go, teamserver/pkg/agent/demons.go,
                 teamserver/cmd/cmd.go, client/src/Havoc/Demon/ConsoleInput.cc,
                 client/src/Havoc/Demon/Commands.cc
```

Four UX improvements to the sequential task execution system (SEQ-EXEC):

1. **COMMAND_CHECKIN excluded from queue blocking:** Check-in tasks no longer
   occupy an in-flight slot in the sequential queue. Added COMMAND_CHECKIN to
   the exclusion list alongside COMMAND_PIVOT and COMMAND_SOCKET in
   `GetQueuedJobs()`.

2. **TaskID in command output:** New `AgentConsoleWithTaskID()` wrapper method
   on Agent injects `TaskID` (uppercase 8-char hex of RequestID) into every
   console output message. All ~40 `AgentConsole` calls in `TaskDispatch` were
   converted. Operators can now correlate output to specific queued tasks.
   COMMAND_SOCKET calls intentionally excluded (async, not task-correlated).

3. **`task cancel` command:** New server-side and client-side command:
   - `task cancel all` — clears JobQueue, Tasks, and InFlightRequestIDs.
   - `task cancel <id>` — removes a specific task from the queue by TaskID.
     If the task is already in-flight, reports it cannot be recalled.

4. **QA fixes:** `task::clear` and `task::cancel all` now also clear the
   `Tasks` tracking slice to prevent phantom entries in `task::list`.
   Cancel of in-flight tasks returns a distinct error message.

**Files changed:** `teamserver/pkg/agent/agent.go`,
`teamserver/pkg/agent/demons.go`, `teamserver/cmd/cmd.go`,
`client/src/Havoc/Demon/ConsoleInput.cc`,
`client/src/Havoc/Demon/Commands.cc`

---

## BUGFIX-007 — 2026-04-17 — Nil map panic in AgentConsoleWithTaskID (v0.8.7)

```
Suggestion ref : N/A (crash bug introduced by TASK-UX)
Status         : Applied
Files          : teamserver/pkg/agent/demons.go, teamserver/cmd/cmd.go
```

**Root cause:** The `AgentConsoleWithTaskID` wrapper introduced in TASK-UX
writes `Message["TaskID"] = ...` to the message map before passing it to
`AgentConsole`. Four command handlers in `TaskDispatch` declared their
`Message` variable as `var Message map[string]string` (nil map) and had
code paths where the map was never initialized before reaching the
`AgentConsoleWithTaskID` call:

1. **COMMAND_PACKAGE_DROPPED** — if `Parser.CanIRead()` failed, `Message`
   remained nil.
2. **COMMAND_TRANSFER** — if SubCommand hit the `default` case, `Message`
   was never assigned.
3. **COMMAND_KERBEROS** — if the outer `Parser.CanIRead()` failed or
   SubCommand hit `default`, `Message` was nil.
4. **COMMAND_SOCKET** — same pattern (though this handler uses `a.Console`
   rather than `AgentConsoleWithTaskID`, the nil map was still latent).

Before TASK-UX, the original `teamserver.AgentConsole(a.NameID, ..., Message)`
passed the nil map to `json.Marshal()`, which safely serialized it as
`"null"`. The client received an empty JSON document and silently skipped
it. After TASK-UX, the wrapper's map write on a nil map caused a Go
runtime panic, crashing the teamserver process and dropping the WebSocket
connection to all connected clients — manifesting as an immediate client
UI crash when any command was issued.

**Fix:** Two-layer defense:
1. Changed all four `var Message map[string]string` declarations to
   `var Message = make(map[string]string)` so the map is always initialized.
2. Added a nil guard in `AgentConsoleWithTaskID` itself:
   `if Message == nil { Message = make(map[string]string) }` — protects
   against any future code path that might pass a nil map.

**Files changed:** `teamserver/pkg/agent/demons.go`, `teamserver/cmd/cmd.go`

---

## HVC-010 — 2026-04-18 — Fix OBF_JMP JMPRAX Behavioral Regression

```
Suggestion ref : SleepObf-Analysis.md §9.6 Phase 1+2
Status         : Applied
Files:
  payloads/Demon/include/core/SleepObf.h               line 18  (added Rip override in JMPRAX branch)
  payloads/Demon/src/core/ObfTimer.c                    lines 71, 158, 166  (diagnostic PRINTF)
  payloads/Demon/test/test_sleepobf.c                   lines 34, 106  (macro sync + assertion update)
  payloads/Demon/test/test_sleepobf_combos.c            lines 65, 145, 373  (macro sync + assertion updates)
  teamserver/cmd/cmd.go                                 line 14  (version 0.8.7 → 0.8.8)
```

The `else if` fix in HVC-009 corrected the OBF_JMP macro's control flow but
introduced a behavioral regression: JMPRAX now actually routes execution
through the `jmp rax` gadget, which requires stack setup that was never
implemented — causing crashes in Ekko/Zilean TimerObf when JMPRAX is selected.

**Fix:** Added `Rop[ i ].Rip = U_PTR( p );` inside the JMPRAX branch so that
Rip is explicitly set to the function address, bypassing the jmp gadget. This
makes JMPRAX functionally equivalent to NONE (direct call) while preserving
the correct `else if` structure. The gadget address in Rax is still set but
unused — a future HVC can implement proper gadget-based dispatch (Phase 2
Option B/C from SleepObf-Analysis.md §9.6).

**Diagnostics:** Three `PRINTF()` calls added to `ObfTimer.c` to trace
JmpBypass/Method on entry, JmpGadget/JmpBypass after gadget search, and
Rop[0].Rsp alignment before the ROP chain. These are compile-time no-ops in
release builds.

**Tests updated:** Both `test_sleepobf.c` and `test_sleepobf_combos.c` macro
copies synced and assertions changed to expect Rip == function address (not
JmpGadget) when JMPRAX is active.

**Version bump:** 0.8.7 → 0.8.8

**To revert:** Remove the `Rop[ i ].Rip = U_PTR( p );` line from the JMPRAX
branch in `SleepObf.h` (line 19), remove the three PRINTF lines from
`ObfTimer.c`, revert test assertions to expect `Rip == JmpGadget`, and change
version back to `0.8.7` in `cmd.go`.

---

## Version History

| Version | CodeName | Date | Key Changes |
|---------|----------|------|-------------|
| 1.0 | Iron Veil | 2026-03-28 | HVC-005 (RSA key wrapping) |
| 1.1 | Cobalt Veil | 2026-03-28 | HVC-007 (LZNT1 compression) |
| 1.2 | Iron Spectre | 2026-03-28 | HVC-008 (SMB framing obfuscation) |
| 1.3 | Silent Anchor | 2026-03-29 | BUGFIX-004 (HTTP beacon stability) |
| 0.8.1 | — | 2026-04-12 | HVC-009 (HWBP + timer fixes) |
| 0.8.2 | — | 2026-04-12 | FIX-10 (Foliage Rsp alignment) |
| 0.8.3 | — | 2026-04-12 | FIX-11..14 (Foliage crash root causes) |
| 0.8.4 | — | 2026-04-13 | FIX-15 (Foliage RC4 stub) |
| 0.8.5 | — | 2026-04-17 | SEQ-EXEC (sequential task execution) |
| 0.8.6 | — | 2026-04-17 | TASK-UX (task system UX improvements) |
| 0.8.7 | — | 2026-04-17 | BUGFIX-007 (nil map panic) |
| 0.8.8 | — | 2026-04-18 | HVC-010 (OBF_JMP JMPRAX behavioral fix) |
| 0.8.9 | — | 2026-04-18 | HVC-011 (non-blocking timer queue cleanup) |
| 0.8.10 | Silent Storm | 2026-04-18 | HVC-012 (revert sizeof(PVOID) Rip copy) |
| 0.8.10 | Silent Storm | 2026-04-24 | SLEEPOBF-REVERT (revert all sleep obf to original) |

**Current versions:**
- Teamserver: `0.8.10` "Silent Storm" (`teamserver/cmd/cmd.go`)
- Client: `1.3` "Silent Anchor" (`client/src/global.cc`)

**Note:** The teamserver and client version numbers diverged during development.
The client version tracks protocol/wire-format changes (HVC-001..008); the
teamserver version tracks agent-side and server-side bugfixes.

---

## Future / Planned

| ID      | Suggestion                          | Status  |
|---------|-------------------------------------|---------|
| HVC-013 | Raw TCP transport                   | Pending |
