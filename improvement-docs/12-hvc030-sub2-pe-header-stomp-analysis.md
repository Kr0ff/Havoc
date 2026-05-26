# HVC-030 Sub-2 — PE Header Stomping During Sleep

**Status:** Applied — 2026-05-21
**Scope:**
- `payloads/Demon/include/core/PeProtect.h` (new)
- `payloads/Demon/src/core/PeProtect.c` (new)
- `payloads/Demon/src/Demon.c` — `DemonInit()`: add `PeProtect_Init()` call
- `payloads/Demon/src/core/ObfTimer.c` — Stomp/Restore around signal+wait
- `payloads/Demon/src/core/ObfFoliage.c` — Stomp/Restore around signal+wait
- `payloads/Demon/src/core/Obf.c` — Stomp/Restore around fallback `SpoofFunc`
- `payloads/Demon/CMakeLists.txt` — add `src/core/PeProtect.c` to COMMON_SOURCE

---

## Simple Explanation

While the Demon agent is sleeping, its PE headers (`MZ`, `PE`, section table — the first
4 KB of the loaded image) remain readable in memory. EDR products and memory scanners
that wake during the idle window can match these headers against known Demon build
signatures to identify the process.

Sub-2 fixes this by saving the first 4 KB of the image once during agent initialisation,
then zeroing those bytes immediately before each sleep and restoring them from the saved
copy immediately after wake. During the sleep window the PE headers are gone; after wake
they are silently restored before any Demon code runs again.

---

## Detailed Technical Explanation

### What PE header stomping prevents

Windows memory scanners (both kernel callbacks and user-mode tools) enumerate loaded
pages and look for the `4D 5A` ("MZ") signature at mapped image bases to identify
known binaries. By zeroing the first 4 KB the agent removes:
- The DOS header (64 bytes including the `MZ` magic and stub)
- The NT headers (`IMAGE_NT_HEADERS64`: signature + `FILE_HEADER` + `OPTIONAL_HEADER`)
- The section table (array of `IMAGE_SECTION_HEADER`)

Without these headers, the mapped region cannot be identified as a PE image by
signature-based scanners. The raw code sections are already encrypted by the sleep
obfuscation (Ekko/Zilean/Foliage), so the combination leaves no identifiable artifact
during the sleep window.

### Module base field correction

The HVC-030 spec refers to `Instance->Modules.Self` as the Demon image base. **This
field does not exist.** Inspecting `Demon.h` confirms that `Modules` contains only:
`Ntdll`, `Kernel32`, `Advapi32`, `Mscoree`, `Oleaut32`, `User32`, `Shell32`, `Msvcrt`,
`Iphlpapi`, `Gdi32`, `NetApi32`, `Ws2_32`, `Sspicli`, `Amsi`, `WinHttp`, `DnsApi`.

The Demon base address is `Instance->Session.ModuleBase`. This is set in `DemonInit()`
at three possible sites depending on deployment mode (shellcode/KArgs or standalone
exe/DLL) and is the same value used by `ObfTimer.c` and `ObfFoliage.c` for the
memory encryption step. All `PeProtect.c` code must use `Instance->Session.ModuleBase`.

### Backup strategy

A static `BYTE PeBackup[0x1000]` array lives in `PeProtect.c`'s BSS section. A
companion `static BOOL PeBackupSaved` flag prevents double-initialisation and guards
`PeProtect_Restore()` against being called before Init runs.

The backup is heap-free by design. Heap allocation is a scan target for Sub-5 and is
unsafe to call during the pre-sleep sensitive window. Stack allocation is unsafe because
the buffer must outlive any single function call frame. BSS allocation is valid for the
agent's entire lifetime.

`PeProtect_Init()` is called at the **end of `DemonInit()`**, after
`Instance->Session.ModuleBase` is fully set. This guarantees the backup is taken before
any sleep occurs, and guarantees it is taken only once (from the original binary).

### Memory protection sequence

Stomping the first page requires write access:

```
NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddr, &StompSize, PAGE_READWRITE, &OldProtect)
MemSet(BaseAddr, 0, StompSize)
NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddr, &StompSize, PAGE_EXECUTE_READ, &OldProtect)
```

`PAGE_EXECUTE_READWRITE` is never used. The sequence is always
`RW` for the write operation followed by `RX` for the final state. The first 4 KB of a
PE image is header data only; no code is stored in this range for well-aligned images
(code starts at the first section, typically at virtual offset `0x1000` or higher).

`NtProtectVirtualMemory` is already resolved in `Instance->Win32` (used by
`ObfFoliage.c`). No new resolution is needed.

### Call site analysis

#### ObfTimer.c (Ekko / Zilean)

The main thread calls `SysNtSignalAndWaitForSingleObject(EvntStart, EvntDelay, FALSE, NULL)`.
This single syscall atomically signals EvntStart (releasing Rop[0]) and blocks until
EvntDelay fires (the last ROP entry). The ROP chain runs entirely while this call
blocks: VirtualProtect(RW) → RC4-encrypt → sleep → RC4-decrypt → VirtualProtect(RX)
→ NtSetEvent(EvntDelay).

```
// Main thread, just before SysNtSignalAndWaitForSingleObject:
PeProtect_Stomp();    // zero first 4 KB; page flips RX→RW→RX
                      // [ROP chain runs: encrypt, sleep, decrypt]
SysNtSignalAndWaitForSingleObject( EvntStart, EvntDelay, FALSE, NULL );
PeProtect_Restore();  // restore from backup; page flips RX→RW→RX
```

**Timing window during sleep:**
- Stomp is called while the image is at its original protection (RX/RWX from the
  Demon loader). PE headers become zero.
- ~100–200 ms later the ROP chain runs VirtualProtect(ImgBase, RW) and RC4-encrypts
  the whole image — the zeroed header region is included in the encrypted blob.
- During sleep: first 4 KB = zero (within encrypted region). No PE signature present.
- On wake: ROP chain decrypts the image (headers are restored as zero by the RC4 round-
  trip), re-protects to RX, signals EvntDelay.
- PeProtect_Restore() fires: copies backup over the zeroed region. Headers present again.

Note: There is a ~100–200 ms window between Stomp and the ROP chain's first
VirtualProtect where PE headers are zero but code is still unencrypted. This is
acceptable — the goal is to eliminate the PE signature, not the code, and the code
encryption is the job of the existing ROP chain.

#### ObfFoliage.c (Foliage)

Foliage queues APCs to a suspended thread. The APC chain mirrors the Ekko/Zilean
sequence: wait → VirtualProtect(RW) → RC4-encrypt → sleep → RC4-decrypt →
VirtualProtect(RX) → exit thread. The main fiber (inside `FoliageObf`) waits with:

```c
SysNtSignalAndWaitForSingleObject( hEvent, hThread, FALSE, NULL );
```

This signals the event that starts the APC chain and waits for the thread to exit
(after the last APC runs `RtlExitUserThread`). Call site is identical in structure:

```
PeProtect_Stomp();
SysNtSignalAndWaitForSingleObject( hEvent, hThread, FALSE, NULL );
PeProtect_Restore();
```

The Stomp/Restore calls go inside the `if ( NT_SUCCESS( SysNtAlertResumeThread(...) ) )`
block, just around the signal+wait. They are never reached if the APC setup fails.

#### Obf.c (default / fallback)

The `DEFAULT` / `SLEEPOBF_NO_OBF` path calls `SpoofFunc` which wraps
`WaitForSingleObjectEx`. There is no memory encryption here, so the code remains
readable during sleep. Stomping the PE headers still removes the signature from the
first 4 KB:

```
PeProtect_Stomp();
SpoofFunc( Instance->Modules.Kernel32, ..., Instance->Win32.WaitForSingleObjectEx, ... );
PeProtect_Restore();
```

This is strictly additive: the operator gains header-level protection even on builds
where `SLEEPOBF_NO_OBF` is selected or where TimerObf falls back to the default path.

### DemonInit call placement

`PeProtect_Init()` is added at the **end of `DemonInit()`** in `Demon.c`, after the
CfgAddressAdd block and just before the final `PUTS("DemonInit COMPLETE")` log line.
At that point `Instance->Session.ModuleBase` is guaranteed to be set (all three
assignment paths — KArgs/shellcode, explicit ModuleInst, and `LdrModulePeb(0)` fallback
— occur earlier in `DemonInit()`).

### CMakeLists.txt

`src/core/PeProtect.c` is added to the `COMMON_SOURCE` list alongside the other
`src/core/*.c` files. No new compile definitions are needed — PE header stomping is
always active (not a compile-time option).

---

## File Map

| File | Action | Change |
|------|--------|--------|
| `payloads/Demon/include/core/PeProtect.h` | Create | `PeProtect_Init`, `PeProtect_Stomp`, `PeProtect_Restore` declarations |
| `payloads/Demon/src/core/PeProtect.c` | Create | Full implementation with static BSS backup |
| `payloads/Demon/src/Demon.c` | Edit | Add `PeProtect_Init()` call at end of `DemonInit()` |
| `payloads/Demon/src/core/ObfTimer.c` | Edit | Stomp before / Restore after `SysNtSignalAndWaitForSingleObject` |
| `payloads/Demon/src/core/ObfFoliage.c` | Edit | Stomp before / Restore after `SysNtSignalAndWaitForSingleObject` |
| `payloads/Demon/src/core/Obf.c` | Edit | Stomp before / Restore after `SpoofFunc` |
| `payloads/Demon/CMakeLists.txt` | Edit | Add `src/core/PeProtect.c` to `COMMON_SOURCE` |

---

## Spec Deviation: `Instance->Modules.Self`

The HVC-030 spec (`04-sleep-obfuscation.md`) references `Instance->Modules.Self` as the
Demon image base in all `PeProtect` code samples. **This field does not exist.** The
correct field is `Instance->Session.ModuleBase`. The implementation uses the correct
field throughout. The spec is incorrect on this point and has not been updated.

---

## Operator Test Plan

Cross-compile Demon with MinGW targeting x86_64-w64-mingw32. Deploy on a Windows test
target (VM or physical). Perform the following checks for each sleep obfuscation mode:

### Test 1 — PE headers zeroed during sleep (all modes)

**Tool needed:** WinPmem, Process Hacker 2, or any tool that can read process memory by
address. A simple C harness that calls `ReadProcessMemory` on the Demon base at 100 ms
intervals is sufficient.

**Steps:**
1. Note the Demon process PID and image base (visible in Process Hacker → Properties →
   Memory or via `NtQueryInformationProcess`).
2. Start the monitoring tool (poll the first 16 bytes of the image base at 1 s intervals).
3. Trigger a sleep cycle (use a configured sleep interval of 10–30 seconds so the window
   is large enough to observe).
4. While the agent is sleeping, verify that the first 16 bytes read as all zeros
   (`00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00`). In particular, byte 0 should
   NOT be `4D` (`M`) and byte 1 should NOT be `5A` (`Z`).
5. After the sleep ends (agent checks in), verify that the first two bytes are restored
   to `4D 5A` (`MZ`).

**Pass criterion:** `MZ` absent during sleep, `MZ` restored after checkin.

### Test 2 — Agent stability over 30+ sleep cycles (Ekko / Zilean modes)

**Steps:**
1. Configure Demon with Ekko or Zilean sleep obfuscation and a 5–10 second sleep.
2. Run for at least 30 consecutive sleep cycles.
3. Confirm the agent checks in normally after each cycle (no crash, no timeout).
4. Monitor the teamserver for any errors.

**Pass criterion:** 30+ cycles complete without crash or checkin failure. Sub-1 (30
cycles confirmed) is the baseline — Sub-2 must not regress it.

### Test 3 — Agent stability over 10+ sleep cycles (Foliage mode)

**Steps:**
1. Configure Demon with Foliage sleep obfuscation.
2. Run for at least 10 consecutive sleep cycles.
3. Confirm normal checkin after each cycle.

**Pass criterion:** 10+ cycles, no crash.

### Test 4 — Agent stability over 10+ sleep cycles (no-obf / fallback mode)

**Steps:**
1. Configure Demon with `SLEEPOBF_NO_OBF` or force the fallback path (e.g., disable
   timer/Foliage compile flags).
2. Run for at least 10 consecutive sleep cycles.
3. Confirm normal checkin.

**Pass criterion:** 10+ cycles, no crash. PE headers should still be zeroed during the
sleep window even in no-obf mode.

### Test 5 — JMPRAX regression (confirm Sub-1 not broken)

**Steps:**
1. Configure Demon with JMPRAX gadget mode and Ekko or Zilean.
2. Run for 10 sleep cycles.
3. Confirm agent survives and checks in normally.

**Pass criterion:** No crash. JMPRAX gadget path was validated in Sub-1 over 30 cycles;
Sub-2 must not introduce a regression.

### Test 6 — Memory scanner / EDR simulation

**Optional, higher fidelity:**
Use a tool such as `pe-sieve` or Moneta to scan the process during a sleep window.

**Steps:**
1. Start a sleep cycle.
2. During the sleep window, run `pe-sieve --pid <PID>` or equivalent.
3. Confirm that the tool does not report a matching Demon signature on the first page.

**Pass criterion:** No PE signature match during sleep. A match after wake (when headers
are restored) is expected and acceptable — the agent is active at that point.

---

## What is NOT Changed

- The RC4 memory encryption (SystemFunction032) is not touched; it operates on the full
  image range and is orthogonal to PE header stomping.
- The ROP chain structure is not modified; Stomp/Restore are called from the main/fiber
  thread before and after the wait, not from inside the chain.
- The `PAGE_EXECUTE_READWRITE` usage in `ObfTimer.c:53` is a pre-existing issue
  outside the scope of Sub-2. `PeProtect.c` never uses `PAGE_EXECUTE_READWRITE`.
- `MmGadgetFind` in `Memory.c` is the existing first-occurrence scan; Sub-3 will extend
  it to collect all occurrences and select randomly. Sub-2 does not touch `Memory.c`.
