---
name: SleepObf timer cleanup fix - unconfirmed
description: RtlDeleteTimerQueueEx fix for beacon dying after time - applied but not yet tested by user
type: project
---

Applied RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE) fix in Obf.c and Win32.c to replace non-blocking RtlDeleteTimerQueue. Also removed redundant Rop[Inc].Rip=NtSetEvent on line 566 of Obf.c. Changes in Defines.h, Demon.h, Demon.c, Obf.c, Win32.c.

**Why:** RtlDeleteTimerQueue doesn't wait for callbacks to complete before returning, causing potential use-after-stack-free race condition that kills the beacon intermittently.

**How to apply:** Status UNCONFIRMED — user needs to test with Ekko sleep obfuscation and verify beacon stays alive over extended periods.
