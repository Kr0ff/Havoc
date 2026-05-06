# Profile Settings Fixes

Six bugs were found and fixed that caused Havoc profile Demon settings to be
silently ignored during payload generation.

## Data Flow

```
Profile (YAOTL)
  -> Go Demon struct (config.go)
    -> json.Marshal -> WebSocket -> Qt client DemonConfig
      -> Payload dialog UI defaults
        -> user generates payload -> UI values JSON
          -> teamserver builder (builder.go)
            -> compiled into Demon binary
```

---

## BUG 1 (HIGH) -- builder.go: "jmp rax" corrupts sleep technique

**File:** `teamserver/pkg/common/builder/builder.go` line 794

**Problem:** The "jmp rax" case in the Sleep Jmp Gadget switch assigned to
`ConfigObfTechnique` instead of `ConfigObfBypass`. This overwrote the sleep
obfuscation technique (e.g. Ekko = 1) with the jmp bypass value (1), and
left `ConfigObfBypass` at 0 (NONE). The "jmp rbx" case at line 801 was
correct and used `ConfigObfBypass`.

**Fix:** Changed `ConfigObfTechnique` to `ConfigObfBypass` on line 794.

**Impact:** Selecting "jmp rax" with any sleep obfuscation technique now
works correctly. Previously it silently broke both the technique and bypass.

---

## BUG 2 (HIGH) -- AmsiEtwPatching: "HWBP" vs "Hardware breakpoints"

**Files:**
- `teamserver/pkg/common/builder/builder.go` line 889
- `client/src/UserInterface/Dialogs/Payload.cc` line 610

**Problem:** The example profile uses `AmsiEtwPatching = "HWBP"` but the
client UI comparison only matched `"Hardware breakpoints"` and the builder
only handled `case "Hardware breakpoints":`. The profile value "HWBP" fell
through to index 0 ("None") in the UI and to `AMSIETW_PATCH_NONE` in the
builder.

**Fix:**
- Builder: Added `"HWBP"` to the case statement: `case "Hardware breakpoints", "HWBP":`
- Client: Added `|| DefaultAmsiEtwPatching == "HWBP"` to the comparison

**Impact:** Setting `AmsiEtwPatching = "HWBP"` in the profile now correctly
enables hardware breakpoint AMSI/ETW patching in generated payloads.

---

## BUG 3 (MEDIUM) -- SleepJmpGadget missing from profile struct

**Files:**
- `teamserver/pkg/profile/config.go` -- Demon struct
- `client/src/UserInterface/Dialogs/Payload.cc`

**Problem:** The `SleepJmpGadget` field did not exist in the Go `Demon`
struct. It could only be set from the client UI, never from the profile
file. The client also did not read a default for it from DemonConfig JSON.

**Fix:**
- Added `SleepJmpGadget string` field with `yaotl:"SleepJmpGadget,optional"` tag
- Client reads `DemonConfig["SleepJmpGadget"]` and sets the combo box default

**Impact:** Operators can now set `SleepJmpGadget = "jmp rax"` or
`SleepJmpGadget = "jmp rbx"` in the profile and have it pre-selected in the
Payload dialog.

---

## BUG 4 (MEDIUM) -- Injection.Alloc and Injection.Execute missing from profile

**Files:**
- `teamserver/pkg/profile/config.go` -- ProcessInjectionBlock struct
- `client/src/UserInterface/Dialogs/Payload.cc`

**Problem:** `ProcessInjectionBlock` only had `Spawn64` and `Spawn32`. The
builder requires `Alloc` and `Execute` (lines 689, 707) but these could not
be set from the profile. The client hardcoded "Native/Syscall" (index 1) as
the default.

**Fix:**
- Added `Alloc string` and `Execute string` fields to ProcessInjectionBlock
- Client reads `DemonConfig["ProcessInjection"]["Alloc"]` and
  `DemonConfig["ProcessInjection"]["Execute"]` to set combo defaults
- Default remains "Native/Syscall" when the fields are absent from the profile

**Impact:** Operators can now set `Alloc = "Win32"` or `Execute = "Win32"`
inside the `Injection {}` block in the profile.

---

## BUG 5 (LOW) -- Copy-paste error messages in builder.go

**File:** `teamserver/pkg/common/builder/builder.go` lines 842, 883, 904

**Problem:** Three different configuration fields (Stack Duplication, Proxy
Loading, Amsi/Etw Patch) all returned the same error message: `"sleep
Obfuscation technique is undefined"`. This was a copy-paste error from the
Sleep Technique block.

**Fix:** Each now returns its own field-specific error:
- `"Stack Duplication is undefined"` (line 842)
- `"Proxy Loading is undefined"` (line 883)
- `"Amsi/Etw Patch is undefined"` (line 904)

---

## BUG 6 (LOW) -- Example profile missing several Demon settings

**File:** `profiles/havoc.yaotl`

**Problem:** The example profile omitted `SleepTechnique`, `SleepJmpGadget`,
`ProxyLoading`, `Injection.Alloc`, and `Injection.Execute`. Operators had no
way to know these existed without reading source code.

**Fix:** All settings are now present in the example profile with comments
listing accepted values.

---

## Files Changed

| File | Changes |
|------|---------|
| `teamserver/pkg/common/builder/builder.go` | Fix line 794 variable name, accept "HWBP" alias at line 889, fix 3 error messages |
| `teamserver/pkg/profile/config.go` | Add SleepJmpGadget to Demon struct, add Alloc+Execute to ProcessInjectionBlock |
| `client/src/UserInterface/Dialogs/Payload.cc` | Read 3 new profile defaults, accept "HWBP" alias for AmsiEtwPatching |
| `profiles/havoc.yaotl` | Add all Demon settings with accepted-value comments |

## All Profile Demon Settings (after fixes)

| Setting | Type | Accepted Values | Default |
|---------|------|-----------------|---------|
| Sleep | int | milliseconds | 10 |
| Jitter | int | 0-100 (percentage) | 15 |
| IndirectSyscall | bool | true/false | true |
| StackDuplication | bool | true/false | true |
| SleepTechnique | string | "WaitForSingleObjectEx", "Foliage", "Ekko", "Zilean" | "WaitForSingleObjectEx" |
| SleepJmpGadget | string | "None", "jmp rax", "jmp rbx" | "None" |
| ProxyLoading | string | "None (LdrLoadDll)", "RtlRegisterWait", "RtlCreateTimer", "RtlQueueWorkItem" | "None (LdrLoadDll)" |
| AmsiEtwPatching | string | "None", "HWBP", "Hardware breakpoints" | "None" |
| Injection.Spawn64 | string | process path | "" |
| Injection.Spawn32 | string | process path | "" |
| Injection.Alloc | string | "Win32", "Native/Syscall" | "Native/Syscall" |
| Injection.Execute | string | "Win32", "Native/Syscall" | "Native/Syscall" |
| TrustXForwardedFor | bool | true/false (server-side only) | false |
| DotNetNamePipe | string | pipe template (server-side only) | (builtin default) |
