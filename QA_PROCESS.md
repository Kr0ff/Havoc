# Havoc QA Process: Systematic Analysis and Change Validation

This document defines the systematic approach for analyzing, identifying,
testing, and resolving issues in the Havoc C2 framework. It serves as a
repeatable checklist for all code changes, especially those touching the
Demon agent, sleep obfuscation, and security-critical code paths.

---

## Phase 1: Analysis (Before Writing Code)

### 1.1 Trace the Full Data Flow

For any config-related issue, trace the complete pipeline:
```
Profile (YAOTL) -> Go struct (config.go) -> json.Marshal -> WebSocket
  -> Qt client DemonConfig -> Payload dialog UI -> config JSON
  -> builder.go PatchConfig() -> binary config blob (packer)
  -> Demon AgentConfig[] -> ParserGetInt32/ParserGetBytes -> Instance->Config
  -> runtime usage in Obf.c, Win32.c, Dotnet.c, etc.
```

At each stage verify:
- Field names match (yaotl tag -> JSON key -> builder map key -> UI label)
- Value types match (string/int/bool at each boundary)
- Numeric constants match (Go constants == C #defines)
- Packing order matches parsing order (builder AddInt sequence == Parser GetInt32 sequence)

### 1.2 Identify All Code Paths

For each feature being modified, enumerate:
- Normal success path
- All error/failure paths (every `return`, `goto`, `break`)
- Cleanup/resource release paths
- Interaction with other features (e.g., HWBP + sleep obfuscation)

### 1.3 Check Compile-Time vs Runtime

The Demon uses compile-time feature flags:
- `SLEEPOBF_USE_FOLIAGE` — Foliage sleep obfuscation code
- `SLEEPOBF_USE_TIMER` — Ekko/Zilean timer-based sleep obfuscation
- `TRANSPORT_HTTP` / `TRANSPORT_SMB` — Transport layer

Verify that runtime config values are consistent with compile-time flags.
A runtime technique value that doesn't match the compiled code should fall
through to a safe default.

### 1.4 Use Specialized Agents

For complex analysis, deploy 3 agents in parallel:
1. **Low-level developer**: ASM, C, Windows internals, ROP chains, syscalls
2. **Code QA**: Cross-reference data flow, type safety, alignment
3. **Tester**: Configuration combination matrix, crash path tracing

Each agent must report with:
- Bug severity (CRITICAL/HIGH/MEDIUM/LOW)
- Exact file:line reference
- Explanation of how the bug causes the observed behavior
- Whether it's confirmed or needs verification

### 1.5 Filter False Positives

After agent analysis, manually verify each finding:
- Read the actual code at the reported line
- Trace macro expansions (especially OBF_JMP, PRINTF, etc.)
- Check if the issue is guarded by conditions the agent missed
- Verify calling code handles the error case
- Test with actual compiler behavior (e.g., sizeof(void) on GCC vs MSVC)

---

## Phase 2: Implementation

### 2.1 Fix Priority Order

1. **Crash fixes first** — NULL dereferences, use-after-free, buffer overflows
2. **Resource leaks next** — Handle leaks, memory leaks
3. **Logic errors** — Wrong variable, wrong constant, wrong branch
4. **Defensive improvements** — NULL guards, bounds checks, error messages
5. **Documentation** — Comments for non-obvious behavior

### 2.2 Minimal Changes

- Fix exactly the bug, nothing else
- Don't refactor surrounding code
- Don't add features
- Don't change coding style
- Match existing patterns (e.g., if other functions use `goto FAILED`, use that too)

### 2.3 Type Safety Checklist

For Demon C code specifically:
- [ ] ParserGetInt32 returns INT, target field might be BYTE/BOOL/ULONG -- check truncation
- [ ] sizeof(VOID) on GCC = 1, use sizeof(PVOID) for pointer sizes
- [ ] HANDLE values must be closed on ALL paths (success and failure)
- [ ] CONTEXT structures on x64 require 16-byte alignment for XMM registers
- [ ] Function pointer casts through C_PTR() must match the calling convention

---

## Phase 3: QA Validation

### 3.1 Compile Check

```bash
# Go teamserver
cd teamserver && go build ./... && go test ./...

# Qt client
cd client && mkdir -p Build && cd Build && cmake .. && make -j4

# Demon (requires MinGW cross-compiler)
# Verify through payload generation in the UI
```

### 3.2 Static Analysis

- Review each changed line against the bug description
- Verify the fix doesn't introduce new issues
- Check that error paths still work after the fix
- Grep for similar patterns elsewhere that might have the same bug

### 3.3 Configuration Combination Matrix

Test these combinations (at minimum):
1. No obfuscation baseline
2. Each sleep technique independently (NONE, Ekko, Zilean, Foliage)
3. Each jmp gadget with timer techniques (NONE, jmp rax, jmp rbx)
4. Stack spoofing on/off with timer techniques
5. HWBP on/off with each sleep technique
6. Proxy loading on/off with timer techniques (check for timer API conflicts)

### 3.4 Runtime Validation (on Windows target)

For each test combination:
- [ ] Agent connects to teamserver successfully
- [ ] Agent survives 5+ sleep cycles without termination
- [ ] Agent responds to commands after sleep
- [ ] Handle count does not grow (check with Process Explorer)
- [ ] .NET assembly execution works and output is captured (if HWBP enabled)
- [ ] Agent recovers from failed .NET assembly execution
- [ ] No unhandled exceptions in Event Viewer

---

## Phase 4: Documentation

### 4.1 Change Log Entry

Every fix gets an entry in CHANGES.md with:
- Unique ID (HVC-NNN or BUGFIX-NNN)
- Date
- Affected files with line numbers
- Root cause description
- Fix description
- How to revert

### 4.2 Detailed Analysis File

For complex multi-bug fixes, create a separate analysis file documenting:
- All bugs found (confirmed and false positives)
- Data flow verification results
- QA test matrix results
- Lessons learned

---

## Anti-Patterns to Avoid

1. **Don't fix what you haven't read** — Always read the file before editing
2. **Don't trust agent findings blindly** — Verify each claim manually
3. **Don't assume cleanup happens** — Trace every error path to confirm
4. **Don't ignore type mismatches** — BYTE vs INT, signed vs unsigned matter
5. **Don't change multiple things at once** — Fix one bug, verify, then next
6. **Don't skip the combination matrix** — Features interact in unexpected ways
7. **Don't assume compile-time == runtime** — Preprocessor guards can mask bugs
