# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Havoc is a post-exploitation C2 (command and control) framework with three main components:
- **Teamserver** — Go backend that orchestrates agents, listeners, and client connections
- **Client** — Qt5/C++ GUI that operators use to interact with the teamserver
- **Demon** — Windows agent written in C + x86/x64 ASM that runs on target hosts

**`Demon.md`** (repo root) is the full technical reference for the Demon agent. Read it before working on any code in `payloads/Demon/`.

**`Teamserver.md`** (repo root) is the full technical reference for the teamserver. Read it before working on any code in `teamserver/`.

**`Client.md`** (repo root) is the full technical reference for the client. Read it before working on any code in `client/`.

## Build Commands

### Full Build
```bash
make all          # Build both teamserver and client
make ts-build     # Build teamserver only (runs Install.sh first)
make client-build # Build client only (runs CMake)
make clean        # Clean all build artifacts
```

### Teamserver (Go)
```bash
cd teamserver
go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go
```

### Client (C++ + Qt5)
```bash
cd client
mkdir -p Build && cd Build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
```

### Dependencies Setup
```bash
cd teamserver && bash Install.sh   # Installs Go, NASM, MinGW, downloads cross-compilers
```

**Requirements:**
- Go 1.21.0+
- CMake 3.15+, C++20 compiler
- Qt5 (Core, Gui, Widgets, Network, WebSockets, Sql)
- Python 3.10+ (for module/scripting support)
- NASM assembler
- MinGW-w64 (downloaded by Install.sh into `data/`)

On macOS, Qt5 and Python paths are resolved via Homebrew in `client/CMakeLists.txt`.

## Running Tests

```bash
cd teamserver
go test ./...                          # All Go tests
go test ./pkg/profile/yaotl/...        # YAOTL config parser tests only
```

Test files are primarily in `teamserver/pkg/profile/yaotl/specsuite/`.

## Architecture

### Communication Flow

```
Client (Qt5 C++) ←─ WebSocket ─→ Teamserver (Go) ←─ HTTP/HTTPS/SMB ─→ Demon Agent (C)
```

### Teamserver (`teamserver/`)

Entry point: `main.go` → `cmd/server/teamserver.go`

Key packages:
- `cmd/server/` — Main server logic: `teamserver.go` (core), `agent.go`, `listener.go`, `dispatch.go`, `service.go`, `types.go`
- `pkg/agent/` — Agent session state management
- `pkg/handlers/` — HTTP/WebSocket request handling
- `pkg/packager/` — Payload/implant generation
- `pkg/profile/` — YAOTL config parsing (HCL-based format)
- `pkg/db/` — SQLite persistence layer
- `pkg/events/` — Event broadcasting to connected clients
- `pkg/service/` — External C2 API support
- `pkg/webhook/` — Discord webhook integration

The `Teamserver` struct (in `types.go`) is the central data structure holding all state. Clients connect via WebSocket and receive events broadcast through `pkg/events`.

### Client (`client/`)

Entry point: `src/Main.cc` → `src/Havoc/` core logic

Key areas:
- `src/Havoc/Connector.cc` — Teamserver WebSocket connection
- `src/Havoc/Packager.cc` — Payload generation UI logic
- `src/Havoc/PythonApi/` — Python scripting integration
- `src/UserInterface/Widgets/` — SessionTable, SessionGraph, Listeners, FileExplorer, ScriptManager
- `src/UserInterface/Dialogs/` — Connect, Payload, Listener dialogs
- `data/` — Qt resources (icons, themes, UI files)

### Demon Agent (`payloads/Demon/`)

Multiple entry points for different deployment modes:
- `src/main/MainExe.c` — Standalone executable
- `src/main/MainDll.c` — DLL injection
- `src/main/MainSvc.c` — Windows service

Core modules in `src/core/`:
- `Command.c` — All agent command implementations (largest file ~120KB)
- `Win32.c` — Windows API wrappers with dynamic resolution
- `Syscalls.c` — Indirect syscall stubs
- `Transport*.c` — HTTP and SMB transport layers
- `Token.c` — Token manipulation/impersonation
- `Obf.c` — Sleep obfuscation (Ekko, Ziliean, FOLIAGE)
- `HwBpEngine.c` — Hardware breakpoint-based AMSI/ETW patching
- `CoffeeLdr.c` — BOF (Beacon Object File) and .NET loader
- `Kerberos.c` — Kerberos authentication support

Assembly stubs in `src/asm/` handle syscall invocation and return address spoofing.

## Configuration

Profiles use the **YAOTL** format (TOML-based dialect), stored in `profiles/`. See `profiles/havoc.yaotl` for a full example.

Key profile sections:
- `Teamserver {}` — Host, port, build compiler paths
- `Operators {}` — User credentials
- `Demon {}` — Agent defaults (sleep, jitter, injection settings)
- `Service {}` — External C2 endpoint (optional)

To run the teamserver:
```bash
./havoc server --profile profiles/havoc.yaotl
```

## Code Constraints

### AMSI / ETW Patching

**Never use memory byte patching for AMSI or ETW evasion.** The only permitted technique is the hardware breakpoint (HWBP) engine already implemented in `src/core/HwBpEngine.c`.

- Do not write `0xC3`, `0xB8 0x57 0x00 0x07 0x80 0xC3`, or any other byte sequence directly over `AmsiScanBuffer`, `NtTraceEvent`, or any other AMSI/ETW function entry point.
- Do not call `NtProtectVirtualMemory` + `memcpy`/`MemCopy` to patch function prologues for evasion purposes.
- All AMSI/ETW suppression must go through `HwBpEngine` — add a breakpoint via `HwBpEngineAdd()`, handle it in the VEH, and return cleanly. This applies to any new evasion code, any refactoring of existing evasion code, and any improvement spec that touches AMSI or ETW.

This rule overrides any improvement spec (including HVC-031) that proposes a memory-patch approach. If an improvement doc conflicts with this rule, follow this rule and note the deviation in the PR description.

## Contributing

- Branch off `main`, submit PRs back to `main`
- Separate PRs for separate features/fixes (no monolithic PRs)

## Improvement Documentation

All improvement proposals, feature specifications, and enhancement plans for new capabilities must be written to the **`improvement-docs/`** directory at the repository root. This is the canonical location for:
- New feature specs (transport additions, evasion techniques, new commands)
- Refactoring proposals (module extraction, architecture changes)
- Traffic encoding / protocol improvement designs

See `improvement-docs/00-index.md` for the master index and item status. Each file follows the standard template (Status, Problem, Scope, Design, File Map, Tests, Notes). Do **not** place improvement specs in root-level markdown files or in memory files — `improvement-docs/` is the only correct location.
