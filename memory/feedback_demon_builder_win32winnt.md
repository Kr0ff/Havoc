---
name: feedback-demon-builder-win32winnt
description: Demon builder.go must include src/commands in SourceDirs and set _WIN32_WINNT=0x0603 in CFlags; WIN_FUNC() cannot reference Vista+/Win8.1+ APIs without these
metadata:
  type: feedback
---

When adding new Demon command groups to `src/commands/`, two things must be done in `teamserver/pkg/common/builder/builder.go`:

1. **Add `"src/commands"` to `builder.compilerOptions.SourceDirs`** — the builder iterates SourceDirs to discover `.c` files for the compile command. If `src/commands` is absent, none of the command group files are compiled.

2. **`-D_WIN32_WINNT=0x0603` is in `CFlags`** — MinGW-w64 defaults to `_WIN32_WINNT=0x0502` (XP SP2) when no override is set. Vista+/Win8.1+ APIs (`GetIpNetTable2`, `FreeMibTable`, `GetIpNetTable2`, `MIB_IPNET_TABLE2`, `PssCaptureSnapshot`, `HPSS`) are all conditionally compiled out of MinGW headers below their version threshold. Without this flag every `.c` file that references those types fails to compile.

**Why:** `WIN_FUNC(x)` expands to `__typeof__(x) * x;` which needs the function already declared by a header. If `_WIN32_WINNT` is too low, the function isn't in any visible header at that point → "undeclared" error repeated for every .c file that includes `Demon.h`.

**How to apply:**
- When adding any Win32 function pointer field to `Demon.h` for an API that is Vista+ or newer, DO NOT use `WIN_FUNC(x)` — use `PVOID x;` instead and add a local typedef cast at the call site. (Applied to PssCaptureSnapshot, PssFreeSnapshot, GetIpNetTable2, FreeMibTable in HVC-032.)
- Verify `src/commands` is in SourceDirs before shipping any new command group.
- `processsnapshot.h` may not be available on all MinGW installs. Use `#ifndef _PROCESSSNAPSHOT_H_` compat block in `Command_Creds.c` with inline typedefs/defines from MSDN instead of `#include <processsnapshot.h>`.

**Related:** [[feedback-commandsend-info-type]] (client-side QMap fix for HVC-032 commands)
