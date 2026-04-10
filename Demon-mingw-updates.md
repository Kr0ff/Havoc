# Demon mingw-w64 v15 Compatibility Fixes

## Problem

The Demon agent fails to compile with mingw-w64 v14+ (GCC 14+). GCC 14 promotes
several previously-warning diagnostics to **hard errors**:

- `-Wincompatible-pointer-types` → error
- `-Wint-conversion` → error
- `-Wimplicit-function-declaration` → error
- Empty `()` parameter lists treated as `(void)` (C23 behavior backported)

The existing `-w` flag in CMakeLists.txt suppresses warnings but cannot suppress
these new errors. These changes restore compilation with mingw-w64 v14/v15 while
maintaining full backward compatibility with mingw-w64 v11.

---

## Changes

### 1. MemSet / MemZero macros (MiniStd.h)

**Root cause:** `__stosb` in mingw-w64 v14+ has a strict signature requiring
`unsigned char*` as its first argument. The old `#define MemSet __stosb` passed
arbitrary struct pointers directly.

**Fix:** Changed macros to cast the pointer argument:

```c
// Before:
#define MemSet          __stosb
#define MemZero( p, l ) __stosb( p, 0, l )

// After:
#define MemSet( d, v, l )  __stosb( (unsigned char*)(d), (v), (l) )
#define MemZero( p, l )    __stosb( (unsigned char*)(p), 0, (l) )
```

**Impact:** Fixes ~60% of all compilation errors. Affects every file that uses
`MemSet`, `MemZero`, or `DATA_FREE` (which expands to `MemSet`).

**Files affected:** `include/core/MiniStd.h` (macro definition only; no call
sites changed)

---

### 2. NULL → 0 for integer type initializations

**Root cause:** `UINT32 x = NULL` and `SIZE_T x = NULL` produce
`-Wint-conversion` errors (makes integer from pointer).

**Fix:** Replaced `NULL` with `0` in integer variable initializations.

| File | Line | Variable |
|------|------|----------|
| `src/core/Command.c` | 721 | `UINT32 PathSize` |
| `src/core/Command.c` | 3510 | `SIZE_T ImageSize` |
| `src/core/Syscalls.c` | 207 | `WORD NeighbourSsn` |
| `src/core/Win32.c` | 1503 | `UINT32 PathSize` |
| `src/core/Socket.c` | 78 | `WSASocketA` last arg (DWORD flags, not pointer) |

---

### 3. Missing function forward declarations

**Root cause:** `-Wimplicit-function-declaration` is now an error. Several
functions were used before being declared.

**Fix:** Added forward declarations to header files:

| Header | Functions added |
|--------|---------------|
| `include/core/MiniStd.h` | `StringCompareIW`, `EndsWithIW` |
| `include/core/Token.h` | `GetTokenInfo`, `IsNotCurrentUser` |
| `src/core/Command.c` | Added `#include <core/Runtime.h>` for `RtMscoree` |

---

### 4. SysInvoke variadic declaration (Syscalls.h)

**Root cause:** GCC 14+ treats `NTSTATUS SysInvoke(_Inout_ /* Args... */)` as
having 0 parameters (since `_Inout_` expands to nothing). All calls from
SysNative.c pass 1-11 arguments, causing "too many arguments" errors.

**Fix:** Changed declaration to use proper variadic syntax:

```c
// Before:
NTSTATUS SysInvoke(
    _Inout_ /* Args... */
);

// After:
NTSTATUS SysInvoke(
    ULONG_PTR Arg1, ...
);
```

This is safe because SysInvoke is an ASM function that reads arguments from
registers per the Windows x64 calling convention. The calling convention is
identical for variadic and non-variadic functions on x64.

**File:** `include/core/Syscalls.h`

---

### 5. Incompatible pointer type casts

**Root cause:** GCC 14+ enforces strict pointer type compatibility. Various
function calls passed pointers of subtly different types.

| File | Line | Fix |
|------|------|-----|
| `src/core/Command.c` | 639 | Cast `SysProcessInfo->ImageName.Buffer` to `(PBYTE)` for `PackageAddBytes` |
| `src/core/Command.c` | 1296-1298 | Changed `DWORD Size/Argc` to `UINT32` for `ParserGetBytes` |
| `src/core/Command.c` | 1414 | Cast `TokenData->DomainUser` to `(PCHAR)` for `PackageAddString` |
| `src/core/Command.c` | 1562 | Changed `CHAR Deli[2]` to `WCHAR Deli[2]` for `StringConcatW` |
| `src/core/ObjectApi.c` | 477,481 | Cast `sInfo` to `(LPSTARTUPINFOW)` for `CreateProcessW`/`CreateProcessWithTokenW` |
| `src/core/Socket.c` | 323 | Cast `&PartialData.Length` to `(u_long*)` for `ioctlsocket` |
| `src/core/Socket.c` | 338 | Cast `&PartialData.Length` to `(PDWORD)` for `RecvAll` |
| `src/Demon.c` | 286,410 | Cast `&OsVersions`/`&OSVersionExW` to `(PRTL_OSVERSIONINFOW)` for `RtlGetVersion` |
| `src/core/Win32.c` | 179,180,197 | Cast `LIST_ENTRY*` Flink to `(PLDR_DATA_TABLE_ENTRY)` for PEB traversal |
| `src/inject/InjectUtil.c` | 47-62 | Cast `ReflectiveLdrAddr` to `(UINT_PTR)` for `Rva2Offset` calls |

---

## Test Coverage

A new test file `test/test_mingw_compat.c` covers:

1. **MemSet with struct pointers** — PTEST_STRUCT, PCONTEXT, PBUFFER
2. **MemZero with WCHAR arrays** — verifies correct zeroing
3. **MemSet with fill values** — verifies 3-arg macro form
4. **DATA_FREE with struct pointers** — verifies macro chain works
5. **Integer zero initialization** — UINT32, SIZE_T, WORD with `= 0`
6. **Pointer type casts** — PWSTR→PBYTE, UINT32*→u_long*, UINT32*→PDWORD
7. **WCHAR delimiter type** — `WCHAR Deli[2] = { L'\\', 0 }`
8. **OSVERSIONINFOEXW→PRTL_OSVERSIONINFOW cast** — field offset compatibility
9. **LDR_DATA_TABLE_ENTRY cast** — LIST_ENTRY* cast preserves address
10. **UINT_PTR pointer arithmetic** — InjectUtil.c patterns

Build and run:
```bash
cd payloads/Demon
x86_64-w64-mingw32-gcc -Iinclude -o test_mingw_compat.exe test/test_mingw_compat.c
# On Windows or via Wine:
./test_mingw_compat.exe
```

---

## Verification

To verify the full Demon agent compiles cleanly with mingw-w64 v15:

```bash
cd payloads/Demon
mkdir -p Build && cd Build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

All changes are backward-compatible with mingw-w64 v11.
