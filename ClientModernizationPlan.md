# Havoc Client — Modernization Action Plan

**Goal:** Update the client to build cleanly against current versions of all
external libraries and add native compilation support for macOS and Windows.
No changes to runtime behaviour or user-visible functionality are included.

---

## Dependency Inventory

| Library | Vendored version | Latest stable | Breaking API changes? |
|---------|-----------------|---------------|-----------------------|
| spdlog | 1.12.0 (bundles fmt 9.1.0) | **1.14.1** (bundles fmt 11.1) | No — `spdlog::info/warn/error/debug/critical/set_pattern` are stable across all 1.x |
| nlohmann/json | 3.11.2 | **3.11.3** | No — patch release only |
| toml11 | 3.7.1 | **3.8.1** | No — API is stable within v3.x |
| Qt | 5.15.18 (system, macOS) | 5.15.x (LTS) / **6.8.x** | Qt 6 has removals (see Step 2.5) |
| Python | 3.10 (hardcoded) | 3.10+ | No — C-API usage is stable |

---

## Major Step 1 — Update Vendored External Libraries

All three libraries live under `client/external/` as header-only copies.
Updating each one is a drop-in replacement; no source-code changes to the
client itself are required.

### 1.1 — Update spdlog (1.12.0 → 1.14.1)

**Why:** spdlog 1.12.0 bundles fmt 9.1.0. On Apple Clang 15 and later the
`consteval` guard in `spdlog/fmt/bundled/core.h` incorrectly enables
`FMT_CONSTEVAL = consteval` via the `__cpp_consteval` branch (the guard was
written to exclude Apple Clang ≤ 13, but Apple Clang 15+ also defines
`__cpp_consteval`, re-enabling consteval). The resulting stricter evaluation
in newer compilers rejects `fmt_helper.h:91`. spdlog 1.13.0 and later bundle
fmt 10.x / 11.x where this guard has been corrected.

**Changes required:**
- Replace `client/external/spdlog/` with the spdlog 1.14.1 header-only release.
- No changes to any client source file; the logging API
  (`spdlog::info`, `spdlog::warn`, `spdlog::error`, `spdlog::debug`,
  `spdlog::critical`, `spdlog::set_pattern`, `spdlog::level`) is identical
  across all 1.x releases.
- The `target_link_libraries` entries for `spdlog::spdlog` and
  `spdlog::spdlog_header_only` remain commented out in `CMakeLists.txt`
  (header-only include-path usage is unchanged).

**Steps:**
```bash
cd client/external
rm -rf spdlog
git clone --depth=1 --branch v1.14.1 \
    https://github.com/gabime/spdlog.git spdlog
# Remove the git metadata — the directory is vendored, not a submodule.
rm -rf spdlog/.git
```

**Verification:** `make client-build` must complete without any error from
`spdlog/details/fmt_helper.h` or `spdlog/fmt/bundled/`.

---

### 1.2 — Update nlohmann/json (3.11.2 → 3.11.3)

**Why:** 3.11.3 is a patch release that fixes a small number of edge-case
bugs. No breaking changes. The client uses only `json::parse()` and standard
value access; both are unchanged.

**Changes required:**
- Replace `client/external/json/` with the single-header release of 3.11.3.
- No changes to any client source file.

**Steps:**
```bash
cd client/external/json/include/nlohmann
# Download the amalgamated single header directly
curl -L https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp \
     -o json.hpp
```

Alternatively replace the full `external/json/` directory:
```bash
cd client/external
rm -rf json
git clone --depth=1 --branch v3.11.3 \
    https://github.com/nlohmann/json.git json
rm -rf json/.git
```

**Verification:** Build succeeds; all JSON parsing functionality (listener
profiles, payload configs, connector messages) behaves identically at runtime.

---

### 1.3 — Update toml11 (3.7.1 → 3.8.1)

**Why:** 3.8.1 is the latest patch in the stable v3 series. It fixes several
edge-case parse bugs and improves error messages. The client uses
`toml::parse`, `toml::find<T>`, `toml::find`, and `toml::discard_comments`;
all are unchanged in the v3.x API.

> **Important:** Do NOT update to toml11 v4.x. The v4 release is a complete
> API rewrite (e.g. `toml::parse` returns a different type, `toml::find` is
> removed). A v4 migration would require changes throughout `src/Havoc/Packager.cc`,
> `src/Havoc/Havoc.cc`, and `include/Havoc/Havoc.hpp` and is therefore out
> of scope for a library-update-only pass.

**Changes required:**
- Replace `client/external/toml/` with the toml11 3.8.1 header-only release.
- No changes to any client source file.

**Steps:**
```bash
cd client/external
rm -rf toml
git clone --depth=1 --branch v3.8.1 \
    https://github.com/ToruNiina/toml11.git toml
rm -rf toml/.git
```

**Verification:** Build succeeds; profile parsing in
`src/Havoc/Packager.cc` and `src/Havoc/Havoc.cc` behaves identically.

---

### 1.4 — Test Step 1 completion

After all three library replacements:

```bash
# Clean stale CMake cache to avoid cached include paths from old libraries.
rm -rf client/Build
make client-build
```

Expected: zero errors from `client/external/`. Deprecation warnings from
older Qt5 APIs are acceptable and addressed in Step 2.

---

## Major Step 2 — Native Compilation for macOS and Windows

The current `CMakeLists.txt` has three problems that prevent native
compilation on macOS (beyond the spdlog issue) and block any native Windows
build entirely:

1. **Cross-compiler override** — `CMAKE_C_COMPILER` and `CMAKE_CPP_COMPILER`
   are hardcoded to MinGW paths, overriding CMake's auto-detected native
   compiler.
2. **Hardcoded Python 3.10 include paths** — macOS uses Homebrew paths that
   are version-specific (`python3.10`); Windows has no working detection at
   all (reads a raw env-var string without locating headers or libraries).
3. **GCC-only compile flag** — `-fpermissive` is a GCC/Clang flag that MSVC
   does not recognise; passing it unconditionally causes MSVC to error out.

Steps 2.1–2.4 fix the CMakeLists.txt. Step 2.5 documents the Qt6 path for
when a full Qt upgrade is desired (required on Windows where Qt5 binaries are
no longer shipped by the official installer).

---

### 2.1 — Remove the hardcoded cross-compiler toolchain from CMakeLists.txt

**File:** `client/CMakeLists.txt`

**Problem:** Lines 12–13 unconditionally override the C and C++ compiler to
the MinGW cross-compiler. On any machine where `/usr/bin/x86_64-w64-mingw32-g++`
does not exist the configure step fails immediately. On macOS it silently
overrides Apple Clang with a non-existent binary; CMake uses the overridden
path at generate time but the error surfaces only at build time.

Setting `CMAKE_C_COMPILER` / `CMAKE_CXX_COMPILER` inside `CMakeLists.txt` is
also explicitly discouraged by CMake — it must be done either on the command
line or via a toolchain file, and only before the first `project()` call.

**Action:** Remove lines 12–13 entirely:
```cmake
# DELETE these two lines:
set( CMAKE_CPP_COMPILER /usr/bin/x86_64-w64-mingw32-g++ )
set( CMAKE_C_COMPILER /usr/bin/x86_64-w64-mingw32-gcc )
```

Cross-compilation to Windows from a Linux/macOS host remains possible by
passing a CMake toolchain file at configure time:
```bash
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/mingw-w64.cmake
```
A sample toolchain file (`client/cmake/toolchains/mingw-w64.cmake`) should be
created with:
```cmake
set( CMAKE_SYSTEM_NAME Windows )
set( CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc )
set( CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++ )
set( CMAKE_RC_COMPILER  x86_64-w64-mingw32-windres )
```

---

### 2.2 — Guard the `-fpermissive` flag for non-MSVC compilers

**File:** `client/CMakeLists.txt`

**Problem:** `-fpermissive` is a GCC/Clang-specific flag that MSVC does not
accept. Passing it unconditionally causes a fatal error when building with
the MSVC toolchain.

**Action:** Replace the unconditional flag with a compiler-aware block:
```cmake
# Replace:
set( CMAKE_CXX_FLAGS "-fpermissive" )

# With:
if( NOT MSVC )
    add_compile_options( -fpermissive )
endif()
```

`add_compile_options` is preferred over `CMAKE_CXX_FLAGS` because it applies
only to the current directory scope and avoids cache pollution.

---

### 2.3 — Unify Python 3 detection across all platforms

**File:** `client/CMakeLists.txt`

**Problem — macOS:** The macOS branch uses `find_package(Python 3 ...)` and
then adds Homebrew include paths hardcoded to `python3.10`:
```cmake
include_directories( "${BREW_PREFIX}/bin/python3.10" )
include_directories( "${BREW_PREFIX}/Frameworks/Python.framework/Headers" )
```
These paths are wrong for Python 3.11, 3.12, or 3.13 and break the build
if the system Python is not exactly 3.10.

**Problem — Linux:** Uses the legacy `find_package(PythonLibs 3 REQUIRED)`
module which has been superseded by `FindPython3` since CMake 3.12 and
deprecated in CMake 3.27.

**Problem — Windows:** The Windows branch does not find Python at all —
it only sets `PYTHONLIBS_VERSION_STRING` from an environment variable,
never locating headers or libraries. The build will fail to compile
`src/Havoc/PythonApi/PythonApi.cc` because `Python.h` is never found.

**Action:** Replace the entire platform-specific Python detection block with
a single `find_package(Python3 ...)` call that works on all three platforms:

```cmake
# Remove the entire if(APPLE)/elseif(UNIX)/else() Python detection block
# and the subsequent if(APPLE)/elseif(UNIX) include_directories block.
# Replace with:

find_package( Python3 3.10 COMPONENTS Interpreter Development REQUIRED )
include_directories( ${Python3_INCLUDE_DIRS} )

# Keep the legacy variable names so the target_link_libraries line
# below compiles without further changes.
set( PYTHON_LIBRARIES ${Python3_LIBRARIES} )
```

`FindPython3` searches the system Python registry on Windows, framework on
macOS, and pkg-config on Linux — no platform-specific code is needed.
The `3.10` minimum version preserves the existing requirement; any Python
≥ 3.10 installed on the host will be accepted automatically.

---

### 2.4 — Windows-specific CMake settings for native MSVC builds

**File:** `client/CMakeLists.txt`

Add a `WIN32` platform block after the `add_executable` call to configure
settings required for a native Windows GUI application:

```cmake
if( WIN32 )
    # Suppress the console window; produce a proper GUI executable.
    set_target_properties( ${PROJECT_NAME} PROPERTIES
        WIN32_EXECUTABLE TRUE
    )

    # Define the minimum supported Windows version (Windows 10).
    target_compile_definitions( ${PROJECT_NAME} PRIVATE
        WINVER=0x0A00
        _WIN32_WINNT=0x0A00
    )

    # Silence MSVC's deprecation warnings for C runtime functions
    # (sprintf → sprintf_s etc.) that do not affect correctness here.
    if( MSVC )
        target_compile_definitions( ${PROJECT_NAME} PRIVATE
            _CRT_SECURE_NO_WARNINGS
        )
    endif()
endif()
```

**Why `WIN32_EXECUTABLE TRUE`:** Without this flag, CMake links with the
`/SUBSYSTEM:CONSOLE` linker flag on Windows, which causes a terminal window
to open alongside the GUI every time the application is launched. This
matches what the MinGW cross-build already produces via the commented
`-mwindows` convention.

**Why `WINVER`/`_WIN32_WINNT`:** Qt5/Qt6 on Windows requires these macros
to enable the correct Windows API surface. Without them, certain socket and
WebSocket APIs resolve to stub versions missing from older SDK headers.

---

### 2.5 — macOS application bundle

**File:** `client/CMakeLists.txt`

Add a macOS bundle block after the `add_executable` call so that `make
client-build` on macOS produces a proper `.app` bundle (required for correct
icon display, dock integration, and code signing):

```cmake
if( APPLE )
    set_target_properties( ${PROJECT_NAME} PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_BUNDLE_NAME        "Havoc"
        MACOSX_BUNDLE_BUNDLE_VERSION     "1.0"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0"
        MACOSX_BUNDLE_GUI_IDENTIFIER     "com.havocframework.client"
        MACOSX_BUNDLE_ICON_FILE          "Havoc.icns"
    )
endif()
```

An `icns` file can be generated from the existing `data/Havoc.ico` with:
```bash
# Requires ImageMagick (brew install imagemagick)
convert data/Havoc.ico data/Havoc.icns
```

---

### 2.6 — Qt6 migration (required for Windows; optional for macOS/Linux)

Qt5 binary packages are no longer distributed by the Qt Company for Windows
via the official Qt online installer (removed after Qt 5.15 LTS). On Windows,
Qt6 is the only version available from the official installer.
On macOS and Linux, Qt5 LTS (5.15.x) remains available via Homebrew and
package managers.

**Scope of source changes:** The client uses one Qt5-only API that was removed
in Qt6:

| Qt5 API | Removed in Qt6 | Qt6 replacement | Files affected |
|---------|---------------|-----------------|----------------|
| `QTextCodec::setCodecForLocale` / `QTextCodec::codecForName` | Yes | Removed; UTF-8 is the default locale in Qt6 | `src/Havoc/Havoc.cc:68`, `include/global.hpp:29` |

All other Qt APIs used (`QWebSocket`, `QSqlDatabase`, `QNetworkAccessManager`,
widget classes, etc.) are present and API-compatible in Qt6.

**Required source changes for Qt6:**

1. **`include/global.hpp`** — remove the `#include <QTextCodec>` line.

2. **`src/Havoc/Havoc.cc`** — remove the `QTextCodec::setCodecForLocale`
   call. In Qt6 the application locale is UTF-8 by default; the call was only
   a UTF-8 enforcement guard and has no functional effect if removed.

**Required CMakeLists.txt changes for Qt6:**

```cmake
# Change:
set( QT_VERSION 5 )
set( REQUIRED_LIBS_QUALIFIED Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network Qt5::WebSockets Qt5::Sql )

# To:
set( QT_VERSION 6 )
set( REQUIRED_LIBS_QUALIFIED Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network Qt6::WebSockets Qt6::Sql )
```

All other `Qt${QT_VERSION}` references in `find_package` already expand
correctly because CMake uses the variable.

**Qt6 installation per platform:**

- **Windows (MSVC):** Qt online installer → Qt 6.8 → MSVC 2022 64-bit
- **Windows (MinGW):** Qt online installer → Qt 6.8 → MinGW 13.1 64-bit
- **macOS:** `brew install qt`
- **Linux (Debian/Ubuntu):** `sudo apt install qt6-base-dev qt6-websockets-dev libqt6sql6-sqlite`

**Optional — support both Qt5 and Qt6 in one CMakeLists.txt:**

```cmake
# Try Qt6 first; fall back to Qt5 if Qt6 is not installed.
find_package( QT NAMES Qt6 Qt5 COMPONENTS ${REQUIRED_LIBS} REQUIRED )
find_package( Qt${QT_MAJOR_VERSION} COMPONENTS ${REQUIRED_LIBS} REQUIRED )

if( QT_MAJOR_VERSION EQUAL 6 )
    set( REQUIRED_LIBS_QUALIFIED
         Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network Qt6::WebSockets Qt6::Sql )
else()
    set( REQUIRED_LIBS_QUALIFIED
         Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network Qt5::WebSockets Qt5::Sql )
endif()
```

---

## Execution Order

| Order | Action | Files changed | Risk |
|-------|--------|--------------|------|
| 1 | Replace `external/spdlog/` with v1.14.1 | vendored headers only | None — API identical |
| 2 | Replace `external/json/include/nlohmann/json.hpp` with v3.11.3 | vendored header only | None — patch release |
| 3 | Replace `external/toml/` with v3.8.1 | vendored headers only | None — API identical within v3 |
| 4 | `rm -rf client/Build && make client-build` | — | Validates Step 1 |
| 5 | Remove hardcoded compiler lines (2.1) | `CMakeLists.txt` | None on macOS/Windows native |
| 6 | Guard `-fpermissive` (2.2) | `CMakeLists.txt` | None |
| 7 | Unify Python3 detection (2.3) | `CMakeLists.txt` | None |
| 8 | Add Windows platform block (2.4) | `CMakeLists.txt` | None on non-Windows |
| 9 | Add macOS bundle properties (2.5) | `CMakeLists.txt` | None on non-macOS |
| 10 | `make client-build` on macOS | — | Validates Steps 5–9 |
| 11 | Remove `QTextCodec` usage (2.6 — if targeting Qt6) | `global.hpp`, `Havoc.cc` | None — call was a no-op guard |
| 12 | Switch to Qt6 in CMakeLists.txt (2.6 — if targeting Qt6) | `CMakeLists.txt` | None |
| 13 | Build on Windows with MSVC + Qt6 | — | Validates full plan |
