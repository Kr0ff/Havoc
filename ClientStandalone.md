## Plan: `client-standalone/` implementation

**Summary:** Create a new `client-standalone/` directory at the repo root containing a fixed
cross-platform CMake build that references `../client/` sources. Two source files in `client/`
get minimal backward-compatible Qt6 guards. Nothing else in `client/` is touched.

---

### Phase 1 — New files (no existing code changed)

**1. `client-standalone/CMakeLists.txt`**

- `get_filename_component(CLIENT_DIR ../client ABSOLUTE)` — all source paths from there
- MinGW lines deleted; no `set(CMAKE_C_COMPILER ...)` or `set(CMAKE_CPP_COMPILER ...)`
- `if(NOT MSVC) add_compile_options(-fpermissive) endif()` replaces `set(CMAKE_CXX_FLAGS)`
- `find_package(QT NAMES Qt6 Qt5 ...)` with Qt6/Qt5 `REQUIRED_LIBS_QUALIFIED` conditional
- `find_package(Python3 3.10 COMPONENTS Interpreter Development REQUIRED)` replaces all 3 broken platform blocks
- `include_directories(${Python3_INCLUDE_DIRS})` — single cross-platform Python include
- All header and source paths prefixed with `${CLIENT_DIR}/`
- `add_definitions(-DFMT_CONSTEVAL=)` and `-DQT_NO_DEBUG_OUTPUT` retained
- `if(APPLE)` block: `MACOSX_BUNDLE TRUE`, bundle metadata, `find_package(OpenSSL REQUIRED)`, `target_link_libraries OpenSSL::SSL OpenSSL::Crypto`
- `if(WIN32)` block: `WIN32_EXECUTABLE TRUE`, `WINVER=0x0A00`, `_WIN32_WINNT=0x0A00`, MSVC `/W3 /wd4996` flags
- `target_link_libraries` using `${REQUIRED_LIBS_QUALIFIED}` + `${Python3_LIBRARIES}`
- No `add_subdirectory(tests)` — tests run from `client/` directly

**2. `client-standalone/cmake/toolchains/mingw-w64.cmake`**

- `CMAKE_SYSTEM_NAME Windows`
- `CMAKE_C_COMPILER x86_64-w64-mingw32-gcc`
- `CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++`
- `CMAKE_RC_COMPILER x86_64-w64-mingw32-windres`
- `CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32`
- `FIND_ROOT_PATH_MODE_*` guards

---

### Phase 2 — Source guards (backward-compatible, Qt5 builds unaffected)

**3. Edit `client/include/global.hpp` line 29**

Wrap `#include <QTextCodec>` with:

```cpp
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#include <QTextCodec>
#endif
```

**4. Edit `client/src/Havoc/Havoc.cc` line 68**

Wrap `QTextCodec::setCodecForLocale(...)` with:

```cpp
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    QTextCodec::setCodecForLocale( QTextCodec::codecForName( "UTF-8" ) );
#endif
```

---

### Files

| Action | Path |
|--------|------|
| CREATE | `client-standalone/CMakeLists.txt` |
| CREATE | `client-standalone/cmake/toolchains/mingw-w64.cmake` |
| EDIT   | `client/include/global.hpp` line 29 — guard `<QTextCodec>` |
| EDIT   | `client/src/Havoc/Havoc.cc` line 68 — guard `QTextCodec::setCodecForLocale()` |

---

### Verification

1. `cd client-standalone && mkdir Build && cd Build && cmake .. -DCMAKE_BUILD_TYPE=Release` — configure must succeed with no Qt or Python errors
2. `cmake --build . -- -j$(nproc)` — must produce `Havoc` binary with zero errors
3. `cd client && mkdir Build && cd Build && cmake .. && make -j$(nproc)` — original build still works (Qt5 guards did not break anything)
4. macOS: re-run configure with `-DQt5_DIR=$(brew --prefix qt@5)/lib/cmake/Qt5 -DPython3_ROOT_DIR=$(brew --prefix python@3.12)` — Python 3.12 now accepted
5. Confirm `Havoc.app` bundle is created on macOS (`ls Build/Havoc.app/Contents/`)

---

### Decisions

- Source files stay in `client/` — `client-standalone/` is build infrastructure only, no duplication
- The original `client/CMakeLists.txt` is not modified — it continues to work as-is for the existing Linux cross-compile workflow
- Qt6 source compatibility changes (QTextCodec guards) go into `client/` since they are `#if`-guarded and do not change Qt5 build behaviour
- `data/Havoc.rc` included unconditionally in `add_executable` — CMake ignores `.rc` files on non-Windows automatically
- Tests not included in `client-standalone/` — they reference `${CMAKE_SOURCE_DIR}/external/...` which would resolve incorrectly from the new root; tests remain under `client/`

