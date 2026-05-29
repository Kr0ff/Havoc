##
## MinGW-w64 cross-compilation toolchain for building a Windows target from a
## Linux host. Pass this file at configure time:
##
##   cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64.cmake
##
## This file is not used for native Linux, macOS, or Windows (MSVC) builds.
## The default (no toolchain file) selects the host's native compiler.
##
set( CMAKE_SYSTEM_NAME     Windows )
set( CMAKE_C_COMPILER      x86_64-w64-mingw32-gcc    )
set( CMAKE_CXX_COMPILER    x86_64-w64-mingw32-g++    )
set( CMAKE_RC_COMPILER     x86_64-w64-mingw32-windres )
set( CMAKE_FIND_ROOT_PATH  /usr/x86_64-w64-mingw32   )

## Search for programs on the host, libraries and headers in the sysroot.
set( CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER )
set( CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY  )
set( CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY  )
