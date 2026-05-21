##
## Unit tests for Havoc client external library API compatibility.
##
## Each test target is a self-contained executable that compiles and links
## against the same headers the main client uses, then runs a set of
## lightweight smoke tests to confirm the library APIs are available and
## behave correctly.
##
## Run after the main build:
##   cmake --build . --target test
##   ctest --output-on-failure
##

cmake_minimum_required( VERSION 3.15 )

## Inherit include paths and compile definitions from the parent scope so
## that -DFMT_CONSTEVAL=, include_directories, and the C++ standard setting
## are automatically applied to every test target.

# ── spdlog ────────────────────────────────────────────────────────────────────
add_executable( test_spdlog test_spdlog.cpp )
target_include_directories( test_spdlog PRIVATE
    ${CMAKE_SOURCE_DIR}/external/spdlog/include
)
add_test( NAME spdlog_api COMMAND test_spdlog )

# ── nlohmann/json ─────────────────────────────────────────────────────────────
add_executable( test_json test_json.cpp )
target_include_directories( test_json PRIVATE
    ${CMAKE_SOURCE_DIR}/external/json/include
)
add_test( NAME json_api COMMAND test_json )

# ── toml11 ────────────────────────────────────────────────────────────────────
add_executable( test_toml test_toml.cpp )
target_include_directories( test_toml PRIVATE
    ${CMAKE_SOURCE_DIR}/external/toml
)
add_test( NAME toml_api COMMAND test_toml )
