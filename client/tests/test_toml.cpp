/**
 * test_toml.cpp — Compile-time and runtime API compatibility test for toml11.
 *
 * Verifies that every toml11 API used by the Havoc client compiles and
 * behaves correctly after the library update from v3.7.1 to v3.8.1.
 *
 * API coverage mirrors the actual usage found in:
 *   src/Havoc/Havoc.cc
 *   src/Havoc/Packager.cc
 *   include/Havoc/Havoc.hpp
 *
 * Client-specific toml type alias:
 *   using toml_t = toml::basic_value<toml::discard_comments,
 *                                    std::unordered_map, std::vector>;
 */

#include <toml.hpp>

#include <cstdio>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// Mirror the client's type alias exactly as declared in include/Havoc/Havoc.hpp.
using toml_t = toml::basic_value<toml::discard_comments,
                                  std::unordered_map,
                                  std::vector>;

// ── helpers ───────────────────────────────────────────────────────────────────

static int failures = 0;

#define CHECK(expr, msg)                                          \
    do {                                                          \
        if ( !(expr) ) {                                          \
            fprintf( stderr, "FAIL [toml] %s\n", msg );          \
            ++failures;                                           \
        } else {                                                  \
            printf(  "PASS [toml] %s\n", msg );                  \
        }                                                         \
    } while(0)

// Helper: parse a TOML string into the client's toml_t type.
static toml_t parse( const std::string& src )
{
    auto ss = std::istringstream{ src };
    return toml::parse<toml::discard_comments,
                       std::unordered_map,
                       std::vector>( ss, "<test>" );
}

// ── tests ─────────────────────────────────────────────────────────────────────

/**
 * toml::parse — the primary entry point used in Havoc.cc when loading the
 * client configuration file.
 */
static void test_parse_basic()
{
    auto v = parse( "[Teamserver]\nHost = \"127.0.0.1\"\nPort = 40056\n" );
    CHECK( v.is_table(), "parse: result is a table" );
}

/**
 * toml::find<std::string> — used throughout Havoc.cc and Packager.cc to
 * extract string configuration values.
 */
static void test_find_string()
{
    auto v    = parse( "[Teamserver]\nHost = \"127.0.0.1\"\n" );
    auto host = toml::find<std::string>( v, "Teamserver", "Host" );
    CHECK( host == "127.0.0.1", "find<string>: Teamserver.Host correct" );
}

/**
 * toml::find<int> — used when reading integer-typed config values such as
 * listener port numbers and sleep intervals.
 */
static void test_find_int()
{
    auto v    = parse( "[Teamserver]\nPort = 40056\n" );
    auto port = toml::find<int>( v, "Teamserver", "Port" );
    CHECK( port == 40056, "find<int>: Teamserver.Port correct" );
}

/**
 * toml::find<bool> — used for boolean flags in payload and listener configs.
 */
static void test_find_bool()
{
    auto v       = parse( "[Demon]\nAmsiPatch = true\nEtwPatch = false\n" );
    auto amsi    = toml::find<bool>( v, "Demon", "AmsiPatch" );
    auto etw     = toml::find<bool>( v, "Demon", "EtwPatch" );
    CHECK(  amsi, "find<bool>: AmsiPatch true" );
    CHECK( !etw,  "find<bool>: EtwPatch false" );
}

/**
 * toml::find<std::vector<std::string>> — used in Packager.cc when reading
 * list-valued config entries such as hosts, URIs, and headers.
 */
static void test_find_string_vector()
{
    auto v    = parse( "[Listener]\nHosts = [\"192.168.1.1\", \"10.0.0.1\"]\n" );
    auto hosts = toml::find<std::vector<std::string>>( v, "Listener", "Hosts" );
    CHECK( hosts.size() == 2,           "find<vector<string>>: two elements" );
    CHECK( hosts[0] == "192.168.1.1",   "find<vector<string>>: element 0" );
    CHECK( hosts[1] == "10.0.0.1",      "find<vector<string>>: element 1" );
}

/**
 * toml::find (non-templated overload returning toml_t) — used when the caller
 * needs to introspect the type or pass it further down the call stack.
 */
static void test_find_subtable()
{
    auto v      = parse( "[Operator]\nUsername = \"ghost\"\n" );
    auto opNode = toml::find( v, "Operator" );
    CHECK( opNode.is_table(), "find subtable: result is table" );
    auto name   = toml::find<std::string>( opNode, "Username" );
    CHECK( name == "ghost",   "find subtable: Username correct" );
}

/**
 * toml::discard_comments type — the client's toml_t alias specifies this as
 * the comment policy. Ensure it still compiles as a template argument.
 */
static void test_discard_comments_type()
{
    // If this compiles, the type alias is valid against toml11 v3.8.1.
    auto v = parse( "# this comment is discarded\nkey = \"value\"\n" );
    auto s = toml::find<std::string>( v, "key" );
    CHECK( s == "value", "discard_comments: key accessible after comment line" );
}

/**
 * Exception on missing key — the client uses try/catch around toml::find
 * when a key may be absent.
 */
static void test_find_missing_key_throws()
{
    auto v     = parse( "[Section]\nkey = 1\n" );
    bool threw = false;
    try {
        (void) toml::find<int>( v, "Section", "nonexistent" );
    } catch ( const std::exception& ) {
        threw = true;
    }
    CHECK( threw, "find missing key throws std::exception" );
}

// ── entry point ───────────────────────────────────────────────────────────────

int main()
{
    // toml11 does not expose a single version macro; read from CMake instead.
    printf( "=== toml11 v3.8.1 API compatibility ===\n" );

    test_parse_basic();
    test_find_string();
    test_find_int();
    test_find_bool();
    test_find_string_vector();
    test_find_subtable();
    test_discard_comments_type();
    test_find_missing_key_throws();

    if ( failures > 0 ) {
        fprintf( stderr, "\n%d test(s) FAILED\n", failures );
        return 1;
    }
    printf( "\nAll toml tests PASSED\n" );
    return 0;
}
