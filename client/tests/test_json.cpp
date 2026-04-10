/**
 * test_json.cpp — Compile-time and runtime API compatibility test for
 * nlohmann/json.
 *
 * Verifies that every nlohmann::json API used by the Havoc client compiles
 * and behaves correctly after the library update from v3.11.2 to v3.11.3.
 *
 * API coverage mirrors the actual usage found in:
 *   src/Havoc/Packager.cc
 *   src/Havoc/Connector.cc
 *   src/UserInterface/Dialogs/Listener.cc
 *   src/UserInterface/Widgets/Store.cc
 *   include/External.h  (typedef: using json = nlohmann::json)
 */

#include <nlohmann/json.hpp>

#include <cstdio>
#include <string>
#include <vector>

using json = nlohmann::json;

// ── helpers ───────────────────────────────────────────────────────────────────

static int failures = 0;

#define CHECK(expr, msg)                                         \
    do {                                                         \
        if ( !(expr) ) {                                         \
            fprintf( stderr, "FAIL [json] %s\n", msg );         \
            ++failures;                                          \
        } else {                                                  \
            printf(  "PASS [json] %s\n", msg );                  \
        }                                                        \
    } while(0)

// ── tests ─────────────────────────────────────────────────────────────────────

/**
 * json::parse() from a raw string — used throughout Connector.cc to decode
 * incoming teamserver messages.
 */
static void test_parse_object()
{
    auto j = json::parse( R"({"key":"value","num":42})" );
    CHECK( j["key"] == "value",  "parse: string field" );
    CHECK( j["num"] == 42,       "parse: integer field" );
}

/**
 * json::parse() from a std::string — the typical call form in the client.
 */
static void test_parse_string()
{
    std::string src = R"({"Body":{"AgentHeader":{"MagicValue":3735928559}}})";
    auto j = json::parse( src );
    CHECK( j.contains( "Body" ), "parse std::string: top-level key present" );
    CHECK( j["Body"]["AgentHeader"]["MagicValue"] == 3735928559u,
           "parse std::string: nested uint value correct" );
}

/**
 * json::parse() array — used when receiving session lists from the teamserver.
 */
static void test_parse_array()
{
    auto j = json::parse( R"([1,2,3])" );
    CHECK( j.is_array(),   "parse array: is_array() true" );
    CHECK( j.size() == 3,  "parse array: size is 3" );
    CHECK( j[0] == 1,      "parse array: first element is 1" );
}

/**
 * Object construction and serialisation — used in Packager.cc when building
 * payload request bodies.
 */
static void test_build_and_dump()
{
    json j;
    j["CommandID"] = "1";
    j["AgentID"]   = "DEADBEEF";
    j["Arguments"] = json::array();
    j["Arguments"].push_back( "arg1" );

    auto dumped = j.dump();
    CHECK( !dumped.empty(), "dump: produces non-empty string" );

    auto j2 = json::parse( dumped );
    CHECK( j2["CommandID"] == "1",       "roundtrip: CommandID preserved" );
    CHECK( j2["AgentID"]   == "DEADBEEF","roundtrip: AgentID preserved" );
    CHECK( j2["Arguments"][0] == "arg1", "roundtrip: Arguments[0] preserved" );
}

/**
 * .contains() and .value() accessors — used in Connector.cc to safely
 * retrieve optional fields from server messages.
 */
static void test_safe_access()
{
    auto j = json::parse( R"({"exists":true})" );
    CHECK(  j.contains( "exists" ),       "contains: present key returns true" );
    CHECK( !j.contains( "missing" ),      "contains: absent key returns false" );
    CHECK(  j.value( "exists",  false ),  "value: present key returns its value" );
    CHECK( !j.value( "missing", false ),  "value: absent key returns default" );
}

/**
 * Iterating over a JSON object — used when processing listener and session
 * tables received from the teamserver.
 */
static void test_iteration()
{
    auto j = json::parse( R"({"a":1,"b":2,"c":3})" );
    int  count = 0;
    for ( auto& [key, val] : j.items() ) {
        (void)key; (void)val;
        ++count;
    }
    CHECK( count == 3, "items() iteration visits all 3 entries" );
}

/**
 * Type-safe get<T>() — used in Packager.cc for extracting typed values.
 */
static void test_get_typed()
{
    auto j = json::parse( R"({"name":"Demon","sleep":5,"active":true})" );
    CHECK( j["name"].get<std::string>()  == "Demon", "get<string>" );
    CHECK( j["sleep"].get<int>()         == 5,       "get<int>" );
    CHECK( j["active"].get<bool>()       == true,    "get<bool>" );
}

/**
 * Exception on invalid JSON — the client wraps parse() in try/catch blocks.
 */
static void test_parse_exception()
{
    bool threw = false;
    try {
        (void) json::parse( "not valid json {{{" );
    } catch ( const json::parse_error& ) {
        threw = true;
    }
    CHECK( threw, "parse_error thrown for invalid input" );
}

// ── entry point ───────────────────────────────────────────────────────────────

int main()
{
    printf( "=== nlohmann/json %d.%d.%d API compatibility ===\n",
            NLOHMANN_JSON_VERSION_MAJOR,
            NLOHMANN_JSON_VERSION_MINOR,
            NLOHMANN_JSON_VERSION_PATCH );

    test_parse_object();
    test_parse_string();
    test_parse_array();
    test_build_and_dump();
    test_safe_access();
    test_iteration();
    test_get_typed();
    test_parse_exception();

    if ( failures > 0 ) {
        fprintf( stderr, "\n%d test(s) FAILED\n", failures );
        return 1;
    }
    printf( "\nAll json tests PASSED\n" );
    return 0;
}
