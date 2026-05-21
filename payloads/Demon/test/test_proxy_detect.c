/**
 * test_proxy_detect.c — Standalone compile+logic test for the proxy string
 * parser introduced in HttpAutoProxyDetect() (HVC-026).
 *
 * Tests the "http=" prefix extraction and URL scheme prepend logic that runs
 * entirely in userspace without calling any Win32 APIs.  Written as a pure C
 * host-compiled binary so it can run on any platform (Linux, macOS, Windows).
 *
 * Build (host):
 *   cc -Wall -Wextra -o test_proxy_detect test/test_proxy_detect.c && ./test_proxy_detect
 *
 * Build (cross, to verify MinGW compile):
 *   x86_64-w64-mingw32-gcc -Wall -o test_proxy_detect.exe test/test_proxy_detect.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* -----------------------------------------------------------------------
 * Minimal Demon-style stubs so the parser logic compiles identically to
 * how it appears in TransportHttp.c, without any headers.
 * --------------------------------------------------------------------- */

typedef wchar_t    WCHAR;
typedef wchar_t*   LPWSTR;
typedef const wchar_t* LPCWSTR;
typedef unsigned long  ULONG;
typedef size_t         SIZE_T;

static SIZE_T StringLengthW( const WCHAR* s ) { return wcslen( s ); }

/* -----------------------------------------------------------------------
 * Replica of the http= prefix extraction + URL scheme prepend logic from
 * HttpAutoProxyDetect() in TransportHttp.c.
 *
 * Input:  ProxyServer — a registry ProxyServer string, may be:
 *           "host:port"
 *           "http=host:port"
 *           "http=host:port;https=other:port"
 *           "ftp=ftp-proxy;http=corp-proxy:8080;https=corp-proxy:8080"
 *
 * Output: writes the final URL (with http:// scheme) into OutBuf (wchar).
 *         OutBuf must be at least 520 wchar_t elements.
 *
 * Returns 1 on success, 0 if nothing useful was found.
 * ----------------------------------------------------------------------- */
static int ExtractProxyUrl( const WCHAR* ProxyServer, WCHAR* OutBuf, SIZE_T OutBufLen )
{
    WCHAR  LocalCopy[ 512 ] = { 0 };
    LPWSTR ParsedProxy      = LocalCopy;
    ULONG  PrefixLen        = 5; /* L"http=" */

    if ( StringLengthW( ProxyServer ) == 0 ) return 0;
    if ( StringLengthW( ProxyServer ) >= 512 ) return 0;

    wcsncpy( LocalCopy, ProxyServer, 511 );

    for ( LPWSTR p = LocalCopy; *p; p++ ) {
        if ( StringLengthW( p ) < 5 ) break;
        if ( p[0] == L'h' && p[1] == L't' && p[2] == L't' && p[3] == L'p' && p[4] == L'=' ) {
            LPWSTR HttpEntry = p + PrefixLen;
            for ( LPWSTR q = HttpEntry; *q; q++ ) {
                if ( *q == L';' ) { *q = L'\0'; break; }
            }
            ParsedProxy = HttpEntry;
            break;
        }
    }

    if ( StringLengthW( ParsedProxy ) == 0 ) return 0;

    /* detect URI scheme by looking for "://" within the first 10 characters */
    {
        int    HasScheme = 0;
        SIZE_T k;
        for ( k = 0; k < 10 && ParsedProxy[ k ]; k++ ) {
            if ( ParsedProxy[k] == L':' && ParsedProxy[k+1] == L'/' && ParsedProxy[k+2] == L'/' ) {
                HasScheme = 1;
                break;
            }
        }
        if ( HasScheme ) {
            wcsncpy( OutBuf, ParsedProxy, OutBufLen - 1 );
        } else {
            swprintf( OutBuf, OutBufLen, L"http://%ls", ParsedProxy );
        }
    }

    return 1;
}

/* -----------------------------------------------------------------------
 * Test harness
 * ----------------------------------------------------------------------- */

static int Tests     = 0;
static int Failures  = 0;

static void check( const char* label, const WCHAR* input, const WCHAR* want )
{
    WCHAR got[ 520 ] = { 0 };
    int   rc         = ExtractProxyUrl( input, got, 520 );

    Tests++;

    if ( want == NULL ) {
        /* expect failure */
        if ( rc != 0 ) {
            fprintf( stderr, "FAIL [%s]: expected failure but got \"%ls\"\n", label, got );
            Failures++;
        } else {
            printf( "PASS [%s]: correctly returned no proxy\n", label );
        }
        return;
    }

    if ( rc == 0 || wcscmp( got, want ) != 0 ) {
        fprintf( stderr, "FAIL [%s]: input=\"%ls\" want=\"%ls\" got=\"%ls\" (rc=%d)\n",
                 label, input, want, got, rc );
        Failures++;
    } else {
        printf( "PASS [%s]: \"%ls\" -> \"%ls\"\n", label, input, got );
    }
}

int main( void )
{
    printf( "=== test_proxy_detect (HVC-026 proxy string parser) ===\n\n" );

    /* Plain host:port — no scheme, no http= prefix */
    check( "plain host:port",
           L"corpproxy:8080",
           L"http://corpproxy:8080" );

    /* Already has http:// scheme */
    check( "already has scheme",
           L"http://corpproxy:8080",
           L"http://corpproxy:8080" );

    /* Single protocol entry: http= */
    check( "http= prefix only",
           L"http=corpproxy:8080",
           L"http://corpproxy:8080" );

    /* Multi-protocol: http= followed by https= */
    check( "http=...;https=...",
           L"http=corpproxy:8080;https=corpproxy:8443",
           L"http://corpproxy:8080" );

    /* ftp entry before http — http= must still be found */
    check( "ftp= then http=",
           L"ftp=ftpproxy:21;http=corpproxy:8080;https=corpproxy:8443",
           L"http://corpproxy:8080" );

    /* https= only — no http= entry present; falls back to raw string.
     * "https=sslproxy:443" contains no "://" so http:// is prepended. */
    check( "https= only (no http= prefix, http:// prepended)",
           L"https=sslproxy:443",
           L"http://https=sslproxy:443" );

    /* Short string — less than 5 chars, prefix scan exits immediately */
    check( "too short to have http= prefix",
           L"px:1",
           L"http://px:1" );

    /* Empty string — should return failure */
    check( "empty string", L"", NULL );

    printf( "\n=== Results: %d/%d passed ===\n", Tests - Failures, Tests );
    return ( Failures > 0 ) ? 1 : 0;
}
