#ifndef DEMON_MACROS_H
#define DEMON_MACROS_H

#include <stdio.h>

#ifdef _WIN64
#define PPEB_PTR __readgsqword( 0x60 )
#else
#define PPEB_PTR __readfsdword( 0x30 )
#endif

#define NT_SUCCESS(Status)              ( ( ( NTSTATUS ) ( Status ) ) >= 0 )
#define NtCurrentProcess()              ( ( HANDLE ) ( LONG_PTR ) - 1 )
#define NtCurrentThread()               ( ( HANDLE ) ( LONG_PTR ) - 2 )
#define NtGetLastError()                Instance->Teb->LastErrorValue
#define NtSetLastError(x)               Instance->Teb->LastErrorValue = x

/* Heap allocation functions */
#define NtProcessHeap()                 Instance->Teb->ProcessEnvironmentBlock->ProcessHeap
#define DLLEXPORT                       __declspec( dllexport )

#define RVA( TYPE, DLLBASE, RVA )  ( TYPE ) ( ( PBYTE ) DLLBASE + RVA )
#define DATA_FREE( d, l ) \
    if ( d ) { \
        MemSet( d, 0, l ); \
        Instance->Win32.LocalFree( d ); \
        d = NULL; \
    }

#define SEC_DATA        __attribute__( ( section( ".data" ) ) )
#define U_PTR( x )      ( ( UINT_PTR ) x )
#define C_PTR( x )      ( ( LPVOID ) x )
#define B_PTR( x )      ( ( PBYTE ) ( x ) )
#define DREF_U8( x )    ( ( BYTE ) *( PBYTE* )( x ) )
#define DREF_U16( x )   ( ( WORD ) *( PWORD* )( x ) )
#define HTONS32( x )    __builtin_bswap32( x )
#define HTONS16( x )    __builtin_bswap16( x )
#define IMAGE_SIZE( IM ) \
    ( ( ( PIMAGE_NT_HEADERS ) ( IM + ( ( PIMAGE_DOS_HEADER ) IM )->e_lfanew ) )->OptionalHeader.SizeOfImage )

/* ─────────────────────────────────────────────────────────────────────────
 * DEBUG MACROS — production-safety contract
 * ─────────────────────────────────────────────────────────────────────────
 * INVARIANT: When DEBUG is not defined (production builds), every macro
 * below MUST expand to a brace-enclosed compound statement no-op. This
 * guarantees:
 *   1. Zero call to printf / DbgPrint / DemonPrintf / LogToConsole / puts
 *   2. Zero "[DEBUG::" format-string literal in the compiled binary
 *   3. Zero linkage dependency on libc stdio (printf/puts)
 *
 * IMPORTANT — call-site convention: throughout the demon codebase, these
 * macros are invoked WITHOUT a trailing semicolon, e.g.
 *     PRINTF( "hello %d\n", x )
 *     PUTS( "ok" )
 * which is why the macro body MUST be a brace-enclosed compound statement
 * `{ ... }` and NOT a `do { ... } while (0)` (the latter requires a `;` at
 * the call site to be a complete statement). Compound-statement form is a
 * complete statement on its own and works regardless of whether the call
 * site adds a `;`.
 *
 * Teamserver flags that control these macros:
 *   --debug-dev           → -DDEBUG, libc linked, PRINTF→printf (UNSTABLE)
 *   --debug-strings-only  → -DDEBUG -DDEBUG_NOSTDLIB, no libc, PRINTF→LogToConsole
 *                           (production-equivalent stability + debug logs)
 *   (default)             → no defines, all macros are no-ops
 *
 * VERIFICATION: After a release build (no --debug-dev / --debug-strings-only),
 * the builder runs `strings` against the produced binary and fails if any
 * `[DEBUG::` marker appears. See verifyNoDebugStringsInBinary() in builder.go.
 * ───────────────────────────────────────────────────────────────────────── */
/* Forward declarations for the debug-output helpers. Each is defined under
 * its own guard in Win32.c — see DemonPrintf / LogToConsole there. */
#ifdef DEBUG
#if SEND_LOGS
VOID DemonPrintf( PCHAR fmt, ... );
#elif defined(SHELLCODE) || defined(DEBUG_NOSTDLIB)
VOID LogToConsole( LPCSTR fmt, ... );
#endif
#endif

#ifdef DEBUG
#if SEND_LOGS
#define PRINTF( f, ... )                { DemonPrintf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { ; }
#elif SVC_EXE
#define PRINTF( f, ... )                { DbgPrint( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { DbgPrint( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#elif defined(SHELLCODE) || defined(DEBUG_NOSTDLIB)
/* No libc available — route through LogToConsole which uses dynamically
 * resolved Instance->Win32.vsnprintf and WriteConsoleA. */
#define PRINTF( f, ... )                { LogToConsole( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { LogToConsole( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#else
#define PRINTF( f, ... )                { printf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { printf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#endif
#else
/* Production: brace-enclosed empty statement. No call, no string literal. */
#define PRINTF( f, ... )                { ; }
#define PRINTF_DONT_SEND( f, ... )      { ; }
#endif

#ifdef DEBUG
#if SEND_LOGS
#define PUTS( s )           { DemonPrintf( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#define PUTS_DONT_SEND( s ) { ; }
#elif SVC_EXE
#define PUTS( s )           { DbgPrint( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#define PUTS_DONT_SEND( s ) { DbgPrint( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#elif defined(SHELLCODE) || defined(DEBUG_NOSTDLIB)
#define PUTS( s )           { LogToConsole( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#define PUTS_DONT_SEND( s ) { LogToConsole( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#else
#define PUTS( s )           { printf( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#define PUTS_DONT_SEND( s ) { printf( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#endif
#else
#define PUTS( s )           { ; }
#define PUTS_DONT_SEND( s ) { ; }
#endif

#ifdef DEBUG
#if defined(SHELLCODE) || defined(DEBUG_NOSTDLIB)
/* No libc available — emit hex dump via LogToConsole one chunk at a time.
 * Wrapped in an inner block so the for-loop scope is contained. */
#define PRINT_HEX( b, l )                                                       \
    {                                                                           \
        LogToConsole( #b ": [%d] [ ", (int)(l) );                               \
        for ( int _ph_i = 0; _ph_i < (l); _ph_i++ )                             \
            LogToConsole( "%02x ", ( ( PUCHAR ) (b) ) [ _ph_i ] );              \
        LogToConsole( "]\n" );                                                  \
    }
#else
#define PRINT_HEX( b, l )                                       \
    {                                                           \
        printf( #b ": [%d] [ ", l );                            \
        for ( int _ph_i = 0; _ph_i < (l); _ph_i++ )             \
            printf( "%02x ", ( ( PUCHAR ) (b) ) [ _ph_i ] );    \
        puts( "]" );                                            \
    }
#endif
#else
#define PRINT_HEX( b, l ) {}
#endif

#endif
