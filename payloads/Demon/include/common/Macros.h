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
 * below MUST expand to a do/while(0) no-op. This guarantees:
 *   1. Zero call to printf / DbgPrint / DemonPrintf / LogToConsole / puts
 *   2. Zero "[DEBUG::" format-string literal in the compiled binary
 *   3. Zero linkage dependency on libc stdio (printf/puts)
 *   4. The macros remain valid single statements (`if (x) PUTS("y");` works)
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
 *
 * If you add a new debug-output macro, follow the same pattern: define the
 * verbose form under #ifdef DEBUG, and a do/while(0) no-op for the #else.
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
#define PRINTF( f, ... )                do { DemonPrintf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); } while ( 0 )
#define PRINTF_DONT_SEND( f, ... )      do { } while ( 0 )
#elif SVC_EXE
#define PRINTF( f, ... )                do { DbgPrint( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); } while ( 0 )
#define PRINTF_DONT_SEND( f, ... )      do { DbgPrint( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); } while ( 0 )
#elif defined(SHELLCODE) || defined(DEBUG_NOSTDLIB)
/* No libc available — route through LogToConsole which uses dynamically
 * resolved Instance->Win32.vsnprintf and WriteConsoleA. */
#define PRINTF( f, ... )                do { LogToConsole( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); } while ( 0 )
#define PRINTF_DONT_SEND( f, ... )      do { LogToConsole( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); } while ( 0 )
#else
#define PRINTF( f, ... )                do { printf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); } while ( 0 )
#define PRINTF_DONT_SEND( f, ... )      do { printf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); } while ( 0 )
#endif
#else
/* Production: stripped to a do/while(0) no-op. The compiler eliminates the
 * empty loop at every -O level. The format string and arguments after the
 * first one are never evaluated and never appear in the compiled binary. */
#define PRINTF( f, ... )                do { } while ( 0 )
#define PRINTF_DONT_SEND( f, ... )      do { } while ( 0 )
#endif

#ifdef DEBUG
#if SEND_LOGS
#define PUTS( s )           do { DemonPrintf( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); } while ( 0 )
#define PUTS_DONT_SEND( s ) do { } while ( 0 )
#elif SVC_EXE
#define PUTS( s )           do { DbgPrint( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); } while ( 0 )
#define PUTS_DONT_SEND( s ) do { DbgPrint( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); } while ( 0 )
#elif defined(SHELLCODE) || defined(DEBUG_NOSTDLIB)
#define PUTS( s )           do { LogToConsole( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); } while ( 0 )
#define PUTS_DONT_SEND( s ) do { LogToConsole( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); } while ( 0 )
#else
#define PUTS( s )           do { printf( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); } while ( 0 )
#define PUTS_DONT_SEND( s ) do { printf( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); } while ( 0 )
#endif
#else
/* Production: stripped to a do/while(0) no-op. */
#define PUTS( s )           do { } while ( 0 )
#define PUTS_DONT_SEND( s ) do { } while ( 0 )
#endif

#ifdef DEBUG
#if defined(SHELLCODE) || defined(DEBUG_NOSTDLIB)
/* No libc available — emit hex dump via LogToConsole one chunk at a time. */
#define PRINT_HEX( b, l )                                                       \
    do {                                                                        \
        LogToConsole( #b ": [%d] [ ", (int)(l) );                               \
        for ( int _ph_i = 0; _ph_i < (l); _ph_i++ )                             \
            LogToConsole( "%02x ", ( ( PUCHAR ) (b) ) [ _ph_i ] );              \
        LogToConsole( "]\n" );                                                  \
    } while ( 0 )
#else
#define PRINT_HEX( b, l )                                       \
    do {                                                        \
        printf( #b ": [%d] [ ", l );                            \
        for ( int _ph_i = 0; _ph_i < (l); _ph_i++ )             \
            printf( "%02x ", ( ( PUCHAR ) (b) ) [ _ph_i ] );    \
        puts( "]" );                                            \
    } while ( 0 )
#endif
#else
/* Production: stripped to a do/while(0) no-op. */
#define PRINT_HEX( b, l ) do { } while ( 0 )
#endif

#endif
