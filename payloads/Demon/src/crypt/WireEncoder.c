/* [HVC-029] WireEncoder — IV generation, AES-256-CTR encryption, HMAC-SHA256
 * authentication and base64 encoding/decoding for the Demon wire protocol.
 *
 * Upload path (WireEncode):
 *   base64( [MaskedHeader | IV(16) | AES-CTR(Plaintext) | HMAC-SHA256(32)] )
 *
 * Download path (WireDecode):
 *   base64( [IV(16) | AES-CTR(payload) | HMAC-SHA256(32)] )
 *
 * No CRT functions used.  All allocations go through
 * Instance->Win32.LocalAlloc / Instance->Win32.LocalFree.
 * All intermediate security buffers are wiped (MemSet) before being freed.
 */

#define CTR    1
#define AES256 1
#include <crypt/WireEncoder.h>
#include <Demon.h>
#include <core/MiniStd.h>
#include <core/Win32.h>

extern PINSTANCE Instance;

/* ------------------------------------------------------------------ */
/*  WireEncode                                                          */
/* ------------------------------------------------------------------ */

BOOL WireEncode(
    PBYTE   Header,
    UINT32  HeaderLen,
    PBYTE   Plaintext,
    SIZE_T  PlaintextLen,
    PBYTE   AesKey,
    PBYTE   MacKey,
    PBYTE*  OutBuf,
    PSIZE_T OutLen
)
{
    AESCTX  AesCtx    = { 0 };
    UCHAR   RandIV[ AES_BLOCKLEN ];
    UINT32  _r;
    UINT32  _i;

    PUCHAR  EncBuf      = NULL;
    PUCHAR  RawBuf      = NULL;
    UINT32  RawLen      = 0;
    UCHAR   Tag[ HMAC_SHA256_SIZE ];
    PUCHAR  AuthBuf     = NULL;
    UINT32  AuthLen     = 0;

    *OutBuf = NULL;
    *OutLen = 0;

    /* ---- Step 1: Generate 16-byte random IV (big-endian per UINT32) ---- */
    for ( _i = 0; _i < AES_BLOCKLEN / sizeof( UINT32 ); _i++ ) {
        _r = RandomNumber32();
        RandIV[ _i * 4 + 0 ] = (UCHAR)( _r >> 24 );
        RandIV[ _i * 4 + 1 ] = (UCHAR)( _r >> 16 );
        RandIV[ _i * 4 + 2 ] = (UCHAR)( _r >>  8 );
        RandIV[ _i * 4 + 3 ] = (UCHAR)  _r;
    }

    /* ---- Step 2: AES-CTR encrypt Plaintext into a temporary EncBuf ---- */
    EncBuf = (PUCHAR) Instance->Win32.LocalAlloc( LPTR, PlaintextLen );
    if ( ! EncBuf )
        return FALSE;

    MemCopy( EncBuf, Plaintext, PlaintextLen );
    AesInit( &AesCtx, AesKey, RandIV );
    AesXCryptBuffer( &AesCtx, EncBuf, PlaintextLen );

    /* ---- Step 3: Build RawBuf = Header | IV | EncBuf ---- */
    RawLen = HeaderLen + AES_BLOCKLEN + (UINT32)PlaintextLen;
    RawBuf = (PUCHAR) Instance->Win32.LocalAlloc( LPTR, RawLen );
    if ( ! RawBuf ) {
        MemSet( EncBuf, 0, PlaintextLen );
        Instance->Win32.LocalFree( EncBuf );
        return FALSE;
    }

    MemCopy( RawBuf,                           Header,  HeaderLen    );
    MemCopy( RawBuf + HeaderLen,               RandIV,  AES_BLOCKLEN );
    MemCopy( RawBuf + HeaderLen + AES_BLOCKLEN, EncBuf, PlaintextLen );

    /* Wipe and free encrypted payload buffer */
    MemSet( EncBuf, 0, PlaintextLen );
    Instance->Win32.LocalFree( EncBuf );
    EncBuf = NULL;

    /* ---- Step 4: HMAC-SHA256 over full RawBuf (header + IV + ciphertext) ---- */
    HmacSha256( MacKey, HMAC_SHA256_SIZE, RawBuf, (SIZE_T)RawLen, Tag );

    /* ---- Step 5: Build AuthBuf = RawBuf | Tag ---- */
    AuthLen = RawLen + HMAC_SHA256_SIZE;
    AuthBuf = (PUCHAR) Instance->Win32.LocalAlloc( LPTR, AuthLen );
    if ( ! AuthBuf ) {
        MemSet( RawBuf, 0, RawLen );
        Instance->Win32.LocalFree( RawBuf );
        MemSet( Tag, 0, sizeof( Tag ) );
        return FALSE;
    }

    MemCopy( AuthBuf,          RawBuf, RawLen          );
    MemCopy( AuthBuf + RawLen, Tag,    HMAC_SHA256_SIZE );

    /* Wipe intermediates */
    MemSet( RawBuf, 0, RawLen );
    Instance->Win32.LocalFree( RawBuf );
    RawBuf = NULL;

    MemSet( Tag, 0, sizeof( Tag ) );

    /* ---- Step 6: Base64-encode AuthBuf → *OutBuf ---- */
    Base64Encode( AuthBuf, (SIZE_T)AuthLen, (PVOID*)OutBuf, OutLen );

    /* ---- Step 7: Wipe and free AuthBuf ---- */
    MemSet( AuthBuf, 0, AuthLen );
    Instance->Win32.LocalFree( AuthBuf );
    AuthBuf = NULL;

    /* ---- Step 8: Return TRUE if output was produced ---- */
    return ( *OutBuf != NULL );
}

/* ------------------------------------------------------------------ */
/*  WireDecode                                                          */
/* ------------------------------------------------------------------ */

BOOL WireDecode(
    PBYTE   Encoded,
    SIZE_T  EncodedLen,
    PBYTE   AesKey,
    PBYTE   MacKey,
    PBYTE*  PlaintextOut,
    PSIZE_T PlaintextLen
)
{
    AESCTX  AesCtx    = { 0 };
    PVOID   RawBuf    = NULL;
    SIZE_T  RawLen    = 0;
    SIZE_T  PayloadLen;
    PUCHAR  Payload;
    PUCHAR  IV;
    PUCHAR  Ciphertext;
    SIZE_T  CiphLen;
    UCHAR   ExpTag[ HMAC_SHA256_SIZE ];
    UCHAR   mismatch;
    UINT32  _i;

    *PlaintextOut = NULL;
    *PlaintextLen = 0;

    /* ---- Step 1: Base64-decode the encoded input ---- */
    Base64Decode( Encoded, EncodedLen, &RawBuf, &RawLen );
    if ( ! RawBuf || RawLen == 0 )
        return FALSE;

    /* ---- Step 2: Sanity check: must have at least IV(16) + HMAC(32) ---- */
    if ( RawLen < (SIZE_T)( AES_BLOCKLEN + HMAC_SHA256_SIZE ) ) {
        MemSet( RawBuf, 0, RawLen );
        Instance->Win32.LocalFree( RawBuf );
        return FALSE;
    }

    /* ---- Step 3: Locate sub-regions ----
     * RawBuf layout: [IV(16) | AES-CTR(payload) | HMAC(32)]
     * PayloadLen = everything before the trailing HMAC tag.
     */
    PayloadLen = RawLen - HMAC_SHA256_SIZE;
    Payload    = (PUCHAR) RawBuf;               /* starts at IV */

    /* ---- Step 4: Compute expected HMAC over [IV | ciphertext] ---- */
    HmacSha256( MacKey, HMAC_SHA256_SIZE, Payload, PayloadLen, ExpTag );

    /* ---- Step 5: Constant-time HMAC compare ---- */
    mismatch = 0;
    for ( _i = 0; _i < HMAC_SHA256_SIZE; _i++ ) {
        mismatch |= ( ((PUCHAR)RawBuf)[ PayloadLen + _i ] ^ ExpTag[ _i ] );
    }
    MemSet( ExpTag, 0, sizeof( ExpTag ) );

    if ( mismatch != 0 ) {
        MemSet( RawBuf, 0, RawLen );
        Instance->Win32.LocalFree( RawBuf );
        return FALSE;
    }

    /* ---- Step 6: Extract IV and Ciphertext from Payload ---- */
    IV         = Payload;                         /* first 16 bytes */
    Ciphertext = Payload + AES_BLOCKLEN;          /* after IV       */
    CiphLen    = PayloadLen - AES_BLOCKLEN;

    /* ---- Step 7: Allocate output buffer and copy ciphertext ---- */
    *PlaintextOut = (PBYTE) Instance->Win32.LocalAlloc( LPTR, CiphLen );
    if ( ! *PlaintextOut ) {
        MemSet( RawBuf, 0, RawLen );
        Instance->Win32.LocalFree( RawBuf );
        return FALSE;
    }

    MemCopy( *PlaintextOut, Ciphertext, CiphLen );

    /* ---- Step 8: Decrypt in-place ---- */
    AesInit( &AesCtx, AesKey, IV );
    AesXCryptBuffer( &AesCtx, *PlaintextOut, CiphLen );

    /* ---- Step 9: Return result ---- */
    *PlaintextLen = CiphLen;

    MemSet( RawBuf, 0, RawLen );
    Instance->Win32.LocalFree( RawBuf );

    return TRUE;
}
