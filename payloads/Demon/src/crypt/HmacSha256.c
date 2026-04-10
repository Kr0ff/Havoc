/* [HVC-006 2026-03-26] SHA-256 + HMAC-SHA-256 — pure C, no CRT.
 * Used to append a 32-byte packet authentication tag in PackageTransmitAll.
 * See TrafficImprovements.md §6. */
#include <crypt/HmacSha256.h>
#include <core/MiniStd.h>

/* SHA-256 round constants (first 32 bits of the fractional parts of the
 * cube roots of the first 64 primes). */
static const UINT32 Sha256K[ 64 ] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* SHA-256 initial hash values (first 32 bits of the fractional parts of the
 * square roots of the first 8 primes). */
static const UINT32 Sha256H0[ 8 ] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

#define SHA256_ROTR( x, n ) ( ( (x) >> (n) ) | ( (x) << ( 32 - (n) ) ) )
#define SHA256_CH( e, f, g )  ( ( (e) & (f) ) ^ ( ~(e) & (g) ) )
#define SHA256_MAJ( a, b, c ) ( ( (a) & (b) ) ^ ( (a) & (c) ) ^ ( (b) & (c) ) )
#define SHA256_EP0( a )  ( SHA256_ROTR(a,  2) ^ SHA256_ROTR(a, 13) ^ SHA256_ROTR(a, 22) )
#define SHA256_EP1( e )  ( SHA256_ROTR(e,  6) ^ SHA256_ROTR(e, 11) ^ SHA256_ROTR(e, 25) )
#define SHA256_SIG0( x ) ( SHA256_ROTR(x,  7) ^ SHA256_ROTR(x, 18) ^ ( (x) >>  3 ) )
#define SHA256_SIG1( x ) ( SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ ( (x) >> 10 ) )

typedef struct {
    UCHAR  Data[ 64 ];   /* current block buffer                */
    UINT32 State[ 8 ];   /* running hash state                  */
    UINT64 ByteCount;    /* total bytes processed (full blocks) */
    UINT32 DataLen;      /* bytes in Data[] not yet transformed */
} SHA256_CTX;

static VOID Sha256Transform( SHA256_CTX *Ctx, const UCHAR *Block )
{
    UINT32 a, b, c, d, e, f, g, h, i, j, t1, t2, W[ 64 ];

    for ( i = 0, j = 0; i < 16; i++, j += 4 ) {
        W[ i ] = ( (UINT32) Block[ j     ] << 24 )
               | ( (UINT32) Block[ j + 1 ] << 16 )
               | ( (UINT32) Block[ j + 2 ] <<  8 )
               | ( (UINT32) Block[ j + 3 ]        );
    }
    for ( ; i < 64; i++ ) {
        W[ i ] = SHA256_SIG1( W[ i -  2 ] ) + W[ i -  7 ]
               + SHA256_SIG0( W[ i - 15 ] ) + W[ i - 16 ];
    }

    a = Ctx->State[ 0 ]; b = Ctx->State[ 1 ];
    c = Ctx->State[ 2 ]; d = Ctx->State[ 3 ];
    e = Ctx->State[ 4 ]; f = Ctx->State[ 5 ];
    g = Ctx->State[ 6 ]; h = Ctx->State[ 7 ];

    for ( i = 0; i < 64; i++ ) {
        t1 = h + SHA256_EP1( e ) + SHA256_CH( e, f, g ) + Sha256K[ i ] + W[ i ];
        t2 = SHA256_EP0( a ) + SHA256_MAJ( a, b, c );
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    Ctx->State[ 0 ] += a; Ctx->State[ 1 ] += b;
    Ctx->State[ 2 ] += c; Ctx->State[ 3 ] += d;
    Ctx->State[ 4 ] += e; Ctx->State[ 5 ] += f;
    Ctx->State[ 6 ] += g; Ctx->State[ 7 ] += h;
}

static VOID Sha256Init( SHA256_CTX *Ctx )
{
    Ctx->DataLen   = 0;
    Ctx->ByteCount = 0;
    Ctx->State[ 0 ] = Sha256H0[ 0 ]; Ctx->State[ 1 ] = Sha256H0[ 1 ];
    Ctx->State[ 2 ] = Sha256H0[ 2 ]; Ctx->State[ 3 ] = Sha256H0[ 3 ];
    Ctx->State[ 4 ] = Sha256H0[ 4 ]; Ctx->State[ 5 ] = Sha256H0[ 5 ];
    Ctx->State[ 6 ] = Sha256H0[ 6 ]; Ctx->State[ 7 ] = Sha256H0[ 7 ];
}

static VOID Sha256Update( SHA256_CTX *Ctx, const UCHAR *Data, SIZE_T Len )
{
    SIZE_T i;
    for ( i = 0; i < Len; i++ ) {
        Ctx->Data[ Ctx->DataLen++ ] = Data[ i ];
        if ( Ctx->DataLen == 64 ) {
            Sha256Transform( Ctx, Ctx->Data );
            Ctx->ByteCount += 64;
            Ctx->DataLen    = 0;
        }
    }
}

static VOID Sha256Final( SHA256_CTX *Ctx, UCHAR *Digest )
{
    UINT32 i;
    UINT64 TotalBits;

    /* Total message length in bits */
    TotalBits = ( Ctx->ByteCount + (UINT64) Ctx->DataLen ) * 8;

    /* Append 0x80 padding byte */
    Ctx->Data[ Ctx->DataLen++ ] = 0x80;

    /* If no room for the 8-byte length field, flush the block first */
    if ( Ctx->DataLen > 56 ) {
        while ( Ctx->DataLen < 64 ) Ctx->Data[ Ctx->DataLen++ ] = 0;
        Sha256Transform( Ctx, Ctx->Data );
        Ctx->DataLen = 0;
    }
    while ( Ctx->DataLen < 56 ) Ctx->Data[ Ctx->DataLen++ ] = 0;

    /* Append message length as 64-bit big-endian */
    Ctx->Data[ 56 ] = (UCHAR)( TotalBits >> 56 );
    Ctx->Data[ 57 ] = (UCHAR)( TotalBits >> 48 );
    Ctx->Data[ 58 ] = (UCHAR)( TotalBits >> 40 );
    Ctx->Data[ 59 ] = (UCHAR)( TotalBits >> 32 );
    Ctx->Data[ 60 ] = (UCHAR)( TotalBits >> 24 );
    Ctx->Data[ 61 ] = (UCHAR)( TotalBits >> 16 );
    Ctx->Data[ 62 ] = (UCHAR)( TotalBits >>  8 );
    Ctx->Data[ 63 ] = (UCHAR)  TotalBits;
    Sha256Transform( Ctx, Ctx->Data );

    /* Write digest as big-endian 32-bit words */
    for ( i = 0; i < 8; i++ ) {
        Digest[ i * 4     ] = (UCHAR)( Ctx->State[ i ] >> 24 );
        Digest[ i * 4 + 1 ] = (UCHAR)( Ctx->State[ i ] >> 16 );
        Digest[ i * 4 + 2 ] = (UCHAR)( Ctx->State[ i ] >>  8 );
        Digest[ i * 4 + 3 ] = (UCHAR)  Ctx->State[ i ];
    }
}

/*!
 * @brief
 *  HMAC-SHA-256. Computes tag = HMAC(Key, Data) into Out (32 bytes).
 *  If KeyLen > 64, the key is first hashed with SHA-256 per RFC 2104.
 *  All intermediate state is wiped with MemSet before return.
 */
VOID HmacSha256(
    _In_  const PUCHAR Key,
    _In_  SIZE_T       KeyLen,
    _In_  const PUCHAR Data,
    _In_  SIZE_T       DataLen,
    _Out_ PUCHAR       Out
) {
    SHA256_CTX Ctx;
    UCHAR      Kpad[ 64 ];
    UCHAR      InnerHash[ 32 ];
    UINT32     i;

    /* Normalise key: if longer than block size, hash it first */
    if ( KeyLen > 64 ) {
        Sha256Init( &Ctx );
        Sha256Update( &Ctx, Key, KeyLen );
        Sha256Final( &Ctx, Kpad );
        MemSet( Kpad + 32, 0, 32 );
    } else {
        MemCopy( Kpad, Key, KeyLen );
        if ( KeyLen < 64 ) MemSet( Kpad + KeyLen, 0, (SIZE_T)( 64 - KeyLen ) );
    }

    /* Inner hash: H((Kpad XOR ipad) || Data),  ipad = 0x36 */
    for ( i = 0; i < 64; i++ ) Kpad[ i ] ^= 0x36;
    Sha256Init( &Ctx );
    Sha256Update( &Ctx, Kpad, 64 );
    Sha256Update( &Ctx, Data, DataLen );
    Sha256Final( &Ctx, InnerHash );

    /* Outer hash: H((Kpad XOR ipad XOR opad) || InnerHash),  opad = 0x5C
     * 0x36 ^ 0x6A = 0x5C; reuse Kpad to avoid a second copy. */
    for ( i = 0; i < 64; i++ ) Kpad[ i ] ^= 0x6A;
    Sha256Init( &Ctx );
    Sha256Update( &Ctx, Kpad, 64 );
    Sha256Update( &Ctx, InnerHash, 32 );
    Sha256Final( &Ctx, Out );

    /* Wipe sensitive intermediate state */
    MemSet( &Ctx,      0, sizeof( Ctx ) );
    MemSet( Kpad,      0, sizeof( Kpad ) );
    MemSet( InnerHash, 0, sizeof( InnerHash ) );
}
