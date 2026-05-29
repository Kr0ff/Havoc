/* ChaCha20 stream cipher (IETF RFC 8439, 20 rounds) - pure C, no CRT, shellcode-safe.
 * Quarter-round uses only 32-bit add/XOR/rotate; no SIMD, no lookup tables required.
 * Compatible with EXE, DLL, SHELLCODE, and KaynLoader build modes. */
#include <crypt/ChaCha20Crypt.h>

/* Rotate left 32-bit - pure bitwise, no compiler intrinsics needed */
#define CC20_ROTL32( x, n )  ( ((x) << (n)) | ((x) >> (32 - (n))) )

/* ChaCha20 quarter-round (RFC 8439 section 2.1) */
#define CC20_QR( a, b, c, d ) \
    (a) += (b); (d) ^= (a); (d) = CC20_ROTL32( (d), 16 ); \
    (c) += (d); (b) ^= (c); (b) = CC20_ROTL32( (b), 12 ); \
    (a) += (b); (d) ^= (a); (d) = CC20_ROTL32( (d),  8 ); \
    (c) += (d); (b) ^= (c); (b) = CC20_ROTL32( (b),  7 )

/* Generate one 64-byte keystream block from 16-word state.
 * In and Out are both 16-element UINT32 arrays.
 * always_inline: eliminates relative CALL so the heap trampoline copy is self-contained. */
static inline __attribute__((always_inline)) VOID ChaCha20Block( UINT32* Out, const UINT32* In )
{
    UINT32 X[ 16 ];
    UINT32 i;

    for ( i = 0; i < 16; i++ ) X[ i ] = In[ i ];

    /* 20 rounds = 10 double-rounds (column then diagonal) */
    for ( i = 0; i < 10; i++ ) {
        /* column rounds */
        CC20_QR( X[ 0], X[ 4], X[ 8], X[12] );
        CC20_QR( X[ 1], X[ 5], X[ 9], X[13] );
        CC20_QR( X[ 2], X[ 6], X[10], X[14] );
        CC20_QR( X[ 3], X[ 7], X[11], X[15] );
        /* diagonal rounds */
        CC20_QR( X[ 0], X[ 5], X[10], X[15] );
        CC20_QR( X[ 1], X[ 6], X[11], X[12] );
        CC20_QR( X[ 2], X[ 7], X[ 8], X[13] );
        CC20_QR( X[ 3], X[ 4], X[ 9], X[14] );
    }

    for ( i = 0; i < 16; i++ ) Out[ i ] = X[ i ] + In[ i ];
}

/* ChaCha20 encryption/decryption (symmetric - same operation for both).
 * Key = 32 bytes, Nonce = 12 bytes (96-bit, RFC 8439), Counter = initial block counter.
 * Maximum safe plaintext per (key, nonce) pair: ~256 GB (UINT32 counter wraps at block 2^32).
 * always_inline: inlined into ChaCha20CryptUString so the heap trampoline copy is self-contained. */
static inline __attribute__((always_inline)) VOID ChaCha20Crypt( PVOID Data, DWORD DataLen, PVOID Key, PVOID Nonce, UINT32 Counter )
{
    UINT32 State[ 16 ];
    UINT32 Block[ 16 ];
    BYTE   KeyStream[ 64 ];
    PBYTE  Buf       = (PBYTE)Data;
    PBYTE  K         = (PBYTE)Key;
    PBYTE  N         = (PBYTE)Nonce;
    DWORD  Remaining = DataLen;
    DWORD  Offset    = 0;
    UINT32 i, Take;

    if ( !Data || !Key || !Nonce || !DataLen ) return;

    /* initial ChaCha20 state (RFC 8439 section 2.3):
     * words  0-3:  "expand 32-byte k" constants
     * words  4-11: 256-bit key  (little-endian byte-by-byte load avoids PVOID aliasing UB)
     * word  12:    block counter
     * words 13-15: 96-bit nonce (little-endian, same safe load) */
    State[ 0] = 0x61707865;  /* "expa" */
    State[ 1] = 0x3320646e;  /* "nd 3" */
    State[ 2] = 0x79622d32;  /* "2-by" */
    State[ 3] = 0x6b206574;  /* "te k" */
    for ( i = 0; i < 8; i++ ) {
        State[ 4 + i ] = (UINT32)K[ i*4+0 ]
                       | ((UINT32)K[ i*4+1 ] <<  8)
                       | ((UINT32)K[ i*4+2 ] << 16)
                       | ((UINT32)K[ i*4+3 ] << 24);
    }
    State[12] = Counter;
    State[13] = (UINT32)N[ 0] | ((UINT32)N[ 1] <<  8) | ((UINT32)N[ 2] << 16) | ((UINT32)N[ 3] << 24);
    State[14] = (UINT32)N[ 4] | ((UINT32)N[ 5] <<  8) | ((UINT32)N[ 6] << 16) | ((UINT32)N[ 7] << 24);
    State[15] = (UINT32)N[ 8] | ((UINT32)N[ 9] <<  8) | ((UINT32)N[10] << 16) | ((UINT32)N[11] << 24);

    while ( Remaining > 0 ) {
        ChaCha20Block( Block, State );

        /* serialise block to little-endian byte stream */
        for ( i = 0; i < 16; i++ ) {
            KeyStream[ i * 4 + 0 ] = (BYTE)( Block[ i ]         & 0xFF );
            KeyStream[ i * 4 + 1 ] = (BYTE)( (Block[ i ] >>  8) & 0xFF );
            KeyStream[ i * 4 + 2 ] = (BYTE)( (Block[ i ] >> 16) & 0xFF );
            KeyStream[ i * 4 + 3 ] = (BYTE)( (Block[ i ] >> 24) & 0xFF );
        }

        Take = ( Remaining > 64 ) ? 64 : Remaining;
        for ( i = 0; i < Take; i++ )
            Buf[ Offset + i ] ^= KeyStream[ i ];

        Offset    += Take;
        Remaining -= Take;
        /* counter wraps at UINT32_MAX (~256 GB); callers must not encrypt >256 GB per key+nonce */
        State[12]++;
    }
}

/* USTRING wrapper for ROP chains - same calling convention as RC4CryptUString.
 * Key->Buffer = [32-byte key | 12-byte nonce] (44 bytes total), Key->Length must be >= 44. */
NTSTATUS WINAPI ChaCha20CryptUString( USTRING* Data, USTRING* Key )
{
    if ( !Data || !Data->Buffer || !Key || !Key->Buffer || Key->Length < 44 )
        return STATUS_INVALID_PARAMETER;

    ChaCha20Crypt(
        Data->Buffer, Data->Length,
        (PBYTE)Key->Buffer,       /* key:   bytes 0-31  */
        (PBYTE)Key->Buffer + 32,  /* nonce: bytes 32-43 */
        0                         /* block counter always starts at 0 per sleep cycle */
    );
    return STATUS_SUCCESS;
}
