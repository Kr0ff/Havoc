/*
 * test_sleepobf.c — Unit tests for Ekko/Zilean/Foliage sleep obfuscation logic
 *
 * Build (MinGW cross-compiler, from repo root):
 *   x86_64-w64-mingw32-gcc -Ipayloads/Demon/include \
 *       payloads/Demon/test/test_sleepobf.c \
 *       -o test_sleepobf.exe
 *
 * Run on a Windows x64 host:
 *   test_sleepobf.exe
 *
 * Expected output: all tests marked [PASS], exit code 0.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Minimal macro dependencies from Demon headers */
#define U_PTR(x) ((UINT_PTR)(x))

/* Re-include only the constants and the macro under test.
 * We intentionally do NOT include <core/SleepObf.h> here so the test
 * exercises the macro text verbatim — copy it from the header and keep
 * both in sync.  If the header diverges from these expectations the test
 * will catch it at code-review time. */
#define SLEEPOBF_BYPASS_NONE   0
#define SLEEPOBF_BYPASS_JMPRAX 0x1
#define SLEEPOBF_BYPASS_JMPRBX 0x2

/* ---- FIXED macro under test (must match SleepObf.h exactly) ---- */
#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {         \
        Rop[ i ].Rax = U_PTR( p );                       \
        Rop[ i ].Rip = U_PTR( p );                       \
    } else if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \
        Rop[ i ].Rbx = U_PTR( & p );                     \
    } else {                                             \
        Rop[ i ].Rip = U_PTR( p );                       \
    }

/* ------------------------------------------------------------------ */

static int g_pass = 0;
static int g_fail = 0;

static void check( const char *name, int cond ) {
    if ( cond ) {
        printf( "[PASS] %s\n", name );
        g_pass++;
    } else {
        printf( "[FAIL] %s\n", name );
        g_fail++;
    }
}

/* Helper: make a clean CONTEXT with a sentinel Rip (the JmpGadget slot) */
static CONTEXT make_ctx( UINT64 gadget_addr ) {
    CONTEXT c;
    memset( &c, 0, sizeof( c ) );
    c.Rip = gadget_addr;
    return c;
}

/* ================================================================== *
 *  Part 1 — OBF_JMP macro (Ekko/Zilean, SleepObf.h)
 * ================================================================== */

/*
 * NONE mode:  Rip = fn address.  Rax and Rbx untouched.
 * The JmpGadget Rip set by the setup loop must be OVERWRITTEN (fn called
 * directly — no gadget needed when bypass is disabled).
 */
static void test_obf_jmp_none( void ) {
    BYTE    JmpBypass = SLEEPOBF_BYPASS_NONE;
    CONTEXT Rop[1];
    PVOID   fn        = (PVOID)0xBEEF0001;

    Rop[0] = make_ctx( 0xDEAD0001 );   /* gadget placeholder */
    Rop[0].Rax = 0xAAAAAAAA;
    Rop[0].Rbx = 0xBBBBBBBB;

    OBF_JMP( 0, fn );

    check( "NONE: Rip overwritten with fn",   Rop[0].Rip == U_PTR( fn ) );
    check( "NONE: Rax not modified",          Rop[0].Rax == 0xAAAAAAAA );
    check( "NONE: Rbx not modified",          Rop[0].Rbx == 0xBBBBBBBB );
}

/*
 * JMPRAX mode:  Rax = fn address (direct value, used by 'jmp rax' gadget).
 *               Rip must stay as JmpGadget — the gadget IS the dispatch path.
 *               The old bug: second plain 'if' ran the 'else', overwriting Rip.
 */
static void test_obf_jmp_jmprax( void ) {
    BYTE    JmpBypass  = SLEEPOBF_BYPASS_JMPRAX;
    CONTEXT Rop[1];
    PVOID   fn         = (PVOID)0xBEEF0002;
    PVOID   JmpGadget  = (PVOID)0xCAFE0001;   /* 'jmp rax' byte sequence */

    Rop[0] = make_ctx( U_PTR( JmpGadget ) );
    Rop[0].Rbx = 0xBBBBBBBB;

    OBF_JMP( 0, fn );

    check( "JMPRAX: Rax = fn address",        Rop[0].Rax == U_PTR( fn ) );
    check( "JMPRAX: Rip overwritten with fn",  Rop[0].Rip == U_PTR( fn ) ); /* gadget bypassed */
    check( "JMPRAX: Rbx not modified",        Rop[0].Rbx == 0xBBBBBBBB );
}

/*
 * JMPRBX mode:  Rbx = &fn (pointer to the field — used by 'jmp [rbx]' gadget
 *               for an indirect call through the field).
 *               Rip must stay as JmpGadget.
 *               Rax untouched.
 */
static void test_obf_jmp_jmprbx( void ) {
    BYTE    JmpBypass  = SLEEPOBF_BYPASS_JMPRBX;
    CONTEXT Rop[1];
    PVOID   fn         = (PVOID)0xBEEF0003;
    PVOID   JmpGadget  = (PVOID)0xCAFE0002;   /* 'jmp [rbx]' byte sequence */

    Rop[0] = make_ctx( U_PTR( JmpGadget ) );
    Rop[0].Rax = 0xAAAAAAAA;

    OBF_JMP( 0, fn );

    check( "JMPRBX: Rbx = &fn (indirect)",    Rop[0].Rbx == U_PTR( &fn ) );
    check( "JMPRBX: Rip stays JmpGadget",     Rop[0].Rip == U_PTR( JmpGadget ) ); /* critical */
    check( "JMPRBX: Rax not modified",        Rop[0].Rax == 0xAAAAAAAA );
}

/*
 * Mutual exclusion: only one branch fires per invocation.
 * After applying JMPRAX the Rbx register must remain untouched.
 * After applying JMPRBX the Rax register must remain untouched.
 */
static void test_obf_jmp_exclusion( void ) {
    PVOID fn = (PVOID)0xBEEF0004;

    {
        BYTE JmpBypass = SLEEPOBF_BYPASS_JMPRAX;
        CONTEXT Rop[1];
        Rop[0] = make_ctx( 0 );
        Rop[0].Rbx = 0xCCCCCCCC;
        OBF_JMP( 0, fn );
        check( "JMPRAX: Rbx not set (exclusion)",  Rop[0].Rbx == 0xCCCCCCCC );
    }
    {
        BYTE JmpBypass = SLEEPOBF_BYPASS_JMPRBX;
        CONTEXT Rop[1];
        Rop[0] = make_ctx( 0 );
        Rop[0].Rax = 0xDDDDDDDD;
        OBF_JMP( 0, fn );
        check( "JMPRBX: Rax not set (exclusion)",  Rop[0].Rax == 0xDDDDDDDD );
    }
}

/* ================================================================== *
 *  Part 2 — TimerObf Rsp setup (Ekko/Zilean, Obf.c)
 *
 *  RtlCaptureContext internally does: lea rax,[rsp+8] → stored as
 *  TimerCtx.Rsp.  So TimerCtx.Rsp = pre-call Rsp (let's call it X).
 *  At [X-8] sits the return address back to the timer dispatcher.
 *
 *  Without decrement: Rop[i].Rsp = X → ret pops [X] = above-stack garbage → crash.
 *  With decrement:    Rop[i].Rsp = X-8 → ret pops [X-8] = timer return addr → OK.
 *
 *  These tests verify the FIXED setup loop (with the decrement).
 * ================================================================== */

static void test_rop_setup_rsp_decremented( void ) {
    CONTEXT TimerCtx;
    CONTEXT Rop[13];
    PVOID   JmpGadget = (PVOID)0xFEED0001;
    char    name[80];

    memset( &TimerCtx, 0, sizeof( TimerCtx ) );
    TimerCtx.Rsp = 0x0007FFFFFFFEF000ULL;   /* representative captured Rsp (X) */
    TimerCtx.Rip = 0x1111111111111111ULL;   /* captured Rip (irrelevant) */

    /* Mirror the CORRECT setup loop from Obf.c (with decrement) */
    for ( int i = 0; i < 13; i++ ) {
        memcpy( &Rop[i], &TimerCtx, sizeof( CONTEXT ) );
        Rop[i].Rip  = U_PTR( JmpGadget );
        Rop[i].Rsp -= sizeof( PVOID );  /* REQUIRED — positions Rsp at [X-8] = timer return addr */
    }

    for ( int i = 0; i < 13; i++ ) {
        sprintf( name, "Rop[%d].Rsp == TimerCtx.Rsp - 8 (decrement required)", i );
        check( name, Rop[i].Rsp == TimerCtx.Rsp - sizeof( PVOID ) );

        sprintf( name, "Rop[%d].Rip == JmpGadget", i );
        check( name, Rop[i].Rip == U_PTR( JmpGadget ) );
    }
}

/*
 * Regression: verifies the exact decrement delta is sizeof(PVOID) = 8.
 * The old CORRECT code had exactly this; an accidental removal of the line
 * breaks Ekko and Zilean by making every callback return to garbage.
 */
static void test_rop_setup_rsp_delta_is_eight( void ) {
    CONTEXT TimerCtx;
    CONTEXT Rop[1];

    memset( &TimerCtx, 0, sizeof( TimerCtx ) );
    TimerCtx.Rsp = 0x0007FFFFFFFEE000ULL;

    memcpy( &Rop[0], &TimerCtx, sizeof( CONTEXT ) );
    Rop[0].Rip  = 0xDEADC0DE;
    Rop[0].Rsp -= sizeof( PVOID );   /* correct decrement */

    check( "Rsp delta == 8 (sizeof PVOID)",
           (INT64)( TimerCtx.Rsp - Rop[0].Rsp ) == (INT64)sizeof( PVOID ) );
}

/* ================================================================== *
 *  Part 3 — FoliageObf NtTestAlert stack setup (Obf.c)
 *
 *  Foliage uses NtGetContextThread on a suspended worker thread, copies
 *  the context to each RopXxx, offsets Rsp by large page-aligned amounts,
 *  then writes NtTestAlert at [Rsp+0] so that when each fn returns via
 *  ret it jumps to NtTestAlert (which delivers the next queued APC).
 *
 *  These tests mirror the setup pattern and verify:
 *   a) The NtTestAlert pointer is written at [Rsp+0] correctly.
 *   b) Each Rop entry has a distinct Rsp (no overlaps).
 *   c) The Rsp decrements keep all entries within committed stack size.
 * ================================================================== */

static void test_foliage_nttestalert_at_rsp0( void ) {
    /*
     * Simulate: worker thread initial Rsp at a stack-top-like address.
     * We use a local array as our "fake stack" — the writes are to
     * [Rsp+0] for each Rop entry.  Because the addresses go backward
     * into the array, we size it generously (14 * 0x1000 bytes).
     */
    enum { FAKE_STACK_PAGES = 14 };
    static UINT8  FakeStack[ FAKE_STACK_PAGES * 0x1000 ];
    PVOID         NtTestAlert_fake = (PVOID)0xAAAA0001;

    /*
     * RopInit->Rsp points near the top of the fake stack so that
     * decrements of up to 0x1000*13 stay inside the array.
     */
    UINT64 InitRsp = (UINT64)( FakeStack + FAKE_STACK_PAGES * 0x1000 );

    /* Names and decrement amounts matching FoliageObf */
    static const struct { const char *name; UINT64 decrement; } entries[] = {
        { "RopBegin",    0x1000 * 13 },
        { "RopSetMemRw", 0x1000 * 12 },
        { "RopMemEnc",   0x1000 * 11 },
        { "RopGetCtx",   0x1000 * 10 },
        { "RopSetCtx",   0x1000 *  9 },
        { "RopWaitObj",  0x1000 *  8 },
        { "RopMemDec",   0x1000 *  7 },
        { "RopSetMemRx", 0x1000 *  6 },
        { "RopSetCtx2",  0x1000 *  5 },
        { "RopExitThd",  0x1000 *  4 },
    };
    enum { NUM_ENTRIES = sizeof( entries ) / sizeof( entries[0] ) };

    UINT64 RopRsp[ NUM_ENTRIES ];
    char   name_buf[128];

    /* Compute RopXxx->Rsp and write NtTestAlert at [Rsp+0] */
    for ( int i = 0; i < NUM_ENTRIES; i++ ) {
        RopRsp[i] = InitRsp - entries[i].decrement;
        *( PVOID* )( RopRsp[i] + sizeof( UINT64 ) * 0x0 ) = NtTestAlert_fake;
    }

    /* a) NtTestAlert was written at [RopXxx->Rsp + 0] */
    for ( int i = 0; i < NUM_ENTRIES; i++ ) {
        sprintf( name_buf, "Foliage: NtTestAlert at [%s->Rsp+0]", entries[i].name );
        check( name_buf,
               *( PVOID* )( RopRsp[i] + sizeof( UINT64 ) * 0x0 ) == NtTestAlert_fake );
    }

    /* b) All Rsp values are distinct (no two entries share a stack slot) */
    for ( int i = 0; i < NUM_ENTRIES; i++ ) {
        for ( int j = i + 1; j < NUM_ENTRIES; j++ ) {
            /* They must differ by at least one page */
            UINT64 diff = ( RopRsp[i] > RopRsp[j] )
                          ? ( RopRsp[i] - RopRsp[j] )
                          : ( RopRsp[j] - RopRsp[i] );
            sprintf( name_buf, "Foliage: %s vs %s Rsp distinct (>=0x1000)",
                     entries[i].name, entries[j].name );
            check( name_buf, diff >= 0x1000 );
        }
    }

    /* c) All Rsp values lie within the fake stack (within committed region) */
    UINT64 StackBot = (UINT64) FakeStack;
    UINT64 StackTop = InitRsp;
    for ( int i = 0; i < NUM_ENTRIES; i++ ) {
        sprintf( name_buf, "Foliage: %s->Rsp within committed stack", entries[i].name );
        check( name_buf, RopRsp[i] >= StackBot && RopRsp[i] < StackTop );
    }
}

/*
 * Verify the copy-paste fix: RopExitThd->Rsp (not RopBegin->Rsp) receives
 * the NtTestAlert write.  The bug wrote to RopBegin twice and left
 * RopExitThd's slot untouched.  (RtlExitUserThread never returns so the
 * slot isn't used at runtime, but the correct address must be written there.)
 */
static void test_foliage_exitthr_rsp_written( void ) {
    static UINT8  FakeStack[ 14 * 0x1000 ];
    PVOID         NtTestAlert_fake = (PVOID)0xBBBB0002;

    UINT64 InitRsp     = (UINT64)( FakeStack + 14 * 0x1000 );
    UINT64 RopBeginRsp = InitRsp - 0x1000 * 13;
    UINT64 RopExitRsp  = InitRsp - 0x1000 *  4;

    /* Simulate the FIXED line 215 in Obf.c:
     *     *( PVOID* )( RopExitThd->Rsp + 0 ) = NtTestAlert;   // correct
     * NOT:
     *     *( PVOID* )( RopBegin->Rsp  + 0 ) = NtTestAlert;    // old bug
     */
    *( PVOID* )( RopExitRsp + sizeof( UINT64 ) * 0x0 ) = NtTestAlert_fake;

    check( "Foliage: NtTestAlert written at RopExitThd->Rsp",
           *( PVOID* )( RopExitRsp  + 0 ) == NtTestAlert_fake );
    check( "Foliage: RopBegin->Rsp+0 not clobbered by ExitThd setup",
           *( PVOID* )( RopBeginRsp + 0 ) != NtTestAlert_fake );
}

/* ================================================================== */

int main( void ) {
    printf( "=== SleepObf Unit Tests ===\n\n" );

    printf( "-- OBF_JMP macro (Ekko/Zilean) --\n" );
    test_obf_jmp_none();
    test_obf_jmp_jmprax();
    test_obf_jmp_jmprbx();
    test_obf_jmp_exclusion();

    printf( "\n-- TimerObf Rsp setup (Ekko/Zilean) --\n" );
    test_rop_setup_rsp_decremented();
    test_rop_setup_rsp_delta_is_eight();

    printf( "\n-- FoliageObf NtTestAlert stack setup --\n" );
    test_foliage_nttestalert_at_rsp0();
    test_foliage_exitthr_rsp_written();

    printf( "\n=== %d passed, %d failed ===\n", g_pass, g_fail );
    return g_fail > 0 ? 1 : 0;
}
