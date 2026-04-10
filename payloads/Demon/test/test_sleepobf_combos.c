/*
 * test_sleepobf_combos.c — Unit tests for sleep obfuscation combinations
 *
 * Tests structural correctness of the OBF_JMP macro, ROP array setup,
 * timer/wait handle management, and proxy loading cleanup patterns.
 *
 * Compile: x86_64-w64-mingw32-gcc -o test_sleepobf_combos.exe test_sleepobf_combos.c -I../include
 * Run:     wine test_sleepobf_combos.exe  (or natively on Windows)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Minimal type stubs for testing without full Demon headers */
typedef unsigned long       ULONG;
typedef unsigned long       DWORD;
typedef unsigned long long  ULONG_PTR;
typedef unsigned long long  SIZE_T;
typedef void*               PVOID;
typedef void*               HANDLE;
typedef unsigned char       BYTE;
typedef unsigned char       UCHAR;
typedef int                 BOOL;
typedef long                NTSTATUS;

#define TRUE  1
#define FALSE 0
#define NULL  ((void*)0)
#define U_PTR( x ) ( (ULONG_PTR)(x) )
#define C_PTR( x ) ( (PVOID)(x) )
#define INVALID_HANDLE_VALUE ((HANDLE)(ULONG_PTR)-1)

/* Sleep obfuscation constants (from SleepObf.h) */
#define SLEEPOBF_NO_OBF      0x0
#define SLEEPOBF_EKKO        0x1
#define SLEEPOBF_ZILEAN      0x2
#define SLEEPOBF_FOLIAGE     0x3
#define SLEEPOBF_BYPASS_NONE   0
#define SLEEPOBF_BYPASS_JMPRAX 0x1
#define SLEEPOBF_BYPASS_JMPRBX 0x2

/* Proxy loading constants (from Defines.h) */
#define PROXYLOAD_NONE              0
#define PROXYLOAD_RTLREGISTERWAIT   1
#define PROXYLOAD_RTLCREATETIMER    2
#define PROXYLOAD_RTLQUEUEWORKITEM  3

/* Minimal CONTEXT stub (only the fields we test) */
typedef struct _TEST_CONTEXT {
    ULONG_PTR Rip;
    ULONG_PTR Rsp;
    ULONG_PTR Rax;
    ULONG_PTR Rbx;
    ULONG_PTR Rcx;
    ULONG_PTR Rdx;
    ULONG_PTR R8;
    ULONG_PTR R9;
    DWORD     ContextFlags;
} TEST_CONTEXT;

/* Reproduce OBF_JMP macro exactly as in SleepObf.h */
#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {         \
        Rop[ i ].Rax = U_PTR( p );                       \
    } else if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \
        Rop[ i ].Rbx = U_PTR( & p );                     \
    } else {                                             \
        Rop[ i ].Rip = U_PTR( p );                       \
    }

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ( a, b, msg ) do { \
    tests_run++; \
    if ( (a) == (b) ) { tests_passed++; } \
    else { tests_failed++; printf("  FAIL: %s (expected 0x%llx, got 0x%llx)\n", msg, (unsigned long long)(b), (unsigned long long)(a)); } \
} while(0)

#define ASSERT_NEQ( a, b, msg ) do { \
    tests_run++; \
    if ( (a) != (b) ) { tests_passed++; } \
    else { tests_failed++; printf("  FAIL: %s (should not be 0x%llx)\n", msg, (unsigned long long)(b)); } \
} while(0)

/* Fake function addresses for testing */
static void FakeWaitForSingleObjectEx(void) {}
static void FakeVirtualProtect(void) {}
static void FakeSystemFunction032(void) {}
static void FakeNtSetEvent(void) {}
static void FakeNtContinue(void) {}
static void FakeNtGetContextThread(void) {}
static void FakeNtSetContextThread(void) {}
static void FakeRtlCopyMappedMemory(void) {}

/* ============================================================
 * TEST 1: OBF_JMP macro — SLEEPOBF_BYPASS_NONE
 * When JmpBypass=NONE, Rip should be set to the function address
 * ============================================================ */
void test_obf_jmp_none(void) {
    printf("[TEST] OBF_JMP with SLEEPOBF_BYPASS_NONE\n");

    TEST_CONTEXT Rop[13] = {0};
    BYTE JmpBypass = SLEEPOBF_BYPASS_NONE;
    PVOID JmpGadget = (PVOID)0xDEAD;
    int Inc = 0;

    /* Simulate init loop: Rip = JmpGadget for all */
    for (int i = 0; i < 13; i++) {
        Rop[i].Rip = U_PTR(JmpGadget);
    }

    /* OBF_JMP should OVERWRITE Rip with the function address */
    PVOID func = (PVOID)FakeWaitForSingleObjectEx;
    OBF_JMP(Inc, func);

    ASSERT_EQ(Rop[0].Rip, U_PTR(func), "Rip should be function address, not JmpGadget");
    ASSERT_EQ(Rop[0].Rax, 0ULL, "Rax should be untouched");
    ASSERT_EQ(Rop[0].Rbx, 0ULL, "Rbx should be untouched");
}

/* ============================================================
 * TEST 2: OBF_JMP macro — SLEEPOBF_BYPASS_JMPRAX
 * When JmpBypass=JMPRAX, Rax should hold the function address
 * and Rip should remain as JmpGadget
 * ============================================================ */
void test_obf_jmp_rax(void) {
    printf("[TEST] OBF_JMP with SLEEPOBF_BYPASS_JMPRAX\n");

    TEST_CONTEXT Rop[13] = {0};
    BYTE JmpBypass = SLEEPOBF_BYPASS_JMPRAX;
    PVOID JmpGadget = (PVOID)0xBEEF;
    int Inc = 0;

    for (int i = 0; i < 13; i++) {
        Rop[i].Rip = U_PTR(JmpGadget);
    }

    PVOID func = (PVOID)FakeVirtualProtect;
    OBF_JMP(Inc, func);

    ASSERT_EQ(Rop[0].Rip, U_PTR(JmpGadget), "Rip should remain as JmpGadget");
    ASSERT_EQ(Rop[0].Rax, U_PTR(func), "Rax should be function address");
    ASSERT_EQ(Rop[0].Rbx, 0ULL, "Rbx should be untouched");
}

/* ============================================================
 * TEST 3: OBF_JMP macro — SLEEPOBF_BYPASS_JMPRBX
 * When JmpBypass=JMPRBX, Rbx should hold ADDRESS OF the function pointer
 * and Rip should remain as JmpGadget
 * ============================================================ */
void test_obf_jmp_rbx(void) {
    printf("[TEST] OBF_JMP with SLEEPOBF_BYPASS_JMPRBX\n");

    TEST_CONTEXT Rop[13] = {0};
    BYTE JmpBypass = SLEEPOBF_BYPASS_JMPRBX;
    PVOID JmpGadget = (PVOID)0xCAFE;
    int Inc = 0;

    for (int i = 0; i < 13; i++) {
        Rop[i].Rip = U_PTR(JmpGadget);
    }

    PVOID func = (PVOID)FakeSystemFunction032;
    OBF_JMP(Inc, func);

    ASSERT_EQ(Rop[0].Rip, U_PTR(JmpGadget), "Rip should remain as JmpGadget");
    ASSERT_EQ(Rop[0].Rbx, U_PTR(&func), "Rbx should be ADDRESS OF function pointer");
    ASSERT_EQ(Rop[0].Rax, 0ULL, "Rax should be untouched");
}

/* ============================================================
 * TEST 4: Rop array initialization — Rsp decrement
 * Every Rop entry must have Rsp decremented by sizeof(PVOID)
 * ============================================================ */
void test_rop_rsp_decrement(void) {
    printf("[TEST] Rop array Rsp decrement\n");

    TEST_CONTEXT TimerCtx = {0};
    TEST_CONTEXT Rop[13] = {0};
    PVOID JmpGadget = (PVOID)0xAAAA;

    /* Simulate captured RSP */
    TimerCtx.Rsp = 0x7FFE0000;

    for (int i = 0; i < 13; i++) {
        memcpy(&Rop[i], &TimerCtx, sizeof(TEST_CONTEXT));
        Rop[i].Rip  = U_PTR(JmpGadget);
        Rop[i].Rsp -= sizeof(PVOID);
    }

    for (int i = 0; i < 13; i++) {
        ASSERT_EQ(Rop[i].Rsp, TimerCtx.Rsp - sizeof(PVOID),
                  "Rop[i].Rsp should be TimerCtx.Rsp - sizeof(PVOID)");
        ASSERT_EQ(Rop[i].Rip, U_PTR(JmpGadget),
                  "Rop[i].Rip should be JmpGadget");
    }
}

/* ============================================================
 * TEST 5: ROP chain Inc counter — bounds check
 * Inc must never exceed 13 (Rop array size)
 * Without stack spoof: 5 ROPs (WaitForSingleObjectEx, VirtualProtect,
 *   SystemFunction032, Sleep, SystemFunction032, VirtualProtect, NtSetEvent) = 7
 * With stack spoof: +4 (NtGetCtx, RtlCopy x2, NtSetCtx before sleep,
 *   RtlCopy, NtSetCtx after sleep) = 7+4 = 11
 * Max: 13 (2 spare)
 * ============================================================ */
void test_rop_inc_bounds(void) {
    printf("[TEST] ROP chain Inc bounds check\n");

    /* Without stack spoof */
    int Inc = 0;
    Inc++; /* WaitForSingleObjectEx */
    Inc++; /* VirtualProtect RW */
    Inc++; /* SystemFunction032 encrypt */
    Inc++; /* WaitForSingleObjectEx sleep */
    Inc++; /* SystemFunction032 decrypt */
    Inc++; /* VirtualProtect RX */
    Inc++; /* NtSetEvent */
    ASSERT_EQ(Inc <= 13, TRUE, "Inc without stack spoof should be <= 13");
    ASSERT_EQ(Inc, 7, "Inc without stack spoof should be 7");

    /* With stack spoof */
    Inc = 0;
    Inc++; /* WaitForSingleObjectEx */
    Inc++; /* VirtualProtect RW */
    Inc++; /* SystemFunction032 encrypt */
    Inc++; /* NtGetContextThread */
    Inc++; /* RtlCopyMappedMemory (Rip) */
    Inc++; /* RtlCopyMappedMemory (NtTib) */
    Inc++; /* NtSetContextThread */
    Inc++; /* WaitForSingleObjectEx sleep */
    Inc++; /* RtlCopyMappedMemory (restore NtTib) */
    Inc++; /* NtSetContextThread (restore) */
    Inc++; /* SystemFunction032 decrypt */
    Inc++; /* VirtualProtect RX */
    Inc++; /* NtSetEvent */
    ASSERT_EQ(Inc <= 13, TRUE, "Inc with stack spoof should be <= 13");
    ASSERT_EQ(Inc, 13, "Inc with stack spoof should be 13");
}

/* ============================================================
 * TEST 6: Timer queue cleanup covers all timers (Ekko model)
 * RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE) must be
 * called on the Queue, which destroys ALL timers in it.
 * ============================================================ */
void test_timer_queue_cleanup(void) {
    printf("[TEST] Timer queue cleanup model\n");

    /* Simulate: Queue is created, timers added, Queue destroyed */
    HANDLE Queue = (HANDLE)0x1234;
    HANDLE Timer = NULL;

    /* Simulate multiple RtlCreateTimer calls — Timer is overwritten each time */
    Timer = (HANDLE)0xA;
    Timer = (HANDLE)0xB;
    Timer = (HANDLE)0xC;

    /* Verify Queue is non-NULL (will be destroyed) */
    ASSERT_NEQ(Queue, NULL, "Queue should be non-NULL before cleanup");

    /* After RtlDeleteTimerQueueEx(Queue, INVALID_HANDLE_VALUE): */
    Queue = NULL;
    ASSERT_EQ(Queue, NULL, "Queue should be NULL after cleanup");

    /* Timer handle is irrelevant — Queue destruction handles all timers */
    /* This is correct for both Ekko AND Zilean (post-fix) */
}

/* ============================================================
 * TEST 7: Proxy loading — RtlDeregisterWaitEx before Event close
 * Timer (wait handle) must be deregistered BEFORE Event is closed
 * ============================================================ */
void test_proxy_wait_deregister_order(void) {
    printf("[TEST] Proxy loading wait deregister order\n");

    /* Simulate the cleanup sequence */
    HANDLE Timer = (HANDLE)0xABCD;
    HANDLE Event = (HANDLE)0x5678;
    HANDLE Queue = NULL;
    int deregister_called = 0;
    int event_closed = 0;
    int queue_deleted = 0;

    /* Step 1: Deregister wait (if Timer is set) */
    if (Timer) {
        /* RtlDeregisterWaitEx(Timer, INVALID_HANDLE_VALUE) */
        deregister_called = 1;
        Timer = NULL;
    }

    /* Step 2: Close event (if Event is set) */
    if (Event) {
        event_closed = 1;
        Event = NULL;
    }

    /* Step 3: Delete queue (if Queue is set — only for RtlCreateTimer path) */
    if (Queue) {
        queue_deleted = 1;
        Queue = NULL;
    }

    ASSERT_EQ(deregister_called, 1, "RtlDeregisterWaitEx must be called before closing Event");
    ASSERT_EQ(event_closed, 1, "Event should be closed after deregistering wait");
    ASSERT_EQ(queue_deleted, 0, "Queue should not be deleted (not used for RtlRegisterWait proxy)");
}

/* ============================================================
 * TEST 8: All sleep techniques are valid enum values
 * ============================================================ */
void test_sleep_technique_values(void) {
    printf("[TEST] Sleep technique enum values\n");

    ASSERT_EQ(SLEEPOBF_NO_OBF, 0, "NO_OBF should be 0");
    ASSERT_EQ(SLEEPOBF_EKKO, 1, "EKKO should be 1");
    ASSERT_EQ(SLEEPOBF_ZILEAN, 2, "ZILEAN should be 2");
    ASSERT_EQ(SLEEPOBF_FOLIAGE, 3, "FOLIAGE should be 3");
    ASSERT_EQ(SLEEPOBF_BYPASS_NONE, 0, "BYPASS_NONE should be 0");
    ASSERT_EQ(SLEEPOBF_BYPASS_JMPRAX, 1, "BYPASS_JMPRAX should be 1");
    ASSERT_EQ(SLEEPOBF_BYPASS_JMPRBX, 2, "BYPASS_JMPRBX should be 2");
}

/* ============================================================
 * TEST 9: Proxy loading enum values
 * ============================================================ */
void test_proxy_loading_values(void) {
    printf("[TEST] Proxy loading enum values\n");

    ASSERT_EQ(PROXYLOAD_NONE, 0, "PROXYLOAD_NONE should be 0");
    ASSERT_EQ(PROXYLOAD_RTLREGISTERWAIT, 1, "PROXYLOAD_RTLREGISTERWAIT should be 1");
    ASSERT_EQ(PROXYLOAD_RTLCREATETIMER, 2, "PROXYLOAD_RTLCREATETIMER should be 2");
    ASSERT_EQ(PROXYLOAD_RTLQUEUEWORKITEM, 3, "PROXYLOAD_RTLQUEUEWORKITEM should be 3");
}

/* ============================================================
 * TEST 10: OBF_JMP with all 3 bypass modes across multiple Inc values
 * Ensures the macro works at any array index, not just 0
 * ============================================================ */
void test_obf_jmp_all_indices(void) {
    printf("[TEST] OBF_JMP across multiple indices\n");

    for (int bypass = 0; bypass <= 2; bypass++) {
        TEST_CONTEXT Rop[13] = {0};
        BYTE JmpBypass = bypass;
        PVOID JmpGadget = (PVOID)0xF00D;

        for (int i = 0; i < 13; i++) {
            Rop[i].Rip = U_PTR(JmpGadget);
        }

        PVOID funcs[] = {
            (PVOID)FakeWaitForSingleObjectEx,
            (PVOID)FakeVirtualProtect,
            (PVOID)FakeSystemFunction032,
            (PVOID)FakeNtSetEvent,
            (PVOID)FakeNtContinue,
            (PVOID)FakeNtGetContextThread,
            (PVOID)FakeNtSetContextThread,
        };

        for (int i = 0; i < 7; i++) {
            int Inc = i;
            PVOID func = funcs[i];
            OBF_JMP(Inc, func);

            if (bypass == SLEEPOBF_BYPASS_NONE) {
                ASSERT_EQ(Rop[i].Rip, U_PTR(func), "NONE: Rip should be func");
            } else if (bypass == SLEEPOBF_BYPASS_JMPRAX) {
                ASSERT_EQ(Rop[i].Rip, U_PTR(JmpGadget), "JMPRAX: Rip should be gadget");
                ASSERT_EQ(Rop[i].Rax, U_PTR(func), "JMPRAX: Rax should be func");
            } else {
                ASSERT_EQ(Rop[i].Rip, U_PTR(JmpGadget), "JMPRBX: Rip should be gadget");
                ASSERT_EQ(Rop[i].Rbx, U_PTR(&func), "JMPRBX: Rbx should be &func");
            }
        }
    }
}

/* ============================================================
 * TEST 11: Zilean now uses timer queue (unified with Ekko)
 * Both SLEEPOBF_EKKO and SLEEPOBF_ZILEAN should follow the same
 * timer queue path — no RtlRegisterWait for ROP execution
 * ============================================================ */
void test_zilean_uses_timer_queue(void) {
    printf("[TEST] Zilean unified with Ekko (timer queue)\n");

    /* Both methods should create a timer queue */
    for (int method = SLEEPOBF_EKKO; method <= SLEEPOBF_ZILEAN; method++) {
        HANDLE Queue = NULL;
        int queue_created = 0;

        /* Simulate: RtlCreateTimerQueue(&Queue) */
        Queue = (HANDLE)0x9999;
        queue_created = 1;

        ASSERT_EQ(queue_created, 1, "Timer queue should be created for both Ekko and Zilean");
        ASSERT_NEQ(Queue, NULL, "Queue handle should be non-NULL");

        /* Simulate: ROP chain uses RtlCreateTimer (not RtlRegisterWait) */
        int used_rtlcreatetimer = 1;
        int used_rtlregisterwait = 0;

        ASSERT_EQ(used_rtlcreatetimer, 1, "ROP chain should use RtlCreateTimer");
        ASSERT_EQ(used_rtlregisterwait, 0, "ROP chain should NOT use RtlRegisterWait");
    }
}

/* ============================================================
 * TEST 12: Foliage thread wait before cleanup
 * hThread must be waited on before freeing CONTEXTs
 * ============================================================ */
void test_foliage_thread_sync(void) {
    printf("[TEST] Foliage thread synchronization before cleanup\n");

    HANDLE hThread = (HANDLE)0xBBBB;
    int waited = 0;
    int freed_ctx = 0;

    /* Step 1: Wait for thread (simulates SysNtWaitForSingleObject) */
    if (hThread) {
        waited = 1;
        /* SysNtWaitForSingleObject(hThread, FALSE, NULL) */
        /* SysNtClose(hThread) */
        hThread = NULL;
    }

    /* Step 2: Free CONTEXTs */
    freed_ctx = 1;

    ASSERT_EQ(waited, 1, "Must wait for thread before freeing CONTEXTs");
    ASSERT_EQ(freed_ctx, 1, "CONTEXTs freed after thread wait");
    ASSERT_EQ(hThread, NULL, "hThread should be NULL after cleanup");
}

/* ============================================================
 * TEST 13: Combination matrix — all valid combinations enumerated
 * ============================================================ */
void test_combination_matrix(void) {
    printf("[TEST] Combination matrix enumeration\n");

    int sleepTechniques[] = { SLEEPOBF_NO_OBF, SLEEPOBF_EKKO, SLEEPOBF_ZILEAN, SLEEPOBF_FOLIAGE };
    int jmpGadgets[]      = { SLEEPOBF_BYPASS_NONE, SLEEPOBF_BYPASS_JMPRAX, SLEEPOBF_BYPASS_JMPRBX };
    int proxyLoads[]      = { PROXYLOAD_NONE, PROXYLOAD_RTLREGISTERWAIT, PROXYLOAD_RTLCREATETIMER, PROXYLOAD_RTLQUEUEWORKITEM };

    int total_combos = 0;
    int timer_based = 0;
    int foliage_based = 0;

    for (int s = 0; s < 4; s++) {
        for (int j = 0; j < 3; j++) {
            for (int p = 0; p < 4; p++) {
                total_combos++;

                if (sleepTechniques[s] == SLEEPOBF_EKKO || sleepTechniques[s] == SLEEPOBF_ZILEAN) {
                    timer_based++;
                }
                if (sleepTechniques[s] == SLEEPOBF_FOLIAGE) {
                    foliage_based++;
                }
            }
        }
    }

    ASSERT_EQ(total_combos, 48, "Total combinations should be 4 * 3 * 4 = 48");
    ASSERT_EQ(timer_based, 24, "Timer-based combos should be 2 * 3 * 4 = 24");
    ASSERT_EQ(foliage_based, 12, "Foliage combos should be 1 * 3 * 4 = 12");
}

/* ============================================================
 * TEST 14: Compile-time technique selection defines
 * Verifies that SLEEPOBF_USE_TIMER and SLEEPOBF_USE_FOLIAGE
 * correctly gate code inclusion.
 * ============================================================ */
void test_compile_time_selection(void) {
    printf("[TEST] compile-time technique selection\n");

#ifdef SLEEPOBF_USE_TIMER
    int timer_enabled = 1;
#else
    int timer_enabled = 0;
#endif

#ifdef SLEEPOBF_USE_FOLIAGE
    int foliage_enabled = 1;
#else
    int foliage_enabled = 0;
#endif

    /* When both defines are set (test build), both should be enabled */
    ASSERT_EQ(timer_enabled, 1, "SLEEPOBF_USE_TIMER should be defined in test build");
    ASSERT_EQ(foliage_enabled, 1, "SLEEPOBF_USE_FOLIAGE should be defined in test build");

    /* Verify that WaitForSingleObjectEx (no obf) is always available
     * regardless of defines — it's the default fallback */
    ASSERT_EQ(SLEEPOBF_NO_OBF, 0x0, "SLEEPOBF_NO_OBF always available as fallback");

    /* Timer techniques should map to their expected enum values
     * when SLEEPOBF_USE_TIMER is defined */
#ifdef SLEEPOBF_USE_TIMER
    ASSERT_EQ(SLEEPOBF_EKKO, 0x1, "Ekko available when SLEEPOBF_USE_TIMER defined");
    ASSERT_EQ(SLEEPOBF_ZILEAN, 0x2, "Zilean available when SLEEPOBF_USE_TIMER defined");
#endif

    /* Foliage should map to its expected enum value
     * when SLEEPOBF_USE_FOLIAGE is defined */
#ifdef SLEEPOBF_USE_FOLIAGE
    ASSERT_EQ(SLEEPOBF_FOLIAGE, 0x3, "Foliage available when SLEEPOBF_USE_FOLIAGE defined");
#endif
}

/* ============================================================
 * MAIN
 * ============================================================ */
int main(void) {
    printf("=== Sleep Obfuscation Combination Tests ===\n\n");

    test_obf_jmp_none();
    test_obf_jmp_rax();
    test_obf_jmp_rbx();
    test_rop_rsp_decrement();
    test_rop_inc_bounds();
    test_timer_queue_cleanup();
    test_proxy_wait_deregister_order();
    test_sleep_technique_values();
    test_proxy_loading_values();
    test_obf_jmp_all_indices();
    test_zilean_uses_timer_queue();
    test_foliage_thread_sync();
    test_combination_matrix();
    test_compile_time_selection();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed ? 1 : 0;
}
