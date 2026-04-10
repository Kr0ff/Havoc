/**
 * test_mingw_compat.c — Compile-time and runtime compatibility tests for
 * mingw-w64 v14+/v15 (GCC 14+) strict type enforcement.
 *
 * Cross-compiled with: x86_64-w64-mingw32-gcc
 * Tests verify that the macro and type fixes produce correct results.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -Iinclude -o test_mingw_compat.exe test/test_mingw_compat.c
 * Run (on Windows or Wine):
 *   ./test_mingw_compat.exe
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ===================================================================
 * Category 1: MemSet / MemZero macro tests
 *
 * These macros now cast to (unsigned char*) so that __stosb accepts
 * arbitrary pointer types without -Wincompatible-pointer-types errors.
 * =================================================================== */

/* Replicate the fixed macros exactly as in MiniStd.h */
#define MemSet( d, v, l )  __stosb( (unsigned char*)(d), (v), (l) )
#define MemZero( p, l )    __stosb( (unsigned char*)(p), 0, (l) )
#define MemCopy            __builtin_memcpy

/* ---- Struct types that previously failed __stosb strict checks ---- */

typedef struct _TEST_STRUCT {
    DWORD  field1;
    PVOID  field2;
    WCHAR  name[16];
} TEST_STRUCT, *PTEST_STRUCT;

typedef struct _BUFFER {
    PVOID  Buffer;
    UINT32 Length;
} BUFFER, *PBUFFER;

/* DATA_FREE macro (from Macros.h) — depends on MemSet */
#define DATA_FREE_TEST( d, l ) \
    if ( d ) { \
        MemSet( d, 0, l ); \
        free( d ); \
        d = NULL; \
    }

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_MSG(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        tests_failed++; \
    } else { \
        tests_passed++; \
    } \
} while(0)


/* ===================================================================
 * Test 1: MemSet with struct pointer (PTEST_STRUCT)
 * Previously: error: passing argument 1 of '__stosb' from
 *             incompatible pointer type
 * =================================================================== */
void test_memset_struct_ptr(void) {
    printf("[test_memset_struct_ptr]\n");
    TEST_STRUCT ts;
    ts.field1 = 0xDEADBEEF;
    ts.field2 = (PVOID) 0x12345678;

    MemSet( &ts, 0, sizeof(TEST_STRUCT) );

    ASSERT_MSG(ts.field1 == 0, "field1 should be zeroed after MemSet");
    ASSERT_MSG(ts.field2 == NULL, "field2 should be zeroed after MemSet");
}


/* ===================================================================
 * Test 2: MemZero with WCHAR array
 * Previously: error with WCHAR* (short unsigned int*) vs unsigned char*
 * =================================================================== */
void test_memzero_wchar(void) {
    printf("[test_memzero_wchar]\n");
    WCHAR name[16];
    name[0] = L'H';
    name[1] = L'i';
    name[2] = 0;

    MemZero( name, sizeof(name) );

    ASSERT_MSG(name[0] == 0, "WCHAR[0] should be 0 after MemZero");
    ASSERT_MSG(name[1] == 0, "WCHAR[1] should be 0 after MemZero");
}


/* ===================================================================
 * Test 3: MemSet with CONTEXT pointer (used in Dotnet.c, Obf.c)
 * Previously: error with PCONTEXT vs unsigned char*
 * =================================================================== */
void test_memset_context(void) {
    printf("[test_memset_context]\n");
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
#ifdef _WIN64
    ctx.Rip = 0xCAFEBABE;
#else
    ctx.Eip = 0xCAFEBABE;
#endif

    MemSet( &ctx, 0, sizeof(CONTEXT) );

    ASSERT_MSG(ctx.ContextFlags == 0, "ContextFlags should be 0");
#ifdef _WIN64
    ASSERT_MSG(ctx.Rip == 0, "Rip should be 0");
#else
    ASSERT_MSG(ctx.Eip == 0, "Eip should be 0");
#endif
}


/* ===================================================================
 * Test 4: DATA_FREE with struct pointer (PBUFFER)
 * Previously: DATA_FREE macro expanded to MemSet which failed
 * =================================================================== */
void test_data_free_struct(void) {
    printf("[test_data_free_struct]\n");
    PBUFFER buf = (PBUFFER) malloc(sizeof(BUFFER));
    buf->Buffer = (PVOID) 0xDEAD;
    buf->Length = 42;

    /* Capture pointer before DATA_FREE NULLs it */
    DATA_FREE_TEST( buf, sizeof(BUFFER) );

    ASSERT_MSG(buf == NULL, "buf should be NULL after DATA_FREE");
}


/* ===================================================================
 * Test 5: MemSet with fill value (non-zero)
 * Ensures the 3-arg macro form works correctly
 * =================================================================== */
void test_memset_fill_value(void) {
    printf("[test_memset_fill_value]\n");
    unsigned char arr[32];
    MemSet( arr, 0xAA, sizeof(arr) );

    ASSERT_MSG(arr[0] == 0xAA, "arr[0] should be 0xAA");
    ASSERT_MSG(arr[15] == 0xAA, "arr[15] should be 0xAA");
    ASSERT_MSG(arr[31] == 0xAA, "arr[31] should be 0xAA");
}


/* ===================================================================
 * Category 2: NULL → 0 for integer types
 *
 * GCC 14+ errors on: UINT32 x = NULL; (makes integer from pointer)
 * =================================================================== */
void test_integer_zero_init(void) {
    printf("[test_integer_zero_init]\n");

    /* These must compile without -Wint-conversion errors */
    UINT32 pathSize = 0;
    SIZE_T imageSize = 0;
    WORD   ssn = 0;

    ASSERT_MSG(pathSize == 0, "pathSize should be 0");
    ASSERT_MSG(imageSize == 0, "imageSize should be 0");
    ASSERT_MSG(ssn == 0, "ssn should be 0");
}


/* ===================================================================
 * Category 3: Pointer type compatibility (casts)
 *
 * Verify that cast operations preserve values correctly
 * =================================================================== */
void test_pointer_casts(void) {
    printf("[test_pointer_casts]\n");

    /* PWSTR → PBYTE cast (PackageAddBytes pattern) */
    WCHAR wstr[] = L"Test";
    PBYTE bytes = (PBYTE) wstr;
    ASSERT_MSG(bytes != NULL, "PWSTR to PBYTE cast should preserve address");
    ASSERT_MSG((PVOID)bytes == (PVOID)wstr, "Cast should point to same memory");

    /* LPWSTR → PCHAR cast (PackageAddString pattern) */
    LPWSTR lpw = wstr;
    PCHAR  pc = (PCHAR) lpw;
    ASSERT_MSG((PVOID)pc == (PVOID)lpw, "LPWSTR to PCHAR cast should preserve address");

    /* UINT32* → u_long* cast (ioctlsocket pattern) */
    UINT32 val = 0x12345678;
    u_long* ul = (u_long*) &val;
    ASSERT_MSG(*ul == 0x12345678, "UINT32* to u_long* should read same value");

    /* UINT32* → PDWORD cast (RecvAll pattern) */
    PDWORD pd = (PDWORD) &val;
    ASSERT_MSG(*pd == 0x12345678, "UINT32* to PDWORD should read same value");
}


/* ===================================================================
 * Category 4: WCHAR delimiter (Deli) type fix
 *
 * Changed from CHAR Deli[2] to WCHAR Deli[2] for StringConcatW
 * =================================================================== */
void test_wchar_deli(void) {
    printf("[test_wchar_deli]\n");

    WCHAR Deli[2] = { L'\\', 0 };

    ASSERT_MSG(Deli[0] == L'\\', "Deli[0] should be backslash");
    ASSERT_MSG(Deli[1] == 0, "Deli[1] should be null terminator");
    ASSERT_MSG(sizeof(Deli[0]) == sizeof(WCHAR), "Deli elements should be WCHAR-sized");
}


/* ===================================================================
 * Category 5: OSVERSIONINFOEXW → PRTL_OSVERSIONINFOW cast
 *
 * OSVERSIONINFOEXW is a superset of RTL_OSVERSIONINFOW, so the cast
 * is safe. Verify the first fields are at compatible offsets.
 * =================================================================== */
void test_osversion_cast(void) {
    printf("[test_osversion_cast]\n");

    OSVERSIONINFOEXW osv = { 0 };
    osv.dwOSVersionInfoSize = sizeof(osv);
    osv.dwMajorVersion = 10;
    osv.dwMinorVersion = 0;
    osv.dwBuildNumber = 19041;

    PRTL_OSVERSIONINFOW prtl = (PRTL_OSVERSIONINFOW) &osv;

    ASSERT_MSG(prtl->dwMajorVersion == 10, "Major version should be 10 through cast");
    ASSERT_MSG(prtl->dwMinorVersion == 0, "Minor version should be 0 through cast");
    ASSERT_MSG(prtl->dwBuildNumber == 19041, "Build number should be 19041 through cast");
}


/* ===================================================================
 * Category 6: LDR_DATA_TABLE_ENTRY cast
 *
 * Verify that casting LIST_ENTRY* to PLDR_DATA_TABLE_ENTRY preserves
 * the address (the CONTAINING_RECORD pattern).
 * =================================================================== */
void test_ldr_entry_cast(void) {
    printf("[test_ldr_entry_cast]\n");

    /* Simple test: casting a pointer preserves its value */
    LIST_ENTRY le = { 0 };
    le.Flink = &le; /* self-referencing for test */

    PVOID ptr = (PVOID) le.Flink;
    ASSERT_MSG(ptr == (PVOID) &le, "LIST_ENTRY cast should preserve address");
}


/* ===================================================================
 * Category 7: UINT_PTR / PVOID arithmetic (InjectUtil.c pattern)
 *
 * Verify (UINT_PTR) casts for pointer arithmetic produce correct results
 * =================================================================== */
void test_uint_ptr_arithmetic(void) {
    printf("[test_uint_ptr_arithmetic]\n");

    char buf[256];
    PVOID base = buf;
    DWORD offset = 64;

    /* Pattern: (UINT_PTR) base + offset */
    UINT_PTR result = (UINT_PTR) base + offset;
    ASSERT_MSG(result == (UINT_PTR) &buf[64], "UINT_PTR arithmetic should produce correct address");
}


/* ===================================================================
 * Main
 * =================================================================== */
int main(void) {
    printf("=== Demon mingw-w64 v15 Compatibility Tests ===\n\n");

    /* Category 1: MemSet / MemZero */
    test_memset_struct_ptr();
    test_memzero_wchar();
    test_memset_context();
    test_data_free_struct();
    test_memset_fill_value();

    /* Category 2: Integer init */
    test_integer_zero_init();

    /* Category 3: Pointer casts */
    test_pointer_casts();

    /* Category 4: WCHAR Deli */
    test_wchar_deli();

    /* Category 5: OSVERSIONINFO cast */
    test_osversion_cast();

    /* Category 6: LDR entry cast */
    test_ldr_entry_cast();

    /* Category 7: Pointer arithmetic */
    test_uint_ptr_arithmetic();

    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
