#include <Demon.h>

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    PRINTF( "WinMain: hInstance:[%p] hPrevInstance:[%p] lpCmdLine:[%s] nShowCmd:[%d]\n", hInstance, hPrevInstance, lpCmdLine, nShowCmd )
    DemonMain( NULL, NULL );
    return 0;
}

/* [DEBUG-STRINGS-ONLY 2026-04-28]
 * When built with --debug-strings-only the EXE is a CONSOLE subsystem app
 * (see builder.go: -mconsole + -e WinMain). The linker's default entry for
 * console subsystem with -nostdlib would be `main`, which doesn't exist
 * here, so we pin the entry to WinMain via -Wl,-e,WinMain.
 *
 * This `main` stub is defensive: some MinGW configurations may emit a
 * reference to `main` from libgcc personality routines or from console
 * subsystem boilerplate. Providing the symbol prevents `undefined reference
 * to main` link errors. The function is gc-sectioned away if unreferenced
 * (we already use -ffunction-sections / --gc-sections). */
#ifdef DEBUG_NOSTDLIB
int main( void )
{
    WinMain( 0, 0, 0, 0 );
    return 0;
}
#endif
