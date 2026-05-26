#ifndef DEMON_NTDLLUNHOOK_H
#define DEMON_NTDLLUNHOOK_H

#include <common/Native.h>

/* Remove EDR inline hooks from the loaded ntdll by overwriting its .text section
 * with a clean copy from \KnownDlls\ntdll.dll. Returns TRUE on success. */
BOOL UnhookNtdll( VOID );

#endif
