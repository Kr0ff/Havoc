#ifndef DEMON_HMACSHA256_H
#define DEMON_HMACSHA256_H

#include <Demon.h>

/* [HVC-006 2026-03-26] HMAC-SHA256 output size in bytes. See TrafficImprovements.md §6. */
#define HMAC_SHA256_SIZE 32

/*!
 * @brief
 *  Compute HMAC-SHA256(Key, Data) and write the 32-byte tag to Out.
 *  Pure C, no CRT. All temporary state is wiped before return.
 *
 * @param Key     HMAC key bytes
 * @param KeyLen  Length of Key in bytes
 * @param Data    Input data to authenticate
 * @param DataLen Length of Data in bytes
 * @param Out     Output buffer; must be at least HMAC_SHA256_SIZE (32) bytes
 */
VOID HmacSha256(
    _In_  const PUCHAR Key,
    _In_  SIZE_T       KeyLen,
    _In_  const PUCHAR Data,
    _In_  SIZE_T       DataLen,
    _Out_ PUCHAR       Out
);

#endif
