package crypt

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/sha256"

    "Havoc/pkg/logger"
)

// [HVC-006 2026-03-26] HmacSHA256 returns HMAC-SHA256(key, data).
// Used to derive the per-session MAC key and to compute/verify packet tags.
// See TrafficImprovements.md §6.
func HmacSHA256(key []byte, data []byte) []byte {
    mac := hmac.New(sha256.New, key)
    mac.Write(data)
    return mac.Sum(nil)
}

func XCryptBytesAES256(XBytes []byte, AESKey []byte, AESIv []byte) []byte {
    var (
        ReverseXBytes = make([]byte, len(XBytes))
    )

    block, err := aes.NewCipher(AESKey)
    if err != nil {
        logger.Error("Decryption Error: " + err.Error())
        return []byte{}
    }

    stream := cipher.NewCTR(block, AESIv)
    stream.XORKeyStream(ReverseXBytes, XBytes)

    return ReverseXBytes
}