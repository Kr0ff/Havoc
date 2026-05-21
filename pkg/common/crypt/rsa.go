package crypt

// [HVC-005 2026-03-28] RSA-2048-OAEP-SHA256 key wrapping for Demon registration.
// The teamserver generates (or loads) an RSA-2048 key pair on startup.
// The public key is embedded into each Demon payload as SERVER_PUBKEY_BLOB
// (a BCRYPT_RSAPUBLIC_BLOB, 283 bytes).  On first check-in the Demon wraps
// its 48-byte AES key material (32-byte key + 16-byte IV) with that public
// key and sends 256 bytes of RSA ciphertext in place of the former plaintext.
// The teamserver decrypts with the private key to recover the session keys.
//
// Key persistence: the private key is stored as PKCS#1 DER at data/havoc.rsa.
// A new key is generated automatically when the file is absent.
//
// See TrafficImprovements.md §5.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const (
	// RSAKeyBits is the modulus size used for the payload wrapping key.
	RSAKeyBits = 2048

	// RSACiphertextLen is the ciphertext length produced by RSA-2048.
	RSACiphertextLen = 256

	// BCryptRSAPublicBlobLen is the total length of a BCRYPT_RSAPUBLIC_BLOB
	// for a 2048-bit key with 3-byte public exponent (65537).
	// Header(24) + Exponent(3) + Modulus(256) = 283 bytes.
	BCryptRSAPublicBlobLen = 283
)

// GenerateOrLoadRSAKeyPair loads the RSA private key from keyPath if it
// exists, otherwise generates a fresh RSA-2048 key pair, saves the private
// key (PKCS#1 DER) to keyPath, and returns the key pair together with the
// BCRYPT_RSAPUBLIC_BLOB-encoded public key ready for embedding in payloads.
func GenerateOrLoadRSAKeyPair(keyPath string) (*rsa.PrivateKey, []byte, error) {
	var privKey *rsa.PrivateKey

	data, err := os.ReadFile(keyPath)
	if err == nil {
		privKey, err = x509.ParsePKCS1PrivateKey(data)
		if err != nil {
			return nil, nil, fmt.Errorf("rsa: parse stored key: %w", err)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		privKey, err = rsa.GenerateKey(rand.Reader, RSAKeyBits)
		if err != nil {
			return nil, nil, fmt.Errorf("rsa: generate key: %w", err)
		}
		der := x509.MarshalPKCS1PrivateKey(privKey)
		if werr := os.WriteFile(keyPath, der, 0600); werr != nil {
			return nil, nil, fmt.Errorf("rsa: save key: %w", werr)
		}
	} else {
		return nil, nil, fmt.Errorf("rsa: read key file: %w", err)
	}

	blob, err := MarshalBCryptRSAPublicBlob(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privKey, blob, nil
}

// MarshalBCryptRSAPublicBlob serialises pub as a BCRYPT_RSAPUBLIC_BLOB so it
// can be embedded into Demon payloads and consumed by BCryptImportKeyPair.
//
// Layout (all LE):
//   Offset  Size  Field
//      0     4    Magic        = 0x31415352  ("RSA1")
//      4     4    BitLength    = 2048
//      8     4    cbPublicExp  = 3
//     12     4    cbModulus    = 256
//     16     4    cbPrime1     = 0
//     20     4    cbPrime2     = 0
//     24     3    PublicExp    (big-endian, most-significant byte first)
//     27   256    Modulus      (big-endian)
func MarshalBCryptRSAPublicBlob(pub *rsa.PublicKey) ([]byte, error) {
	if pub.N.BitLen() != RSAKeyBits {
		return nil, fmt.Errorf("rsa: expected %d-bit key, got %d", RSAKeyBits, pub.N.BitLen())
	}

	blob := make([]byte, BCryptRSAPublicBlobLen)

	// Header (24 bytes, little-endian 32-bit fields)
	binary.LittleEndian.PutUint32(blob[0:], 0x31415352) // Magic "RSA1"
	binary.LittleEndian.PutUint32(blob[4:], uint32(RSAKeyBits))
	binary.LittleEndian.PutUint32(blob[8:], 3)   // cbPublicExp
	binary.LittleEndian.PutUint32(blob[12:], 256) // cbModulus
	binary.LittleEndian.PutUint32(blob[16:], 0)   // cbPrime1
	binary.LittleEndian.PutUint32(blob[20:], 0)   // cbPrime2

	// Public exponent — 3 bytes, big-endian (65537 = 0x010001)
	exp := pub.E
	blob[24] = byte(exp >> 16)
	blob[25] = byte(exp >> 8)
	blob[26] = byte(exp)

	// Modulus — 256 bytes, big-endian
	modBytes := pub.N.Bytes()
	if len(modBytes) > 256 {
		return nil, fmt.Errorf("rsa: modulus too large (%d bytes)", len(modBytes))
	}
	// Right-align into the 256-byte field (pad leading zeros if needed)
	copy(blob[27+(256-len(modBytes)):], modBytes)

	return blob, nil
}

// RsaDecryptOAEP decrypts a 256-byte RSA-OAEP-SHA256 ciphertext produced by
// the Demon's BCryptEncrypt call and returns the recovered plaintext.
func RsaDecryptOAEP(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != RSACiphertextLen {
		return nil, fmt.Errorf("rsa: expected %d-byte ciphertext, got %d", RSACiphertextLen, len(ciphertext))
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa: decrypt: %w", err)
	}
	return plain, nil
}
