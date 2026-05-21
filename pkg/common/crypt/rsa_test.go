package crypt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"hash"
	"os"
	"path/filepath"
	"testing"

	"Havoc/pkg/common/crypt"
)

func sha256New() hash.Hash { return sha256.New() }

// TestMarshalBCryptRSAPublicBlob verifies the serialised blob is exactly
// BCryptRSAPublicBlobLen bytes and carries the RSA1 magic value.
func TestMarshalBCryptRSAPublicBlob(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	blob, err := crypt.MarshalBCryptRSAPublicBlob(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalBCryptRSAPublicBlob: %v", err)
	}

	if len(blob) != crypt.BCryptRSAPublicBlobLen {
		t.Errorf("blob length: want %d, got %d", crypt.BCryptRSAPublicBlobLen, len(blob))
	}

	// Magic "RSA1" = 0x31415352 little-endian
	magic := uint32(blob[0]) | uint32(blob[1])<<8 | uint32(blob[2])<<16 | uint32(blob[3])<<24
	if magic != 0x31415352 {
		t.Errorf("magic: want 0x31415352, got 0x%08x", magic)
	}

	// BitLength field
	bits := uint32(blob[4]) | uint32(blob[5])<<8 | uint32(blob[6])<<16 | uint32(blob[7])<<24
	if bits != 2048 {
		t.Errorf("BitLength: want 2048, got %d", bits)
	}

	// cbPublicExp = 3
	cbExp := uint32(blob[8]) | uint32(blob[9])<<8 | uint32(blob[10])<<16 | uint32(blob[11])<<24
	if cbExp != 3 {
		t.Errorf("cbPublicExp: want 3, got %d", cbExp)
	}

	// cbModulus = 256
	cbMod := uint32(blob[12]) | uint32(blob[13])<<8 | uint32(blob[14])<<16 | uint32(blob[15])<<24
	if cbMod != 256 {
		t.Errorf("cbModulus: want 256, got %d", cbMod)
	}
}

// TestRsaOaepRoundtrip encrypts a 48-byte payload with Go's rsa package and
// decrypts it with RsaDecryptOAEP, verifying the full round-trip.
func TestRsaOaepRoundtrip(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	plain := make([]byte, 48) // 32-byte AES key + 16-byte IV
	for i := range plain {
		plain[i] = byte(i + 1)
	}

	ciphertext, err := rsa.EncryptOAEP(sha256New(), rand.Reader, &privKey.PublicKey, plain, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ciphertext) != crypt.RSACiphertextLen {
		t.Fatalf("ciphertext length: want %d, got %d", crypt.RSACiphertextLen, len(ciphertext))
	}

	recovered, err := crypt.RsaDecryptOAEP(privKey, ciphertext)
	if err != nil {
		t.Fatalf("RsaDecryptOAEP: %v", err)
	}
	if string(recovered) != string(plain) {
		t.Errorf("roundtrip mismatch: want %x, got %x", plain, recovered)
	}
}

// TestGenerateOrLoadRSAKeyPair_Generate verifies a fresh key is generated and
// persisted when the target path does not exist, and that a second call loads
// the same key.
func TestGenerateOrLoadRSAKeyPair_Generate(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.rsa")

	privKey, blob, err := crypt.GenerateOrLoadRSAKeyPair(keyPath)
	if err != nil {
		t.Fatalf("GenerateOrLoadRSAKeyPair: %v", err)
	}
	if privKey == nil {
		t.Fatal("returned nil private key")
	}
	if len(blob) != crypt.BCryptRSAPublicBlobLen {
		t.Errorf("blob length: want %d, got %d", crypt.BCryptRSAPublicBlobLen, len(blob))
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("key file was not persisted")
	}

	// Reload — must return the same public key and blob
	privKey2, blob2, err := crypt.GenerateOrLoadRSAKeyPair(keyPath)
	if err != nil {
		t.Fatalf("GenerateOrLoadRSAKeyPair reload: %v", err)
	}
	if privKey2.PublicKey.N.Cmp(privKey.PublicKey.N) != 0 {
		t.Error("reloaded key has different modulus")
	}
	if string(blob2) != string(blob) {
		t.Error("reloaded blob differs from generated blob")
	}
}
