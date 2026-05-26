package wire_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"Havoc/pkg/common/crypt"
	"Havoc/pkg/common/wire"
)

// randKey returns n random bytes, fatally failing the test on error.
func randKey(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read(%d): %v", n, err)
	}
	return b
}

// TestEncodeDecode_RoundTrip verifies that Encode produces output that can be
// base64-decoded, HMAC-verified, and AES-CTR-decrypted back to the original
// plaintext — simulating the Demon-side WireDecode logic in Go.
func TestEncodeDecode_RoundTrip(t *testing.T) {
	aesKey := randKey(t, 32)
	macKey := crypt.HmacSHA256(aesKey, []byte("mac"))
	plaintext := []byte("hello, wire protocol round-trip test")

	encoded, err := wire.Encode(plaintext, aesKey, macKey)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Simulate WireDecode: base64-decode → HMAC verify → extract IV → AES-CTR decrypt.
	raw, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	// raw = [IV(16) | AES-CTR(plaintext) | HMAC(32)]
	const tagSize = 32
	const ivSize = 16
	if len(raw) < ivSize+tagSize {
		t.Fatalf("raw too short: %d bytes", len(raw))
	}

	payload := raw[:len(raw)-tagSize]
	tag := raw[len(raw)-tagSize:]

	// Verify HMAC.
	expected := crypt.HmacSHA256(macKey, payload)
	if !bytes.Equal(expected, tag) {
		t.Fatal("HMAC mismatch in round-trip")
	}

	// Extract IV and decrypt.
	iv := payload[:ivSize]
	ciphertext := payload[ivSize:]
	decrypted := crypt.XCryptBytesAES256(ciphertext, aesKey, iv)

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip: got %q, want %q", decrypted, plaintext)
	}
}

// TestEncodeDecode_HMACTampering verifies that flipping a byte in the middle
// of the base64 ciphertext (after decoding and re-encoding) causes HMAC
// verification to fail when we try to verify the modified payload.
func TestEncodeDecode_HMACTampering(t *testing.T) {
	aesKey := randKey(t, 32)
	macKey := crypt.HmacSHA256(aesKey, []byte("mac"))
	plaintext := []byte("tamper-detection test payload — must be long enough to have a middle byte")

	encoded, err := wire.Encode(plaintext, aesKey, macKey)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Decode, flip a byte in the ciphertext region, re-encode.
	raw, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(raw) < 32+1 {
		t.Fatal("encoded payload too short to tamper with")
	}

	// Flip a byte in the middle (well inside the ciphertext, before the HMAC).
	middle := len(raw) / 2
	raw[middle] ^= 0xFF
	tampered := []byte(base64.StdEncoding.EncodeToString(raw))

	// Try to verify the tampered payload via DecodeAndVerify.
	// First base64-decode it, then call DecodeAndVerify with the binary body.
	tamperedBin, err := base64.StdEncoding.DecodeString(string(tampered))
	if err != nil {
		t.Fatalf("base64 decode tampered: %v", err)
	}

	_, err = wire.DecodeAndVerify(tamperedBin, macKey)
	if err == nil {
		t.Error("DecodeAndVerify accepted a tampered payload — expected an error")
	}
}

// TestDecodeAndVerify_RejectsShortBody verifies that bodies shorter than the
// HMAC tag size (32 bytes) are rejected immediately.
func TestDecodeAndVerify_RejectsShortBody(t *testing.T) {
	macKey := randKey(t, 32)

	// Body is 10 bytes — well under the 32-byte minimum.
	_, err := wire.DecodeAndVerify(make([]byte, 10), macKey)
	if err == nil {
		t.Error("DecodeAndVerify accepted body shorter than 32 bytes — expected error")
	}
}

// TestDecodeAndVerify_ValidPayload verifies that a correctly constructed binary
// payload (mock_header | HMAC) is accepted and that the returned bytes equal
// the payload without the tag.
//
// Layout: [mock_header(20 bytes) | HMAC-SHA256(header)(32 bytes)]
// This mirrors the Demon's upload packet format where the teamserver receives
// the binary body (base64 already stripped by the HTTP transport layer) and
// verifies the appended HMAC tag.
func TestDecodeAndVerify_ValidPayload(t *testing.T) {
	macKey := randKey(t, 32)

	// Build a mock payload: 20 bytes of fake header data.
	mockPayload := randKey(t, 20)

	// Compute the correct HMAC tag.
	tag := crypt.HmacSHA256(macKey, mockPayload)

	// Assemble body = payload || tag.
	body := append(mockPayload, tag...)

	got, err := wire.DecodeAndVerify(body, macKey)
	if err != nil {
		t.Fatalf("DecodeAndVerify returned error on valid payload: %v", err)
	}

	if !bytes.Equal(got, mockPayload) {
		t.Errorf("DecodeAndVerify: got %x, want %x", got, mockPayload)
	}
}
