// Package wire provides wire-encoding primitives for the Havoc teamserver.
//
// The upload path (Demon → Teamserver) uses [DecodeAndVerify] to authenticate
// and strip the 32-byte HMAC-SHA256 tag that the Demon's PackageTransmitAll
// appends via WireEncode. The caller is responsible for base64-decoding the
// HTTP body before calling DecodeAndVerify; this keeps the function usable for
// both HTTP and DNS transports that hand off binary bodies to parseAgentRequest.
//
// The download path (Teamserver → Demon) uses [Encode] to AES-256-CTR encrypt,
// authenticate, and base64-encode a response payload. The output format is
// base64([IV(16) | AES-CTR(plaintext) | HMAC-SHA256(32)]), which is what the
// Demon's WireDecode function in WireEncoder.c expects.
//
// Neither function handles registration packets (DEMON_INIT / unknown agents);
// the caller must route those through the existing path unchanged.
package wire

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"Havoc/pkg/common/crypt"
)

// DecodeAndVerify verifies the 32-byte HMAC-SHA256 tag appended by the
// Demon's PackageTransmitAll (encrypt-then-MAC) and returns the authenticated
// binary payload (header + IV + AES-CTR ciphertext) without the tag.
//
// body must already be binary-decoded (i.e. base64 has been stripped by the
// HTTP/external transport layer before calling parseAgentRequest). The function
// does NOT decrypt; callers parse the header and decrypt separately using the
// existing ParseHeader / DecryptBuffer pipeline.
//
// macKey must be the derived MAC key: HMAC-SHA256(sessionAESKey, []byte("mac")).
// This matches the Demon-side derivation in PackageTransmitAll.
func DecodeAndVerify(body, macKey []byte) ([]byte, error) {
	const tagSize = 32

	if len(body) < tagSize {
		return nil, errors.New("wire: body too short to contain HMAC tag")
	}

	payload := body[:len(body)-tagSize]
	tag := body[len(body)-tagSize:]

	expected := crypt.HmacSHA256(macKey, payload)
	if !hmac.Equal(expected, tag) {
		return nil, errors.New("wire: HMAC verification failed")
	}

	return payload, nil
}

// Encode encrypts, authenticates, and base64-encodes a plaintext payload for
// transmission to a Demon agent.
//
// A fresh 16-byte random IV is generated internally on each call.
// The output format is base64([IV(16) | AES-CTR(plaintext) | HMAC-SHA256(32)]),
// which matches the layout that the Demon's WireDecode (WireEncoder.c) expects.
//
// aesKey must be 32 bytes (AES-256). macKey must be 32 bytes and should be
// derived as HMAC-SHA256(aesKey, []byte("mac")).
func Encode(plaintext, aesKey, macKey []byte) ([]byte, error) {
	// Step 1: generate a fresh 16-byte random IV.
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, errors.New("wire: failed to generate IV: " + err.Error())
	}

	// Step 2: AES-256-CTR encrypt the plaintext.
	ciphertext := crypt.XCryptBytesAES256(plaintext, aesKey, iv)

	// Step 3: build raw = IV || ciphertext.
	raw := make([]byte, 0, len(iv)+len(ciphertext))
	raw = append(raw, iv...)
	raw = append(raw, ciphertext...)

	// Step 4: compute HMAC-SHA256 over IV+ciphertext (encrypt-then-MAC).
	tag := crypt.HmacSHA256(macKey, raw)

	// Step 5: build authenticated payload = raw || tag.
	auth := make([]byte, 0, len(raw)+len(tag))
	auth = append(auth, raw...)
	auth = append(auth, tag...)

	// Step 6: base64-encode and return.
	encoded := base64.StdEncoding.EncodeToString(auth)
	return []byte(encoded), nil
}
