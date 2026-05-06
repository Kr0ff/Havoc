package agent

// [BUGFIX-002 / HVC-004 / HVC-006 / HVC-007] Unit tests for the SMB agent
// traffic pipeline between child Demon → parent HTTP Demon → teamserver and
// back down.
//
// Scope:
//   - Wire-packet construction (HVC-003 XOR mask, HVC-004 per-request IV,
//     HVC-007 LZNT1 compression flag)
//   - HMAC-SHA256 append / strip / verify (HVC-006)
//   - ParseHeader round-trip (MagicValue, AgentID, Compressed, Header.Data)
//   - BuildPayloadMessage layout (LE command/reqID/size header + AES-CTR body)
//   - AES-256-CTR encrypt → decrypt round-trip
//   - AddJobToQueue routing: direct agent (own queue) vs pivot agent (parent queue)
//   - PivotAddJob COMMAND_PIVOT envelope (sub-command, child AgentID, payload)
//   - Multi-hop pivot chain: job propagates to the root HTTP parent
//
// All tests are pure (no file I/O, no network, no teamserver instance).

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"Havoc/pkg/common/crypt"
	"Havoc/pkg/common/parser"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildWirePacket assembles a minimal Demon-to-teamserver wire packet.
//
// Wire layout (HMAC tag not included here — caller appends via appendHmacTag):
//
//	[4]  SIZE (big-endian)             – may carry bit 31 (LZNT1 flag, HVC-007)
//	[4]  MAGIC (big-endian, masked)    – XOR'd with SIZE^HeaderMaskSeed (HVC-003)
//	[4]  AgentID (big-endian, masked)  – XOR'd
//	[4]  Command (big-endian, masked)  – XOR'd; first field of Header.Data
//	[4]  RequestID (big-endian, masked)– XOR'd; second field of Header.Data
//	[16] per-request IV (plaintext)    – third field of Header.Data (HVC-004)
//	[N]  AES-256-CTR encrypted payload – remainder of Header.Data
//
// sizeVal is the raw SIZE written to the wire (including any bit-31 flag).
// The XOR mask is computed from sizeVal exactly as the Demon does it.
func buildWirePacket(sizeVal, magic, agentID, command, requestID uint32, iv, encPayload []byte) []byte {
	// 16 masked bytes + IV + encrypted payload
	inner := make([]byte, 16+len(iv)+len(encPayload))
	binary.BigEndian.PutUint32(inner[0:4], magic)
	binary.BigEndian.PutUint32(inner[4:8], agentID)
	binary.BigEndian.PutUint32(inner[8:12], command)
	binary.BigEndian.PutUint32(inner[12:16], requestID)
	copy(inner[16:], iv)
	copy(inner[16+len(iv):], encPayload)

	// [HVC-003] XOR mask on bytes 0-15 of inner (== wire bytes 4-19).
	// Mask = sizeVal ^ HeaderMaskSeed, applied big-endian cycling every 4 bytes.
	mask := sizeVal ^ uint32(HeaderMaskSeed)
	mb := [4]byte{byte(mask >> 24), byte(mask >> 16), byte(mask >> 8), byte(mask)}
	for i := 0; i < 16; i++ {
		inner[i] ^= mb[i%4]
	}

	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, sizeVal)
	return append(sizeBuf, inner...)
}

// appendHmacTag appends the 32-byte HVC-006 tag to payload.
// macKey = HMAC-SHA256(aesKey, "mac"); tag = HMAC-SHA256(macKey, payload).
func appendHmacTag(payload, aesKey []byte) []byte {
	macKey := crypt.HmacSHA256(aesKey, []byte("mac"))
	tag := crypt.HmacSHA256(macKey, payload)
	out := make([]byte, len(payload)+len(tag))
	copy(out, payload)
	copy(out[len(payload):], tag)
	return out
}

// stripAndVerifyHmac removes and verifies the 32-byte HVC-006 tag.
// Returns the payload and whether verification passed.
func stripAndVerifyHmac(body, aesKey []byte) ([]byte, bool) {
	const tagSize = 32
	if len(body) < tagSize {
		return nil, false
	}
	payload := body[:len(body)-tagSize]
	tag := body[len(body)-tagSize:]
	macKey := crypt.HmacSHA256(aesKey, []byte("mac"))
	expected := crypt.HmacSHA256(macKey, payload)
	return payload, hmac.Equal(expected, tag)
}

// testKeys returns deterministic 32-byte AES key and 16-byte AES IV for tests.
func testKeys() ([]byte, []byte) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range iv {
		iv[i] = byte(i + 0x40)
	}
	return key, iv
}

// testAgent creates a minimal Agent suitable for queue/pivot tests.
// nameID must be a valid lowercase hex string whose value fits in int32
// (i.e. ≤ 0x7FFFFFFF) because PivotAddJob uses strconv.ParseInt(..., 16, 32).
func testAgent(nameID string, key, iv []byte) *Agent {
	return &Agent{
		NameID: nameID,
		Encryption: struct {
			AESKey []byte
			AESIv  []byte
		}{AESKey: key, AESIv: iv},
	}
}

// ---------------------------------------------------------------------------
// ParseHeader tests
// ---------------------------------------------------------------------------

// TestSmbParsHeaderMagicAndAgentID verifies that ParseHeader correctly recovers
// MagicValue and AgentID from a HVC-003 masked packet.
func TestSmbParseHeaderMagicAndAgentID(t *testing.T) {
	const (
		agentID = uint32(0x11223344)
		sizeVal = uint32(0x00000020)
	)
	iv := make([]byte, 16)
	pkt := buildWirePacket(sizeVal, DEMON_MAGIC_VALUE, agentID, COMMAND_GET_JOB, 1, iv, nil)

	hdr, err := ParseHeader(pkt)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if uint32(hdr.MagicValue) != DEMON_MAGIC_VALUE {
		t.Errorf("MagicValue = 0x%08X, want 0x%08X", hdr.MagicValue, DEMON_MAGIC_VALUE)
	}
	if uint32(hdr.AgentID) != agentID {
		t.Errorf("AgentID = 0x%08X, want 0x%08X", hdr.AgentID, agentID)
	}
}

// TestSmbParseHeaderCompressionFlagSet verifies that SIZE bit 31 sets
// Header.Compressed = true and is stripped from Header.Size (HVC-007).
func TestSmbParseHeaderCompressionFlagSet(t *testing.T) {
	const sizeVal = uint32(0x80000020) // bit 31 set
	iv := make([]byte, 16)
	pkt := buildWirePacket(sizeVal, DEMON_MAGIC_VALUE, 0x12345678, COMMAND_GET_JOB, 1, iv, nil)

	hdr, err := ParseHeader(pkt)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if !hdr.Compressed {
		t.Error("Compressed = false, want true when SIZE bit 31 is set")
	}
	if hdr.Size&0x80000000 != 0 {
		t.Error("Header.Size still has bit 31 after ParseHeader")
	}
}

// TestSmbParseHeaderCompressionFlagClear verifies SIZE without bit 31 leaves
// Header.Compressed = false.
func TestSmbParseHeaderCompressionFlagClear(t *testing.T) {
	const sizeVal = uint32(0x00000020)
	iv := make([]byte, 16)
	pkt := buildWirePacket(sizeVal, DEMON_MAGIC_VALUE, 0x12345678, COMMAND_GET_JOB, 1, iv, nil)

	hdr, err := ParseHeader(pkt)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if hdr.Compressed {
		t.Error("Compressed = true, want false when SIZE bit 31 is clear")
	}
}

// TestSmbParseHeaderDataLayout verifies that Header.Data begins with Command,
// RequestID, and IV in the expected order.
func TestSmbParseHeaderDataLayout(t *testing.T) {
	const (
		sizeVal   = uint32(0x00000020)
		command   = uint32(COMMAND_GET_JOB)
		requestID = uint32(0xABCD1234)
	)
	iv := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}
	pkt := buildWirePacket(sizeVal, DEMON_MAGIC_VALUE, 0x11111111, command, requestID, iv, nil)

	hdr, err := ParseHeader(pkt)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}

	gotCmd := uint32(hdr.Data.ParseInt32())
	gotReqID := uint32(hdr.Data.ParseInt32())
	gotIV := hdr.Data.ParseAtLeastBytes(16)

	if gotCmd != command {
		t.Errorf("Command = 0x%08X, want 0x%08X", gotCmd, command)
	}
	if gotReqID != requestID {
		t.Errorf("RequestID = 0x%08X, want 0x%08X", gotReqID, requestID)
	}
	if !bytes.Equal(gotIV, iv) {
		t.Errorf("IV = %x, want %x", gotIV, iv)
	}
}

// TestSmbParseHeaderDifferentSizesGiveDifferentMasks verifies that two packets
// with different SIZE values produce different XOR masks (so the masking is
// not a static key).
func TestSmbParseHeaderDifferentSizesGiveDifferentMasks(t *testing.T) {
	iv := make([]byte, 16)
	const (
		agentID = uint32(0x11223344)
		command = uint32(COMMAND_GET_JOB)
	)

	pkt1 := buildWirePacket(0x00000020, DEMON_MAGIC_VALUE, agentID, command, 1, iv, nil)
	pkt2 := buildWirePacket(0x00000030, DEMON_MAGIC_VALUE, agentID, command, 1, iv, nil)

	// Bytes 4-7 are the masked MAGIC field; they must differ between the two packets
	// because SIZE differs and the mask = SIZE ^ HeaderMaskSeed.
	if bytes.Equal(pkt1[4:8], pkt2[4:8]) {
		t.Error("different SIZE values produced identical masked MAGIC bytes; XOR mask is not varying")
	}

	// Both must still parse to the same MagicValue.
	hdr1, _ := ParseHeader(pkt1)
	hdr2, _ := ParseHeader(pkt2)
	if uint32(hdr1.MagicValue) != DEMON_MAGIC_VALUE || uint32(hdr2.MagicValue) != DEMON_MAGIC_VALUE {
		t.Error("ParseHeader did not recover correct MagicValue after varying-SIZE masking")
	}
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 tests (HVC-006)
// ---------------------------------------------------------------------------

// TestSmbHmacTagRoundTrip verifies appendHmacTag → stripAndVerifyHmac recovers
// the original payload.
func TestSmbHmacTagRoundTrip(t *testing.T) {
	key, _ := testKeys()
	payload := []byte("smb-beacon-test-payload-data-12345")

	tagged := appendHmacTag(payload, key)
	recovered, ok := stripAndVerifyHmac(tagged, key)
	if !ok {
		t.Fatal("HMAC verification failed for unmodified payload")
	}
	if !bytes.Equal(recovered, payload) {
		t.Errorf("recovered payload = %x, want %x", recovered, payload)
	}
}

// TestSmbHmacTagTamperDetection verifies that a modified payload fails HMAC
// verification (integrity protection).
func TestSmbHmacTagTamperDetection(t *testing.T) {
	key, _ := testKeys()
	tagged := appendHmacTag([]byte("original-payload"), key)
	tagged[0] ^= 0xFF // flip a bit in payload region

	_, ok := stripAndVerifyHmac(tagged, key)
	if ok {
		t.Error("HMAC verification passed for tampered payload; expected failure")
	}
}

// TestSmbHmacTagWrongKey verifies that verification with a different AES key fails.
func TestSmbHmacTagWrongKey(t *testing.T) {
	key, _ := testKeys()
	wrongKey := bytes.Repeat([]byte{0xFF}, 32)

	tagged := appendHmacTag([]byte("payload"), key)
	_, ok := stripAndVerifyHmac(tagged, wrongKey)
	if ok {
		t.Error("HMAC verification passed with wrong key; expected failure")
	}
}

// TestSmbHmacMacKeyDerivation verifies the MAC key derivation used by HVC-006:
// macKey = HMAC-SHA256(aesKey, "mac").
func TestSmbHmacMacKeyDerivation(t *testing.T) {
	aesKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	h := hmac.New(sha256.New, aesKey)
	h.Write([]byte("mac"))
	expected := h.Sum(nil)

	got := crypt.HmacSHA256(aesKey, []byte("mac"))
	if !bytes.Equal(got, expected) {
		t.Errorf("MAC key = %x, want %x", got, expected)
	}
}

// TestSmbHmacTagLength verifies the HMAC tag is always exactly 32 bytes.
func TestSmbHmacTagLength(t *testing.T) {
	key, _ := testKeys()
	for _, payloadLen := range []int{0, 1, 16, 100, 1024} {
		payload := make([]byte, payloadLen)
		tagged := appendHmacTag(payload, key)
		if len(tagged) != payloadLen+32 {
			t.Errorf("tagged length = %d for payload %d, want %d", len(tagged), payloadLen, payloadLen+32)
		}
	}
}

// ---------------------------------------------------------------------------
// BuildPayloadMessage tests
// ---------------------------------------------------------------------------

// TestSmbBuildPayloadGetJob verifies that a COMMAND_GET_JOB job with no data
// produces exactly 12 bytes: [Command(4,LE)][RequestID(4,LE)][DataSize=0(4,LE)].
func TestSmbBuildPayloadGetJob(t *testing.T) {
	key, iv := testKeys()
	job := Job{Command: COMMAND_GET_JOB, RequestID: 0x00000001, Data: []interface{}{}}

	result := BuildPayloadMessage([]Job{job}, key, iv)
	if len(result) != 12 {
		t.Fatalf("GET_JOB payload length = %d, want 12", len(result))
	}

	gotCmd := binary.LittleEndian.Uint32(result[0:4])
	gotReqID := binary.LittleEndian.Uint32(result[4:8])
	gotDataSize := binary.LittleEndian.Uint32(result[8:12])

	if gotCmd != COMMAND_GET_JOB {
		t.Errorf("Command = 0x%X, want COMMAND_GET_JOB (0x%X)", gotCmd, COMMAND_GET_JOB)
	}
	if gotReqID != 0x00000001 {
		t.Errorf("RequestID = 0x%X, want 0x00000001", gotReqID)
	}
	if gotDataSize != 0 {
		t.Errorf("DataSize = %d, want 0 for no-data job", gotDataSize)
	}
}

// TestSmbBuildPayloadUint32DataEncrypted verifies that a job with a single uint32
// data item produces 16 bytes and that the encrypted data decrypts correctly.
func TestSmbBuildPayloadUint32DataEncrypted(t *testing.T) {
	key, iv := testKeys()
	const testValue = uint32(0xDEADBEEF)
	job := Job{Command: COMMAND_SLEEP, RequestID: 0x42, Data: []interface{}{testValue}}

	result := BuildPayloadMessage([]Job{job}, key, iv)
	// 12-byte header + 4-byte encrypted payload
	if len(result) != 16 {
		t.Fatalf("payload length = %d, want 16", len(result))
	}
	gotDataSize := binary.LittleEndian.Uint32(result[8:12])
	if gotDataSize != 4 {
		t.Errorf("DataSize = %d, want 4", gotDataSize)
	}

	decData := crypt.XCryptBytesAES256(result[12:], key, iv)
	gotValue := binary.LittleEndian.Uint32(decData[0:4])
	if gotValue != testValue {
		t.Errorf("decrypted value = 0x%08X, want 0x%08X", gotValue, testValue)
	}
}

// TestSmbBuildPayloadMultipleJobs verifies two consecutive no-data jobs produce
// 24 bytes (2 × 12) with the correct command IDs in order.
func TestSmbBuildPayloadMultipleJobs(t *testing.T) {
	key, iv := testKeys()
	jobs := []Job{
		{Command: COMMAND_GET_JOB, RequestID: 1, Data: []interface{}{}},
		{Command: COMMAND_NOJOB, RequestID: 2, Data: []interface{}{}},
	}

	result := BuildPayloadMessage(jobs, key, iv)
	if len(result) != 24 {
		t.Fatalf("two no-data jobs length = %d, want 24", len(result))
	}

	cmd1 := binary.LittleEndian.Uint32(result[0:4])
	cmd2 := binary.LittleEndian.Uint32(result[12:16])

	if cmd1 != COMMAND_GET_JOB {
		t.Errorf("job[0] Command = 0x%X, want COMMAND_GET_JOB", cmd1)
	}
	if cmd2 != COMMAND_NOJOB {
		t.Errorf("job[1] Command = 0x%X, want COMMAND_NOJOB", cmd2)
	}
}

// TestSmbBuildPayloadStringDataNullTerminated verifies that string data items are
// null-terminated and prefixed with a 4-byte LE length (including the null byte).
func TestSmbBuildPayloadStringDataNullTerminated(t *testing.T) {
	key, iv := testKeys()
	const msg = "hello"
	job := Job{Command: COMMAND_OUTPUT, RequestID: 1, Data: []interface{}{msg}}

	result := BuildPayloadMessage([]Job{job}, key, iv)
	// header(12) + encrypted(4 len + 6 "hello\0") = 12 + 10 = 22
	if len(result) < 22 {
		t.Fatalf("string job payload too short: %d", len(result))
	}

	encData := result[12:]
	dec := crypt.XCryptBytesAES256(encData, key, iv)

	// First 4 bytes: LE length of "hello\0" = 6
	strLen := binary.LittleEndian.Uint32(dec[0:4])
	if strLen != 6 {
		t.Errorf("string length field = %d, want 6 (len(\"hello\\0\"))", strLen)
	}
	if dec[4] != 'h' || dec[8] != 'o' || dec[9] != 0x00 {
		t.Errorf("unexpected string bytes: %x", dec[4:4+strLen])
	}
}

// ---------------------------------------------------------------------------
// AES-CTR round-trip
// ---------------------------------------------------------------------------

// TestSmbAesCtrRoundTrip verifies that XCryptBytesAES256 is its own inverse.
// AES-CTR XOR is symmetric, which is the basis of HVC-004 IV usage.
func TestSmbAesCtrRoundTrip(t *testing.T) {
	key, iv := testKeys()
	plaintext := []byte("the quick brown fox jumps over!!")

	enc := crypt.XCryptBytesAES256(plaintext, key, iv)
	dec := crypt.XCryptBytesAES256(enc, key, iv)

	if !bytes.Equal(dec, plaintext) {
		t.Errorf("AES-CTR round-trip failed: got %x, want %x", dec, plaintext)
	}
}

// TestSmbAesCtrDifferentIVsDifferentCiphertext verifies that the same plaintext
// encrypted under the same key but different IVs produces different ciphertext.
// This is the property that makes HVC-004 per-request IVs meaningful.
func TestSmbAesCtrDifferentIVsDifferentCiphertext(t *testing.T) {
	key, iv1 := testKeys()
	iv2 := make([]byte, 16)
	for i := range iv2 {
		iv2[i] = 0xFF
	}

	plaintext := []byte("same plaintext data for iv test!!")
	ct1 := crypt.XCryptBytesAES256(plaintext, key, iv1)
	ct2 := crypt.XCryptBytesAES256(plaintext, key, iv2)

	if bytes.Equal(ct1, ct2) {
		t.Error("same plaintext + same key + different IVs produced identical ciphertext")
	}
}

// ---------------------------------------------------------------------------
// Parser XorMaskNextBytes round-trip
// ---------------------------------------------------------------------------

// TestSmbXorMaskRoundTrip verifies that XorMaskNextBytes is idempotent
// (double-XOR restores original) — the property both Demon and teamserver rely
// on for HVC-003.
func TestSmbXorMaskRoundTrip(t *testing.T) {
	original := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}

	buf := make([]byte, len(original))
	copy(buf, original)

	p := parser.NewParser(buf)
	p.XorMaskNextBytes(0x12345678, 16)
	p.XorMaskNextBytes(0x12345678, 16)

	if !bytes.Equal(p.Buffer(), original) {
		t.Errorf("double XorMaskNextBytes did not restore original: got %x", p.Buffer())
	}
}

// ---------------------------------------------------------------------------
// Full pipeline tests (child → parent → teamserver)
// ---------------------------------------------------------------------------

// TestSmbChildGetJobCheckinPipeline simulates a child Demon's GET_JOB checkin
// travelling through the full teamserver receive path:
//
//	buildWirePacket → appendHmacTag → stripAndVerifyHmac → ParseHeader → verify
func TestSmbChildGetJobCheckinPipeline(t *testing.T) {
	key, _ := testKeys()
	aesIv := make([]byte, 16)
	for i := range aesIv {
		aesIv[i] = byte(0x20 + i)
	}

	const (
		agentID   = uint32(0x11223344)
		requestID = uint32(0xAABBCCDD)
		sizeVal   = uint32(0x00000028) // 40 bytes after SIZE field
	)

	perReqIV := make([]byte, 16)
	for i := range perReqIV {
		perReqIV[i] = byte(0x50 + i)
	}

	// Build raw packet (no encrypted payload — GET_JOB carries no data body).
	rawPkt := buildWirePacket(sizeVal, DEMON_MAGIC_VALUE, agentID, COMMAND_GET_JOB, requestID, perReqIV, nil)

	// HVC-006: append HMAC tag.
	tagged := appendHmacTag(rawPkt, key)

	// parseAgentRequest-style: strip + verify HMAC.
	payload, ok := stripAndVerifyHmac(tagged, key)
	if !ok {
		t.Fatal("HMAC verification failed for valid GET_JOB packet")
	}

	hdr, err := ParseHeader(payload)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}

	if uint32(hdr.MagicValue) != DEMON_MAGIC_VALUE {
		t.Errorf("MagicValue = 0x%08X, want 0x%08X", hdr.MagicValue, DEMON_MAGIC_VALUE)
	}
	if uint32(hdr.AgentID) != agentID {
		t.Errorf("AgentID = 0x%08X, want 0x%08X", hdr.AgentID, agentID)
	}
	if hdr.Compressed {
		t.Error("Compressed = true for plain GET_JOB; want false")
	}

	gotCmd := uint32(hdr.Data.ParseInt32())
	gotReqID := uint32(hdr.Data.ParseInt32())
	gotIV := hdr.Data.ParseAtLeastBytes(16)

	if gotCmd != COMMAND_GET_JOB {
		t.Errorf("Command = 0x%X, want COMMAND_GET_JOB", gotCmd)
	}
	if gotReqID != requestID {
		t.Errorf("RequestID = 0x%X, want 0x%X", gotReqID, requestID)
	}
	if !bytes.Equal(gotIV, perReqIV) {
		t.Errorf("IV = %x, want %x", gotIV, perReqIV)
	}
	if hdr.Data.Length() != 0 {
		t.Errorf("unexpected %d trailing bytes after IV in GET_JOB packet", hdr.Data.Length())
	}
}

// TestSmbChildDataPacketPipeline simulates a child Demon sending a COMMAND_OUTPUT
// response through the full pipeline including per-request IV (HVC-004):
//
//	plaintext → AES encrypt with perReqIV → buildWirePacket →
//	appendHmacTag → stripAndVerifyHmac → ParseHeader → extract IV → decrypt → verify
func TestSmbChildDataPacketPipeline(t *testing.T) {
	key, _ := testKeys()

	const (
		agentID   = uint32(0x55667788)
		requestID = uint32(0x00000099)
		sizeVal   = uint32(0x00000050)
	)

	plaintext := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}

	perReqIV := make([]byte, 16)
	for i := range perReqIV {
		perReqIV[i] = byte(0x60 + i)
	}

	// Child encrypts plaintext with the per-request IV.
	encPayload := crypt.XCryptBytesAES256(plaintext, key, perReqIV)

	rawPkt := buildWirePacket(sizeVal, DEMON_MAGIC_VALUE, agentID, COMMAND_OUTPUT, requestID, perReqIV, encPayload)
	tagged := appendHmacTag(rawPkt, key)

	payload, ok := stripAndVerifyHmac(tagged, key)
	if !ok {
		t.Fatal("HMAC verification failed")
	}

	hdr, err := ParseHeader(payload)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}

	gotCmd := uint32(hdr.Data.ParseInt32())
	_ = uint32(hdr.Data.ParseInt32()) // RequestID, consumed
	if gotCmd != COMMAND_OUTPUT {
		t.Errorf("Command = 0x%X, want COMMAND_OUTPUT (0x%X)", gotCmd, COMMAND_OUTPUT)
	}

	// Extract per-request IV and decrypt.
	gotIV := hdr.Data.ParseAtLeastBytes(16)
	hdr.Data.DecryptBuffer(key, gotIV)

	decrypted := hdr.Data.Buffer()
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted payload = %x, want %x", decrypted, plaintext)
	}
}

// TestSmbTeamserverResponseToChild verifies that BuildPayloadMessage produces a
// response that a Demon parser (simulated here) can decode correctly.
// This covers the teamserver → parent → child direction.
func TestSmbTeamserverResponseToChild(t *testing.T) {
	key, iv := testKeys()

	// Teamserver sends COMMAND_SLEEP(10) to the child.
	jobs := []Job{{Command: COMMAND_SLEEP, RequestID: 5, Data: []interface{}{uint32(10)}}}
	resp := BuildPayloadMessage(jobs, key, iv)

	// Demon parses the response (little-endian).
	if len(resp) < 16 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	cmdID := binary.LittleEndian.Uint32(resp[0:4])
	reqID := binary.LittleEndian.Uint32(resp[4:8])
	dataSize := binary.LittleEndian.Uint32(resp[8:12])

	if cmdID != COMMAND_SLEEP {
		t.Errorf("cmdID = 0x%X, want COMMAND_SLEEP (0x%X)", cmdID, COMMAND_SLEEP)
	}
	if reqID != 5 {
		t.Errorf("reqID = %d, want 5", reqID)
	}
	if dataSize != 4 {
		t.Errorf("dataSize = %d, want 4", dataSize)
	}

	decData := crypt.XCryptBytesAES256(resp[12:], key, iv)
	sleepVal := binary.LittleEndian.Uint32(decData[0:4])
	if sleepVal != 10 {
		t.Errorf("sleep value = %d, want 10", sleepVal)
	}
}

// ---------------------------------------------------------------------------
// Job queue routing tests
// ---------------------------------------------------------------------------

// TestSmbAddJobToQueueDirectAgent verifies that AddJobToQueue appends the job to
// the agent's own JobQueue when the agent has no parent (HTTP agent).
func TestSmbAddJobToQueueDirectAgent(t *testing.T) {
	key, iv := testKeys()
	a := testAgent("deadbeef", key, iv)

	job := Job{Command: COMMAND_SLEEP, RequestID: 1, Data: []interface{}{}}
	a.AddJobToQueue(job)

	if len(a.JobQueue) != 1 {
		t.Fatalf("JobQueue length = %d, want 1", len(a.JobQueue))
	}
	if a.JobQueue[0].Command != COMMAND_SLEEP {
		t.Errorf("JobQueue[0].Command = 0x%X, want COMMAND_SLEEP", a.JobQueue[0].Command)
	}
}

// TestSmbAddJobToQueuePivotAgentRoutesThroughParent verifies that AddJobToQueue
// wraps the job in COMMAND_PIVOT on the parent's JobQueue for an SMB pivot agent.
// PivotAddJob also keeps a display-only copy in the child's JobQueue.
func TestSmbAddJobToQueuePivotAgentRoutesThroughParent(t *testing.T) {
	pKey, pIV := testKeys()
	cKey := bytes.Repeat([]byte{0x33}, 32)
	cIV := bytes.Repeat([]byte{0x44}, 16)

	parent := testAgent("0aabbccd", pKey, pIV) // 0x0AABBCCD — fits in int32
	child := testAgent("11223344", cKey, cIV)
	child.Pivots.Parent = parent

	job := Job{Command: COMMAND_SLEEP, RequestID: 2, Data: []interface{}{}}
	child.AddJobToQueue(job)

	// Parent must have exactly one COMMAND_PIVOT job.
	if len(parent.JobQueue) != 1 {
		t.Fatalf("parent.JobQueue length = %d, want 1", len(parent.JobQueue))
	}
	if parent.JobQueue[0].Command != COMMAND_PIVOT {
		t.Errorf("parent.JobQueue[0].Command = 0x%X, want COMMAND_PIVOT (0x%X)",
			parent.JobQueue[0].Command, COMMAND_PIVOT)
	}

	// Child also gets a display-only copy.
	if len(child.JobQueue) != 1 {
		t.Errorf("child.JobQueue length = %d, want 1 (display-only copy)", len(child.JobQueue))
	}
}

// TestSmbPivotEnvelopeSubCommand verifies that the COMMAND_PIVOT job created by
// PivotAddJob carries DEMON_PIVOT_SMB_COMMAND as Data[0].
func TestSmbPivotEnvelopeSubCommand(t *testing.T) {
	pKey, pIV := testKeys()
	cKey := bytes.Repeat([]byte{0x55}, 32)
	cIV := bytes.Repeat([]byte{0x66}, 16)

	parent := testAgent("0aabbccd", pKey, pIV)
	child := testAgent("11223344", cKey, cIV)
	child.Pivots.Parent = parent

	child.AddJobToQueue(Job{Command: COMMAND_NOJOB, RequestID: 0, Data: []interface{}{}})

	if len(parent.JobQueue) == 0 {
		t.Fatal("parent.JobQueue is empty")
	}
	data := parent.JobQueue[0].Data
	if len(data) < 1 {
		t.Fatal("COMMAND_PIVOT job has no data")
	}
	subCmd, ok := data[0].(int)
	if !ok || subCmd != DEMON_PIVOT_SMB_COMMAND {
		t.Errorf("Data[0] = %v (%T), want DEMON_PIVOT_SMB_COMMAND (%d)", data[0], data[0], DEMON_PIVOT_SMB_COMMAND)
	}
}

// TestSmbPivotEnvelopeAgentID verifies that the COMMAND_PIVOT job carries the
// child's AgentID as Data[1] (uint32).
func TestSmbPivotEnvelopeAgentID(t *testing.T) {
	pKey, pIV := testKeys()
	cKey := bytes.Repeat([]byte{0x77}, 32)
	cIV := bytes.Repeat([]byte{0x88}, 16)

	parent := testAgent("0aabbccd", pKey, pIV)
	// 0x11223344 = 287,454,020 — fits in int32, so strconv.ParseInt succeeds.
	child := testAgent("11223344", cKey, cIV)
	child.Pivots.Parent = parent

	child.AddJobToQueue(Job{Command: COMMAND_NOJOB, RequestID: 0, Data: []interface{}{}})

	if len(parent.JobQueue) == 0 {
		t.Fatal("parent.JobQueue is empty")
	}
	data := parent.JobQueue[0].Data
	if len(data) < 2 {
		t.Fatal("COMMAND_PIVOT job has fewer than 2 data items")
	}
	gotID, ok := data[1].(uint32)
	if !ok {
		t.Fatalf("Data[1] type = %T, want uint32", data[1])
	}
	const wantID = uint32(0x11223344)
	if gotID != wantID {
		t.Errorf("pivot AgentID = 0x%08X, want 0x%08X", gotID, wantID)
	}
}

// TestSmbPivotEnvelopePayloadNonEmpty verifies that Data[2] of the COMMAND_PIVOT
// job is a non-empty byte slice (the Packer buffer containing [AgentID][payload]).
func TestSmbPivotEnvelopePayloadNonEmpty(t *testing.T) {
	pKey, pIV := testKeys()
	cKey := bytes.Repeat([]byte{0xAA}, 32)
	cIV := bytes.Repeat([]byte{0xBB}, 16)

	parent := testAgent("0aabbccd", pKey, pIV)
	child := testAgent("11223344", cKey, cIV)
	child.Pivots.Parent = parent

	child.AddJobToQueue(Job{Command: COMMAND_SLEEP, RequestID: 7, Data: []interface{}{uint32(5)}})

	if len(parent.JobQueue) == 0 {
		t.Fatal("parent.JobQueue is empty")
	}
	data := parent.JobQueue[0].Data
	if len(data) < 3 {
		t.Fatal("COMMAND_PIVOT job has fewer than 3 data items")
	}
	buf, ok := data[2].([]byte)
	if !ok {
		t.Fatalf("Data[2] type = %T, want []byte", data[2])
	}
	if len(buf) == 0 {
		t.Error("COMMAND_PIVOT payload buffer is empty")
	}
}

// TestSmbMultiHopPivotChain tests a 3-level chain: grandchild → child → parent.
// The job should end up on the root parent's JobQueue wrapped in nested
// COMMAND_PIVOT envelopes.
func TestSmbMultiHopPivotChain(t *testing.T) {
	mk := func(seed byte) ([]byte, []byte) {
		k := bytes.Repeat([]byte{seed}, 32)
		v := bytes.Repeat([]byte{seed + 1}, 16)
		return k, v
	}

	pk, pv := mk(0x11)
	ck, cv := mk(0x22)
	gk, gv := mk(0x33)

	// 3-level chain: grandchild (gc) → child (c) → parent (p)
	parent := testAgent("00aabbcc", pk, pv)  // 0x00AABBCC fits int32
	child := testAgent("0aabbccd", ck, cv)   // 0x0AABBCCD fits int32
	grandchild := testAgent("11223344", gk, gv)

	child.Pivots.Parent = parent
	grandchild.Pivots.Parent = child

	job := Job{Command: COMMAND_SLEEP, RequestID: 9, Data: []interface{}{}}
	grandchild.AddJobToQueue(job)

	// The root parent's queue must have a COMMAND_PIVOT job.
	if len(parent.JobQueue) != 1 {
		t.Fatalf("root parent.JobQueue length = %d, want 1", len(parent.JobQueue))
	}
	if parent.JobQueue[0].Command != COMMAND_PIVOT {
		t.Errorf("root parent job command = 0x%X, want COMMAND_PIVOT", parent.JobQueue[0].Command)
	}
}

// ---------------------------------------------------------------------------
// Edge-case / regression tests
// ---------------------------------------------------------------------------

// TestSmbParseHeaderTooShortReturnsError verifies ParseHeader rejects packets
// that are too short to contain a SIZE field.
func TestSmbParseHeaderTooShortReturnsError(t *testing.T) {
	_, err := ParseHeader([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("ParseHeader accepted a 3-byte packet; expected error")
	}
}

// TestSmbHmacTagTooShortBodyReturnsFalse verifies stripAndVerifyHmac returns
// false when the body is shorter than 32 bytes.
func TestSmbHmacTagTooShortBodyReturnsFalse(t *testing.T) {
	key, _ := testKeys()
	_, ok := stripAndVerifyHmac(make([]byte, 10), key)
	if ok {
		t.Error("stripAndVerifyHmac returned ok for body shorter than 32 bytes")
	}
}

// TestSmbBuildPayloadEmptyJobSlice verifies BuildPayloadMessage returns nil/empty
// for an empty job slice (no jobs to deliver).
func TestSmbBuildPayloadEmptyJobSlice(t *testing.T) {
	key, iv := testKeys()
	result := BuildPayloadMessage([]Job{}, key, iv)
	if len(result) != 0 {
		t.Errorf("empty job slice produced %d bytes, want 0", len(result))
	}
}
