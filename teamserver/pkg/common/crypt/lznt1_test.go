package crypt

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildUncompressedChunk constructs an LZNT1 uncompressed chunk for data.
// The caller must ensure len(data) <= 4096.
func buildUncompressedChunk(data []byte) []byte {
	hdr := uint16(len(data) - 1) // bit 15 clear = uncompressed
	buf := make([]byte, 2+len(data))
	binary.LittleEndian.PutUint16(buf, hdr)
	copy(buf[2:], data)
	return buf
}

// TestDecompressLZNT1_Empty verifies that empty input returns empty output.
func TestDecompressLZNT1_Empty(t *testing.T) {
	out, err := DecompressLZNT1(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty output, got %d bytes", len(out))
	}
}

// TestDecompressLZNT1_ZeroTerminator verifies the end-of-stream sentinel.
func TestDecompressLZNT1_ZeroTerminator(t *testing.T) {
	out, err := DecompressLZNT1([]byte{0x00, 0x00})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty output, got %d bytes", len(out))
	}
}

// TestDecompressLZNT1_UncompressedChunk verifies passthrough of an uncompressed chunk.
func TestDecompressLZNT1_UncompressedChunk(t *testing.T) {
	plain := []byte("HelloWorld")
	input := buildUncompressedChunk(plain)

	out, err := DecompressLZNT1(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("expected %q, got %q", plain, out)
	}
}

// TestDecompressLZNT1_MultipleUncompressedChunks verifies chained uncompressed chunks.
func TestDecompressLZNT1_MultipleUncompressedChunks(t *testing.T) {
	parts := [][]byte{
		[]byte("Hello"),
		[]byte(", "),
		[]byte("World!"),
	}
	var input []byte
	for _, p := range parts {
		input = append(input, buildUncompressedChunk(p)...)
	}

	out, err := DecompressLZNT1(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte("Hello, World!")
	if !bytes.Equal(out, expected) {
		t.Fatalf("expected %q, got %q", expected, out)
	}
}

// TestDecompressLZNT1_CompressedChunk_Repeated verifies decompression of a
// hand-crafted LZNT1 compressed chunk encoding 16 repeated 'A' bytes.
//
// LZNT1 encoding of 16×'A':
//   Chunk header: 0x8003 (compressed, data = 4 bytes: flag + literal + 2-byte ref)
//   Flag byte:    0x02   (bit 1 set → item 1 is a back-reference)
//   Item 0 (bit 0 clear): literal 0x41 = 'A'  → out = [A], pos=1
//   Item 1 (bit 1 set):   back-ref 0x000C (LE)
//     pos=1 → j=4, lengthBits=12, lengthMask=0x0FFF
//     length = (0x000C & 0x0FFF) + 3 = 12 + 3 = 15
//     offset = (0x000C >> 12) + 1 = 0 + 1 = 1
//     → copy out[-1] 15 times → 15×'A'
//   Total output: 1 + 15 = 16×'A'
func TestDecompressLZNT1_CompressedChunk_Repeated(t *testing.T) {
	// Chunk header 0x8003 → compressed, chunk data size = 3+1 = 4 bytes
	input := []byte{
		0x03, 0x80, // chunk header (LE) = 0x8003
		0x02,       // flag byte: bit 1 set
		0x41,       // literal 'A'
		0x0C, 0x00, // back-reference 0x000C (LE)
	}

	out, err := DecompressLZNT1(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := bytes.Repeat([]byte("A"), 16)
	if !bytes.Equal(out, expected) {
		t.Fatalf("expected 16×'A', got %q (len=%d)", out, len(out))
	}
}

// TestDecompressLZNT1_CompressedChunk_LiteralRun verifies a compressed chunk
// consisting entirely of literals (flag bytes all zero).
//
// LZNT1 encoding of "ABCDEFGH" using 1 group (flag=0x00, 8 literals):
//   Chunk header: 0x8008 (compressed, data = 8+1 = 9 bytes)
//   Flag byte:    0x00  (all bits clear = all literals)
//   Literals:     A B C D E F G H
func TestDecompressLZNT1_CompressedChunk_LiteralRun(t *testing.T) {
	// data = flag(1) + 8 literals = 9 bytes; chunkHdr = 0x8000 | (9-1) = 0x8008
	input := []byte{
		0x08, 0x80, // chunk header (LE) = 0x8008
		0x00,                                           // flag byte: all literals
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', // 8 literals
	}

	out, err := DecompressLZNT1(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte("ABCDEFGH")
	if !bytes.Equal(out, expected) {
		t.Fatalf("expected %q, got %q", expected, out)
	}
}

// TestDecompressLZNT1_MixedChunks verifies a stream mixing uncompressed and
// compressed chunks.
func TestDecompressLZNT1_MixedChunks(t *testing.T) {
	// Uncompressed chunk: "Hello "
	chunk1 := buildUncompressedChunk([]byte("Hello "))

	// Compressed chunk encoding 8×'Z':
	//   flag=0x02, literal 'Z', backref 0x0004 (LE)
	//   length = (0x0004 & 0x0FFF) + 3 = 4+3 = 7
	//   offset = (0x0004 >> 12) + 1 = 1
	//   → 'Z' + 7×'Z' = 8×'Z'
	// data = flag(1) + literal(1) + ref(2) = 4 bytes
	// chunkHdr = 0x8000 | (4-1) = 0x8003
	chunk2 := []byte{
		0x03, 0x80,
		0x02, 'Z', 0x04, 0x00,
	}

	input := append(chunk1, chunk2...)
	out, err := DecompressLZNT1(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := append([]byte("Hello "), bytes.Repeat([]byte("Z"), 8)...)
	if !bytes.Equal(out, expected) {
		t.Fatalf("expected %q, got %q", expected, out)
	}
}

// TestDecompressLZNT1_BitSplitBoundaryPos16 exercises the threshold at pos=16.
// With the >= fix: j=4 at pos=16 (offsetBits=4, max encoded offset=16).
// With the old > bug: j=5 at pos=16 (offsetBits=5), misreads offset 15→31 and
// returns "offset 31 exceeds output length 16".
//
// Encoding: 16 literal bytes (A×16) then a back-reference referencing the
// first byte (offset=16) for length=3 at pos=16.
//   j=4: offsetBits=4, lengthBits=12.
//   offset_field = 16-1 = 15, length_field = 3-3 = 0.
//   ref = (15 << 12) | 0 = 0xF000  LE = [0x00, 0xF0].
// Expected output: A×19.
func TestDecompressLZNT1_BitSplitBoundaryPos16(t *testing.T) {
	// flag(1) + 8 lits + flag(1) + 8 lits + flag(1) + ref(2) = 21 bytes
	// chunkHdr = 0x8000 | (21-1) = 0x8014
	input := []byte{
		0x14, 0x80, // chunk header 0x8014
		0x00, 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', // 8 literals → pos=8
		0x00, 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', // 8 literals → pos=16
		0x01,       // flag: bit 0 = back-reference
		0x00, 0xF0, // ref 0xF000 LE: offset=(0xF000>>12)+1=16, length=(0&0xFFF)+3=3
	}
	out, err := DecompressLZNT1(input)
	if err != nil {
		t.Fatalf("unexpected error (possible >= threshold bug): %v", err)
	}
	expected := bytes.Repeat([]byte("A"), 19)
	if !bytes.Equal(out, expected) {
		t.Fatalf("expected A×19, got %q (len=%d)", out, len(out))
	}
}

// TestDecompressLZNT1_BitSplitBoundaryPos128 reproduces the exact production
// failure: "lznt1: back-reference offset 255 exceeds output length 128".
//
// After 128 bytes of output, j=7 (>= fix) gives offsetBits=7 (max offset=128).
// The old > bug uses j=8 (offsetBits=8), misreading the 7-bit offset field as
// 8 bits → offset=255 > 128.
//
// Encoding: 16 groups of 8 literals (= 128 bytes output) then a back-reference
// with ref = 0xFE00 (LE = [0x00, 0xFE]):
//   j=7: offset_field = 0xFE00 >> 9 = 127 → offset=128 (valid).
//          length_field = 0xFE00 & 0x1FF = 0 → length=3.
//   j=8 (buggy): offset_field = 0xFE00 >> 8 = 254 → offset=255 > 128 → error.
// Expected output: 128 bytes then 3 bytes from position 0 (first 3 literals).
func TestDecompressLZNT1_BitSplitBoundaryPos128(t *testing.T) {
	// 16 × (flag=0x00 + 8 literals) = 16 × 9 = 144 bytes of chunk data for the literals
	// then flag=0x01 + ref[0x00, 0xFE] = 3 more bytes
	// total chunk data = 147 bytes → chunkHdr = 0x8000 | (147-1) = 0x8092
	var chunkData []byte
	// 16 groups of 8 literals 'A'...'H' repeated
	literal8 := []byte("ABCDEFGH")
	for i := 0; i < 16; i++ {
		chunkData = append(chunkData, 0x00)    // flag: all literals
		chunkData = append(chunkData, literal8...) // 8 bytes
	}
	// back-reference group
	chunkData = append(chunkData, 0x01)       // flag: bit 0 = back-ref
	chunkData = append(chunkData, 0x00, 0xFE) // ref 0xFE00 LE

	var input []byte
	hdr := uint16(0x8000 | (len(chunkData) - 1))
	input = append(input, byte(hdr), byte(hdr>>8))
	input = append(input, chunkData...)

	out, err := DecompressLZNT1(input)
	if err != nil {
		t.Fatalf("unexpected error (possible >= threshold bug): %v", err)
	}
	// 128 literal bytes + 3 bytes copied from out[0:3] = "ABC"
	expected := bytes.Repeat(literal8, 16)
	expected = append(expected, 'A', 'B', 'C')
	if !bytes.Equal(out, expected) {
		t.Fatalf("expected 131 bytes, got len=%d; first mismatch check", len(out))
	}
}

// TestDecompressLZNT1_BackRefOffsetBitSplit verifies the variable bit-split for
// back-references at different output positions (tests j > 4 path).
//
// Encoding "AAAABBBBAAAABBBB" (16 bytes):
//   Produce output A×4 B×4 A×4 B×4.
//   One way: 4 literals (A,A,A,A, B,B,B,B) then two back-references of length 4 offset 8.
//   After 8 literals, pos=8 → j=4 (2^4=16>8), lengthBits=12, offsetBits=4.
//   Back-ref for 4 bytes offset 8:
//     length = 4 → ref & 0x0FFF = 1 (4-3=1)
//     offset = 8 → ref >> 12 = 7 (8-1=7)
//     ref = (7 << 12) | 1 = 0x7001
//   Second back-ref for 4 bytes offset 8 (pos now 12):
//     pos=12 → j=4 (16>12), same split
//     ref = 0x7001
//
//   Flag bytes:
//     Group 1: flag=0x00 → 8 literals (A,A,A,A,B,B,B,B)
//     Group 2: flag=0x03 → item 0 = back-ref 0x7001, item 1 = back-ref 0x7001
//
//   Chunk data = 1(flag)+8(lits) + 1(flag)+2(ref)+2(ref) = 14 bytes
//   chunkHdr = 0x8000 | (14-1) = 0x800D
func TestDecompressLZNT1_BackRefOffsetBitSplit(t *testing.T) {
	input := []byte{
		0x0D, 0x80, // chunk header 0x800D
		0x00,                               // flag: all literals
		'A', 'A', 'A', 'A', 'B', 'B', 'B', 'B', // 8 literals
		0x03,       // flag: bits 0 and 1 set = two back-references
		0x01, 0x70, // back-ref 0x7001 (LE): length=(1&0xFFF)+3=4, offset=(0x7001>>12)+1=8
		0x01, 0x70, // back-ref 0x7001 (LE): same
	}

	out, err := DecompressLZNT1(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte("AAAABBBBAAAABBBB")
	if !bytes.Equal(out, expected) {
		t.Fatalf("expected %q, got %q", expected, out)
	}
}
