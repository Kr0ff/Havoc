package crypt

// [HVC-007 2026-03-28] LZNT1 decompressor for Demon → teamserver packets.
//
// The Demon compresses its payload with Windows RtlCompressBuffer using
// COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_STANDARD before AES encryption.
// The teamserver decompresses after AES decryption with DecompressLZNT1.
//
// LZNT1 format (per Microsoft):
//   - Data is a sequence of variable-length chunks.
//   - Each chunk begins with a 2-byte LE header:
//       Bit 15 (0x8000) — set if chunk is compressed.
//       Bits 11:0       — (chunk_data_size - 1), so actual data bytes = (hdr & 0x0FFF) + 1.
//     A header of 0x0000 signals end of stream.
//   - Uncompressed chunk: header || raw bytes.
//   - Compressed chunk: header || groups of (flag_byte, items...).
//       Each flag byte encodes 8 items LSB-first:
//         bit = 0 → next byte is a literal.
//         bit = 1 → next 2 bytes (LE) are a back-reference.
//       Back-reference encoding:
//         The bit-split between offset and length fields changes with the current
//         output position `pos` within the chunk (0-indexed):
//           Find the smallest j in [4,12] such that 2^j > pos.
//           lengthBits = 16 - j   (# bits for length field)
//           offsetBits = j        (# bits for offset field)
//         Decode:
//           length = (ref & ((1<<lengthBits)-1)) + 3
//           offset = (ref >> lengthBits) + 1  (1-based, measured from end of output)
//
// See TrafficImprovements.md §7.

import (
	"encoding/binary"
	"fmt"
)

// DecompressLZNT1 decompresses an LZNT1-compressed byte slice produced by
// Windows RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1).
// Returns the decompressed data or a non-nil error on malformed input.
func DecompressLZNT1(data []byte) ([]byte, error) {
	var out []byte
	i := 0

	for i < len(data) {
		if i+2 > len(data) {
			break // trailing padding is allowed
		}
		chunkHdr := binary.LittleEndian.Uint16(data[i:])
		i += 2
		if chunkHdr == 0 {
			break // end-of-stream sentinel
		}

		chunkSize := int(chunkHdr&0x0FFF) + 1
		isCompressed := (chunkHdr & 0x8000) != 0

		if i+chunkSize > len(data) {
			chunkSize = len(data) - i // truncated final chunk — decompress what we have
		}
		chunkData := data[i : i+chunkSize]
		i += chunkSize

		if isCompressed {
			dec, err := lznt1DecompressChunk(chunkData)
			if err != nil {
				return nil, err
			}
			out = append(out, dec...)
		} else {
			out = append(out, chunkData...)
		}
	}

	return out, nil
}

// lznt1DecompressChunk decompresses a single LZNT1 compressed chunk.
func lznt1DecompressChunk(data []byte) ([]byte, error) {
	var out []byte
	i := 0

	for i < len(data) {
		flags := data[i]
		i++

		for bit := 0; bit < 8 && i < len(data); bit++ {
			if flags&(1<<uint(bit)) != 0 {
				// back-reference: 2-byte LE value
				if i+2 > len(data) {
					return nil, fmt.Errorf("lznt1: truncated back-reference at byte %d", i)
				}
				ref := int(binary.LittleEndian.Uint16(data[i:]))
				i += 2

				// Compute bit-split based on current output position.
				// Per MS-XCA §2.6.1.2 COPY_TOKEN_HELP: find smallest j in [4,12]
				// such that 2^j >= pos (note >=, not >).  This matches the Windows
				// encoder: a 4-bit offset field can represent offsets 1..16 (== 2^4),
				// so the threshold is inclusive.  Using > here mis-selects j=8 at
				// pos=128 (where j=7 is correct), causing an 8-bit offset decode on
				// Windows 7-bit-encoded data → "offset 255 exceeds output length 128".
				pos := len(out)
				lengthBits := 12 // default for pos in [0, 16] (j = 4)
				for j := 4; j <= 12; j++ {
					if 1<<j >= pos {
						lengthBits = 16 - j
						break
					}
				}
				lengthMask := (1 << uint(lengthBits)) - 1
				length := (ref & lengthMask) + 3
				offset := (ref >> uint(lengthBits)) + 1

				if offset > len(out) {
					return nil, fmt.Errorf("lznt1: back-reference offset %d exceeds output length %d", offset, len(out))
				}
				// Copy byte-by-byte to handle overlapping runs correctly.
				for k := 0; k < length; k++ {
					out = append(out, out[len(out)-offset])
				}
			} else {
				// literal byte
				out = append(out, data[i])
				i++
			}
		}
	}

	return out, nil
}
