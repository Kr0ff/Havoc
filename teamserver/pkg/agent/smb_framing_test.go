package agent

// [HVC-008 2026-03-28] Unit tests for SMB pipe framing obfuscation.
//
// The parent Demon XORs [DemonID][PackageSize] with HEADER_MASK_SEED-derived
// masks before writing them to the child's named pipe. The child Demon
// unmasks with the same constants in SmbRecv. These tests verify the
// round-trip property and that the Go constant matches the C constant.

import "testing"

// TestSmbFramingConstant verifies HeaderMaskSeed matches the C compile-time
// constant HEADER_MASK_SEED (0xA3F1C2B4) defined in Defines.h.
func TestSmbFramingConstant(t *testing.T) {
	const expected uint32 = 0xA3F1C2B4
	if HeaderMaskSeed != expected {
		t.Errorf("HeaderMaskSeed = 0x%08X, want 0x%08X", HeaderMaskSeed, expected)
	}
}

// TestSmbFramingRoundTrip verifies that masking then unmasking recovers the
// original DemonID and PackageSize values.
func TestSmbFramingRoundTrip(t *testing.T) {
	cases := []struct {
		demonID uint32
		pkgSize uint32
	}{
		{0x00000001, 0x00000001},
		{0xDEADBEEF, 1024},
		{0xCAFEBABE, 65536},
		{0x00000000, 0x00000000},
		{0xFFFFFFFF, 0xFFFFFFFF},
		{HeaderMaskSeed, HeaderMaskSeed >> 8},
	}

	idMask   := uint32(HeaderMaskSeed)
	sizeMask := uint32(HeaderMaskSeed) >> 8

	for _, c := range cases {
		maskedID   := c.demonID ^ idMask
		maskedSize := c.pkgSize ^ sizeMask

		recoveredID   := maskedID ^ idMask
		recoveredSize := maskedSize ^ sizeMask

		if recoveredID != c.demonID {
			t.Errorf("demonID round-trip failed: got 0x%08X, want 0x%08X", recoveredID, c.demonID)
		}
		if recoveredSize != c.pkgSize {
			t.Errorf("pkgSize round-trip failed: got 0x%08X, want 0x%08X", recoveredSize, c.pkgSize)
		}
	}
}

// TestSmbFramingMaskChangesValue verifies that masking actually changes the
// values (i.e., HEADER_MASK_SEED is non-zero on both mask positions).
func TestSmbFramingMaskChangesValue(t *testing.T) {
	// The identity mask would mean a zero constant — catch that.
	if HeaderMaskSeed == 0 {
		t.Fatal("HeaderMaskSeed must not be zero")
	}
	if (HeaderMaskSeed >> 8) == 0 {
		t.Fatal("HeaderMaskSeed >> 8 must not be zero")
	}

	demonID := uint32(0x12345678)
	pkgSize := uint32(0xABCDEF01)

	if demonID^HeaderMaskSeed == demonID {
		t.Error("masking DemonID with HEADER_MASK_SEED produced no change")
	}
	if pkgSize^(HeaderMaskSeed>>8) == pkgSize {
		t.Error("masking PackageSize with HEADER_MASK_SEED>>8 produced no change")
	}
}

// TestSmbFramingIDandSizeMaskDiffer verifies the two masks are different so
// the same plaintext in both fields produces different ciphertext.
func TestSmbFramingIDandSizeMaskDiffer(t *testing.T) {
	if HeaderMaskSeed == HeaderMaskSeed>>8 {
		t.Error("DemonID mask and PackageSize mask are identical; they should differ")
	}
}
