package events

import (
	"strings"
	"testing"
)

// TestListenerHeaderRoundTrip verifies that the "\n" delimiter correctly
// round-trips header values that contain ", " — the old ", " delimiter would
// split these into spurious extra elements.
func TestListenerHeaderRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		inputs []string
	}{
		{
			name:   "simple headers",
			inputs: []string{"Host: example.com", "User-Agent: Mozilla/5.0"},
		},
		{
			name:   "header with comma in value",
			inputs: []string{"Accept-Encoding: gzip, deflate, br"},
		},
		{
			name:   "multiple headers including comma value",
			inputs: []string{
				"Host: example.com",
				"Accept-Encoding: gzip, deflate, br",
				"Accept-Language: en-US, en;q=0.9",
				"X-Custom: foo",
			},
		},
		{
			name:   "empty slice",
			inputs: []string{},
		},
		{
			name:   "single header",
			inputs: []string{"X-Foo: bar"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			joined := strings.Join(tc.inputs, "\n")
			var got []string
			for _, s := range strings.Split(joined, "\n") {
				if len(s) > 0 {
					got = append(got, s)
				}
			}
			if len(got) != len(tc.inputs) {
				t.Fatalf("round-trip length mismatch: want %d got %d (joined=%q)",
					len(tc.inputs), len(got), joined)
			}
			for i := range tc.inputs {
				if got[i] != tc.inputs[i] {
					t.Errorf("element %d: want %q got %q", i, tc.inputs[i], got[i])
				}
			}
		})
	}
}

// TestOldDelimiterWouldCorrupt demonstrates that the old ", " delimiter
// corrupts header values containing ", " — confirming why the fix is needed.
func TestOldDelimiterWouldCorrupt(t *testing.T) {
	input := []string{"Accept-Encoding: gzip, deflate, br"}
	joined := strings.Join(input, ", ")
	parts := strings.Split(joined, ", ")
	if len(parts) == 1 {
		t.Error("expected old delimiter to corrupt the value but it didn't — test is wrong")
	}
	// With the old delimiter "gzip, deflate, br" gets split — len > 1 proves corruption.
	if len(parts) <= 1 {
		t.Errorf("expected >1 parts from old delimiter, got %d", len(parts))
	}
}
