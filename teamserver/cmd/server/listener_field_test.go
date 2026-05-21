package server

import (
	"testing"
)

// TestSplitListenerFieldNewFormat verifies the new "\n" delimiter is split correctly.
//
// Key invariant: when two or more headers are joined with "\n", even if any
// header VALUE contains ", ", the round-trip is lossless.  The single-element
// edge case (one header whose value contains ", ") is inherently ambiguous
// because join of a one-element slice produces no delimiter — that limitation
// pre-dates this fix and is not addressed here.
func TestSplitListenerFieldNewFormat(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{
			input: "Host: example.com\nUser-Agent: Go",
			want:  []string{"Host: example.com", "User-Agent: Go"},
		},
		{
			// Multi-host with new delimiter.
			input: "10.0.0.1\n10.0.0.2",
			want:  []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			// Multiple headers; the critical case — Accept-Encoding value contains ", "
			// and must not be split when other headers are also present.
			input: "Host: example.com\nAccept-Encoding: gzip, deflate, br\nX-Custom: foo",
			want:  []string{"Host: example.com", "Accept-Encoding: gzip, deflate, br", "X-Custom: foo"},
		},
	}

	for _, tc := range cases {
		got := splitListenerField(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("input=%q: want %d elements got %d (%v)", tc.input, len(tc.want), len(got), got)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("input=%q element[%d]: want %q got %q", tc.input, i, tc.want[i], got[i])
			}
		}
	}
}

// TestSplitListenerFieldLegacyFormat verifies backward compatibility: legacy
// DB entries stored with ", " delimiter are still split correctly.
func TestSplitListenerFieldLegacyFormat(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{
			// Two simple headers, old format.
			input: "Host: example.com, User-Agent: Go",
			want:  []string{"Host: example.com", "User-Agent: Go"},
		},
		{
			// Single host, no delimiter.
			input: "10.0.0.1",
			want:  []string{"10.0.0.1"},
		},
		{
			// Multiple IPs, old format.
			input: "10.0.0.1, 10.0.0.2",
			want:  []string{"10.0.0.1", "10.0.0.2"},
		},
	}

	for _, tc := range cases {
		got := splitListenerField(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("input=%q: want %d elements got %d (%v)", tc.input, len(tc.want), len(got), got)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("input=%q element[%d]: want %q got %q", tc.input, i, tc.want[i], got[i])
			}
		}
	}
}
