package handlers

import (
	"strings"
	"testing"
)

// buildIgnoreList mirrors the logic in http.go: always skip the two
// hop-by-hop headers, then append any operator-configured extras.
func buildIgnoreList(configIgnore []string) []string {
	return append([]string{"Connection", "Accept-Encoding"}, configIgnore...)
}

// isIgnored returns true when headerName matches any entry in the ignore list
// (case-insensitive), mirroring the loop in ServeDNS/http.go.
func isIgnored(headerName string, ignoreList []string) bool {
	for _, ig := range ignoreList {
		if strings.ToLower(headerName) == strings.ToLower(ig) {
			return true
		}
	}
	return false
}

// TestIgnoreHeadersMerge verifies that the merged list always contains the
// two built-in defaults plus any caller-supplied extras.
func TestIgnoreHeadersMerge(t *testing.T) {
	cases := []struct {
		name          string
		configIgnore  []string
		expectIgnored []string
		expectChecked []string
	}{
		{
			name:          "no extras — defaults only",
			configIgnore:  nil,
			expectIgnored: []string{"Connection", "Accept-Encoding", "connection", "ACCEPT-ENCODING"},
			expectChecked: []string{"Accept-Language", "X-Custom"},
		},
		{
			name:          "CDN strips Accept-Language",
			configIgnore:  []string{"Accept-Language"},
			expectIgnored: []string{"Connection", "Accept-Encoding", "Accept-Language", "accept-language"},
			expectChecked: []string{"X-Custom", "Host"},
		},
		{
			name: "full Cloudfront header set",
			configIgnore: []string{
				"Accept-Language",
				"Sec-Fetch-Dest",
				"Sec-Fetch-Mode",
				"Sec-Fetch-Site",
				"Sec-Fetch-User",
				"Upgrade-Insecure-Requests",
			},
			expectIgnored: []string{
				"Connection", "Accept-Encoding",
				"Accept-Language", "Sec-Fetch-Dest", "sec-fetch-mode",
				"SEC-FETCH-SITE", "Upgrade-Insecure-Requests",
			},
			expectChecked: []string{"Host", "X-Forwarded-For"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := buildIgnoreList(tc.configIgnore)

			for _, h := range tc.expectIgnored {
				if !isIgnored(h, list) {
					t.Errorf("expected %q to be ignored but it was not (list=%v)", h, list)
				}
			}
			for _, h := range tc.expectChecked {
				if isIgnored(h, list) {
					t.Errorf("expected %q to be checked but it was in ignore list (list=%v)", h, list)
				}
			}
		})
	}
}

// TestIgnoreHeadersFilter verifies that the filter correctly classifies
// profile headers as "skip validation" or "validate" depending on the
// ignore list.
func TestIgnoreHeadersFilter(t *testing.T) {
	profileHeaders := []string{
		"Host: example.com",
		"Connection: keep-alive",
		"Accept-Encoding: gzip, deflate, br",
		"Accept-Language: en-US,en;q=0.9",
		"X-Custom: secret",
	}

	type result struct {
		header  string
		ignored bool
	}

	// No extras: Connection and Accept-Encoding ignored, rest validated.
	ignoreList := buildIgnoreList(nil)
	expected := []result{
		{"Host", false},
		{"Connection", true},
		{"Accept-Encoding", true},
		{"Accept-Language", false},
		{"X-Custom", false},
	}

	for i, hdr := range profileHeaders {
		nameValue := strings.SplitN(hdr, ": ", 2)
		name := nameValue[0]
		got := isIgnored(name, ignoreList)
		if got != expected[i].ignored {
			t.Errorf("header %q: want ignored=%v got ignored=%v", name, expected[i].ignored, got)
		}
	}

	// With Accept-Language added to config ignore list.
	ignoreList2 := buildIgnoreList([]string{"Accept-Language"})
	expected2 := []result{
		{"Host", false},
		{"Connection", true},
		{"Accept-Encoding", true},
		{"Accept-Language", true},
		{"X-Custom", false},
	}

	for i, hdr := range profileHeaders {
		nameValue := strings.SplitN(hdr, ": ", 2)
		name := nameValue[0]
		got := isIgnored(name, ignoreList2)
		if got != expected2[i].ignored {
			t.Errorf("(with IgnoreHeaders) header %q: want ignored=%v got ignored=%v",
				name, expected2[i].ignored, got)
		}
	}
}
