package builder

import (
	"encoding/binary"
	"testing"

	"Havoc/pkg/handlers"
)

// minimalHTTPListener returns the smallest HTTP listener config that makes
// PatchConfig() succeed without a real network interface.
func minimalHTTPListener() *handlers.HTTP {
	return &handlers.HTTP{
		Config: handlers.HTTPConfig{
			PortBind:     "8080",
			KillDate:     0,
			WorkingHours: "",
			Methode:      "POST",
			HostRotation: "round-robin",
			Hosts:        []string{"127.0.0.1"},
			Uris:         []string{"/"},
			Headers:      []string{},
			UserAgent:    "Mozilla/5.0",
			Secure:       false,
		},
	}
}

// newHTTPTestBuilder creates a Builder wired to an HTTP listener for PatchConfig tests.
func newHTTPTestBuilder(cfg map[string]any) *Builder {
	bc := BuilderConfig{
		Compiler64: "/fake/x86_64-w64-mingw32-gcc",
		Compiler86: "/fake/i686-w64-mingw32-gcc",
		Nasm:       "/fake/nasm",
		SendLogs:   false,
	}
	b := NewBuilder(bc)
	b.SetSilent(true)
	b.SendConsoleMessage = func(_, _ string) {}
	b.SetArch(ARCHITECTURE_X64)
	b.SetFormat(FILETYPE_WINDOWS_EXE)
	b.SetListener(handlers.LISTENER_HTTP, minimalHTTPListener())
	b.config.Config = cfg
	return b
}

// minimalHTTPConfig returns a config map that passes all validation gates in
// PatchConfig() for an HTTP listener.
func minimalHTTPConfig() map[string]any {
	return map[string]any{
		"Sleep":  "5000",
		"Jitter": "0",
		"Indirect Syscall": false,
		"Injection": map[string]any{
			"Alloc":   "Win32",
			"Execute": "Win32",
			"Spawn64": "C:\\Windows\\System32\\notepad.exe",
			"Spawn32": "C:\\Windows\\SysWOW64\\notepad.exe",
		},
		"Sleep Technique":   "WaitForSingleObjectEx",
		"Sleep Jmp Gadget":  "jmp rax",
		"Stack Duplication": false,
		"Proxy Loading":     "None (LdrLoadDll)",
		"Amsi/Etw Patch":    "None",
	}
}

// lastInt32LE reads the last 4 bytes of b as a little-endian int32.
func lastInt32LE(b []byte) int32 {
	if len(b) < 4 {
		return -1
	}
	return int32(binary.LittleEndian.Uint32(b[len(b)-4:]))
}

// TestAutoProxyDetection_DefaultIsTrue verifies that when "Auto Proxy Detection"
// is absent from the config map, the default value (win32.TRUE = 1) is packed.
func TestAutoProxyDetection_DefaultIsTrue(t *testing.T) {
	cfg := minimalHTTPConfig()
	// do NOT set "Auto Proxy Detection" — should default to TRUE
	b := newHTTPTestBuilder(cfg)

	blob, err := b.PatchConfig()
	if err != nil {
		t.Fatalf("PatchConfig() error: %v", err)
	}

	got := lastInt32LE(blob)
	if got != 1 {
		t.Errorf("Auto Proxy Detection default: want 1 (TRUE), got %d", got)
	}
}

// TestAutoProxyDetection_ExplicitTrue verifies that setting "Auto Proxy Detection"
// to true packs win32.TRUE (1) as the last int32 in the HTTP config section.
func TestAutoProxyDetection_ExplicitTrue(t *testing.T) {
	cfg := minimalHTTPConfig()
	cfg["Auto Proxy Detection"] = true
	b := newHTTPTestBuilder(cfg)

	blob, err := b.PatchConfig()
	if err != nil {
		t.Fatalf("PatchConfig() error: %v", err)
	}

	got := lastInt32LE(blob)
	if got != 1 {
		t.Errorf("Auto Proxy Detection=true: want 1 (TRUE), got %d", got)
	}
}

// TestAutoProxyDetection_ExplicitFalse verifies that setting "Auto Proxy Detection"
// to false packs win32.FALSE (0) as the last int32 in the HTTP config section.
func TestAutoProxyDetection_ExplicitFalse(t *testing.T) {
	cfg := minimalHTTPConfig()
	cfg["Auto Proxy Detection"] = false
	b := newHTTPTestBuilder(cfg)

	blob, err := b.PatchConfig()
	if err != nil {
		t.Fatalf("PatchConfig() error: %v", err)
	}

	got := lastInt32LE(blob)
	if got != 0 {
		t.Errorf("Auto Proxy Detection=false: want 0 (FALSE), got %d", got)
	}
}

// TestAutoProxyDetection_TrueFalseBytesDiffer verifies that enabling vs disabling
// auto proxy detection produces blobs that differ in the last 4 bytes only.
func TestAutoProxyDetection_TrueFalseBytesDiffer(t *testing.T) {
	run := func(enabled bool) []byte {
		cfg := minimalHTTPConfig()
		cfg["Auto Proxy Detection"] = enabled
		b := newHTTPTestBuilder(cfg)
		blob, err := b.PatchConfig()
		if err != nil {
			t.Fatalf("PatchConfig(enabled=%v) error: %v", enabled, err)
		}
		return blob
	}

	blobTrue  := run(true)
	blobFalse := run(false)

	if len(blobTrue) != len(blobFalse) {
		t.Fatalf("blob length differs: true=%d false=%d", len(blobTrue), len(blobFalse))
	}
	n := len(blobTrue)
	if n < 4 {
		t.Fatal("blob too short to contain an int32")
	}

	// all bytes except the last 4 should be identical
	for i := 0; i < n-4; i++ {
		if blobTrue[i] != blobFalse[i] {
			t.Errorf("blobs differ at byte %d (before the auto proxy flag)", i)
		}
	}

	// last 4 bytes must differ
	trueFlag  := lastInt32LE(blobTrue)
	falseFlag := lastInt32LE(blobFalse)
	if trueFlag == falseFlag {
		t.Errorf("auto proxy flag did not differ: both = %d", trueFlag)
	}
}
