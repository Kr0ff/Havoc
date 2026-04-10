package builder

import (
	"strings"
	"testing"

	"Havoc/pkg/handlers"
)

// minimalConfig returns the smallest config map that makes PatchConfig() succeed
// for every beacon format (SMB listener is used because it has no host/port parsing).
func minimalConfig() map[string]any {
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
		"Sleep Jmp Gadget":  "jmp rax", // must be non-empty; ignored when Sleep Technique == WaitForSingleObjectEx
		"Stack Duplication": false,
		"Proxy Loading":     "None (LdrLoadDll)",
		"Amsi/Etw Patch":    "None",
	}
}

// smbListener returns a minimal SMB listener (simpler than HTTP: no port/host parsing).
func smbListener() *handlers.SMB {
	return &handlers.SMB{
		Config: handlers.SMBConfig{
			PipeName:     "testpipe",
			KillDate:     0,
			WorkingHours: "",
		},
	}
}

// newTestBuilder creates a Builder pre-wired for unit tests:
//   - fake compiler paths (no real MinGW required)
//   - SMB listener with minimal config
//   - silent mode so untested console messages don't panic
//   - no-op SendConsoleMessage
//   - testCmdRunner set to the provided function
func newTestBuilder(arch, format int, runner func(string) (bool, string)) *Builder {
	cfg := BuilderConfig{
		Compiler64: "/fake/x86_64-w64-mingw32-gcc",
		Compiler86: "/fake/i686-w64-mingw32-gcc",
		Nasm:       "/fake/nasm",
		DebugDev:   false,
		SendLogs:   false,
	}
	b := NewBuilder(cfg)
	b.SetSilent(true)
	b.SendConsoleMessage = func(_, _ string) {}
	b.SetArch(arch)
	b.SetFormat(format)
	b.SetListener(handlers.LISTENER_PIVOT_SMB, smbListener())
	b.config.Config = minimalConfig()
	b.testCmdRunner = runner
	return b
}

// captureRunner returns a testCmdRunner that records the last command it receives
// and always reports success.
func captureRunner(last *string) func(string) (bool, string) {
	return func(cmd string) (bool, string) {
		*last = cmd
		return true, ""
	}
}

// ── EXE (x64) ───────────────────────────────────────────────────────────────

// TestBuildExeX64_EntryPoint verifies that an x64 EXE uses -e WinMain and
// includes the EXE main source file.
func TestBuildExeX64_EntryPoint(t *testing.T) {
	var captured string
	b := newTestBuilder(ARCHITECTURE_X64, FILETYPE_WINDOWS_EXE, captureRunner(&captured))

	ok := b.Build()
	if !ok {
		t.Fatal("Build() returned false for EXE x64")
	}
	if !strings.Contains(captured, "-e WinMain") {
		t.Errorf("EXE x64: expected '-e WinMain' in compile command, got:\n%s", captured)
	}
	if strings.Contains(captured, "-e _WinMain") {
		t.Errorf("EXE x64: unexpected '-e _WinMain' (x86 entry point) in compile command")
	}
	if !strings.Contains(captured, "MainExe.c") {
		t.Errorf("EXE x64: expected 'MainExe.c' in compile command, got:\n%s", captured)
	}
	if strings.Contains(captured, "-shared") {
		t.Errorf("EXE x64: unexpected '-shared' flag in EXE compile command")
	}
}

// ── EXE (x86) ───────────────────────────────────────────────────────────────

// TestBuildExeX86_EntryPoint verifies that an x86 EXE uses -e _WinMain (stdcall
// decoration) and includes the EXE main source file.
func TestBuildExeX86_EntryPoint(t *testing.T) {
	var captured string
	b := newTestBuilder(ARCHITECTURE_X86, FILETYPE_WINDOWS_EXE, captureRunner(&captured))

	ok := b.Build()
	if !ok {
		t.Fatal("Build() returned false for EXE x86")
	}
	if !strings.Contains(captured, "-e _WinMain") {
		t.Errorf("EXE x86: expected '-e _WinMain' in compile command, got:\n%s", captured)
	}
	if strings.Contains(captured, "-e WinMain ") {
		// "-e WinMain " (with trailing space) to avoid matching "-e _WinMain"
		t.Errorf("EXE x86: unexpected '-e WinMain' (x64 entry point) in compile command")
	}
	if !strings.Contains(captured, "MainExe.c") {
		t.Errorf("EXE x86: expected 'MainExe.c' in compile command, got:\n%s", captured)
	}
}

// ── Service EXE (x64) ───────────────────────────────────────────────────────

// TestBuildServiceExeX64_Flags verifies that a service EXE includes the
// SVC_EXE define, the ntdll link flag, the advapi32 import, and the service
// main source file.
func TestBuildServiceExeX64_Flags(t *testing.T) {
	var captured string
	b := newTestBuilder(ARCHITECTURE_X64, FILETYPE_WINDOWS_SERVICE_EXE, captureRunner(&captured))
	// Service name must be present for service format
	cfg := minimalConfig()
	cfg["Service Name"] = "TestSvc"
	b.config.Config = cfg

	ok := b.Build()
	if !ok {
		t.Fatal("Build() returned false for Service EXE x64")
	}
	for _, want := range []string{"-D SVC_EXE", "-lntdll", "MainSvc.c"} {
		if !strings.Contains(captured, want) {
			t.Errorf("Service EXE x64: expected %q in compile command, got:\n%s", want, captured)
		}
	}
	if strings.Contains(captured, "-shared") {
		t.Errorf("Service EXE x64: unexpected '-shared' flag")
	}
}

// TestBuildServiceExeX86_Flags verifies the x86 service EXE uses _WinMain.
func TestBuildServiceExeX86_Flags(t *testing.T) {
	var captured string
	b := newTestBuilder(ARCHITECTURE_X86, FILETYPE_WINDOWS_SERVICE_EXE, captureRunner(&captured))
	cfg := minimalConfig()
	cfg["Service Name"] = "TestSvc"
	b.config.Config = cfg

	ok := b.Build()
	if !ok {
		t.Fatal("Build() returned false for Service EXE x86")
	}
	if !strings.Contains(captured, "-e _WinMain") {
		t.Errorf("Service EXE x86: expected '-e _WinMain', got:\n%s", captured)
	}
}

// ── DLL (x64) ───────────────────────────────────────────────────────────────

// TestBuildDllX64_SharedFlag verifies that a DLL build uses -shared and the
// DLL entry point -e DllMain, not an EXE entry point.
func TestBuildDllX64_SharedFlag(t *testing.T) {
	var captured string
	b := newTestBuilder(ARCHITECTURE_X64, FILETYPE_WINDOWS_DLL, captureRunner(&captured))

	ok := b.Build()
	if !ok {
		t.Fatal("Build() returned false for DLL x64")
	}
	if !strings.Contains(captured, "-shared") {
		t.Errorf("DLL x64: expected '-shared' in compile command, got:\n%s", captured)
	}
	if !strings.Contains(captured, "-e DllMain") {
		t.Errorf("DLL x64: expected '-e DllMain' in compile command, got:\n%s", captured)
	}
	if strings.Contains(captured, "WinMain") {
		t.Errorf("DLL x64: unexpected WinMain entry point in DLL compile command")
	}
	if !strings.Contains(captured, "MainDll.c") {
		t.Errorf("DLL x64: expected 'MainDll.c' in compile command, got:\n%s", captured)
	}
}

// TestBuildDllX86_SharedFlag verifies the x86 DLL uses -e _DllMain.
func TestBuildDllX86_SharedFlag(t *testing.T) {
	var captured string
	b := newTestBuilder(ARCHITECTURE_X86, FILETYPE_WINDOWS_DLL, captureRunner(&captured))

	ok := b.Build()
	if !ok {
		t.Fatal("Build() returned false for DLL x86")
	}
	if !strings.Contains(captured, "-shared") {
		t.Errorf("DLL x86: expected '-shared' in compile command, got:\n%s", captured)
	}
	if !strings.Contains(captured, "-e _DllMain") {
		t.Errorf("DLL x86: expected '-e _DllMain' in compile command, got:\n%s", captured)
	}
}

// ── Shellcode / Raw Binary ───────────────────────────────────────────────────

// TestBuildShellcode_InnerDllFailReturnsImmediately verifies the fallthrough fix:
// when the inner DLL compilation fails, Build() returns false immediately and
// does NOT continue to run the outer compile command (which would cause an
// "undefined reference to WinMain" linker error).
func TestBuildShellcode_InnerDllFailReturnsImmediately(t *testing.T) {
	// outerCalled is set to true if the outer testCmdRunner is ever invoked,
	// which would mean the code fell through to the outer CompileCmd call.
	outerCalled := false
	b := newTestBuilder(ARCHITECTURE_X64, FILETYPE_WINDOWS_RAW_BINARY,
		func(cmd string) (bool, string) {
			outerCalled = true
			return true, ""
		})

	// Inner builder gets no testCmdRunner, so Cmd() calls exec.Command with
	// the fake compiler path — fails immediately with "no such file or directory".
	// The inner Build() returns false.
	ok := b.Build()
	if ok {
		t.Error("Build() should return false when inner DLL compilation fails")
	}
	if outerCalled {
		t.Error("outer compile command was executed after inner DLL failure — fallthrough bug not fixed")
	}
}

// TestBuildShellcode_InnerDllUsesSharedFlag verifies that the inner DLL builder
// (created inside the shellcode case) compiles with -shared and -e DllMain.
func TestBuildShellcode_InnerDllUsesSharedFlag(t *testing.T) {
	var innerCmd string
	b := newTestBuilder(ARCHITECTURE_X64, FILETYPE_WINDOWS_RAW_BINARY, nil)
	// The outer testCmdRunner is not used for shellcode (returns before CompileCmd).
	// Capture the inner builder's compile command via innerBuilderSetup.
	b.innerBuilderSetup = func(inner *Builder) {
		inner.testCmdRunner = func(cmd string) (bool, string) {
			innerCmd = cmd
			return false, "test: skip shellcode template read"
		}
	}

	// Build returns false because inner testCmdRunner returns false (no template file).
	// We only care about what the inner compile command looked like.
	b.Build()

	if innerCmd == "" {
		t.Fatal("inner DLL compiler was never invoked")
	}
	if !strings.Contains(innerCmd, "-shared") {
		t.Errorf("inner DLL: expected '-shared', got:\n%s", innerCmd)
	}
	if !strings.Contains(innerCmd, "-e DllMain") {
		t.Errorf("inner DLL: expected '-e DllMain', got:\n%s", innerCmd)
	}
	if strings.Contains(innerCmd, "WinMain") {
		t.Errorf("inner DLL: unexpected WinMain in inner DLL compile command")
	}
}

// TestBuildShellcode_RSAKeyPropagatedToInnerBuilder verifies that when a RSA
// public key blob is set on the outer builder, it is propagated to the inner DLL
// builder before that builder's Build() runs.  Without this propagation the
// Demon compilation fails because SERVER_PUBKEY_BLOB is undefined.
func TestBuildShellcode_RSAKeyPropagatedToInnerBuilder(t *testing.T) {
	fakeKey := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	var innerKeyBlob []byte

	b := newTestBuilder(ARCHITECTURE_X64, FILETYPE_WINDOWS_RAW_BINARY, nil)
	b.SetRSAPublicKey(fakeKey)
	b.innerBuilderSetup = func(inner *Builder) {
		innerKeyBlob = inner.rsaPublicKeyBlob
		// Abort inner build (no real compiler needed for this test).
		inner.testCmdRunner = func(cmd string) (bool, string) {
			return false, "test: RSA propagation check only"
		}
	}

	b.Build()

	if len(innerKeyBlob) == 0 {
		t.Fatal("RSA public key blob was NOT propagated to the inner DLL builder")
	}
	if string(innerKeyBlob) != string(fakeKey) {
		t.Errorf("RSA key mismatch: outer=%x inner=%x", fakeKey, innerKeyBlob)
	}
}

// TestBuildShellcode_ShellcodeDefineSetOnInnerBuilder verifies that the inner DLL
// builder has the SHELLCODE preprocessor define added before compilation.  This
// define gates shellcode-specific code paths in Demon.c.
func TestBuildShellcode_ShellcodeDefineSetOnInnerBuilder(t *testing.T) {
	var innerCmd string
	b := newTestBuilder(ARCHITECTURE_X64, FILETYPE_WINDOWS_RAW_BINARY, nil)
	b.innerBuilderSetup = func(inner *Builder) {
		inner.testCmdRunner = func(cmd string) (bool, string) {
			innerCmd = cmd
			return false, "test: SHELLCODE define check"
		}
	}

	b.Build()

	if !strings.Contains(innerCmd, "-DSHELLCODE") {
		t.Errorf("inner DLL: expected '-DSHELLCODE' define, got:\n%s", innerCmd)
	}
}
