# Client Reference

Authoritative technical reference for the Havoc client component. Read this before working on any code under `client/`. Covers startup, connection flow, global state, the package protocol, command dispatch, output handling, the payload generator, UI widgets, and Python scripting integration.

---

## Source Layout

```
client/
├── CMakeLists.txt
├── include/
│   ├── External.h             # External library forward declarations
│   ├── global.hpp             # All shared types, HavocX:: globals, namespace forward decls
│   ├── Havoc/
│   │   ├── Havoc.hpp          # Havoc class declaration
│   │   ├── Connector.hpp      # Connector class (WebSocket to teamserver)
│   │   ├── Packager.hpp       # Packager class + all event type constants
│   │   ├── Service.hpp        # ServiceAgent, AgentCommands, CommandParam structs
│   │   ├── DemonCmdDispatch.h # Commands enum, DemonCommands, CommandExecute, DispatchOutput
│   │   ├── CmdLine.hpp        # CLI argument parser
│   │   ├── DBManager/DBManager.hpp
│   │   └── PythonApi/         # Python embedding headers
│   ├── UserInterface/
│   │   ├── HavocUI.hpp        # HavocUi main window class
│   │   ├── Dialogs/           # Connect, Listener, Payload, About dialogs
│   │   ├── Widgets/           # SessionTable, DemonInteracted, ListenersTable, etc.
│   │   └── SmallWidgets/      # EventViewer
│   └── Util/
│       ├── Base.hpp           # FileRead, CurrentTime, MessageBox helpers
│       ├── Base64.h
│       └── ColorText.h
├── src/
│   ├── Main.cc                # Entry point
│   ├── global.cc              # HavocX:: global definitions
│   ├── Havoc/
│   │   ├── Havoc.cc           # Havoc::Init, Start, Exit
│   │   ├── Connector.cc       # WebSocket setup + SendLogin + SendPackage
│   │   ├── Packager.cc        # Decode/Encode/Dispatch + all event type constant values
│   │   ├── Service.cc         # DemonMagicValue definition
│   │   ├── DBManger/          # SQLite connection profile persistence
│   │   └── Demon/
│   │       ├── Commands.cc    # DemonCommandList static definition (all built-in commands)
│   │       ├── CommandSend.cc # CommandExecute::* methods — build + send packages
│   │       ├── CommandOutput.cc # DispatchOutput::MessageOutput — render output
│   │       └── ConsoleInput.cc  # DemonCommands::DispatchCommand, ParseCommandLine
│   └── UserInterface/
│       ├── HavocUi.cc
│       ├── Dialogs/           # Connect, Listener, Payload, About
│       └── Widgets/           # All widget implementations
├── external/
│   ├── json/                  # nlohmann/json
│   ├── spdlog/                # logging
│   └── toml/                  # TOML config parser
└── data/
    ├── img/                   # Icons
    ├── stylesheets/           # Qt stylesheets (Dracula-themed)
    ├── themes/
    └── UIs/                   # .ui form files
```

---

## Key Types

### Global State (`HavocX::` namespace, defined in `src/global.cc`)

```cpp
namespace HavocX {
    bool                                    DebugMode;
    bool                                    GateGUI;       // true while payload dialog is awaiting build
    PyObject*                               callbackGate;  // Python callback for payload
    PyObject*                               callbackMessage; // Python callback for command output
    HavocNamespace::Util::ConnectionInfo    Teamserver;    // central state
    HavocNamespace::UserInterface::HavocUi* HavocUserInterface;
    HavocNamespace::Connector*              Connector;
}
```

`HavocX::Teamserver` is the single global `ConnectionInfo` instance that holds all runtime state.

### `Util::ConnectionInfo` (`include/global.hpp`)

```cpp
typedef struct {
    QString Name;     // profile name
    QString Host;     // teamserver hostname
    QString Port;     // teamserver port
    QString User;     // operator username
    QString Password; // operator password (cleartext, hashed before send)

    std::vector<ListenerItem>      Listeners;           // active listeners
    std::vector<json>              RegisteredListeners;  // service-registered listener types
    std::vector<SessionItem>       Sessions;            // active agent sessions
    std::vector<RegisteredCommand> RegisteredCommands;  // python-registered commands
    std::vector<RegisteredModule>  RegisteredModules;
    std::vector<PyObject*>         RegisteredCallbacks; // python new-session callbacks
    std::vector<ServiceAgent>      ServiceAgents;       // 3rd-party agents

    QStringList   AddedCommands;   // command names added via Python API
    QJsonDocument DemonConfig;     // Demon config from teamserver (profile)
    QStringList   IpAddresses;     // teamserver IP addresses
    std::string   LoadingScript;   // script currently being loaded

    UserInterface::Widgets::TeamserverTabSession* TabSession;
} ConnectionInfo;
```

### `Util::SessionItem` (`include/global.hpp`)

Per-agent runtime state:

```cpp
typedef struct {
    QString TeamserverID;
    QString Name;           // hex AgentID, e.g. "deadbeef"
    u64     MagicValue;     // 0xDEADBEEF for Demon; custom value for service agents
    QString External;       // external IP
    QString Internal;       // internal IP
    QString Listener;
    QString User;           // username@domain
    QString Computer;       // hostname
    QString Domain;
    QString OS, OSBuild, OSArch;
    QString Process, PID;
    QString Arch;
    QString First, Last;    // first/last check-in timestamp strings (server UTC, "dd-MM-yyyy HH:mm:ss")
    QDateTime LastUTC;      // Qt::UTC QDateTime used by UpdateSessionsHealth for elapsed-time display.
                            // Initial load (DB restore): parsed from Last with setTimeSpec(Qt::UTC).
                            // Live CALLBACK event: set to QDateTime::currentDateTimeUtc() at receipt,
                            // bypassing CDN transit latency on the Demon→server path.
    QString Elevated;       // "true"/"false"
    QString PivotParent;    // parent AgentID if SMB pivot
    QString Marked;         // "Alive" | "Dead"
    QString Health;         // "healthy" | "dead"
    u32     SleepDelay, SleepJitter;
    u64     KillDate;
    u32     WorkingHours;

    UserInterface::Widgets::DemonInteracted* InteractedWidget;
    UserInterface::Widgets::ProcessList*     ProcessList;
    FileBrowser*                             FileBrowser;

    std::map<QString, PyObject*> TaskIDToPythonCallbacks;
} SessionItem;
```

### `Util::Packager::Package` (`include/Havoc/Packager.hpp`)

Client-side mirror of the server's `packager.Package`:

```cpp
typedef struct {
    int    Event;
    string User;
    string Time;
    string OneTime;
} Head_t;

typedef struct {
    int                    SubEvent;
    QMap<string, string>   Info;    // flat string→string map
} Body_t;

typedef struct Package {
    Head_t Head;
    Body_t Body;
} Package, *PPackage;
```

**Note:** `Body_t::Info` uses `QMap<string, string>` — all values are strings. Binary payloads are base64-encoded before insertion.

### `ServiceAgent` (`include/Havoc/Service.hpp`)

```cpp
typedef struct {
    QString                    Name;
    QString                    Description;
    QString                    Version;
    QString                    Author;
    uint64_t                   MagicValue;   // identifies agent type in DispatchCommand
    QStringList                Arch;
    std::vector<AgentFormat>   Formats;
    QStringList                SupportedOS;
    std::vector<AgentCommands> Commands;
    QJsonDocument              BuildingConfig;
} ServiceAgent;

extern uint64_t DemonMagicValue;  // defined in Service.cc; value = 0xDEADBEEF
```

---

## Startup Sequence (`src/Havoc/Havoc.cc`)

1. `main()` creates `QApplication` and `Havoc` instance (`HavocApplication`), calls `Init()`
2. `Havoc::Havoc()`: sets invisible `QMainWindow`, initializes spdlog, creates `DBManager("data/client.db")`
3. `Havoc::Init()`:
   - Parses CLI args (`--debug`, `--config`)
   - Reads TOML config (`client/config.toml` or `config.toml`) — sets font family/size
   - Shows `Connect::setupUi` + `StartDialog` (blocks with `QDialog::exec()`)
   - `StartDialog` returns a populated `Util::ConnectionInfo`; stores in `HavocX::Teamserver`
   - Creates `HavocNamespace::Connector(&HavocX::Teamserver)` — opens WebSocket
4. `Connector` constructor triggers `QWebSocket::open(wss://host:port/havoc/)`
5. On `connected` signal → `SendLogin()` → sends `InitConnection::Type` + `Login` sub-event
6. Server responds with `InitConnection::Success` → `DispatchInitConnection` → `HavocApplication->Start()`
7. `Havoc::Start()`: shows `QMainWindow`, sets central widget to `HavocAppUI`; loads scripts from config
8. `QApplication::exec()` runs the event loop

---

## Connection and Authentication (`src/Havoc/Connector.cc`)

```cpp
Connector::Connector( Util::ConnectionInfo* ConnectionInfo )
```

- Creates `QWebSocket`, sets `QSslSocket::VerifyNone` (ignores all SSL errors)
- Connects to `wss://<Host>:<Port>/havoc/`
- On `binaryMessageReceived`: `Packager::DecodePackage(Message)` → `Packager::DispatchPackage(Package)`
- On `connected`: creates `Packager` instance, calls `SendLogin()`
- On `disconnected`: shows error `MessageBox`, calls `Havoc::Exit()`

### `SendLogin()`

```cpp
Head.Event              = InitConnection::Type;   // 0x1
Head.User               = teamserver->User;
Body.SubEvent           = InitConnection::Login;  // 0x3
Body.Info["User"]       = username;
Body.Info["Password"]   = QCryptographicHash::hash(password.toLocal8Bit(),
                              QCryptographicHash::Sha3_256).toHex();
```

Password is hashed client-side with SHA3-256 before transmission. The teamserver compares the hex hash directly.

### `SendPackage(PPackage)`

```cpp
Socket->sendBinaryMessage(
    Packager->EncodePackage(*Package).toJson(QJsonDocument::Compact)
);
```

All packages are sent as compact JSON, as `websocket::BinaryMessage`.

---

## Package Encoding/Decoding (`src/Havoc/Packager.cc`)

### Event Type Constants

Defined as `const int` globals in `Packager.cc`:

| Namespace | Constant | Value |
|-----------|----------|-------|
| `InitConnection::Type` | 0x1 | |
| `InitConnection::Success` | 0x1 | |
| `InitConnection::Error` | 0x2 | |
| `InitConnection::Login` | 0x3 | |
| `Listener::Type` | 0x2 | |
| `Listener::Add/Edit/Remove/Mark/Error` | 0x1–0x5 | |
| `Chat::Type` | 0x4 | |
| `Chat::NewMessage/NewListener/NewSession/NewUser/UserDisconnect` | 0x1–0x5 | |
| `Gate::Type` | 0x5 | |
| `Gate::Staged/Stageless` | 0x1/0x2 | |
| `Session::Type` | 0x7 | |
| `Session::NewSession/Remove/SendCommand/ReceiveCommand/MarkAs` | 0x1–0x5 | |
| `Service::Type` | 0x9 | |
| `Service::AgentRegister/ListenerRegister` | 0x1/0x2 | |
| `Teamserver::Type` | 0x10 | |
| `Teamserver::Logger/Profile` | 0x1/0x2 | |

### `DecodePackage(QString json)` → `PPackage`

Parses JSON: reads `Head.{Event, Time, User}`, `Body.{SubEvent}`, and all `Body.Info` key/value pairs as strings into `QMap<string, string>`.

### `EncodePackage(Package)` → `QJsonDocument`

Converts `Info` map to `QVariantMap`, serializes `Head` + `Body` into JSON object.

### `DispatchPackage(PPackage)` — master router

```
Head.Event → switch:
  InitConnection::Type  → DispatchInitConnection
  Listener::Type        → DispatchListener
  Chat::Type            → DispatchChat
  Gate::Type            → DispatchGate
  Session::Type         → DispatchSession
  Service::Type         → DispatchService
  Teamserver::Type      → DispatchTeamserver
```

#### `DispatchInitConnection`

| SubEvent | Action |
|----------|--------|
| `Success` | First connect: `setupUi` + load scripts + `Havoc::Start()`; subsequent connect: `NewTeamserverTab` |
| `Error` | Show error `MessageBox` |
| `0x5` (Profile) | Store `TeamserverIPs` in `HavocX::Teamserver.IpAddresses`; store Demon config JSON in `HavocX::Teamserver.DemonConfig` |

#### `DispatchListener`

| SubEvent | Action |
|----------|--------|
| `Add` | Ignores if `Head.User` is non-empty (own operator's request echo — skip). Constructs `ListenerItem` with protocol-specific config struct, calls `ListenerTableWidget->ListenerAdd()`. Logs to EventViewer. |
| `Remove` | `ListenerTableWidget->ListenerRemove(name)` |
| `Edit` | Reconstructs `ListenerItem`, calls `ListenerTableWidget->ListenerEdit()` |
| `Error` | Shows `MessageBox` only if `Head.User == HavocX::Teamserver.User` or empty |

**Listener protocol strings:** `"Http"`, `"Https"`, `"Smb"`, `"External"` (see `Listener::PayloadHTTP/HTTPS/SMB/External` static constants).

#### `DispatchChat`

| SubEvent | Action |
|----------|--------|
| `NewMessage` | `TeamserverChat->AddUserMessage(time, user, base64decode(message))` |
| `NewUser` | EventViewer: `[+] user connected to teamserver` |
| `UserDisconnect` | EventViewer: `[-] user disconnected from teamserver` |

#### `DispatchGate`

| SubEvent | Action |
|----------|--------|
| `Stageless` | If `PayloadArray` present + `GateGUI=true`: `PayloadDialog->ReceivedImplantAndSave(FileName, bytes)`. If Python callback set: `PyObject_CallFunctionObjArgs(callbackGate, base64bytes, NULL)`. If `MessageType` present + `GateGUI`: `PayloadDialog->addConsoleLog(type, message)`. |

#### `DispatchSession`

| SubEvent | Action |
|----------|--------|
| `NewSession` | Constructs `Util::SessionItem` from `Info` map. Adds to `SessionTableWidget` + `LootWidget`. Appends to `HavocX::Teamserver.Sessions`. Fires all `RegisteredCallbacks` (Python). |
| `SendCommand` | Finds session by DemonID. Displays command prompt in agent console. Updates `CommandInputList`, records `CommandTaskInfo` if present. Calls `DispatchCommand(false, taskID, commandLine)` for UI-only render. |
| `ReceiveCommand` | Finds session. Switches on `CommandID`: `CONSOLE_MESSAGE` → `OutputDispatch.MessageOutput()`; `BOF_CALLBACK` → Python callback; `CALLBACK` → updates `Last/Sleep/Jitter/KillDate/WorkingHours` |
| `MarkAs` | Updates `session.Marked`, changes table row icon and background color |

---

## Command Dispatch Flow

### Input → Send path

1. Operator types in `DemonInteracted::DemonInput` (QLineEdit)
2. `lineEdit::returnPressed` → `DemonInteracted::AppendFromInput()` → `AppendText(text)`
3. `AppendText`: builds prompt string, checks MagicValue for agent type name, calls `DemonCommands::DispatchCommand(true, TaskID, commandline)` — `Send=true`
4. `DemonCommands::DispatchCommand`:
   - `ParseCommandLine(commandline)` → `QStringList InputCommands`
   - Checks `MagicValue == DemonMagicValue`; if not, finds matching `ServiceAgent`
   - For Demon: matches `InputCommands[0]` against `DemonCommandList`; calls appropriate `Execute.*` method via `SEND(Execute.X(...))` macro
   - For service agents: dispatches to registered Python command handler via `AgentCommand()`
5. `CommandExecute::X(TaskID, ...)`: builds `Util::Packager::Body_t` with `SubEvent=Session::SendCommand` and Info fields, calls `NewPackageCommand(TeamserverName, Body)`
6. `NewPackageCommand`: wraps in `Head{Event=Session::Type, User, Time}`, calls `HavocX::Connector->SendPackage(Package)`

### Info fields sent to teamserver for every command

| Field | Value |
|-------|-------|
| `DemonID` | hex AgentID (e.g. `"deadbeef"`) |
| `CommandID` | string representation of `Commands` enum integer |
| `TaskID` | UUID-style task identifier |
| `CommandLine` | original command line text (from `CommandInputList[TaskID]`) |
| `CommandLine` | original command line text |
| *(command-specific)* | varies per command |

### `Commands` enum (`include/Havoc/DemonCmdDispatch.h`)

```cpp
enum class Commands {
    CHECKIN             = 100,
    CALLBACK            = 10,
    CONSOLE_MESSAGE     = 0x80,
    BOF_CALLBACK        = 0x81,
    SLEEP               = 11,
    PROC_LIST           = 12,
    FS                  = 15,
    INLINE_EXECUTE      = 20,
    JOB                 = 21,
    INJECT_DLL          = 22,
    INJECT_SHELLCODE    = 24,
    INJECT_DLL_SPAWN    = 26,
    TOKEN               = 40,
    PROC                = 0x1010,
    INLINE_EXECUTE_ASSEMBLY = 0x2001,
    ASSEMBLY_LIST_VERSIONS  = 0x2003,
    NET                 = 2100,
    CONFIG              = 2500,
    SCREENSHOT          = 2510,
    PIVOT               = 2520,
    TRANSFER            = 2530,
    SOCKET              = 2540,
    KERBEROS            = 2550,
    OUTPUT              = 90,
    ERROR               = 91,
    EXIT                = 92,
};
```

### Binary content in command packages

Files are read locally, then base64-encoded into the `Info["Binary"]` field:
```cpp
auto Content = FileRead( Path );
Body.Info["Binary"] = Content.toBase64().toStdString();
```

Arguments may be double-base64 encoded (first `base64_encode(Args)`, then the whole Info map's values are strings) — the teamserver `TaskPrepare` cases know to `base64.StdEncoding.DecodeString` them.

---

## Command Output Handling (`src/Havoc/Demon/CommandOutput.cc`)

`DispatchOutput::MessageOutput(QString JsonString, const QString& Date)`:

1. Base64-decode `JsonString` → parse as JSON
2. Read fields: `TaskID`, `Type`, `Message`, `Output`, `MiscType`, `MiscData`, `MiscData2`
3. Render `Message` by type:
   - `"Error"` / `"Erro"` → `TaskError(message)` (red)
   - `"Good"` → `[+] message` (green)
   - `"Info"` → `[*] message` (cyan)
   - `"Warning"` / `"Warn"` → `[!] message` (yellow)
   - Other → `[^] message` (purple)
4. Append `Output` to console (calls Python `callbackMessage` if set, then clears it)
5. Handle `MiscType` side-channel data:
   - `"screenshot"` → base64-decode `MiscData`, save to `LootWidget`
   - `"download"` → parse `MiscData2` (`name;size`), add to `LootWidget`
   - `"ProcessUI"` → decode JSON, call `Session.ProcessList->UpdateProcessListJson()`
   - `"FileExplorer"` → decode JSON, call `Session.FileBrowser->AddData()`
   - `"disconnect"` → `SessionGraphWidget->GraphPivotNodeDisconnect(AgentID)`
   - `"reconnect"` → `SessionGraphWidget->GraphPivotNodeReconnect(parent, child)`

---

## Built-in Command List (`src/Havoc/Demon/Commands.cc`)

`DemonCommands::DemonCommandList` is a static `std::vector<Command_t>` initialized with all built-in commands and their sub-commands, descriptions, MITRE techniques, usage, and behavior labels:

| Command | Sub-commands / notes |
|---------|----------------------|
| `help` | shows help for any command |
| `sleep` | `[delay] (jitter)` — T1029/TA0005 |
| `checkin` | request checkin |
| `job` | `list`, `suspend`, `resume`, `kill` |
| `task` | `list`, `clear` (Teamserver-side) |
| `proc` | `list`, `modules`, `grep`, `create`, `kill`, `suspend`, `resume` |
| `shell` | `cmd.exe` execution |
| `run` | process creation without shell |
| `execute` | shellcode/BOF execution |
| `inline-execute` | BOF execution |
| `assembly inline-execute` | .NET inline assembly |
| `dotnet` | .NET management |
| `inject` | shellcode injection sub-commands |
| `spawndll` | DLL spawn |
| `injectdll` | DLL injection |
| `token` | token manipulation sub-commands |
| `fs` | file system operations (`dir`, `download`, `upload`, `cd`, `rm`, `mkdir`, `cp`, `mv`, `pwd`, `cat`) |
| `net` | network enumeration |
| `config` | agent config update |
| `screenshot` | desktop capture |
| `pivot` | SMB pivot management |
| `transfer` | file transfer management |
| `socket` | SOCKS5 proxy management |
| `kerberos` | `luid`, `klist`, `purge`, `ptt` |
| `exit` | agent termination |

---

## Payload Generation Dialog (`src/UserInterface/Dialogs/Payload.cc`)

### UI Components

- `ComboAgentType`: "Demon" + service agent names
- `ComboArch`: "x64", "x86"
- `ComboFormat`: "Windows Exe", "Windows Dll", "Windows Shellcode"
- `ComboListener`: populated from `HavocX::Teamserver.Listeners` (online only)
- `TreeConfig`: per-format Demon config tree (populated by `DefaultConfig()` and `AddConfigFromJson()`)
- `ConsoleText`: build log output

### `buttonGenerate()`

Sends `Gate::Stageless` package (marked `OneTime="true"`):
```cpp
Head.Event    = Gate::Type;
Head.OneTime  = "true";
Body.SubEvent = Gate::Stageless;
Body.Info = {
    { "AgentType", comboAgentType },
    { "Listener",  comboListener  },
    { "Arch",      comboArch      },
    { "Format",    comboFormat    },
    { "Config",    GetConfigAsJson().toJson() },
};
HavocX::GateGUI = true;
HavocX::Connector->SendPackage(Package);
```

### `AddConfigFromJson(QJsonDocument)`

Populates `TreeConfig` from a JSON document received when a module/format is selected.
For each JSON key:
- **bool** → `QCheckBox` widget
- **string** → `QLineEdit` widget
- **array** → `QComboBox` widget
- **object** → nested `QTreeWidgetItem` children with the same type rules

`QCheckBox` items have their palette explicitly set so they match the active theme:

```cpp
p.setColor( QPalette::Window,     QColor( ThemeManager::Instance().ActiveColors().panel ) );
p.setColor( QPalette::WindowText, QColor( ThemeManager::Instance().ActiveColors().text  ) );
```

`QLineEdit` and `QComboBox` items inherit colors from the application-wide palette.

### `ReceivedImplantAndSave(FileName, bytes)`

Triggered from `DispatchGate` when the built payload arrives. Opens a `QFileDialog` save dialog, writes the binary to disk, shows success `MessageBox`.

---

## UI Widgets

### `DemonInteracted` (`include/UserInterface/Widgets/DemonInteracted.h`)

The per-agent interaction console:
- `Console`: `QTextEdit` (read-only) — all output
- `lineEdit`: `DemonInput` (custom `QLineEdit`) — command input
- `label_2`: session info bar (`[user/computer] process/pid arch (domain)`)
- `DemonCommands`: `HavocSpace::DemonCommands*` — command dispatcher
- `SessionInfo`: copy of the session's `Util::SessionItem`
- Tab key auto-completion via `QCompleter` over `DemonCommandList` + registered commands
- Up/Down arrow key cycles through `CommandHistory`

### `SessionTable` (`src/UserInterface/Widgets/SessionTable.cc`)

10-column `QTableWidget`:

| Col | Header |
|-----|--------|
| 0 | ID (hex AgentID) |
| 1 | External |
| 2 | Internal |
| 3 | User |
| 4 | Computer |
| 5 | OS |
| 6 | Process |
| 7 | PID |
| 8 | Last |
| 9 | Health |

Row icons use Windows version icons; elevated sessions show a different icon variant. Dead sessions are greyed out with a skull icon.

**Column 8 — Last (elapsed time):** Updated every second by `UpdateSessionsHealth()` (`HavocUi.cc`), which fires on a 1-second `QTimer`. The elapsed value is computed as:

```cpp
qint64 diff = session.LastUTC.secsTo( QDateTime::currentDateTimeUtc() );
auto days    = static_cast<int>( diff / 86400 );
auto hours   = static_cast<int>( ( diff % 86400 ) / 3600 );
auto minutes = static_cast<int>( ( diff % 3600 ) / 60 );
auto seconds = static_cast<int>( diff % 60 );
```

Display format: `Xs` / `Xm Xs` / `Xh Xm` / `Xd Xh`. `LastUTC` is always `Qt::UTC`
(no local-timezone adjustment), set either from the server's UTC-formatted timestamp
(initial load) or from `currentDateTimeUtc()` at live CALLBACK receipt.

### `TeamserverTabSession` (`include/UserInterface/Widgets/TeamserverTabSession.h`)

The main tab containing all sub-widgets:
- `SessionTableWidget`: `SessionTable*`
- `SessionGraphWidget`: `SessionGraph*` (pivot graph)
- `ListenerTableWidget`: `ListenersTable*`
- `LootWidget`: `LootWidget*` (downloads, screenshots, credentials)
- `TeamserverChat`: `Chat*`
- `SmallAppWidgets` → `EventViewer`: event log
- `PayloadDialog`: `Payload*`

### Connect Dialog (`src/UserInterface/Dialogs/Connect.cc`)

Fields: Name, Host, Port, User, Password (echoed as `*`). Left panel lists saved profiles from `DBManager`. "New Profile" button clears to empty form. `StartDialog(bool)` blocks on `QDialog::exec()` and returns the filled `Util::ConnectionInfo`.

---

## Python Scripting API

Embedded CPython via `#include <Python.h>` (slots macro guard required).

### Module Registration

`PythonApi.cc` registers a custom `emb.StdoutType` to redirect `sys.stdout` → Qt console output. The `havoc` Python module is created with methods exposing:
- `RegisterCommand(agent, module, command, help, behavior, usage, example, fn)` — extends `DemonCommandList` at runtime
- `RegisterCallback(fn)` — called on every new Demon session
- `GetDemonByName(name)` → `PyDemonClass` instance
- UI factory functions (dialogs, widgets, trees)

### Python callbacks in session flow

- **New session**: All `HavocX::Teamserver.RegisteredCallbacks` are called with `agent.Name` as arg
- **BOF/inline-execute output**: `Session.TaskIDToPythonCallbacks[TaskID]` is called with `(agentId, taskId, worked, output, error)` and then removed
- **Payload received**: `HavocX::callbackGate(base64bytes)` if set; cleared after call
- **Command output**: `HavocX::callbackMessage(output)` if set; cleared after call

---

## DB Manager (`src/Havoc/DBManger/DBManager.cc`)

Stores saved teamserver connection profiles in `data/client.db` (SQLite). Methods:
- `listTeamservers()` → `std::vector<Util::ConnectionInfo>` — shown in Connect dialog list
- `addTeamserver(ConnectionInfo)` — persists after successful connect
- `removeTeamserver(name)` — context menu "Remove"

---

## Configuration File (`config.toml`)

TOML format. Read on startup by `Havoc::Init()`. Required sections:

```toml
[font]
family = "Hack"
size   = 9

[scripts]
files = [ "path/to/script.py", ... ]
```

Scripts are loaded on the first successful `InitConnection::Success` via `ScriptManager::AddScript()`.

---

## Listener Protocol Strings

Static `QString` constants on `HavocSpace::Listener`:

```cpp
Listener::PayloadHTTPS    = "Https"
Listener::PayloadHTTP     = "Http"
Listener::PayloadSMB      = "Smb"
Listener::PayloadExternal = "External"
```

Used when categorizing received listener info and building listener config structs from `Info` map fields.

---

## Coding Conventions

- **`auto` everywhere** — nearly all local variables use `auto`. Only parameters and members use explicit types.
- **Designated initializers** — structs are initialized with `.Field = value` syntax (`Head_t { .Event = ..., .User = ... }`).
- **`QMap<string, string>` for `Body_t::Info`** — all values are flat strings. Binary data is base64-encoded. Numbers are `to_string(int)`.
- **`CommandID` is a string** in `Info` — always `to_string( static_cast<int>( Commands::X ) )`.
- **No direct Qt UI file loading** — all UI is constructed programmatically in `setupUi()` methods; stylesheets are read from Qt resources via `FileRead(":/stylesheets/...")`.
- **`SEND(f)` macro** — `if ( Send ) f; return true;` — the same `DispatchCommand` path runs in both "send" mode (user input, `Send=true`) and "display" mode (replayed from server, `Send=false`).
- **Prompt is a formatted HTML string** — built with `ColorText::*` helpers that wrap text in `<span style="color:...">` tags; appended to `QTextEdit::Console` which renders HTML.
- **`spdlog`** for all logging — `spdlog::info`, `spdlog::error`, `spdlog::debug`, `spdlog::critical`. Pattern: `"[%T] [%^%l%$] %v"`.
- **`#pragma push/pop slots`** — required before/after `#include <Python.h>` because Python redefines `slots` which conflicts with Qt's `Q_SLOTS`.
