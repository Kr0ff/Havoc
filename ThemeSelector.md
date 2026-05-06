# Theme Selector — Havoc Client

A QoL feature for the Havoc Qt5 client: operators can pick a UI theme from
the menu bar, drop custom themes into `~/.havoc/themes/`, and keep the
client safe from broken or malicious stylesheets through startup-time
validation.

## Summary

- **Before**: a single Dracula-inspired stylesheet was compiled into the
  client binary via Qt resources and loaded through 21 scattered
  `FileRead(":/stylesheets/<name>")` call sites. No way to change themes
  short of rebuilding.
- **After**: a single `ThemeManager` singleton serves stylesheet bytes from
  whichever theme is active. Six themes ship as built-ins (`Dracula`,
  `Light`, `Green Night`, `Pink Lady`, `Emerald`, `Dark Bubble`). Users can
  drop more themes into `~/.havoc/themes/`. A new **Havoc → Theme** submenu
  lets operators switch themes; changes are persisted to
  `~/.havoc/theme.conf` and take effect on next launch.

## Architecture

### Single choke point

Every stylesheet load in the client used to go through
`FileRead(":/stylesheets/<name>")` in `Util/Base.cpp`. All 21 call sites now
go through `ThemeManager::Instance().Stylesheet("<name>")` instead. The
manager preloads the active theme's bytes into an in-memory cache at
startup and serves them from there. On a cache miss (i.e., a theme that
does not override a particular logical stylesheet), the accessor falls
through to `FileRead(":/stylesheets/<name>")` — the original embedded
Dracula resource. This guarantees the UI always has a working stylesheet,
even if a user theme only overrides one or two files.

### Built-in themes are Qt resources

Neither built-in theme lives on disk next to the binary. `Dracula` is served
directly from the existing `:/stylesheets/<name>` resources (zero
duplication — the original stylesheet tree IS the Dracula theme). `Light`
ships as a new set of resources under `:/themes/Light/<name>`, added in a
new `<qresource prefix="/themes/Light">` block in `client/data/Havoc.qrc`.
No `install(...)` rules are needed, matching how the client handles every
other data asset today.

### User themes live in `~/.havoc/themes/`

`ThemeManager::Init()` creates `~/.havoc/` and `~/.havoc/themes/` on first
run if they are missing, then walks every direct subdirectory of
`~/.havoc/themes/`. Each subdirectory that passes validation becomes a
selectable theme. A user theme shares the same layout as the built-in
Light theme (see `client/data/themes/README.md`).

### Restart-to-apply semantics

`ThemeManager::SetActive()` writes the selected theme name to
`~/.havoc/theme.conf` atomically (via `QSaveFile`) and returns — it does
NOT update any running widgets. Many Havoc widgets cache their stylesheet
in their constructor, so a live switch would leave the UI half-themed.
The **Havoc → Theme** menu handler shows a "Restart required" dialog after
a successful save.

### Startup hook

`ThemeManager::Instance().Init()` runs from `client/src/Main.cc`
immediately after `QApplication` is constructed and before the `Havoc`
object is created. This is the earliest valid point — every `setStyleSheet`
in the codebase runs later, inside `HavocUi::setupUi` (called from
`Packager.cc` after a successful websocket connection).

## Validation rules

Enforced by `ThemeManager::Validate()` on user themes only (built-ins are
trusted). A theme that fails any check is skipped with a warning; the UI
falls back to Dracula.

- `theme.json` exists, parses, and has string `name` + `displayName`
- At most **32 files** in the theme directory (recursive)
- Every file is at most **64 KB**
- Every byte in every `.qss` file is printable ASCII (`0x20..0x7E`) or
  whitespace (`\t`, `\n`, `\r`)
- Per `.qss` file, count of `{` equals count of `}`
- No `.qss` file contains `@import` (case-insensitive)
- Every `url(...)` argument: no scheme, not absolute, and its cleaned
  absolute path stays inside the theme directory (no `..` escape)

Validation runs once at startup during `Discover()`, never on user input.

## Fallback chain

At every step, a missing or broken resource falls through to a safe
default — the UI can never be left empty.

1. `Stylesheet(name)` → in-memory cache of the active theme.
2. If not cached → `FileRead(":/stylesheets/<name>")` — the embedded
   Dracula resource (always present in the binary).
3. `Init()` → if the configured theme name is unknown, fall back to
   `Dracula` with a log warning.
4. `Init()` → if a user theme fails `Validate()`, skip it and log the
   exact reason.

## Files created

| Path | Purpose |
|------|---------|
| `client/include/Util/ThemeManager.hpp` | `ThemeManager` singleton declaration |
| `client/src/Util/ThemeManager.cpp` | Discovery, validation, active-theme loading, `Stylesheet()` accessor |
| `client/data/themes/Light/Havoc.qss` | Light main stylesheet with palette reference header |
| `client/data/themes/Light/menubar.qss` | Light menu bar |
| `client/data/themes/Light/teamserverTab.qss` | Light primary tab strip |
| `client/data/themes/Light/bottomTab.qss` | Light secondary tab strip |
| `client/data/themes/Light/MessageBox.qss` | Light QMessageBox styling |
| `client/data/themes/Light/MenuStyle.qss` | Light QMenu popup styling |
| `client/data/themes/Light/Dialogs/BasicDialog.qss` | Light generic modal dialog |
| `client/data/themes/Light/Dialogs/Connect.qss` | Light connect dialog |
| `client/data/themes/Light/Dialogs/FileDialog.qss` | Light file dialog |
| `client/data/themes/Light/Dialogs/Listener.qss` | Light listener dialog |
| `client/data/themes/Light/Dialogs/Preferences.qss` | Light preferences dialog |
| `client/data/themes/Light/theme.json` | Light manifest |
| `client/data/themes/Template/` | Editable copy of the Light theme + `README.txt` with "copy to ~/.havoc/themes/MyTheme/" instructions |
| `client/data/themes/GreenNight/` (12 files) | Dark green Xresources theme (bg #0b0f0c, accent #6ab67c) |
| `client/data/themes/PinkLady/` (12 files) | Dark magenta Xresources theme (bg #190d16, accent #d479c3) |
| `client/data/themes/Emerald/` (12 files) | Dark teal Xresources theme (bg #080b0d, accent #49aac5) |
| `client/data/themes/DarkBubble/` (12 files) | Near-black Xresources theme with pink/gold accents (bg #050606, accent #ee5285) |
| `client/data/themes/README.md` | User-facing theme authoring documentation |
| `ThemeSelector.md` (this file) | Change log + architecture notes |

## Files modified

| Path | Change |
|------|--------|
| `client/CMakeLists.txt` | Add `src/Util/ThemeManager.cpp` to `HAVOC_UTIL`; add `include/Util/ThemeManager.hpp` to `HAVOC_INCLUDE` |
| `client/data/Havoc.qrc` | Resource blocks for Light, GreenNight, PinkLady, Emerald, DarkBubble (2 blocks each: top-level + Dialogs/) |
| `client/src/Main.cc` | `ThemeManager::Instance().Init();` called immediately after `QApplication` construction, before the `Havoc` object |
| `client/include/UserInterface/HavocUI.hpp` | New `QMenu* menuTheme` member |
| `client/src/UserInterface/HavocUi.cc` | New "Theme" submenu under `menuHavoc`, dynamically populated via `QActionGroup`; 3 `FileRead(":/stylesheets/...")` sites migrated |
| `client/src/global.cc` | 2 call sites migrated (FileDialog, MessageBox) |
| `client/src/Util/Base.cpp` | 1 call site migrated (MessageBox) |
| `client/src/UserInterface/Dialogs/Connect.cc` | 7 call sites migrated (Connect + 6 MessageBox) |
| `client/src/UserInterface/Dialogs/Listener.cc` | 1 call site migrated |
| `client/src/UserInterface/Dialogs/Payload.cc` | 4 call sites migrated (BasicDialog, MessageBox x2, FileDialog) |
| `client/src/UserInterface/Widgets/ScriptManager.cc` | 2 call sites migrated (FileDialog, MessageBox) |
| `client/src/UserInterface/Widgets/FileBrowser.cc` | 1 call site migrated (MessageBox) |

## Adding a custom theme

See `client/data/themes/README.md` for the full authoring guide. Short
version:

```bash
cp -r <havoc-repo>/client/data/themes/Template ~/.havoc/themes/MyTheme
# edit ~/.havoc/themes/MyTheme/theme.json and *.qss files
# restart Havoc, pick Havoc -> Theme -> My Custom Theme
```

## Known limitations

- **No hot-reload.** Switching themes requires a client restart. This is
  intentional — many widgets cache their stylesheet at construction time
  and rewiring every widget for live re-themeing was out of scope.
- **No per-agent / per-dialog overrides.** One theme applies globally.
- **Built-ins cannot be edited at runtime.** They live inside the Qt
  resource bundle compiled into the binary. To tweak one, edit the files
  under `client/data/themes/Light/` (or `client/data/stylesheets/` for
  Dracula) and rebuild the client.
- **Icon resources are not themed.** Icons stay as Qt resources regardless
  of the active theme.

## Verification checklist

- [ ] Clean build succeeds: `cd client && mkdir -p Build && cd Build && cmake .. && make -j4`
- [ ] Default launch with no `~/.havoc/theme.conf` loads Dracula and looks
      byte-identical to the pre-change client.
- [ ] `Havoc → Theme → Light` shows a "Restart required" dialog; after
      restart the UI is light-themed.
- [ ] `~/.havoc/theme.conf` contains `Light` after the previous step.
- [ ] Edit `~/.havoc/theme.conf` to `NonExistent`, restart — the client
      still launches (Dracula fallback) and the log contains
      `ThemeManager: configured theme 'NonExistent' not found`.
- [ ] `mkdir -p ~/.havoc/themes/Broken && echo 'QMainWindow { background' > ~/.havoc/themes/Broken/Havoc.qss`
      — `Broken` does not appear in the Theme menu because it lacks a
      `theme.json`; the log contains `ThemeManager: user theme 'Broken' rejected: missing theme.json`.
- [ ] Drop a 200 KB `.qss` file into a test theme — it's rejected with a
      size error.
- [ ] Put `QMainWindow { background-image: url(file:///etc/passwd); }`
      into a test theme — it's rejected with a scheme error.
