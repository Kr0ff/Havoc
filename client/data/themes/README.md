# Havoc Client Themes

The Havoc Qt client supports pluggable UI themes. Two themes ship with the
client as built-ins, and any user can drop their own theme into
`~/.havoc/themes/` to have it appear in the `Havoc → Theme` menu.

## Built-in themes

| Name      | Description                                                           |
|-----------|-----------------------------------------------------------------------|
| `Dracula` | The default dark palette that has shipped with Havoc since day one.   |
| `Light`   | A light palette (white panels, indigo accent). Doubles as a template. |

Built-ins live inside the compiled client binary via the Qt resource system
(`client/data/Havoc.qrc`). They cannot be edited at runtime and are always
available as a fallback.

## Selecting a theme

1. Launch the Havoc client.
2. Open **Havoc → Theme** and pick the theme you want.
3. A dialog will tell you that the change takes effect on the next launch.
   Close and reopen the client.

The selected theme is persisted to `~/.havoc/theme.conf` as a single line
containing the theme name. You can edit this file by hand if you prefer.

Themes are not hot-reloaded because many Havoc widgets read their stylesheet
once in their constructor — a live switch would leave the UI half-themed.
Restarting guarantees every widget sees the new stylesheet on first paint.

## Installing a custom theme

1. Copy the template:
   ```bash
   cp -r <havoc-repo>/client/data/themes/Template ~/.havoc/themes/MyTheme
   ```
2. Edit `~/.havoc/themes/MyTheme/theme.json` and set `"name": "MyTheme"`
   (must match the directory name).
3. Edit any of the `.qss` files to taste. Missing files fall back to the
   Dracula default, so you can override as little or as much as you want.
4. Restart the client and choose **Havoc → Theme → My Custom Theme**.

## Theme directory layout

```
~/.havoc/themes/MyTheme/
├── theme.json                 # manifest (required)
├── Havoc.qss                  # main window + global widgets
├── menubar.qss                # top menu bar
├── teamserverTab.qss          # primary teamserver tab strip
├── bottomTab.qss              # secondary/bottom tab strip
├── MessageBox.qss             # QMessageBox styling
├── MenuStyle.qss              # QMenu popup styling
└── Dialogs/
    ├── BasicDialog.qss
    ├── Connect.qss
    ├── FileDialog.qss
    ├── Listener.qss
    └── Preferences.qss
```

Every file except `theme.json` is optional. Any logical stylesheet the user
theme does not provide is served from the embedded Dracula resource as a
safe fallback.

### `theme.json`

Minimum shape:

```json
{
    "name":        "MyTheme",
    "displayName": "My Custom Theme",
    "author":      "Your Name",
    "version":     "1.0",
    "description": "Short description shown in the menu tooltip."
}
```

Only `name` and `displayName` are required. `name` MUST match the directory
name and MUST be a JSON string.

## Validation

When the client starts, every user theme is validated before being added to
the menu. A theme that fails any check is skipped with a warning in the log,
and the UI falls back to the Dracula default. These checks are intentionally
strict so a broken or malicious theme can never corrupt the client.

A theme is accepted only if **all** of the following are true:

- `theme.json` exists, parses as JSON, and contains string fields `name` and
  `displayName`.
- The theme directory contains at most **32 files** (recursive). Extra files
  like screenshots or notes are allowed but still count against the cap.
- Every file (including non-`.qss` files) is at most **64 KB**.
- Every byte in every `.qss` file is printable ASCII (`0x20..0x7E`) or one
  of `\t`, `\n`, `\r`. No NUL bytes, no non-ASCII characters, no smart
  quotes, no zero-width characters.
- Every `.qss` file has a balanced number of `{` and `}`.
- No `.qss` file contains the substring `@import` (case-insensitive).
- Every `url(...)` argument in every `.qss` file:
  - Has no scheme (no `file://`, `http://`, etc.)
  - Is not an absolute path
  - Resolves via `QDir::cleanPath` to a path **inside** the theme directory
    (no `..` escape)

The full validator lives in `client/src/Util/ThemeManager.cpp`
(`ThemeManager::Validate`).

## Palette conventions

The `Light` theme uses the palette below. Use the same roles when designing
a custom theme and you only need to substitute eight hex values throughout
the `.qss` files to retarget it.

| Role                          | Light     |
|-------------------------------|-----------|
| Main background               | `#f5f5f5` |
| Panel / dialog background     | `#ffffff` |
| Selection / hover             | `#e8e8f0` |
| Purple accent (buttons/border)| `#5a4fcf` |
| Pink tab highlight            | `#c94f7c` |
| OK / success accent           | `#1e8449` |
| Muted text / disabled         | `#4a4e6a` |
| Primary text                  | `#1e1e2e` |

The palette block at the top of `Light/Havoc.qss` documents every role
in place.

## Troubleshooting

- **My theme doesn't appear in the menu.** Check `~/.havoc/havoc.log` for
  a line starting with `ThemeManager: user theme '...' rejected:`. The
  validator prints the exact reason it failed.
- **The client crashes or looks broken after I switched theme.** That
  shouldn't be possible — the validator blocks unsafe themes and the
  fallback chain always lands on the embedded Dracula stylesheets. If it
  does happen, file an issue with the contents of your theme directory.
- **Where's `~/.havoc/theme.conf`?** It only exists after you pick a
  non-default theme at least once. Before that, the client boots into
  Dracula by default.
