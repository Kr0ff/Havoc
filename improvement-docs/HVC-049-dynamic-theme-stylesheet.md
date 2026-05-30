# HVC-049 — Dynamic Theme-Aware Global Stylesheet

## Status
Planned

## Problem

All Qt5 client `.qss` files contain hardcoded Dracula theme colors (`#282a36`, `#ff79c6`,
`#bd93f9`, etc.). Dracula renders correctly by coincidence. Every other theme (Light,
GreenNight, PinkLady, Emerald, DarkBubble) and any future user-defined theme shows:

- QCheckBox indicators: Dracula pink border (`#ff79c6`) regardless of active theme
- QLineEdit / QSpinBox / QComboBox: no visible border on focus (or Dracula purple `#bd93f9`)
- QPlainTextEdit / QTextEdit: no focus outline
- Dialog backgrounds, button colors, label text: all Dracula values

The root cause: `ThemeManager::Stylesheet()` falls back to the embedded Dracula QSS
when no per-theme QSS file exists. Per-theme QSS files only exist for Dracula.

## Goal

A single `GlobalStylesheet()` method in `ThemeManager` that generates the entire client
stylesheet dynamically from `ActiveColors()`. Applied once via `qApp->setStyleSheet()`.
Any present or future theme automatically gets correct widget outlines, focus borders,
and colors with zero per-theme QSS files required.

## Color Mapping

All QSS rules use these `ThemeColors` fields:

| Token | Field | DarkBubble example | Role |
|---|---|---|---|
| `%1` | `bgMain` | `#050606` | Main window background |
| `%2` | `panel` | `#090b0b` | Widget/dialog background |
| `%3` | `text` | `#cddeda` | Foreground text |
| `%4` | `selection` | `#252929` | Secondary bg, normal borders |
| `%5` | `accent` | `#ee5285` | **Focus borders, checkbox fill, button bg** |
| `%6` | `muted` | `#5a6160` | Disabled text, scrollbar handles |
| `%7` | `tabHighlight` | `#cd9f45` | Active tab underline |
| `%8` | `okAccent` | `#518880` | OK/confirm button accent |
| `%9` | `green` | `#518880` | Config item value color (ConfigItem, #bool etc.) |

## Widget Coverage

### Missing from ALL existing QSS (the core bug)
- `QCheckBox::indicator` — border and checked state (was `#ff79c6` hardcoded)
- `QLineEdit:focus` — focus border
- `QSpinBox` — any border
- `QTextEdit:focus` / `QPlainTextEdit:focus` — focus border

### Present in existing QSS but with hardcoded colors (converted to dynamic)
- `QMainWindow`, `QDialog`, `QWidget` — backgrounds and text
- `QPushButton` — bg, border, pressed state
- `QComboBox` — bg, color, item colors
- `QGroupBox` — title color, border
- `QListWidget` / `QListView` — bg, selected
- `QLabel` — text color
- `QMenuBar` — bg, text, hover
- `QTabBar` — bg, active indicator
- `QScrollBar` — track, handle
- `QProgressBar` — fill
- `#ConfigItem, #list, #text, #bool` — special payload builder item colors
- `QTreeWidget` / `QTableWidget` / `QHeaderView` — border, selection, header bg

## Implementation

### 1. `ThemeManager.hpp` — add public static method

```cpp
static QString GlobalStylesheet();
```

Add after `MenuStyleSheet()` declaration (line ~79).

### 2. `ThemeManager.cpp` — implement `GlobalStylesheet()`

Add after `MenuStyleSheet()` body (~line 490). The method accesses
`Instance().activeColors_` and uses `.arg()` substitution with 9 parameters.

Full QSS structure (structural properties preserved from original QSS files):

```cpp
QString ThemeManager::GlobalStylesheet()
{
    const auto& c = Instance().activeColors_;
    return QStringLiteral(
        /* === Main containers === */
        "QMainWindow { background-color: %1; color: %3; }"
        "QDialog { background-color: %2; color: %3; }"
        "QWidget { background-color: %2; color: %3; }"
        "QFrame { background-color: %2; }"

        /* === Labels === */
        "QLabel { color: %3; background: transparent; }"

        /* === Line edits === */
        "QLineEdit {"
        "    background-color: %4; color: %3;"
        "    border: 1px solid %4; border-radius: 2px; padding: 2px;"
        "}"
        "QLineEdit:focus { border: 1px solid %5; }"
        "QLineEdit:read-only { background-color: %1; color: %3; }"
        "QLineEdit:disabled { background-color: %1; color: %6; border-color: %4; }"

        /* === Plain text / text edits === */
        "QPlainTextEdit { background-color: %4; color: %3; border: 1px solid %4; }"
        "QPlainTextEdit:focus { border: 1px solid %5; }"
        "QTextEdit { background-color: %4; color: %3; border: 1px solid %4; }"
        "QTextEdit:focus { border: 1px solid %5; }"

        /* === Spin box === */
        "QSpinBox {"
        "    background-color: %4; color: %3;"
        "    border: 1px solid %4; border-radius: 2px; padding: 2px;"
        "}"
        "QSpinBox:focus { border: 1px solid %5; }"

        /* === Combo box === */
        "QComboBox {"
        "    background-color: %4; color: %3;"
        "    border: 1px solid %4; border-radius: 2px; padding: 2px;"
        "}"
        "QComboBox:focus { border: 1px solid %5; }"
        "QComboBox:!enabled { background-color: %1; color: %6; }"
        "QComboBox::drop-down { border-left: 1px solid %4; }"
        "QComboBox::item { background: %4; color: %3; }"
        "QComboBox::item:selected { background: %6; color: %3; }"
        "QComboBox QAbstractItemView {"
        "    background-color: %4; color: %3; border: 1px solid %4;"
        "    selection-background-color: %6;"
        "}"

        /* === Checkboxes === */
        "QCheckBox { color: %3; background: transparent; }"
        "QCheckBox::indicator {"
        "    width: 12px; height: 12px;"
        "    border: 1px solid %5; border-radius: 2px; background: %2;"
        "}"
        "QCheckBox::indicator:checked { background: %5; border-color: %5; }"
        "QCheckBox::indicator:hover { border-color: %3; }"
        "QCheckBox::indicator:disabled { border-color: %6; background: %1; }"
        "QCheckBox:disabled { color: %6; }"

        /* === Buttons === */
        "QPushButton {"
        "    background-color: %5; color: %1;"
        "    border: 1px solid %5; border-radius: 2px;"
        "    padding-top: 3px; padding-bottom: 3px;"
        "}"
        "QPushButton:hover { background-color: %4; color: %3; border-color: %5; }"
        "QPushButton:pressed { background-color: %1; color: %3; border-color: %5; }"
        "QPushButton:disabled { background-color: %6; color: %2; border-color: %6; }"

        /* === Group boxes === */
        "QGroupBox {"
        "    color: %3; border: 1px solid %4; border-radius: 3px; margin-top: 6px;"
        "}"
        "QGroupBox::title {"
        "    color: %3; subcontrol-origin: margin; left: 7px; padding: 0 3px;"
        "}"

        /* === List / tree / table widgets === */
        "QListWidget { background-color: %4; color: %3; border: 1px solid %4; border-radius: 2px; margin-top: 2px; }"
        "QListWidget::item:selected { background-color: %2; color: %3; }"
        "QListView { background-color: %4; color: %3; }"
        "QListView::item { height: 22px; }"
        "QListView::item:selected { background: %2; color: %3; }"
        "QTreeWidget { background-color: %4; color: %3; border: 1px solid %4; }"
        "QTreeWidget::item:selected { background-color: %6; color: %3; }"
        "QTableWidget { background-color: %4; color: %3; border: 1px solid %4; }"
        "QTableWidget::item:selected { background-color: %6; }"
        "QHeaderView::section { background-color: %6; color: %3; border: 1px solid %4; }"

        /* === Menu bar === */
        "QMenuBar { background-color: %2; color: %3; }"
        "QMenuBar::item { padding: 1px 4px; background: transparent; }"
        "QMenuBar::item:selected { background: %6; }"
        "QMenuBar::item:pressed { background: %4; }"

        /* === Tabs === */
        "QTabBar { border-top-color: %5; }"
        "QTabBar::tab { height: 26px; background: %2; color: %6; padding: 0 8px; }"
        "QTabBar::tab:selected { color: %3; border-bottom: 2px solid %7; }"
        "QTabBar::tab:hover { color: %3; }"
        "QTabBar::close-button {"
        "    image: url(:/icons/tab-close-button); subcontrol-position: right;"
        "}"
        "QTabWidget::pane { border: 1px solid %4; }"

        /* === Scroll bars === */
        "QScrollBar:vertical {"
        "    background-color: %2; width: 8px; border-radius: 4px; margin: 0px;"
        "}"
        "QScrollBar::handle:vertical {"
        "    background-color: %6; border-radius: 4px; min-height: 20px;"
        "}"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }"
        "QScrollBar:horizontal {"
        "    background-color: %2; height: 8px; border-radius: 4px; margin: 0px;"
        "}"
        "QScrollBar::handle:horizontal {"
        "    background-color: %6; border-radius: 4px; min-width: 20px;"
        "}"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }"

        /* === Progress bar === */
        "QProgressBar { background-color: %4; border: 1px solid %4; border-radius: 2px; text-align: center; color: %3; }"
        "QProgressBar::chunk { background-color: %5; }"

        /* === Payload builder config items === */
        "#ConfigItem, #list, #text, #bool { background-color: %1; color: %9; }"

    ).arg(
        c.bgMain,       /* %1 */
        c.panel,        /* %2 */
        c.text,         /* %3 */
        c.selection,    /* %4 */
        c.accent,       /* %5 */
        c.muted,        /* %6 */
        c.tabHighlight, /* %7 */
        c.okAccent,     /* %8 */
        c.green         /* %9 */
    );
}
```

### 3. `HavocUi.cc` — replace per-widget static calls with one global call

**Current (3 separate widget-level calls, all with Dracula fallback):**
```cpp
HavocWindow->setStyleSheet( ThemeManager::Instance().Stylesheet( "Havoc" ) );
TeamserverTabWidget->setStyleSheet( ThemeManager::Instance().Stylesheet( "teamserverTab" ) );
menubar->setStyleSheet( ThemeManager::Instance().Stylesheet( "menubar" ) );
```

**Replace with one application-level call:**
```cpp
qApp->setStyleSheet( ThemeManager::Instance().GlobalStylesheet() );
```

Adding `#include <QApplication>` at the top of HavocUi.cc if not already present.

### 4. `Connect.cc` — dynamic inline stylesheet

The Connect dialog calls `Form->setStyleSheet(Stylesheet("Dialogs/Connect"))` which
loads the hardcoded QSS. Replace with inline dynamic generation following the Listener.cc
pattern, or just remove and rely on the qApp-level GlobalStylesheet().

Recommended: remove `Form->setStyleSheet(...)` in Connect.cc since GlobalStylesheet()
covers all the widget types that Connect.qss styles. The dialog inherits from qApp.

### 5. `Preferences.cc` / any other dialogs calling `Stylesheet()`

Same approach: remove per-dialog static stylesheet calls and rely on GlobalStylesheet()
cascading from qApp. Only keep dialog-specific calls if they provide structural styling
not covered by GlobalStylesheet (e.g., very specific padding or layout rules).

## Files to Change

| File | Change |
|---|---|
| `client/include/Util/ThemeManager.hpp` | Add `static QString GlobalStylesheet();` declaration |
| `client/src/Util/ThemeManager.cpp` | Implement `GlobalStylesheet()` after `MenuStyleSheet()` |
| `client/src/UserInterface/HavocUi.cc` | Replace 3 setStyleSheet calls with `qApp->setStyleSheet(GlobalStylesheet())` |
| `client/src/UserInterface/Dialogs/Connect.cc` | Remove static QSS call; rely on qApp global |

## Why qApp::setStyleSheet is the correct integration point

Qt's stylesheet cascade: `qApp` < widget < child widget. Any widget-specific inline
stylesheet (e.g., Listener.cc's dynamic generation) still takes full precedence over
the qApp base. Existing correct theming is unaffected. Future dialogs automatically
inherit correct colors without any extra work.

## Verification

1. Build the client and launch with each theme: Dracula, Light, GreenNight, PinkLady,
   Emerald, DarkBubble.
2. For each theme, verify:
   - QCheckBox indicator border = `accent` color of that theme (not Dracula pink)
   - QLineEdit gains colored border on focus = `accent` color
   - QComboBox border matches theme
   - Payload builder dialog Config/Value tree items (#ConfigItem) have correct text color
   - TabBar active tab shows `tabHighlight` color underline
   - The Listener, Connect, Payload dialogs all look themed
3. Create a minimal user theme with a unique accent color and verify it works without
   any additional QSS files.
