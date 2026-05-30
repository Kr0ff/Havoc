# HVC-049 Dynamic Theme Stylesheet Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace all hardcoded Dracula-color QSS files with a single dynamic `GlobalStylesheet()` method in ThemeManager that generates theme-correct Qt stylesheets for every widget type from `ActiveColors()`.

**Architecture:** Add `GlobalStylesheet()` as a public static method on `ThemeManager` following the existing `MenuStyleSheet()` pattern. Apply once via `qApp->setStyleSheet()` in `HavocUi.cc` so it cascades to every widget in the application. Remove per-widget static QSS calls in Connect.cc and Payload.cc. Re-apply on theme switch. Document patterns in CLAUDE.md/AGENTS.md/SKILL.md.

**Tech Stack:** Qt5 (QApplication::setStyleSheet, QSS), C++, ThemeManager singleton

---

## File Map

| File | Change |
|---|---|
| `client/include/Util/ThemeManager.hpp` | Add `static QString GlobalStylesheet();` after line 79 |
| `client/src/Util/ThemeManager.cpp` | Implement `GlobalStylesheet()` after `MenuStyleSheet()` at line 490 |
| `client/src/UserInterface/HavocUi.cc` | Add `<QApplication>` include; replace 3 setStyleSheet calls with `qApp->setStyleSheet(GlobalStylesheet())`; re-apply on theme change |
| `client/src/UserInterface/Dialogs/Connect.cc` | Remove line 21 static QSS call |
| `client/src/UserInterface/Dialogs/Payload.cc` | Remove line 150 static QSS call |
| `CLAUDE.md` | Add theming pattern constraint |
| `AGENTS.md` | Add QA checklist item |
| `SKILL.md` | Add theming lesson |
| `CHANGES.md` | Add HVC-049 entry |

---

### Task 1: Declare `GlobalStylesheet()` in ThemeManager.hpp

**Files:**
- Modify: `client/include/Util/ThemeManager.hpp:79`

- [ ] **Step 1: Read the file to confirm current line 79**

```bash
grep -n "MenuStyleSheet\|GlobalStylesheet" client/include/Util/ThemeManager.hpp
```

Expected output: `79:    static QString MenuStyleSheet();`

- [ ] **Step 2: Add the declaration immediately after line 79**

Find this exact text:
```cpp
    static QString MenuStyleSheet();
```

Replace with:
```cpp
    static QString MenuStyleSheet();
    static QString GlobalStylesheet();
```

- [ ] **Step 3: Verify the edit is in place**

```bash
grep -n "GlobalStylesheet\|MenuStyleSheet" client/include/Util/ThemeManager.hpp
```

Expected: both declarations on adjacent lines.

- [ ] **Step 4: Commit**

```bash
git add client/include/Util/ThemeManager.hpp
git commit -m "feat(client): declare ThemeManager::GlobalStylesheet() in header"
```

---

### Task 2: Implement `GlobalStylesheet()` in ThemeManager.cpp

**Files:**
- Modify: `client/src/Util/ThemeManager.cpp` (after line 490, after `MenuStyleSheet()` body closes)

- [ ] **Step 1: Read lines 470–492 to see exactly where MenuStyleSheet ends**

```bash
sed -n '465,495p' client/src/Util/ThemeManager.cpp
```

Note the exact closing brace line of `MenuStyleSheet()`.

- [ ] **Step 2: Insert GlobalStylesheet() implementation immediately after MenuStyleSheet()'s closing brace**

Find this exact closing block of MenuStyleSheet():
```cpp
    ).arg( c.panel, c.text, c.selection );
}
```

Replace with:
```cpp
    ).arg( c.panel, c.text, c.selection );
}

QString ThemeManager::GlobalStylesheet()
{
    const auto& c = Instance().activeColors_;
    return QStringLiteral(
        /* Main containers */
        "QMainWindow { background-color: %1; color: %3; }"
        "QDialog { background-color: %2; color: %3; }"
        "QWidget { background-color: %2; color: %3; }"

        /* Labels */
        "QLabel { color: %3; background: transparent; }"

        /* Line edits */
        "QLineEdit {"
        "    background-color: %4; color: %3;"
        "    border: 1px solid %4; border-radius: 2px; padding: 2px;"
        "}"
        "QLineEdit:focus { border: 1px solid %5; }"
        "QLineEdit:read-only { background-color: %1; color: %3; }"
        "QLineEdit:disabled { background-color: %1; color: %6; border-color: %4; }"

        /* Plain text / text edits */
        "QPlainTextEdit { background-color: %4; color: %3; border: 1px solid %4; }"
        "QPlainTextEdit:focus { border: 1px solid %5; }"
        "QTextEdit { background-color: %4; color: %3; border: 1px solid %4; }"
        "QTextEdit:focus { border: 1px solid %5; }"

        /* Spin box */
        "QSpinBox {"
        "    background-color: %4; color: %3;"
        "    border: 1px solid %4; border-radius: 2px; padding: 2px;"
        "}"
        "QSpinBox:focus { border: 1px solid %5; }"

        /* Combo box */
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

        /* Checkboxes - THE KEY FIX: indicator uses accent color, not hardcoded Dracula pink */
        "QCheckBox { color: %3; background: transparent; }"
        "QCheckBox::indicator {"
        "    width: 12px; height: 12px;"
        "    border: 1px solid %5; border-radius: 2px; background: %2;"
        "}"
        "QCheckBox::indicator:checked { background: %5; border-color: %5; }"
        "QCheckBox::indicator:hover { border-color: %3; }"
        "QCheckBox::indicator:disabled { border-color: %6; background: %1; }"
        "QCheckBox:disabled { color: %6; }"

        /* Buttons */
        "QPushButton {"
        "    background-color: %5; color: %1;"
        "    border: 1px solid %5; border-radius: 2px;"
        "    padding-top: 3px; padding-bottom: 3px;"
        "}"
        "QPushButton:hover { background-color: %4; color: %3; border-color: %5; }"
        "QPushButton:pressed { background-color: %1; color: %3; border-color: %5; }"
        "QPushButton:disabled { background-color: %6; color: %2; border-color: %6; }"

        /* Group boxes */
        "QGroupBox {"
        "    color: %3; border: 1px solid %4; border-radius: 3px; margin-top: 6px;"
        "}"
        "QGroupBox::title {"
        "    color: %3; subcontrol-origin: margin; left: 7px; padding: 0 3px;"
        "}"

        /* List / tree / table widgets */
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

        /* Menu bar */
        "QMenuBar { background-color: %2; color: %3; }"
        "QMenuBar::item { padding: 1px 4px; background: transparent; }"
        "QMenuBar::item:selected { background: %6; }"
        "QMenuBar::item:pressed { background: %4; }"

        /* Tabs */
        "QTabBar { border-top-color: %5; }"
        "QTabBar::tab { height: 26px; background: %2; color: %6; padding: 0 8px; }"
        "QTabBar::tab:selected { color: %3; border-bottom: 2px solid %7; }"
        "QTabBar::tab:hover { color: %3; }"
        "QTabBar::close-button {"
        "    image: url(:/icons/tab-close-button); subcontrol-position: right;"
        "}"
        "QTabWidget::pane { border: 1px solid %4; }"

        /* Scroll bars */
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

        /* Progress bar */
        "QProgressBar { background-color: %4; border: 1px solid %4; border-radius: 2px; text-align: center; color: %3; }"
        "QProgressBar::chunk { background-color: %5; }"

        /* Payload builder config items (objectName-based selectors) */
        "#ConfigItem, #list, #text, #bool { background-color: %1; color: %9; }"

    ).arg(
        c.bgMain,        /* %1 */
        c.panel,         /* %2 */
        c.text,          /* %3 */
        c.selection,     /* %4 */
        c.accent,        /* %5 */
        c.muted,         /* %6 */
        c.tabHighlight,  /* %7 */
        c.okAccent,      /* %8 */
        c.green          /* %9 */
    );
}
```

- [ ] **Step 3: Verify the method compiles (Go toolchain check is irrelevant; use grep to check structure)**

```bash
grep -c "GlobalStylesheet\|arg(" client/src/Util/ThemeManager.cpp
```

Expected: at least 2 matches.

- [ ] **Step 4: Commit**

```bash
git add client/src/Util/ThemeManager.cpp
git commit -m "feat(client): implement ThemeManager::GlobalStylesheet() dynamic QSS generator"
```

---

### Task 3: Apply global stylesheet in HavocUi.cc and handle theme switching

**Files:**
- Modify: `client/src/UserInterface/HavocUi.cc:40,109,129` (remove 3 calls, add 1)
- Modify: `client/src/UserInterface/HavocUi.cc:186` (re-apply on theme change)

- [ ] **Step 1: Add QApplication include**

Read current includes at the top of HavocUi.cc and verify `<QApplication>` is not already present. In the include block, add it after the existing Qt includes:

Find:
```cpp
#include <QPixmap>
```

Replace with:
```cpp
#include <QApplication>
#include <QPixmap>
```

- [ ] **Step 2: Replace the three static stylesheet calls with one qApp call**

Find this exact block (lines 40, 109, 129):
```cpp
    HavocWindow->setStyleSheet( ThemeManager::Instance().Stylesheet( "Havoc" ) );
```

Replace that single line with:
```cpp
    qApp->setStyleSheet( ThemeManager::GlobalStylesheet() );
```

Then find and **delete** these two lines (they are now covered by the qApp call above):
```cpp
    TeamserverTabWidget->setStyleSheet( ThemeManager::Instance().Stylesheet( "teamserverTab" ) );
```
```cpp
    menubar->setStyleSheet( ThemeManager::Instance().Stylesheet( "menubar" ) );
```

- [ ] **Step 3: Re-apply global stylesheet when the user switches themes**

Find the theme-switch handler (around line 186). It currently reads:
```cpp
                if ( ThemeManager::Instance().SetActive( name ) ) {
```

Add the re-application line immediately inside the `if` block after `SetActive` returns true. Find the first statement after that `if (` line and add before it:
```cpp
                    qApp->setStyleSheet( ThemeManager::GlobalStylesheet() );
```

So the block becomes:
```cpp
                if ( ThemeManager::Instance().SetActive( name ) ) {
                    qApp->setStyleSheet( ThemeManager::GlobalStylesheet() );
                    // ... existing code that was here ...
```

- [ ] **Step 4: Verify the changes**

```bash
grep -n "setStyleSheet\|GlobalStylesheet\|QApplication" client/src/UserInterface/HavocUi.cc | head -20
```

Expected: `#include <QApplication>`, one `qApp->setStyleSheet( ThemeManager::GlobalStylesheet() )` in setupUi, one `qApp->setStyleSheet( ThemeManager::GlobalStylesheet() )` in the theme-change handler. NO remaining calls to `Stylesheet("Havoc")`, `Stylesheet("teamserverTab")`, or `Stylesheet("menubar")`.

- [ ] **Step 5: Commit**

```bash
git add client/src/UserInterface/HavocUi.cc
git commit -m "feat(client): apply dynamic global stylesheet via qApp; re-apply on theme switch"
```

---

### Task 4: Remove redundant static QSS calls from dialogs

**Files:**
- Modify: `client/src/UserInterface/Dialogs/Connect.cc:21`
- Modify: `client/src/UserInterface/Dialogs/Payload.cc:150`

- [ ] **Step 1: Remove the static QSS call in Connect.cc**

Find this exact line (line 21):
```cpp
    Form->setStyleSheet( ThemeManager::Instance().Stylesheet( "Dialogs/Connect" ) );
```

Delete this line entirely. The Connect dialog now inherits from `qApp` global stylesheet which covers all its widget types.

- [ ] **Step 2: Remove the static QSS call in Payload.cc**

Find this exact line (around line 150):
```cpp
    PayloadDialog->setStyleSheet( ThemeManager::Instance().Stylesheet( "Dialogs/BasicDialog" ) );
```

Delete this line entirely. Same reason — `GlobalStylesheet()` covers `QDialog`, `QLineEdit`, `QComboBox`, `#ConfigItem`, `#bool`, `#text`, `#list` etc.

- [ ] **Step 3: Verify neither file has the removed calls**

```bash
grep -n 'Stylesheet.*Connect\|Stylesheet.*BasicDialog' \
  client/src/UserInterface/Dialogs/Connect.cc \
  client/src/UserInterface/Dialogs/Payload.cc
```

Expected: no output (both lines removed).

- [ ] **Step 4: Commit**

```bash
git add client/src/UserInterface/Dialogs/Connect.cc client/src/UserInterface/Dialogs/Payload.cc
git commit -m "refactor(client): remove redundant static QSS calls — GlobalStylesheet() covers these dialogs"
```

---

### Task 5: Update documentation files

**Files:**
- Modify: `CLAUDE.md`
- Modify: `AGENTS.md`
- Modify: `SKILL.md`
- Modify: `CHANGES.md`

- [ ] **Step 1: Add theming constraint to CLAUDE.md**

Find the `### Debug Output String Formatting` section in CLAUDE.md. Insert the following block **before** it:

```markdown
### Qt5 Client Theming (HVC-049)

**Never hardcode theme colors in QSS files or inline stylesheets.** All color values
must come from `ThemeManager::ActiveColors()`. The Dracula QSS files in
`client/data/stylesheets/` are legacy references only — they are not loaded for any
non-Dracula theme and must not be extended.

**Widget styling must use `ThemeManager::GlobalStylesheet()`** applied at application
level via `qApp->setStyleSheet(ThemeManager::GlobalStylesheet())`. This single call
propagates to every widget in the application. Per-widget `setStyleSheet()` calls are
only permitted when a widget needs structural overrides (sizes, padding, radius) that
differ from the global defaults — never for color-only overrides.

**On theme switch**, always call `qApp->setStyleSheet(ThemeManager::GlobalStylesheet())`
immediately after `ThemeManager::Instance().SetActive(name)` succeeds. Failing to do
this leaves all widgets showing stale colors until the application restarts.

**ThemeColors field roles for QSS:**
- `accent` — focus borders, checkbox indicator, button background
- `selection` — normal (unfocused) widget borders, secondary backgrounds
- `panel` — dialog/widget background
- `bgMain` — main window background
- `text` — foreground text
- `muted` — disabled text, scrollbar handles
- `tabHighlight` — active tab underline
- `green` — config item value text (`#ConfigItem`, `#bool`, `#text`, `#list`)
```

- [ ] **Step 2: Add QA checklist item to AGENTS.md**

Find the QA Checklist section in AGENTS.md. Add after the last checklist item before the next major heading:

```markdown
- [ ] **Theme color hardcoding (HVC-049):** No QSS file or inline `setStyleSheet()` call
  may contain hardcoded hex colors. All colors must come from `ThemeManager::ActiveColors()`
  fields. New widgets added to any dialog must be covered by `GlobalStylesheet()` — verify
  by switching to DarkBubble theme and confirming all borders/fills use yellow/pink accent
  rather than Dracula purple `#bd93f9` or Dracula pink `#ff79c6`. Check that `qApp->setStyleSheet()`
  is called on theme switch (`ThemeManager::SetActive()` success path in HavocUi.cc).
```

- [ ] **Step 3: Add theming lesson to SKILL.md**

Find the `skill: implement-demon-feature` section. Add a new skill section for client theming at the end of SKILL.md:

```markdown
---

### skill: add-themed-widget

**When to invoke:** Adding any new Qt5 widget (QCheckBox, QLineEdit, QComboBox, QSpinBox,
QGroupBox, QPushButton, etc.) to any dialog or widget in the Havoc client.

#### Procedure

**Step 1 — No per-widget color styling**
Do NOT call `widget->setStyleSheet("QCheckBox::indicator { border: 1px solid #ff79c6; }")`.
This hardcodes Dracula colors and breaks every other theme.

**Step 2 — Check if GlobalStylesheet() already covers it**
Open `ThemeManager::GlobalStylesheet()` in `client/src/Util/ThemeManager.cpp`. If the
widget type is already styled there (QLineEdit, QCheckBox, QComboBox, etc.), no additional
work is needed — the widget inherits from `qApp->setStyleSheet()` automatically.

**Step 3 — If the widget type is missing from GlobalStylesheet(), add it there**
Follow the existing pattern: use `%5` for accent/focus colors, `%4` for normal borders,
`%2` for backgrounds, `%3` for text, `%6` for disabled/muted states. Never use a literal
hex color.

**Step 4 — Structural overrides only in per-widget calls**
If the widget needs custom SIZE/PADDING (not color), use a per-widget `setStyleSheet()`
with only structural properties: `border-radius`, `padding`, `margin`, `min-height`, etc.
Example: `widget->setStyleSheet("QPushButton { padding: 30px; border-radius: 4px; }");`

**Step 5 — Test with DarkBubble theme**
Switch to DarkBubble. The accent color is `#ee5285` (pink-red). Any widget showing
Dracula purple (`#bd93f9`) or Dracula pink (`#ff79c6`) has a hardcoded color that must
be moved into `GlobalStylesheet()`.
```

- [ ] **Step 4: Add CHANGES.md entry**

Find the top of CHANGES.md (after the header/format section, before the first `## Version` block). Insert:

```markdown
### HVC-049 — Dynamic Theme-Aware Global Stylesheet

- Root cause: all `.qss` files in `client/data/stylesheets/` hardcoded Dracula colors
  (`#282a36`, `#ff79c6`, `#bd93f9`). Every non-Dracula theme silently loaded the Dracula
  QSS because per-theme QSS files did not exist.
- Fix: added `ThemeManager::GlobalStylesheet()` — generates a complete application
  stylesheet from `ActiveColors()` using 9 theme color fields as QSS parameters.
- Covers all previously missing widget types: `QCheckBox::indicator` border/fill,
  `QLineEdit:focus` border, `QSpinBox`, `QComboBox:focus`, `QPlainTextEdit:focus`,
  `QTextEdit:focus`, plus all existing widget types now using correct theme colors.
- Applied via `qApp->setStyleSheet(ThemeManager::GlobalStylesheet())` at startup and
  on every theme switch. Widget-level inline stylesheets (Listener.cc dynamic generation)
  take full Qt precedence and are unaffected.
- Removed redundant per-widget calls: `HavocWindow->setStyleSheet(Stylesheet("Havoc"))`,
  `TeamserverTabWidget->setStyleSheet(Stylesheet("teamserverTab"))`,
  `menubar->setStyleSheet(Stylesheet("menubar"))`, `Form->setStyleSheet(Stylesheet("Dialogs/Connect"))`,
  `PayloadDialog->setStyleSheet(Stylesheet("Dialogs/BasicDialog"))`.
- Any present or future theme (including user-defined) automatically gets correct styling
  by defining its 15 `ThemeColors` fields — no per-theme QSS files ever required.
- Architecture doc: `improvement-docs/HVC-049-dynamic-theme-stylesheet.md`

Files: `client/include/Util/ThemeManager.hpp`, `client/src/Util/ThemeManager.cpp`,
       `client/src/UserInterface/HavocUi.cc`,
       `client/src/UserInterface/Dialogs/Connect.cc`,
       `client/src/UserInterface/Dialogs/Payload.cc`

---
```

- [ ] **Step 5: Commit documentation**

```bash
git add CLAUDE.md AGENTS.md SKILL.md CHANGES.md
git commit -m "docs: document HVC-049 theming pattern in CLAUDE.md, AGENTS.md, SKILL.md, CHANGES.md"
```

---

## Self-Review

**Spec coverage check:**
- ✅ QCheckBox indicator border/fill → Task 2 (`QCheckBox::indicator:checked { background: %5; }`)
- ✅ QLineEdit focus border → Task 2 (`QLineEdit:focus { border: 1px solid %5; }`)
- ✅ QSpinBox border → Task 2
- ✅ QComboBox focus → Task 2
- ✅ QPlainTextEdit/QTextEdit → Task 2
- ✅ All other widget types → Task 2
- ✅ Apply via qApp → Task 3
- ✅ Theme switch re-apply → Task 3
- ✅ Remove Connect.cc static call → Task 4
- ✅ Remove Payload.cc static call → Task 4
- ✅ Future themes automatic → follows from GlobalStylesheet() design
- ✅ CLAUDE.md/AGENTS.md/SKILL.md/CHANGES.md → Task 5

**Placeholder scan:** No TBDs, no "handle appropriately", all steps have exact code.

**Type consistency:** `ThemeManager::GlobalStylesheet()` declared in Task 1, implemented in Task 2, called in Task 3. Consistent throughout.
