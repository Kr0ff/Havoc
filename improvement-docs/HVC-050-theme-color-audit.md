# HVC-050: Theme Color Audit — Findings and Fix Plan

**Status:** Pending Approval
**Date:** 2026-05-29
**Scope:** All non-Dracula themes (Light, GreenNight, PinkLady, Emerald, DarkBubble)
**Components:** client/data/themes/, client/src/UserInterface/, client/src/Util/ThemeManager.cpp

---

## Executive Summary

A thorough audit of all five non-Dracula themes identified five distinct issues causing theme
colors to be ignored or incorrectly applied. The most critical is that the Connect dialog
receives **no stylesheet at all** — it always shows with the system default Qt style. The
second most critical is a Dracula-adjacent color (`#1c1e25`) hardcoded in the disabled
QGroupBox style for ALL per-theme Listener.qss files, producing a near-black box on the
Light theme's white background.

All per-theme QSS files have correct internal contrast (dark backgrounds paired with light
text on dark themes; light backgrounds with dark text on the Light theme). No full-palette
Dracula color leaks were found in the per-theme QSS files. The issues are localized to
specific hardcoded values and one missing `setStyleSheet()` call.

---

## Theme Palettes (Reference)

| Theme     | Main BG    | Panel BG   | Selection  | Text       | Accent     | Muted      |
|-----------|------------|------------|------------|------------|------------|------------|
| Light     | `#f5f5f5`  | `#ffffff`  | `#e8e8f0`  | `#1e1e2e`  | `#5a4fcf`  | `#4a4e6a`  |
| GreenNight| `#0b0f0c`  | `#141915`  | `#2b342d`  | `#b7d3bd`  | `#6ab67c`  | `#5c6a5e`  |
| PinkLady  | `#190d16`  | `#261623`  | `#472d42`  | `#dabed4`  | `#d479c3`  | `#885b7f`  |
| Emerald   | `#080b0d`  | `#101416`  | `#272f32`  | `#c1d5de`  | `#49aac5`  | `#57666c`  |
| DarkBubble| `#050606`  | `#090b0b`  | `#252929`  | `#cddeda`  | `#ee5285`  | `#5a6160`  |

---

## Issues Found

### ISSUE 1 — CRITICAL: Connect dialog has no stylesheet applied

**File:** `client/src/UserInterface/Dialogs/Connect.cc`
**Severity:** Critical — entire dialog is unthemed regardless of active theme

**Root Cause:**
`Connect::setupUi(QDialog* Form)` never calls `Form->setStyleSheet()`. QDialog is a
top-level window; it does not inherit from `HavocWindow` and receives no stylesheet.
Since `qApp->setStyleSheet()` is also not used (HVC-049 v1 was reverted), the Connect
dialog always renders with the system default Qt style on every theme.

The per-theme `Dialogs/Connect.qss` files exist in all five themes and are properly
registered in `Havoc.qrc`, but are never loaded.

**Impact:**
- Connect dialog background, text, buttons, and fields all show in system default colors
- The dialog appears visually inconsistent on every non-default theme
- `Qt::gray` and `Qt::white` QPalette colors (lines 106-109, 312, 332) compound this —
  they are applied to `lineEdit_Name` to indicate read-only state, but since the dialog
  is unthemed the whole field base color is already wrong

**Fix:**
Add one line in `setupUi()` after `Form->setWindowTitle(...)` (line 111):
```cpp
Form->setStyleSheet( ThemeManager::Instance().Stylesheet( "Dialogs/Connect" ) );
```

Additionally, replace the hardcoded `Qt::gray` / `Qt::white` QPalette for the
read-only field indicator with theme-aware colors:
```cpp
// Replace line 106:
paletteGray->setColor( QPalette::Base, QColor( ThemeManager::Instance().ActiveColors().selection ) );
// Replace line 109:
paletteWhite->setColor( QPalette::Base, QColor( ThemeManager::Instance().ActiveColors().panel ) );
```

---

### ISSUE 2 — HIGH: `#1c1e25` hardcoded in all per-theme Listener.qss (disabled QGroupBox)

**Files:**
- `client/data/themes/Light/Dialogs/Listener.qss` lines 59-60
- `client/data/themes/GreenNight/Dialogs/Listener.qss` lines 59-60
- `client/data/themes/PinkLady/Dialogs/Listener.qss` lines 59-60
- `client/data/themes/Emerald/Dialogs/Listener.qss` lines 59-60
- `client/data/themes/DarkBubble/Dialogs/Listener.qss` lines 59-60

**Severity:** Critical for Light theme; Moderate for all dark themes

**Root Cause:**
The `QGroupBox:!enabled` rule was copied from the Dracula reference without being adapted
to each theme's palette. `#1c1e25` is a Dracula-adjacent near-black not defined in any
non-Dracula theme's palette.

**Impact per theme:**
- **Light**: `#1c1e25` (near-black) on `#f5f5f5` (near-white) background — disabled
  GroupBox appears as a black rectangle on a white page. **Severe readability failure.**
- **GreenNight**: `#1c1e25` (blue-gray) vs. theme panel `#141915` (green-black) — wrong
  tint, should use the theme's own green-black tone
- **PinkLady**: `#1c1e25` (blue-gray) vs. theme panel `#261623` (deep magenta-black) — wrong hue
- **Emerald**: `#1c1e25` (blue-gray) vs. theme panel `#101416` (teal-black) — wrong hue
- **DarkBubble**: `#1c1e25` (blue-gray) vs. theme panel `#090b0b` (near-black) — closest
  in darkness but still wrong tint

**Fix (per file):**
The `QGroupBox:!enabled` background and border should use the theme's own panel color, making
the disabled group blend into the parent background (standard disabled-state pattern).

```css
/* Light/Dialogs/Listener.qss lines 59-60 */
    background: #e8e8f0;          /* was #1c1e25 — use theme selection color for disabled */
    border: 1px solid #e8e8f0;

/* GreenNight/Dialogs/Listener.qss lines 59-60 */
    background: #141915;          /* was #1c1e25 — use theme panel color */
    border: 1px solid #141915;

/* PinkLady/Dialogs/Listener.qss lines 59-60 */
    background: #261623;          /* was #1c1e25 — use theme panel color */
    border: 1px solid #261623;

/* Emerald/Dialogs/Listener.qss lines 59-60 */
    background: #101416;          /* was #1c1e25 — use theme panel color */
    border: 1px solid #101416;

/* DarkBubble/Dialogs/Listener.qss lines 59-60 */
    background: #090b0b;          /* was #1c1e25 — use theme panel color */
    border: 1px solid #090b0b;
```

---

### ISSUE 3 — HIGH: Store.cc hardcodes `#71e0cb` (cyan) for author label text

**File:** `client/src/UserInterface/Widgets/Store.cc`
**Lines:** 44 and 143
**Severity:** High — color ignores theme; not readable on all backgrounds

**Root Cause:**
```cpp
// Line 44:
panelLabelAuthor = new QLabel( "<span style='color:#71e0cb'>The author</span>", panelStore );
// Line 143:
panelLabelAuthor->setText(QString("<span style='color:#71e0cb'>%1</span>").arg(author));
```

`#71e0cb` is a teal/cyan color chosen for Dracula readability. It is not in any theme
palette and is not routed through `ThemeManager::ActiveColors()`.

**Impact:**
- On dark themes (all non-Light): teal text is generally readable but off-palette
- On Light theme (`#f5f5f5` background): `#71e0cb` may have insufficient contrast
  (light teal on near-white background — WCAG ratio ~2.1:1, below 4.5:1 minimum)

**Fix:**
Replace the hardcoded color with the theme's accent color:
```cpp
// Line 44:
panelLabelAuthor = new QLabel(
    QString( "<span style='color:%1'>The author</span>" )
        .arg( ThemeManager::Instance().ActiveColors().accent ),
    panelStore );
// Line 143:
panelLabelAuthor->setText(
    QString( "<span style='color:%1'>%2</span>" )
        .arg( ThemeManager::Instance().ActiveColors().accent )
        .arg( author ) );
```

Note: `ThemeColors` must have an `accent` member. Based on the palette table above,
the accent color for each theme is already present and readable on each theme's background.

---

### ISSUE 4 — MEDIUM: About.cc hardcodes `#e100ff` (bright magenta) in HTML link

**File:** `client/src/UserInterface/Dialogs/About.cc`
**Line:** 43
**Severity:** Medium — color is readable but does not follow any theme palette

**Root Cause:**
```cpp
"<span style=\" text-decoration: underline; color:#e100ff;\">5pider</span>"
```

`#e100ff` is a saturated magenta not present in any theme palette. It was likely chosen
for visibility on the Dracula background.

**Impact:**
- On dark themes: readable but visually inconsistent with the theme accent
- On Light theme (`#ffffff` background): `#e100ff` has sufficient contrast (~3.8:1)
  but does not match the theme style

**Fix:**
Generate the HTML color dynamically:
```cpp
QString linkColor = ThemeManager::Instance().ActiveColors().accent;
// Use linkColor in the HTML string construction instead of hardcoded #e100ff
```

The specific implementation depends on how the full HTML string is built in About.cc line 43.

---

### ISSUE 5 — LOW: ThemeManager::InitPalette() falls back to Dracula for unknown themes

**File:** `client/src/Util/ThemeManager.cpp` (lines ~559-572)
**Severity:** Low — only affects user-added custom themes, not the five built-in themes

**Root Cause:**
The `else` branch of `InitPalette()` assigns Dracula colors to `activeColors_` for any
theme not explicitly handled (Light, GreenNight, PinkLady, Emerald, DarkBubble, Dracula).
This means inline-styled widgets (Chat, LootWidget, etc.) use Dracula colors even if the
custom theme's QSS files define completely different colors.

**Impact:** Inline stylesheet components (chat input, loot widget labels) use Dracula colors
for any user-added custom theme. The QSS-based styling applies correctly; only the
`ActiveColors()` path is wrong.

**Note:** This issue does NOT affect the five built-in themes. No fix is required for HVC-050;
document for a future custom-theme support ticket.

---

## No Issues Found In

- All per-theme `Havoc.qss` files: correct contrast for their respective palettes
- All per-theme `menubar.qss` files: correct per-theme colors
- All per-theme `teamserverTab.qss` files: correct per-theme colors
- All per-theme `MenuStyle.qss` files: correct per-theme colors
- All per-theme `MessageBox.qss` files: correct per-theme colors
- All per-theme `Dialogs/Preferences.qss` files: correct per-theme colors
- All per-theme `Dialogs/BasicDialog.qss` files: correct per-theme colors
- All per-theme `Dialogs/FileDialog.qss` files: correct per-theme colors
- `ThemeManager::Stylesheet()` routing: correct for all five built-in themes
- `Havoc.qrc` registration: all per-theme QSS files properly registered
- `HavocUi.cc` stylesheet calls: correct (post-construction, using ThemeManager)
- `Listener.cc` inline stylesheet: correctly uses ThemeManager::ActiveColors()
- `LootWidget.cc` inline stylesheet: correctly uses ThemeManager::ActiveColors()
- `Payload.cc` inline stylesheet: correctly uses ThemeManager::ActiveColors()

---

## Fix Priority and Implementation Order

| # | Issue | Files | Priority |
|---|-------|-------|----------|
| 1 | Connect dialog: missing `Form->setStyleSheet()` + `Qt::gray`/`Qt::white` palette | `Connect.cc` | P0 — CRITICAL |
| 2 | `#1c1e25` in disabled GroupBox (all Listener.qss) | 5 × `Dialogs/Listener.qss` | P0 — CRITICAL (Light) / P1 (dark) |
| 3 | `#71e0cb` hardcoded cyan in Store.cc | `Store.cc` | P1 — HIGH |
| 4 | `#e100ff` hardcoded magenta in About.cc | `About.cc` | P2 — MEDIUM |
| 5 | Dracula fallback for unknown themes in ThemeManager | `ThemeManager.cpp` | P3 — future ticket |

---

## File Map for Implementation

```
client/src/UserInterface/Dialogs/Connect.cc     — add setStyleSheet + fix QPalette
client/data/themes/Light/Dialogs/Listener.qss  — fix #1c1e25 → #e8e8f0
client/data/themes/GreenNight/Dialogs/Listener.qss — fix #1c1e25 → #141915
client/data/themes/PinkLady/Dialogs/Listener.qss   — fix #1c1e25 → #261623
client/data/themes/Emerald/Dialogs/Listener.qss    — fix #1c1e25 → #101416
client/data/themes/DarkBubble/Dialogs/Listener.qss — fix #1c1e25 → #090b0b
client/src/UserInterface/Widgets/Store.cc       — fix #71e0cb → ActiveColors().accent
client/src/UserInterface/Dialogs/About.cc       — fix #e100ff → ActiveColors().accent
```

---

## ThemeColors Struct Field Required for P1/P2 Fix

Issues 3 and 4 require `ThemeManager::ActiveColors()` to expose an `accent` field. Verify
whether `ThemeColors` already has this field by reading `client/include/Util/ThemeManager.hpp`.
If absent, the field must be added to the struct and populated in `InitPalette()` for all
five themes using the accent colors from the palette table above.

---

## QA Checklist (post-fix)

1. Connect dialog: launch client, open Connect dialog on each theme — background and fields
   must match the theme palette; the `lineEdit_Name` read-only indicator must not appear as
   a bright white or gray box on dark themes.
2. Listener dialog: open Listener dialog on each theme; disable a GroupBox if possible —
   the disabled GroupBox must blend with the panel (not appear as a black rectangle).
3. Store widget: open the Store on each theme — author label text must be readable against
   the panel background.
4. About dialog: open About on each theme — the link text must match the theme accent.
5. Theme switch at runtime: switch between all themes after opening Store and About dialogs;
   verify colors update correctly.
6. Light theme contrast: specifically verify all changed elements on Light theme for WCAG
   AA compliance (4.5:1 ratio for normal text).
