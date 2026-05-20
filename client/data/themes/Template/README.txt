HAVOC CUSTOM THEME TEMPLATE
===========================

This directory is a ready-to-edit starting point for custom themes.

HOW TO USE
----------
1. Copy this entire directory to ~/.havoc/themes/MyTheme/
      cp -r <havoc-repo>/client/data/themes/Template ~/.havoc/themes/MyTheme
2. Edit theme.json and set "name" to "MyTheme" (must match the directory name)
3. Edit the .qss files to taste. Every hex color in the files is listed in
   the palette block at the top of Havoc.qss.
4. Restart Havoc and pick your theme from: Havoc > Theme > My Custom Theme

FILES
-----
  theme.json                    Manifest (required). Must contain string fields
                                "name" and "displayName".
  Havoc.qss                     Main window + global widgets (required).
  menubar.qss                   Top menu bar.
  teamserverTab.qss             Primary teamserver tab strip.
  bottomTab.qss                 Secondary/bottom tab strip.
  MessageBox.qss                QMessageBox dialog.
  MenuStyle.qss                 QMenu popup styling.
  Dialogs/BasicDialog.qss       Generic modal dialogs.
  Dialogs/Connect.qss           Connect-to-teamserver dialog.
  Dialogs/FileDialog.qss        File open/save dialog.
  Dialogs/Listener.qss          Listener configuration dialog.
  Dialogs/Preferences.qss       Preferences dialog.

Missing files are allowed — anything you don't override falls back to the
Dracula default. Extra files (screenshots, notes) are ignored.

VALIDATION RULES
----------------
A user theme is only loaded if it passes ALL of these checks:
  - theme.json parses and has string "name" and "displayName"
  - At most 32 files in the theme directory (recursive)
  - Every .qss file is at most 64 KB
  - Every byte is printable ASCII (0x20-0x7E) or whitespace (\t \n \r)
  - Per file, the count of '{' equals the count of '}'
  - No '@import' substring
  - Every url(...) argument is a relative path whose cleaned form stays
    inside the theme directory (no '..', no absolute paths, no file:// to
    anywhere outside the theme dir)

A theme that fails any check is skipped with an error in the log, and the
active theme falls back to Dracula.

PALETTE CONVENTIONS (as used by the Light builtin)
--------------------------------------------------
  #f5f5f5   main background
  #ffffff   panel / dialog background
  #e8e8f0   selection / hover
  #5a4fcf   purple accent (buttons, borders)
  #c94f7c   pink tab highlight
  #1e8449   ok / success accent
  #4a4e6a   muted text / disabled
  #1e1e2e   primary text
  #dcdce6   disabled widget background

Pick the same roles for your custom palette and substitute hex values
throughout the .qss files. The palette block in Havoc.qss documents every
role in place.
