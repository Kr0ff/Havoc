#ifndef HAVOC_THEME_MANAGER_HPP
#define HAVOC_THEME_MANAGER_HPP

#include <QString>
#include <QByteArray>
#include <QList>
#include <QMap>

/*
 * ThemeManager
 * ------------
 * Central authority for the Havoc client's UI theme. Replaces scattered
 * FileRead(":/stylesheets/<name>") calls with a single indirection that can
 * serve stylesheet bytes from:
 *
 *   1. A user theme directory under ~/.havoc/themes/<ThemeName>/
 *   2. A builtin theme embedded in Qt resources (Dracula -> :/stylesheets/<name>,
 *      Light -> :/themes/Light/<name>)
 *   3. The embedded Dracula resource as a guaranteed fallback if the active
 *      theme does not override a particular logical name.
 *
 * Theme changes are NOT applied live — many Havoc widgets cache their
 * stylesheet in their constructor, so mid-run swaps would leave the UI
 * half-themed. SetActive() persists the selection to ~/.havoc/theme.conf and
 * the caller is expected to show a "Restart required" dialog.
 */
class ThemeManager {
public:
    struct ThemeInfo {
        QString name;         // directory / identifier used in theme.conf
        QString displayName;  // shown in the menu
        QString author;
        QString version;
        QString description;
        QString path;         // absolute path (empty for builtins)
        bool    builtin;      // true  -> served from Qt resources
                              // false -> served from ~/.havoc/themes/
    };

    struct ThemeColors {
        QString bgMain;       // main window background
        QString panel;        // dialogs, tables, menus, text edits bg
        QString selection;    // selected items, headers, borders
        QString text;         // primary foreground
        QString accent;       // button bg/border
        QString muted;        // disabled/comment text
        QString tabHighlight; // active tab border
        QString okAccent;     // message box OK button border
        // Console/terminal colors (mapped to ColorText globals)
        QString cyan;
        QString green;
        QString orange;
        QString pink;
        QString purple;
        QString red;
        QString yellow;
    };

    static ThemeManager& Instance();

    // Discover all themes, select the configured one, and preload its
    // stylesheets into an in-memory cache. Call exactly once at startup,
    // after QApplication is constructed but before any setStyleSheet call.
    void Init();

    // All discovered themes (builtins + validated user themes).
    QList<ThemeInfo> Available() const;

    // Name of the currently active theme (never empty after Init()).
    QString ActiveName() const;

    // Color palette for the active theme. Used by C++ code that builds
    // inline stylesheets or needs theme colors outside of QSS files.
    const ThemeColors& ActiveColors() const;

    // Returns a QMenu + QAction inline stylesheet using the active theme
    // palette. Replaces the hardcoded Dracula MenuStyle strings scattered
    // across ~10 widget source files.
    static QString MenuStyleSheet();

    // Persist a new active theme. Returns false if the name is not in
    // Available(). Does NOT hot-reload — caller shows a restart dialog.
    bool SetActive( const QString& name );

    // Main accessor used by the rest of the UI code. logicalName is one of:
    //   "Havoc", "menubar", "teamserverTab", "bottomTab",
    //   "MessageBox", "MenuStyle",
    //   "Dialogs/Connect", "Dialogs/Listener", "Dialogs/BasicDialog",
    //   "Dialogs/FileDialog", "Dialogs/Preferences"
    // On cache miss, falls back to the embedded Dracula resource so the UI
    // always has a valid stylesheet.
    QByteArray Stylesheet( const QString& logicalName ) const;

private:
    ThemeManager() = default;
    ThemeManager( const ThemeManager& )            = delete;
    ThemeManager& operator=( const ThemeManager& ) = delete;

    void       Discover();
    bool       Validate( const QString& themeDir, QString* err ) const;
    QByteArray LoadLogical( const ThemeInfo& info, const QString& logicalName ) const;
    void       PopulateCache( const ThemeInfo& info );
    void       InitPalette();
    void       ApplyColorText() const;

    QString                   userThemesDir_;
    QMap<QString, ThemeInfo>  themes_;       // name -> info
    QMap<QString, QByteArray> activeCache_;  // logicalName -> contents
    QString                   activeName_;
    ThemeColors               activeColors_;
};

#endif // HAVOC_THEME_MANAGER_HPP
