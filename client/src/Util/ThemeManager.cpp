#include <Util/ThemeManager.hpp>
#include <Util/Base.hpp>
#include <Util/ColorText.h>

#include <spdlog/spdlog.h>

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDirIterator>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTextStream>

/*
 * ThemeManager implementation — see ThemeManager.hpp for the design overview.
 *
 * Loading strategy at startup (Init):
 *   1. Ensure ~/.havoc/ and ~/.havoc/themes/ exist (never touch anything else).
 *   2. Register two builtin themes: Dracula (served from :/stylesheets/...)
 *      and Light (served from :/themes/Light/...).
 *   3. Walk ~/.havoc/themes/ and register every subdirectory that passes
 *      Validate(). Invalid directories are logged and skipped.
 *   4. Read ~/.havoc/theme.conf. If the named theme is registered, pick it;
 *      otherwise fall back to "Dracula" with a warning.
 *   5. Pre-load every known logical stylesheet name for the active theme
 *      into activeCache_. Missing entries are tolerated — Stylesheet() falls
 *      back to the embedded Dracula resource on cache miss.
 */

namespace {

// Logical stylesheet names the rest of the client asks for. Kept here as a
// single source of truth so Init() can preload them without hardcoding the
// same list in multiple places.
const QStringList kLogicalNames = {
    QStringLiteral( "Havoc" ),
    QStringLiteral( "menubar" ),
    QStringLiteral( "teamserverTab" ),
    QStringLiteral( "bottomTab" ),
    QStringLiteral( "MessageBox" ),
    QStringLiteral( "MenuStyle" ),
    QStringLiteral( "Dialogs/Connect" ),
    QStringLiteral( "Dialogs/Listener" ),
    QStringLiteral( "Dialogs/BasicDialog" ),
    QStringLiteral( "Dialogs/FileDialog" ),
    QStringLiteral( "Dialogs/Preferences" ),
};

// Validation limits — tight enough to stop a malicious theme from doing
// anything unusual, loose enough to fit every existing Havoc stylesheet
// (the largest today is Havoc.qss at ~5 KB).
constexpr qint64 kMaxFileBytes    = 64 * 1024;
constexpr int    kMaxFilesInTheme = 32;

bool IsAllowedByte( unsigned char b )
{
    // Printable ASCII plus tab/lf/cr. Rejects NUL, most control codes, and
    // anything outside 7-bit (keeps copy-pasted smart quotes, zero-width
    // chars, and weird Unicode out of stylesheets entirely).
    if ( b == 0x09 || b == 0x0A || b == 0x0D ) return true;
    return b >= 0x20 && b <= 0x7E;
}

} // namespace

ThemeManager& ThemeManager::Instance()
{
    static ThemeManager instance;
    return instance;
}

void ThemeManager::Init()
{
    // Resolve and, if necessary, create the user themes directory. We only
    // create the missing pieces — never touch anything else under ~/.havoc/.
    const QString home  = QDir::homePath();
    const QString havoc = home + QStringLiteral( "/.havoc" );
    userThemesDir_      = havoc + QStringLiteral( "/themes" );

    QDir dir;
    if ( ! dir.exists( havoc ) ) {
        dir.mkpath( havoc );
    }
    if ( ! dir.exists( userThemesDir_ ) ) {
        dir.mkpath( userThemesDir_ );
    }

    Discover();

    // Read the saved preference. An empty, missing, or unknown value falls
    // back to the Dracula builtin — which is always registered, so this
    // cannot fail after Discover() has run.
    QString wanted;
    const QString confPath = havoc + QStringLiteral( "/theme.conf" );
    QFile confFile( confPath );
    if ( confFile.exists() && confFile.open( QIODevice::ReadOnly | QIODevice::Text ) ) {
        wanted = QString::fromUtf8( confFile.readAll() ).trimmed();
        confFile.close();
    }

    if ( wanted.isEmpty() || ! themes_.contains( wanted ) ) {
        if ( ! wanted.isEmpty() ) {
            spdlog::warn( "ThemeManager: configured theme '{}' not found, falling back to Dracula",
                          wanted.toStdString() );
        }
        wanted = QStringLiteral( "Dracula" );
    }

    activeName_ = wanted;
    PopulateCache( themes_[ activeName_ ] );
    InitPalette();
    ApplyColorText();

    spdlog::info( "ThemeManager: active theme = '{}' ({} themes available)",
                  activeName_.toStdString(), themes_.size() );
}

void ThemeManager::Discover()
{
    themes_.clear();

    // Builtin: Dracula — the existing Qt-resource stylesheet tree. No files
    // on disk; content is read from :/stylesheets/<name>.
    {
        ThemeInfo info;
        info.name        = QStringLiteral( "Dracula" );
        info.displayName = QStringLiteral( "Dracula (default)" );
        info.author      = QStringLiteral( "Havoc" );
        info.version     = QStringLiteral( "1.0" );
        info.description = QStringLiteral( "Default dark theme that ships with Havoc." );
        info.path        = QString();
        info.builtin     = true;
        themes_.insert( info.name, info );
    }

    // Builtin: Light — ships embedded under :/themes/Light/<name>.
    {
        ThemeInfo info;
        info.name        = QStringLiteral( "Light" );
        info.displayName = QStringLiteral( "Light" );
        info.author      = QStringLiteral( "Havoc" );
        info.version     = QStringLiteral( "1.0" );
        info.description = QStringLiteral( "Light palette builtin theme. Doubles as a template for custom themes." );
        info.path        = QString();
        info.builtin     = true;
        themes_.insert( info.name, info );
    }

    // Builtin: GreenNight — ships embedded under :/themes/GreenNight/<name>.
    {
        ThemeInfo info;
        info.name        = QStringLiteral( "GreenNight" );
        info.displayName = QStringLiteral( "Green Night" );
        info.author      = QStringLiteral( "Havoc" );
        info.version     = QStringLiteral( "1.0" );
        info.description = QStringLiteral( "Dark green palette from Xresources." );
        info.path        = QString();
        info.builtin     = true;
        themes_.insert( info.name, info );
    }

    // Builtin: PinkLady — ships embedded under :/themes/PinkLady/<name>.
    {
        ThemeInfo info;
        info.name        = QStringLiteral( "PinkLady" );
        info.displayName = QStringLiteral( "Pink Lady" );
        info.author      = QStringLiteral( "Havoc" );
        info.version     = QStringLiteral( "1.0" );
        info.description = QStringLiteral( "Dark magenta palette from Xresources." );
        info.path        = QString();
        info.builtin     = true;
        themes_.insert( info.name, info );
    }

    // Builtin: Emerald — ships embedded under :/themes/Emerald/<name>.
    {
        ThemeInfo info;
        info.name        = QStringLiteral( "Emerald" );
        info.displayName = QStringLiteral( "Emerald" );
        info.author      = QStringLiteral( "Havoc" );
        info.version     = QStringLiteral( "1.0" );
        info.description = QStringLiteral( "Dark teal palette from Xresources." );
        info.path        = QString();
        info.builtin     = true;
        themes_.insert( info.name, info );
    }

    // Builtin: DarkBubble — ships embedded under :/themes/DarkBubble/<name>.
    {
        ThemeInfo info;
        info.name        = QStringLiteral( "DarkBubble" );
        info.displayName = QStringLiteral( "Dark Bubble" );
        info.author      = QStringLiteral( "Havoc" );
        info.version     = QStringLiteral( "1.0" );
        info.description = QStringLiteral( "Near-black palette with pink and gold accents from Xresources." );
        info.path        = QString();
        info.builtin     = true;
        themes_.insert( info.name, info );
    }

    // User themes: walk ~/.havoc/themes/<subdir>/. Every direct child that
    // validates successfully becomes a theme. User themes with the same name
    // as a builtin shadow the builtin.
    QDir root( userThemesDir_ );
    if ( ! root.exists() ) {
        return;
    }
    const QStringList entries = root.entryList(
        QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name );
    for ( const QString& entry : entries ) {
        const QString themeDir = root.absoluteFilePath( entry );
        QString err;
        if ( ! Validate( themeDir, &err ) ) {
            spdlog::warn( "ThemeManager: user theme '{}' rejected: {}",
                          entry.toStdString(), err.toStdString() );
            continue;
        }

        // Read metadata from theme.json. Validate() already confirmed it
        // parses and has the required fields, so this re-read is safe.
        QFile manifest( themeDir + QStringLiteral( "/theme.json" ) );
        manifest.open( QIODevice::ReadOnly );
        const QJsonDocument doc = QJsonDocument::fromJson( manifest.readAll() );
        manifest.close();
        const QJsonObject obj = doc.object();

        ThemeInfo info;
        info.name        = obj.value( QStringLiteral( "name" ) ).toString( entry );
        info.displayName = obj.value( QStringLiteral( "displayName" ) ).toString( info.name );
        info.author      = obj.value( QStringLiteral( "author" ) ).toString();
        info.version     = obj.value( QStringLiteral( "version" ) ).toString();
        info.description = obj.value( QStringLiteral( "description" ) ).toString();
        info.path        = themeDir;
        info.builtin     = false;
        themes_.insert( info.name, info );
    }
}

bool ThemeManager::Validate( const QString& themeDir, QString* err ) const
{
    const auto fail = [ err ]( const QString& msg ) {
        if ( err ) *err = msg;
        return false;
    };

    // theme.json must exist, parse, and have string fields name + displayName.
    const QString manifestPath = themeDir + QStringLiteral( "/theme.json" );
    QFile manifest( manifestPath );
    if ( ! manifest.exists() ) {
        return fail( QStringLiteral( "missing theme.json" ) );
    }
    if ( manifest.size() > kMaxFileBytes ) {
        return fail( QStringLiteral( "theme.json is too large" ) );
    }
    if ( ! manifest.open( QIODevice::ReadOnly ) ) {
        return fail( QStringLiteral( "cannot open theme.json" ) );
    }
    const QByteArray manifestBytes = manifest.readAll();
    manifest.close();

    QJsonParseError parseErr{};
    const QJsonDocument doc = QJsonDocument::fromJson( manifestBytes, &parseErr );
    if ( parseErr.error != QJsonParseError::NoError || ! doc.isObject() ) {
        return fail( QStringLiteral( "theme.json is not a valid JSON object" ) );
    }
    const QJsonObject obj = doc.object();
    if ( ! obj.value( QStringLiteral( "name" ) ).isString() ||
         ! obj.value( QStringLiteral( "displayName" ) ).isString() ) {
        return fail( QStringLiteral( "theme.json must contain 'name' and 'displayName' strings" ) );
    }

    // Walk the directory, enforce size / count / content rules on every .qss.
    QDir themeDirObj( themeDir );
    int  fileCount = 0;

    // Precompiled regex used to sanity-check url(...) arguments in stylesheets.
    static const QRegularExpression urlRe(
        QStringLiteral( R"(url\s*\(\s*([^)]*)\s*\))" ),
        QRegularExpression::CaseInsensitiveOption );

    QDirIterator it( themeDir, QDir::Files, QDirIterator::Subdirectories );
    while ( it.hasNext() ) {
        const QString filePath = it.next();
        ++fileCount;
        if ( fileCount > kMaxFilesInTheme ) {
            return fail( QStringLiteral( "theme has more than %1 files" ).arg( kMaxFilesInTheme ) );
        }

        const QFileInfo fi( filePath );

        // Non-QSS files are allowed (screenshots, notes, theme.json itself),
        // but they still count against the file cap and the size cap.
        if ( fi.size() > kMaxFileBytes ) {
            return fail( QStringLiteral( "file '%1' exceeds %2 bytes" )
                         .arg( fi.fileName() )
                         .arg( kMaxFileBytes ) );
        }
        if ( fi.suffix().toLower() != QStringLiteral( "qss" ) ) {
            continue;
        }

        QFile f( filePath );
        if ( ! f.open( QIODevice::ReadOnly ) ) {
            return fail( QStringLiteral( "cannot open '%1'" ).arg( fi.fileName() ) );
        }
        const QByteArray bytes = f.readAll();
        f.close();

        int braceDepthOpen  = 0;
        int braceDepthClose = 0;
        for ( int i = 0; i < bytes.size(); ++i ) {
            const unsigned char b = static_cast<unsigned char>( bytes[ i ] );
            if ( ! IsAllowedByte( b ) ) {
                return fail( QStringLiteral( "file '%1' contains a disallowed byte 0x%2 at offset %3" )
                             .arg( fi.fileName() )
                             .arg( b, 2, 16, QChar( '0' ) )
                             .arg( i ) );
            }
            if ( b == '{' ) ++braceDepthOpen;
            else if ( b == '}' ) ++braceDepthClose;
        }
        if ( braceDepthOpen != braceDepthClose ) {
            return fail( QStringLiteral( "file '%1' has unbalanced braces (%2 open vs %3 close)" )
                         .arg( fi.fileName() )
                         .arg( braceDepthOpen )
                         .arg( braceDepthClose ) );
        }

        const QString text = QString::fromLatin1( bytes );
        if ( text.contains( QStringLiteral( "@import" ), Qt::CaseInsensitive ) ) {
            return fail( QStringLiteral( "file '%1' uses forbidden @import" ).arg( fi.fileName() ) );
        }

        // url() argument whitelist: must resolve to something inside the
        // theme directory. Reject absolute paths, parent traversal, and any
        // explicit scheme (file://, http://, etc).
        QRegularExpressionMatchIterator mi = urlRe.globalMatch( text );
        while ( mi.hasNext() ) {
            QString arg = mi.next().captured( 1 ).trimmed();
            if ( arg.startsWith( '"' ) && arg.endsWith( '"' ) && arg.size() >= 2 ) {
                arg = arg.mid( 1, arg.size() - 2 );
            } else if ( arg.startsWith( '\'' ) && arg.endsWith( '\'' ) && arg.size() >= 2 ) {
                arg = arg.mid( 1, arg.size() - 2 );
            }
            if ( arg.contains( QStringLiteral( "://" ) ) ) {
                return fail( QStringLiteral( "file '%1' uses url() with a scheme: %2" )
                             .arg( fi.fileName(), arg ) );
            }
            if ( QDir::isAbsolutePath( arg ) ) {
                return fail( QStringLiteral( "file '%1' uses url() with an absolute path: %2" )
                             .arg( fi.fileName(), arg ) );
            }
            const QString resolved = QDir::cleanPath( themeDirObj.absoluteFilePath( arg ) );
            const QString themeAbs = QDir::cleanPath( themeDirObj.absolutePath() ) +
                                     QStringLiteral( "/" );
            if ( ! ( resolved + QStringLiteral( "/" ) ).startsWith( themeAbs ) &&
                 resolved != QDir::cleanPath( themeDirObj.absolutePath() ) ) {
                return fail( QStringLiteral( "file '%1' uses url() that escapes the theme dir: %2" )
                             .arg( fi.fileName(), arg ) );
            }
        }
    }

    return true;
}

QByteArray ThemeManager::LoadLogical( const ThemeInfo& info, const QString& logicalName ) const
{
    // Builtin Dracula -> :/stylesheets/<name>
    // Builtin Light   -> :/themes/Light/<name>
    // User themes     -> <themeDir>/<name>.qss
    if ( info.builtin ) {
        if ( info.name == QStringLiteral( "Dracula" ) ) {
            return FileRead( QStringLiteral( ":/stylesheets/" ) + logicalName );
        }
        if ( info.name == QStringLiteral( "Light" ) ) {
            return FileRead( QStringLiteral( ":/themes/Light/" ) + logicalName );
        }
        if ( info.name == QStringLiteral( "GreenNight" ) ) {
            return FileRead( QStringLiteral( ":/themes/GreenNight/" ) + logicalName );
        }
        if ( info.name == QStringLiteral( "PinkLady" ) ) {
            return FileRead( QStringLiteral( ":/themes/PinkLady/" ) + logicalName );
        }
        if ( info.name == QStringLiteral( "Emerald" ) ) {
            return FileRead( QStringLiteral( ":/themes/Emerald/" ) + logicalName );
        }
        if ( info.name == QStringLiteral( "DarkBubble" ) ) {
            return FileRead( QStringLiteral( ":/themes/DarkBubble/" ) + logicalName );
        }
        return QByteArray();
    }

    const QString diskPath = info.path + QStringLiteral( "/" ) + logicalName + QStringLiteral( ".qss" );
    if ( ! QFile::exists( diskPath ) ) {
        return QByteArray();
    }
    QFile f( diskPath );
    if ( ! f.open( QIODevice::ReadOnly ) ) {
        return QByteArray();
    }
    const QByteArray bytes = f.readAll();
    f.close();
    return bytes;
}

void ThemeManager::PopulateCache( const ThemeInfo& info )
{
    activeCache_.clear();
    for ( const QString& logical : kLogicalNames ) {
        QByteArray bytes = LoadLogical( info, logical );
        if ( ! bytes.isEmpty() ) {
            activeCache_.insert( logical, bytes );
        }
    }
}

QByteArray ThemeManager::Stylesheet( const QString& logicalName ) const
{
    const auto it = activeCache_.find( logicalName );
    if ( it != activeCache_.end() ) {
        return it.value();
    }
    // Guaranteed fallback: the original Dracula resource. This keeps the UI
    // functional even if the active theme is missing this logical name.
    return FileRead( QStringLiteral( ":/stylesheets/" ) + logicalName );
}

QList<ThemeManager::ThemeInfo> ThemeManager::Available() const
{
    return themes_.values();
}

QString ThemeManager::ActiveName() const
{
    return activeName_;
}

bool ThemeManager::SetActive( const QString& name )
{
    if ( ! themes_.contains( name ) ) {
        spdlog::warn( "ThemeManager::SetActive: unknown theme '{}'", name.toStdString() );
        return false;
    }

    const QString confPath = QDir::homePath() + QStringLiteral( "/.havoc/theme.conf" );
    QSaveFile saver( confPath );
    if ( ! saver.open( QIODevice::WriteOnly | QIODevice::Text ) ) {
        spdlog::error( "ThemeManager::SetActive: cannot write '{}'", confPath.toStdString() );
        return false;
    }
    const QByteArray payload = name.toUtf8() + '\n';
    if ( saver.write( payload ) != payload.size() || ! saver.commit() ) {
        spdlog::error( "ThemeManager::SetActive: failed to commit '{}'", confPath.toStdString() );
        return false;
    }
    spdlog::info( "ThemeManager::SetActive: saved '{}' (takes effect on next launch)",
                  name.toStdString() );
    return true;
}

const ThemeManager::ThemeColors& ThemeManager::ActiveColors() const
{
    return activeColors_;
}

QString ThemeManager::MenuStyleSheet()
{
    const auto& c = Instance().activeColors_;
    return QStringLiteral(
        "QMenu {"
        "    background-color: %1;"
        "    color: %2;"
        "    border: 1px solid %3;"
        "}"
        "QMenu::separator {"
        "    background: %3;"
        "}"
        "QMenu::item:selected {"
        "    background: %3;"
        "}"
        "QAction {"
        "    background-color: %1;"
        "    color: %2;"
        "}"
    ).arg( c.panel, c.text, c.selection );
}
void ThemeManager::InitPalette()
{
    if ( activeName_ == QStringLiteral( "Dracula" ) ) {
        activeColors_ = {
            QStringLiteral( "#313342" ), QStringLiteral( "#282a36" ),
            QStringLiteral( "#44475a" ), QStringLiteral( "#f8f8f2" ),
            QStringLiteral( "#bd93f9" ), QStringLiteral( "#6272a4" ),
            QStringLiteral( "#ff79c6" ), QStringLiteral( "#50fa7b" ),
            QStringLiteral( "#8be9fd" ), QStringLiteral( "#50fa7b" ),
            QStringLiteral( "#ffb86c" ), QStringLiteral( "#ff79c6" ),
            QStringLiteral( "#bd93f9" ), QStringLiteral( "#ff5555" ),
            QStringLiteral( "#f1fa8c" )
        };
    } else if ( activeName_ == QStringLiteral( "Light" ) ) {
        activeColors_ = {
            QStringLiteral( "#f5f5f5" ), QStringLiteral( "#ffffff" ),
            QStringLiteral( "#e8e8f0" ), QStringLiteral( "#1e1e2e" ),
            QStringLiteral( "#5a4fcf" ), QStringLiteral( "#4a4e6a" ),
            QStringLiteral( "#c94f7c" ), QStringLiteral( "#1e8449" ),
            QStringLiteral( "#0097a7" ), QStringLiteral( "#1e8449" ),
            QStringLiteral( "#d35400" ), QStringLiteral( "#c94f7c" ),
            QStringLiteral( "#5a4fcf" ), QStringLiteral( "#c0392b" ),
            QStringLiteral( "#b7950b" )
        };
    } else if ( activeName_ == QStringLiteral( "GreenNight" ) ) {
        activeColors_ = {
            QStringLiteral( "#0b0f0c" ), QStringLiteral( "#141915" ),
            QStringLiteral( "#2b342d" ), QStringLiteral( "#b7d3bd" ),
            QStringLiteral( "#6ab67c" ), QStringLiteral( "#5c6a5e" ),
            QStringLiteral( "#d191c7" ), QStringLiteral( "#6ab67c" ),
            QStringLiteral( "#7ba9aa" ), QStringLiteral( "#6ab67c" ),
            QStringLiteral( "#ada378" ), QStringLiteral( "#d191c7" ),
            QStringLiteral( "#8ea2d8" ), QStringLiteral( "#e5c5e0" ),
            QStringLiteral( "#ebc3e4" )
        };
    } else if ( activeName_ == QStringLiteral( "PinkLady" ) ) {
        activeColors_ = {
            QStringLiteral( "#190d16" ), QStringLiteral( "#261623" ),
            QStringLiteral( "#472d42" ), QStringLiteral( "#dabed4" ),
            QStringLiteral( "#d479c3" ), QStringLiteral( "#885b7f" ),
            QStringLiteral( "#6687e6" ), QStringLiteral( "#53a36d" ),
            QStringLiteral( "#6687e6" ), QStringLiteral( "#53a36d" ),
            QStringLiteral( "#b2a75e" ), QStringLiteral( "#d479c3" ),
            QStringLiteral( "#968f65" ), QStringLiteral( "#db604b" ),
            QStringLiteral( "#aaa16f" )
        };
    } else if ( activeName_ == QStringLiteral( "Emerald" ) ) {
        activeColors_ = {
            QStringLiteral( "#080b0d" ), QStringLiteral( "#101416" ),
            QStringLiteral( "#272f32" ), QStringLiteral( "#c1d5de" ),
            QStringLiteral( "#49aac5" ), QStringLiteral( "#57666c" ),
            QStringLiteral( "#f276b7" ), QStringLiteral( "#76c2a8" ),
            QStringLiteral( "#49aac5" ), QStringLiteral( "#76c2a8" ),
            QStringLiteral( "#f69c3f" ), QStringLiteral( "#f276b7" ),
            QStringLiteral( "#5a91a3" ), QStringLiteral( "#eda771" ),
            QStringLiteral( "#91a652" )
        };
    } else if ( activeName_ == QStringLiteral( "DarkBubble" ) ) {
        activeColors_ = {
            QStringLiteral( "#050606" ), QStringLiteral( "#090b0b" ),
            QStringLiteral( "#252929" ), QStringLiteral( "#cddeda" ),
            QStringLiteral( "#ee5285" ), QStringLiteral( "#5a6160" ),
            QStringLiteral( "#cd9f45" ), QStringLiteral( "#518880" ),
            QStringLiteral( "#3a8ebe" ), QStringLiteral( "#518880" ),
            QStringLiteral( "#cd9f45" ), QStringLiteral( "#ee5285" ),
            QStringLiteral( "#ef7396" ), QStringLiteral( "#e06589" ),
            QStringLiteral( "#d1a13e" )
        };
    } else {
        // User theme or unknown — fall back to Dracula palette so inline
        // styles stay consistent with the default.
        activeColors_ = {
            QStringLiteral( "#313342" ), QStringLiteral( "#282a36" ),
            QStringLiteral( "#44475a" ), QStringLiteral( "#f8f8f2" ),
            QStringLiteral( "#bd93f9" ), QStringLiteral( "#6272a4" ),
            QStringLiteral( "#ff79c6" ), QStringLiteral( "#50fa7b" ),
            QStringLiteral( "#8be9fd" ), QStringLiteral( "#50fa7b" ),
            QStringLiteral( "#ffb86c" ), QStringLiteral( "#ff79c6" ),
            QStringLiteral( "#bd93f9" ), QStringLiteral( "#ff5555" ),
            QStringLiteral( "#f1fa8c" )
        };
    }
}

void ThemeManager::ApplyColorText() const
{
    using Hex = HavocNamespace::Util::ColorText::Colors::Hex;

    Hex::Background  = activeColors_.panel;
    Hex::Foreground  = activeColors_.text;
    Hex::Comment     = activeColors_.muted;
    Hex::CurrentLine = activeColors_.selection;
    Hex::Cyan        = activeColors_.cyan;
    Hex::Green       = activeColors_.green;
    Hex::Orange      = activeColors_.orange;
    Hex::Pink        = activeColors_.pink;
    Hex::Purple      = activeColors_.purple;
    Hex::Red         = activeColors_.red;
    Hex::Yellow      = activeColors_.yellow;
}
