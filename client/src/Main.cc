#include <global.hpp>
#include <Havoc/Havoc.hpp>
#include <Util/ThemeManager.hpp>
#include <QTimer>

auto main(
    int    argc,
    char** argv
) -> int {
    auto HavocApp = QApplication( argc, argv );
    auto Status   = 0;

    // Load the selected theme before any widget is constructed, so that
    // setStyleSheet() calls inside HavocUi::setupUi() and the various
    // dialogs read from the right source.
    ThemeManager::Instance().Init();

    QGuiApplication::setWindowIcon( QIcon( ":/Havoc.ico" ) );

    HavocNamespace::HavocApplication = new HavocNamespace::HavocSpace::Havoc( new QMainWindow );
    HavocNamespace::HavocApplication->Init( argc, argv );

    Status = QApplication::exec();

    spdlog::info( "Havoc Application status: {}", Status );

    return Status;
}
