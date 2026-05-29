cmake_minimum_required( VERSION 3.15 )
project( Havoc )

##
## Resolve the client source tree relative to this file.
## All header and source paths are prefixed with CLIENT_DIR so this build
## directory can live anywhere without duplicating any source files.
##
get_filename_component( CLIENT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../client" ABSOLUTE )

##
## C++ standard and Qt meta-object / resource compiler settings
##
set( CMAKE_CXX_STANDARD 20 )
set( CMAKE_AUTOMOC ON )
set( CMAKE_AUTORCC ON )
set( CMAKE_AUTOUIC ON )
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}" )
set( CMAKE_INCLUDE_CURRENT_DIR ON )

##
## Compiler flags
## -fpermissive is a GCC/Clang-only flag; guard it so MSVC builds are not broken.
##
if( NOT MSVC )
    add_compile_options( -fpermissive )
endif()

##
## Windows: target Windows 10+ APIs and suppress console window
##
if( WIN32 )
    add_compile_definitions( WINVER=0x0A00 _WIN32_WINNT=0x0A00 )
    if( MSVC )
        add_compile_definitions( _CRT_SECURE_NO_WARNINGS )
        add_compile_options( /W3 /wd4996 )
    endif()
endif()

##
## spdlog bundles fmt 9.1.0 whose consteval guard incorrectly enables
## FMT_CONSTEVAL=consteval on Apple Clang 15+ via the __cpp_consteval branch.
## Defining FMT_CONSTEVAL as empty disables compile-time format-string checking
## (a debug-only feature) while leaving all runtime logging behaviour unchanged.
##
add_definitions( -DFMT_CONSTEVAL= )
add_definitions( -DQT_NO_DEBUG_OUTPUT )

##
## Qt: prefer Qt6, fall back to Qt5.
## Qt5 is still the current version in use; Qt6 is required for native Windows
## builds because the Qt Company discontinued Qt5 Windows installer packages
## after 5.15 LTS.
##
set( REQUIRED_LIBS Core Gui Widgets Network WebSockets Sql )
find_package( QT NAMES Qt6 Qt5 COMPONENTS ${REQUIRED_LIBS} REQUIRED )
find_package( Qt${QT_MAJOR_VERSION} COMPONENTS ${REQUIRED_LIBS} REQUIRED )

if( QT_MAJOR_VERSION EQUAL 6 )
    set( REQUIRED_LIBS_QUALIFIED
         Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network Qt6::WebSockets Qt6::Sql )
else()
    set( REQUIRED_LIBS_QUALIFIED
         Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network Qt5::WebSockets Qt5::Sql )
endif()

##
## Python 3.10+: cross-platform detection via FindPython3 (CMake 3.12+).
## Replaces the three broken platform-specific blocks in the original CMakeLists.txt:
##   - Apple: hardcoded Homebrew python3.10 paths broken on 3.11+
##   - Unix:  deprecated find_package(PythonLibs 3) removed in CMake 3.27
##   - Win:   only set a version string, never found headers or libraries
##
find_package( Python3 3.10 COMPONENTS Interpreter Development REQUIRED )

##
## macOS: OpenSSL must be found explicitly because macOS ships LibreSSL which
## is not binary-compatible with Qt's TLS backend.
##
if( APPLE )
    find_package( OpenSSL REQUIRED )
endif()

##
## Include paths
##
include_directories( "${CLIENT_DIR}/include" )
include_directories( "${CLIENT_DIR}/external/spdlog/include" )
include_directories( "${CLIENT_DIR}/external/json/include" )
include_directories( "${CLIENT_DIR}/external/toml" )
include_directories( ${Python3_INCLUDE_DIRS} )

##
## Header list (consumed by add_executable for IDE source-tree visibility)
##
set( HAVOC_INCLUDE

        # Misc
        ${CLIENT_DIR}/include/Havoc/Connector.hpp
        ${CLIENT_DIR}/include/Havoc/DBManager/DBManager.hpp
        ${CLIENT_DIR}/include/Havoc/DemonCmdDispatch.h
        ${CLIENT_DIR}/include/Havoc/Packager.hpp
        ${CLIENT_DIR}/include/Havoc/Havoc.hpp
        ${CLIENT_DIR}/include/Havoc/Service.hpp
        ${CLIENT_DIR}/include/Havoc/CmdLine.hpp

        # Python Api
        ${CLIENT_DIR}/include/Havoc/PythonApi/PythonApi.h
        ${CLIENT_DIR}/include/Havoc/PythonApi/Event.h
        ${CLIENT_DIR}/include/Havoc/PythonApi/HavocUi.h
        ${CLIENT_DIR}/include/Havoc/PythonApi/PyAgentClass.hpp
        ${CLIENT_DIR}/include/Havoc/PythonApi/UI/PyDialogClass.hpp
        ${CLIENT_DIR}/include/Havoc/PythonApi/UI/PyLoggerClass.hpp
        ${CLIENT_DIR}/include/Havoc/PythonApi/UI/PyTreeClass.hpp
        ${CLIENT_DIR}/include/Havoc/PythonApi/UI/PyWidgetClass.hpp

        # Dialogs
        ${CLIENT_DIR}/include/UserInterface/Dialogs/Payload.hpp
        ${CLIENT_DIR}/include/UserInterface/Dialogs/About.hpp
        ${CLIENT_DIR}/include/UserInterface/Dialogs/Connect.hpp
        ${CLIENT_DIR}/include/UserInterface/Dialogs/Listener.hpp

        # SmallWidgets
        ${CLIENT_DIR}/include/UserInterface/SmallWidgets/EventViewer.hpp

        # Widgets
        ${CLIENT_DIR}/include/UserInterface/Widgets/Chat.hpp
        ${CLIENT_DIR}/include/UserInterface/Widgets/DemonInteracted.h
        ${CLIENT_DIR}/include/UserInterface/Widgets/ListenerTable.hpp
        ${CLIENT_DIR}/include/UserInterface/Widgets/ProcessList.hpp
        ${CLIENT_DIR}/include/UserInterface/Widgets/PythonScript.hpp
        ${CLIENT_DIR}/include/UserInterface/Widgets/SessionTable.hpp
        ${CLIENT_DIR}/include/UserInterface/Widgets/SessionGraph.hpp
        ${CLIENT_DIR}/include/UserInterface/Widgets/TeamserverTabSession.h
        ${CLIENT_DIR}/include/UserInterface/Widgets/ScriptManager.h
        ${CLIENT_DIR}/include/UserInterface/Widgets/LootWidget.h
        ${CLIENT_DIR}/include/UserInterface/Widgets/FileBrowser.hpp
        ${CLIENT_DIR}/include/UserInterface/Widgets/Teamserver.hpp
        ${CLIENT_DIR}/include/UserInterface/Widgets/Store.hpp
        ${CLIENT_DIR}/include/UserInterface/HavocUI.hpp

        # Util
        ${CLIENT_DIR}/include/Util/ThemeManager.hpp
)

##
## UI source files
##
set( HAVOC_UI

        ${CLIENT_DIR}/src/UserInterface/HavocUi.cc
        ${CLIENT_DIR}/src/global.cc

        # Dialogs
        ${CLIENT_DIR}/src/UserInterface/Dialogs/About.cc
        ${CLIENT_DIR}/src/UserInterface/Dialogs/Connect.cc
        ${CLIENT_DIR}/src/UserInterface/Dialogs/Listener.cc
        ${CLIENT_DIR}/src/UserInterface/Dialogs/Payload.cc

        # Widgets
        ${CLIENT_DIR}/src/UserInterface/Widgets/SessionTable.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/SessionGraph.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/Chat.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/ListenersTable.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/DemonInteracted.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/TeamserverTabSession.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/PythonScript.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/ScriptManager.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/LootWidget.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/FileBrowser.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/Teamserver.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/Store.cc
        ${CLIENT_DIR}/src/UserInterface/Widgets/ProcessList.cc

        # SmallWidgets
        ${CLIENT_DIR}/src/UserInterface/SmallWidgets/EventViewer.cc
)

##
## Utility source files
##
set( HAVOC_UTIL

        ${CLIENT_DIR}/src/Util/ColorText.cpp
        ${CLIENT_DIR}/src/Util/Base64.cpp
        ${CLIENT_DIR}/src/Util/Base.cpp
        ${CLIENT_DIR}/src/Util/ThemeManager.cpp
)

##
## Core source files
##
set( HAVOC_SOURCE

        ${CLIENT_DIR}/src/Main.cc

        ${CLIENT_DIR}/src/Havoc/Packager.cc
        ${CLIENT_DIR}/src/Havoc/Connector.cc
        ${CLIENT_DIR}/src/Havoc/Service.cc

        ${CLIENT_DIR}/src/Havoc/DBManger/DBManager.cc
        ${CLIENT_DIR}/src/Havoc/DBManger/Teamserver.cc
        ${CLIENT_DIR}/src/Havoc/DBManger/Scripts.cc

        ${CLIENT_DIR}/src/Havoc/Demon/ConsoleInput.cc
        ${CLIENT_DIR}/src/Havoc/Demon/CommandSend.cc
        ${CLIENT_DIR}/src/Havoc/Demon/CommandOutput.cc
        ${CLIENT_DIR}/src/Havoc/Demon/Commands.cc

        ${CLIENT_DIR}/src/Havoc/PythonApi/PythonApi.cc
        ${CLIENT_DIR}/src/Havoc/PythonApi/Havoc.cc
        ${CLIENT_DIR}/src/Havoc/PythonApi/HavocUi.cc
        ${CLIENT_DIR}/src/Havoc/PythonApi/UI/PyDialogClass.cc
        ${CLIENT_DIR}/src/Havoc/PythonApi/UI/PyLoggerClass.cc
        ${CLIENT_DIR}/src/Havoc/PythonApi/UI/PyTreeClass.cc
        ${CLIENT_DIR}/src/Havoc/PythonApi/UI/PyWidgetClass.cc
        ${CLIENT_DIR}/src/Havoc/PythonApi/PyDemonClass.cc
        ${CLIENT_DIR}/src/Havoc/PythonApi/Event.cc
        ${CLIENT_DIR}/src/Havoc/PythonApi/PyAgentClass.cc

        ${CLIENT_DIR}/src/Havoc/Havoc.cc

    ${HAVOC_UI}
)

##
## Executable target
## Note: CMake silently ignores .rc files on non-Windows platforms.
##
add_executable( ${PROJECT_NAME}
    ${HAVOC_INCLUDE}
    ${HAVOC_SOURCE}
    ${HAVOC_UTIL}
    ${CLIENT_DIR}/data/Havoc.qrc
    ${CLIENT_DIR}/data/Havoc.rc
)

##
## Platform-specific target properties
##
if( APPLE )
    set_target_properties( ${PROJECT_NAME} PROPERTIES
        MACOSX_BUNDLE                      TRUE
        MACOSX_BUNDLE_BUNDLE_NAME          "Havoc"
        MACOSX_BUNDLE_BUNDLE_VERSION       "1.9"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "1.9"
        MACOSX_BUNDLE_GUI_IDENTIFIER       "com.havocframework.client"
        MACOSX_BUNDLE_ICON_FILE            "Havoc.icns"
    )
endif()

if( WIN32 )
    set_target_properties( ${PROJECT_NAME} PROPERTIES
        WIN32_EXECUTABLE TRUE
    )
endif()

##
## Link libraries
##
target_link_libraries( ${PROJECT_NAME}
    ${REQUIRED_LIBS_QUALIFIED}
    ${Python3_LIBRARIES}
)

if( APPLE )
    target_link_libraries( ${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto )
endif()
