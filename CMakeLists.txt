cmake_minimum_required(VERSION 3.19)

project(SRCRecon VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network Concurrent)

set(SRC_RECON_SOURCES
    src/main.cpp

    src/core/Types.h
    src/core/EngineOptions.h
    src/core/Wordlists.h
    src/core/NetUtil.h
    src/core/NetUtil.cpp
    src/core/Settings.h
    src/core/Settings.cpp
    src/core/DemoData.h
    src/core/DemoData.cpp
    src/core/ReconState.h
    src/core/CdnDetect.h
    src/core/CdnDetect.cpp
    src/core/JsExtract.h
    src/core/JsExtract.cpp
    src/core/ReconEngine.h
    src/core/ReconEngine.cpp

    src/modules/IReconModule.h
    src/modules/SubdomainModule.h
    src/modules/SubdomainModule.cpp
    src/modules/AssetInfoModule.h
    src/modules/AssetInfoModule.cpp
    src/modules/CdnModule.h
    src/modules/CdnModule.cpp
    src/modules/PortScanModule.h
    src/modules/PortScanModule.cpp
    src/modules/WebFingerModule.h
    src/modules/WebFingerModule.cpp
    src/modules/DirScanModule.h
    src/modules/DirScanModule.cpp
    src/modules/CrawlerModule.h
    src/modules/CrawlerModule.cpp

    src/ui/MainWindow.h
    src/ui/MainWindow.cpp
)

# 默认生成无控制台的 GUI 程序；-DSRC_RECON_CONSOLE=ON 可保留控制台便于调试
option(SRC_RECON_CONSOLE "Build with a console window for debugging" OFF)

if(SRC_RECON_CONSOLE)
    add_executable(SRCRecon ${SRC_RECON_SOURCES})
else()
    add_executable(SRCRecon WIN32 ${SRC_RECON_SOURCES})
endif()

target_include_directories(SRCRecon PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(SRCRecon PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    Qt6::Concurrent
)

if(MSVC)
    target_compile_options(SRCRecon PRIVATE /W3 /utf-8)
else()
    target_compile_options(SRCRecon PRIVATE
        -Wall -Wextra -Wno-unused-parameter
        -finput-charset=UTF-8 -fexec-charset=UTF-8)
endif()

# 构建后自动拷贝 Qt 运行时依赖（Windows）
if(WIN32)
    find_program(WINDEPLOYQT_EXE windeployqt HINTS "${QT6_INSTALL_PREFIX}/bin"
                 "${CMAKE_PREFIX_PATH}/bin")
    if(WINDEPLOYQT_EXE)
        add_custom_command(TARGET SRCRecon POST_BUILD
            COMMAND "${WINDEPLOYQT_EXE}" --no-translations --no-system-d3d-compiler
                    --no-opengl-sw "$<TARGET_FILE:SRCRecon>"
            COMMENT "Running windeployqt")
    endif()
endif()
