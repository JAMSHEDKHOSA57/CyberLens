cmake_minimum_required(VERSION 3.16)
project(CyberLens1 VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt6 or Qt5, requiring Widgets and Network
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network)

# Create the executable
qt_add_executable(CyberLens1
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
)

# Link required Qt modules
target_link_libraries(CyberLens1
    PRIVATE
        Qt${QT_VERSION_MAJOR}::Widgets
        Qt${QT_VERSION_MAJOR}::Network
)

# For Qt6: finalize the executable (helps with deployment)
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_finalize_executable(CyberLens1)
endif()

# Make it a proper app on Windows/macOS
set_target_properties(CyberLens1 PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
)

# Install rules (optional, for deployment)
include(GNUInstallDirs)
install(TARGETS CyberLens1
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
