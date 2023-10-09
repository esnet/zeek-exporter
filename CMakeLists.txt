cmake_minimum_required(VERSION 3.15)

project(ZeekPluginZeek_Exporter)

include(ZeekPlugin)
include(CheckIncludeFileCXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_subdirectory(3rdparty/prometheus-cpp)

set(ENABLE_TESTING OFF CACHE BOOL "Build tests")
include_directories(BEFORE ${prometheus-cpp_INCLUDE_DIR})

zeek_plugin_begin(ESnet Zeek_Exporter)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_bif(src/zeek_exporter.bif)
zeek_plugin_link_library(prometheus-cpp::pull)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()

target_compile_options(${_plugin_lib} PRIVATE -Wno-deprecated-declarations)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
