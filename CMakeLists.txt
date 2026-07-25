cmake_minimum_required(VERSION 3.20)
project(pcapgrammar CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Support both Ubuntu apt packages and Conan
option(PCAPGRAMMAR_USE_CONAN "Use Conan-generated CMake files" OFF)

if(PCAPGRAMMAR_USE_CONAN)
    find_package(libpcap  REQUIRED)
    find_package(yaml-cpp REQUIRED)
    find_package(GTest    REQUIRED)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBPCAP REQUIRED libpcap)
    find_package(yaml-cpp REQUIRED)

    # GoogleTest via FetchContent — no system package required.
    # Conan path (PCAPGRAMMAR_USE_CONAN=ON) is for offline/corporate environments.
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(BUILD_GMOCK   OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

enable_testing()
add_subdirectory(src)
add_subdirectory(tests)
