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
    find_package(GTest REQUIRED)
endif()

enable_testing()
add_subdirectory(src)
add_subdirectory(tests)
