# Copyright (C) 2021 C. Fernandez-Prades, CTTC cfernandez@cttc.es
# Copyright (C) 2021 Javier Arribas, CTTC jarribas@cttc.es
#
################################################################################
# Project setup
################################################################################
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(WARNING "In-tree build is bad practice. Try 'cd build && cmake ..'")
endif()
cmake_minimum_required(VERSION 3.5..3.19)
project(plutosdr_gnss CXX C)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)


################################################################################
# Plutosdr_GNSS version information
################################################################################
set(THIS_IS_A_RELEASE OFF)   # only related to version name, no further implications.
if(NOT ${THIS_IS_A_RELEASE})
    # Get the current working branch
    execute_process(
        COMMAND git rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # Get the latest abbreviated commit hash of the working branch
    execute_process(
        COMMAND git log -1 --format=%h
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

set(VERSION_INFO_MAJOR_VERSION 0)
set(VERSION_INFO_API_COMPAT    9)
if(${THIS_IS_A_RELEASE})
    set(VERSION_INFO_MINOR_VERSION 0)
else()
    set(VERSION_INFO_MINOR_VERSION git-${GIT_BRANCH}-${GIT_COMMIT_HASH})
endif()

set(VERSION ${VERSION_INFO_MAJOR_VERSION}.${VERSION_INFO_API_COMPAT}.${VERSION_INFO_MINOR_VERSION})



################################################################################
# Environment setup
################################################################################
include(FeatureSummary)

# Detect Linux Distribution
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux|kFreeBSD|GNU")
    include(DetectLinuxDistro)
    if(CMAKE_CROSSCOMPILING)
        message(STATUS "Configuring PlutoSDR_GNSS (device tools) v${VERSION} to be cross-compiled on ${LINUX_DISTRIBUTION} ${LINUX_VER} (${CMAKE_HOST_SYSTEM_PROCESSOR}) for ${CMAKE_SYSTEM_PROCESSOR} ${ARCHITECTURE_STRING}")
    else()
        message(STATUS "Configuring PlutoSDR_GNSS (device tools) v${VERSION} to be built on GNU/Linux ${LINUX_DISTRIBUTION} ${LINUX_VER} ${ARCHITECTURE_STRING}")
    endif()
endif()


# Append -O2 optimization flag for Debug builds
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O2")

# If this is an out-of-tree build, do not pollute the original source directory
if(${CMAKE_BINARY_DIR} MATCHES ${CMAKE_SOURCE_DIR})
    set(LOCAL_INSTALL_BASE_DIR ${CMAKE_SOURCE_DIR})
else()
    set(LOCAL_INSTALL_BASE_DIR ${CMAKE_BINARY_DIR})
endif()


################################################################################
# Set minimal C and C++ standards
################################################################################
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_EXTENSIONS OFF)

# Visibility
# See https://gcc.gnu.org/wiki/Visibility
if(POLICY CMP0063)
    cmake_policy(SET CMP0063 NEW)
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
    set(CMAKE_C_VISIBILITY_PRESET hidden)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
else()
    if((CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU") AND NOT WIN32)
        add_definitions(-fvisibility=hidden)
    endif()
endif()



################################################################################
# Minimum required versions
################################################################################
set(PLUTOSDR_GNSS_BOOST_MIN_VERSION "1.53")


################################################################################
# pkg-config - Helper tool used when compiling applications and libraries.
################################################################################
set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH TRUE)
find_package(PkgConfig)


################################################################################
# Find the POSIX thread (pthread) libraries
################################################################################
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
if(CMAKE_CROSSCOMPILING)
    set(THREADS_PREFER_PTHREAD_FLAG FALSE)
else()
    set(THREADS_PREFER_PTHREAD_FLAG TRUE)
endif()
find_package(Threads REQUIRED)
set_package_properties(Threads PROPERTIES
    URL "https://computing.llnl.gov/tutorials/pthreads/"
    DESCRIPTION "Implements the POSIX Threads execution model"
    PURPOSE "Used to implement parallelism."
    TYPE REQUIRED
)


################################################################################
# Boost - https://www.boost.org
################################################################################
set(BOOST_COMPONENTS date_time system filesystem thread serialization chrono program_options)
find_package(Boost ${PLUTOSDR_GNSS_BOOST_MIN_VERSION}) ## COMPONENTS ${BOOST_COMPONENTS} REQUIRED)

if(NOT Boost_FOUND)
    message(FATAL_ERROR "Fatal error: Boost (version >=${PLUTOSDR_GNSS_BOOST_MIN_VERSION}) required.")
endif()

set_package_properties(Boost PROPERTIES
    URL "https://www.boost.org"
    PURPOSE "Used widely across the source code."
    TYPE REQUIRED
)

if(CMAKE_VERSION VERSION_LESS 3.14)
    set(Boost_VERSION_STRING "${Boost_MAJOR_VERSION}.${Boost_MINOR_VERSION}.${Boost_SUBMINOR_VERSION}")
endif()
if(POLICY CMP0093)
    cmake_policy(SET CMP0093 NEW)  # FindBoost reports Boost_VERSION in x.y.z format.
endif()

# Define Boost::headers target if CMake < 3.15
if(CMAKE_VERSION VERSION_LESS 3.15)
    if(NOT TARGET Boost::headers)
        add_library(Boost::headers INTERFACE IMPORTED)
        set_target_properties(Boost::headers PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIR}
        )
    endif()
endif()

set_package_properties(Boost PROPERTIES
    DESCRIPTION "Portable C++ source libraries (found: v${Boost_VERSION_STRING})"
)

################################################################################
# Set compiler flags
################################################################################
set(CXX_WARNING_FLAGS -Wall -Wextra)
if((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") AND NOT WIN32)
    # Add warning flags
    # For "-Wall" see https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
    add_compile_options("$<$<STREQUAL:$<TARGET_PROPERTY:LINKER_LANGUAGE>,CXX>:${CXX_WARNING_FLAGS}>")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "5.0")
        add_compile_options(-Wno-missing-field-initializers)
    endif()
    if(CMAKE_CROSSCOMPILING)
        add_compile_options(-Wno-psabi)
    endif()
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options("$<$<STREQUAL:$<TARGET_PROPERTY:LINKER_LANGUAGE>,CXX>:${CXX_WARNING_FLAGS}>")
endif()


################################################################################
# Create uninstall target
################################################################################
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
    @ONLY
)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)



################################################################################
# Add subdirectories (in order of deps)
################################################################################
add_subdirectory(src)
add_subdirectory(tools)
