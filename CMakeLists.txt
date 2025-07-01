cmake_minimum_required(VERSION 3.10)
project(SecureIoT-Sim VERSION 1.0.0 LANGUAGES C)

# C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Options
option(STATIC_BUILD "Build statically linked executable" ON)
option(WITH_TLS "Enable TLS support" ON)
option(DEBUG "Enable debug build" OFF)
option(ENABLE_TESTS "Build tests" ON)

# Base compiler flags (less strict, for compatibility with third-party code)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
    )
    
    if(DEBUG)
        add_compile_options(-g -O0 -DDEBUG)
    else()
        add_compile_options(-O2 -DNDEBUG)
    endif()
elseif(MSVC)
    add_compile_options(/W4)
    if(DEBUG)
        add_compile_options(/Od /DDEBUG)
    else()
        add_compile_options(/O2 /DNDEBUG)
    endif()
endif()

# Define strict flags for our own code (will be applied per-target)
set(STRICT_C_FLAGS "")
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(STRICT_C_FLAGS
        -Werror
        -Wno-unused-parameter
        -Wno-unused-variable
        -Wstrict-prototypes
        -Wmissing-prototypes
        -Wpointer-arith
        -Wcast-align
        -Wwrite-strings
        -Wswitch-default
        -Wunreachable-code
        -Winit-self
        -Wmissing-field-initializers
        -Wno-unknown-pragmas
        -Wstrict-aliasing=2
        -Wundef
        -Wold-style-definition
    )
endif()

# Static linking
if(STATIC_BUILD)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(BUILD_SHARED_LIBS OFF)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set(CMAKE_EXE_LINKER_FLAGS "-static")
    endif()
endif()

# mbedTLS configuration
if(WITH_TLS)
    set(MBEDTLS_DIR ${CMAKE_SOURCE_DIR}/third_party/mbedtls)
    
    # Check if mbedTLS exists
    if(NOT EXISTS ${MBEDTLS_DIR}/CMakeLists.txt)
        message(FATAL_ERROR "mbedTLS not found. Run: git submodule update --init --recursive")
    endif()
    
    # Build mbedTLS as static library
    set(ENABLE_PROGRAMS OFF CACHE BOOL "Build mbedTLS programs")
    set(ENABLE_TESTING OFF CACHE BOOL "Build mbedTLS tests")
    set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "Build mbedTLS shared library")
    set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "Build mbedTLS static library")
    
    # For mbedTLS 3.6.x, ensure Python modules are available
    set(MBEDTLS_PYTHON_EXECUTABLE ${PYTHON_EXECUTABLE} CACHE INTERNAL "")
    set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "Compiler warnings treated as errors")
    
    add_subdirectory(${MBEDTLS_DIR} mbedtls_build)
    
    # mbedTLS include directories
    include_directories(${MBEDTLS_DIR}/include)
endif()

# Project include directories
include_directories(${CMAKE_SOURCE_DIR}/src)

# Source files
set(SOURCES
    src/main.c
    src/tls_client.c
    src/key_store.c
    src/msg_protocol.c
)

# Main executable
add_executable(secureiot_sim ${SOURCES})

# Apply strict flags only to our executable
if(STRICT_C_FLAGS)
    target_compile_options(secureiot_sim PRIVATE ${STRICT_C_FLAGS})
endif()

# Link libraries
if(WITH_TLS)
    target_link_libraries(secureiot_sim
        mbedtls
        mbedx509
        mbedcrypto
    )
endif()

# Platform-specific libraries
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(secureiot_sim pthread)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(secureiot_sim ws2_32)
endif()

# Tests
if(ENABLE_TESTS)
    enable_testing()
    
    # Unit tests
    add_executable(test_key_store tests/test_key_store.c src/key_store.c)
    target_compile_options(test_key_store PRIVATE ${STRICT_C_FLAGS})
    add_test(NAME KeyStore COMMAND test_key_store)
    
    add_executable(test_msg_protocol tests/test_msg_protocol.c src/msg_protocol.c)
    target_compile_options(test_msg_protocol PRIVATE ${STRICT_C_FLAGS})
    add_test(NAME MsgProtocol COMMAND test_msg_protocol)
    
    if(WITH_TLS)
        add_executable(test_tls_client tests/test_tls_client.c src/tls_client.c src/key_store.c)
        target_compile_options(test_tls_client PRIVATE ${STRICT_C_FLAGS})
        target_link_libraries(test_tls_client mbedtls mbedx509 mbedcrypto)
        add_test(NAME TLSClient COMMAND test_tls_client)
        
        add_executable(test_mtls_connection 
            tests/test_mtls_connection.c 
            src/tls_client.c 
            src/key_store.c 
            src/msg_protocol.c
        )
        target_compile_options(test_mtls_connection PRIVATE ${STRICT_C_FLAGS})
        target_link_libraries(test_mtls_connection mbedtls mbedx509 mbedcrypto)
        add_test(NAME MTLSConnection COMMAND test_mtls_connection)
    endif()
endif()

# Installation
install(TARGETS secureiot_sim DESTINATION bin)
install(DIRECTORY certs/ DESTINATION share/secureiot_sim/certs)

# CPack configuration
set(CPACK_PACKAGE_NAME "SecureIoT-Sim")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Secure IoT Device Simulator")
include(CPack)