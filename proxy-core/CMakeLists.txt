cmake_minimum_required(VERSION 3.18)
project(proxy-core VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Boost 1.74 REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)

# Shared security library.
if (NOT TARGET shared_security)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../shared-security
                     ${CMAKE_CURRENT_BINARY_DIR}/shared-security)
endif()

# ── proxy-core library (reusable by tests) ────────────────────────────────────
add_library(proxy_core_lib STATIC
    src/config.cpp
    src/rate_limiter.cpp
    src/policy_engine.cpp
    src/session.cpp
    src/connection_manager.cpp
    src/proxy_server.cpp
)

target_include_directories(proxy_core_lib
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${OPENSSL_INCLUDE_DIR}
            ${Boost_INCLUDE_DIRS}
)

target_link_libraries(proxy_core_lib
    PUBLIC  shared_security
            OpenSSL::SSL
            OpenSSL::Crypto
            Boost::system
            Threads::Threads
)

target_compile_options(proxy_core_lib PRIVATE
    -Wall -Wextra -Wpedantic
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# ── proxy-core executable ─────────────────────────────────────────────────────
add_executable(proxy-core src/main.cpp)
target_link_libraries(proxy-core PRIVATE proxy_core_lib)

# ── unit tests ────────────────────────────────────────────────────────────────
option(BUILD_TESTS "Build unit tests" ON)
if (BUILD_TESTS)
    enable_testing()
    find_package(Catch2 QUIET)

    if (Catch2_FOUND)
        foreach(test_src tests/test_rate_limiter.cpp tests/test_policy_engine.cpp)
            get_filename_component(test_name ${test_src} NAME_WE)
            add_executable(${test_name} ${test_src})
            target_link_libraries(${test_name} PRIVATE proxy_core_lib Catch2::Catch2)
            add_test(NAME ${test_name} COMMAND ${test_name})
        endforeach()
    else()
        message(STATUS "Catch2 not found – skipping unit tests")
    endif()
endif()
