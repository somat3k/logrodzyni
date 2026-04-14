cmake_minimum_required(VERSION 3.18)
project(shared-security VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)
find_package(Boost 1.74 REQUIRED COMPONENTS system)

add_library(shared_security STATIC
    src/crypto.cpp
    src/cert_manager.cpp
    src/tls_context.cpp
)

target_include_directories(shared_security
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${OPENSSL_INCLUDE_DIR}
            ${Boost_INCLUDE_DIRS}
)

target_link_libraries(shared_security
    PUBLIC  OpenSSL::SSL
            OpenSSL::Crypto
            Boost::system
)

target_compile_options(shared_security PRIVATE
    -Wall -Wextra -Wpedantic
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIE
)
