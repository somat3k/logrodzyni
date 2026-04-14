cmake_minimum_required(VERSION 3.18)
project(masking-client VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost 1.74 REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

if (NOT TARGET shared_security)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../shared-security
                     ${CMAKE_CURRENT_BINARY_DIR}/shared-security)
endif()

add_executable(masking-client
    src/main.cpp
    src/masking_client.cpp
    src/profile_manager.cpp
    src/kill_switch.cpp
)

target_include_directories(masking-client
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${Boost_INCLUDE_DIRS}
            ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(masking-client
    PRIVATE shared_security
            Boost::system
            Threads::Threads
)

target_compile_options(masking-client PRIVATE
    -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2
)
