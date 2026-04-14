cmake_minimum_required(VERSION 3.18)
project(logrodzyni-proxy-circuit VERSION 1.0.0)

# Build all C++ modules from the root.
add_subdirectory(shared-security)
add_subdirectory(proxy-core)
add_subdirectory(masking-client)
