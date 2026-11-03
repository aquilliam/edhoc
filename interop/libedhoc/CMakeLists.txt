cmake_minimum_required(VERSION 3.21)
project(libedhoc_peer C)

set(LIBEDHOC_ENABLE_TESTS OFF CACHE BOOL "" FORCE)
set(CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE 0 CACHE STRING "" FORCE)
set(CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE 0 CACHE STRING "" FORCE)
set(CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE 0 CACHE STRING "" FORCE)
set(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE 0 CACHE STRING "" FORCE)
set(CONFIG_LIBEDHOC_LOG_LEVEL 0 CACHE STRING "" FORCE)

add_subdirectory(${LIBEDHOC_SRC} libedhoc)
target_compile_options(libedhoc PRIVATE -Wno-error)

include(${LIBEDHOC_SRC}/cmake/sources.cmake)
add_executable(peer peer.c ${LIBEDHOC_CIPHER_SUITE_SOURCES})
target_include_directories(peer PRIVATE ${LIBEDHOC_INTERNAL_INCLUDE_DIR})
target_link_libraries(peer PRIVATE
    libedhoc::edhoc libedhoc::cipher_suites libedhoc::backend_memory)
