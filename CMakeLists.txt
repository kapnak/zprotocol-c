cmake_minimum_required(VERSION 3.18.4)
project(zprotocol C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_C_COMPILER cc)
set(CMAKE_CXX_COMPILER c++)
set(COMPILE_FLAGS "--coverage")
set(CMAKE_EXE_LINKER_FLAGS "--coverage")


# Example : Asynchronous Server
add_executable(sync-server example/sync-server.c src/zprotocol.c src/zprotocol.h src/helpers.c
        src/utils.c)
target_link_libraries(sync-server -lsodium)

# Example : Asynchronous Client
add_executable(sync-client example/sync-client.c src/zprotocol.c src/zprotocol.h src/helpers.c
        src/utils.c)
target_link_libraries(sync-client -lsodium)

# Example : Concurrent Server
add_executable(concurrent-server example/concurrent-server.c src/zprotocol.c src/zprotocol.h src/helpers.c
        src/utils.c)
target_link_libraries(concurrent-server -lsodium)

# Example : Concurrent Client
add_executable(concurrent-client example/concurrent-client.c src/zprotocol.c src/zprotocol.h src/helpers.c
        src/utils.c)
target_link_libraries(concurrent-client -lsodium)

# Test
add_executable(test test/test.c src/zprotocol.c src/zprotocol.h src/helpers.c
        src/utils.c)
target_link_libraries(test -lsodium)

# Test - time
add_executable(time test/time.c src/zprotocol.c src/zprotocol.h src/helpers.c
        src/utils.c)
target_link_libraries(time -lsodium)
