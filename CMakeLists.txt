cmake_minimum_required(VERSION 3.31)
project(gouda_sockets)

set(CMAKE_CXX_STANDARD 23)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

add_executable(gouda_sockets main.cpp
        base_socket.hpp)

target_link_libraries(gouda_sockets OpenSSL::SSL OpenSSL::Crypto)
