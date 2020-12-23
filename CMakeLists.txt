cmake_minimum_required(VERSION 3.0)
project(pangolin)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)
include_directories(shellcode)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

add_executable(target sample/target.cpp)
add_executable(inject sample/inject.cpp)

add_executable(pangolin main.cpp inject/pt_inject.h inject/pt_inject.cpp share/sh_args.h share/sh_args.cpp inject/shellcode.cpp inject/shellcode.h)
target_link_libraries(pangolin)