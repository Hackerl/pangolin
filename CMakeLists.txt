cmake_minimum_required(VERSION 3.0)
project(pangolin)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)
include_directories(shellcode)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)

add_executable(pangolin main.cpp inject/pt_inject.h inject/pt_inject.cpp share/sh_args.h share/sh_args.cpp)
target_link_libraries(pangolin ${CMAKE_DL_LIBS})