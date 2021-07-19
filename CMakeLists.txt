cmake_minimum_required(VERSION 3.0)
project(pangolin)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)
include_directories(shellcode)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include(cmake/ELFIO.cmake)

add_executable(target sample/target.cpp)
add_executable(inject sample/inject.cpp)

add_executable(pangolin main.cpp inject/pt_inject.cpp inject/shellcode.cpp)
target_link_libraries(pangolin elfio $<$<BOOL:${STATIC_BUILD}>:-static-pie>)