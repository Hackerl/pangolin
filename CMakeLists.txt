cmake_minimum_required(VERSION 3.0)
project(pangolin)

set(CMAKE_CXX_STANDARD 14)

include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

add_subdirectory(zero)

add_executable(pangolin main.cpp ptrace/tracee.cpp ptrace/executor.cpp inject/injector.cpp)
target_link_libraries(pangolin zero $<$<BOOL:${STATIC_BUILD}>:-static-pie>)