cmake_minimum_required(VERSION 3.17)
project(pangolin)

set(CMAKE_CXX_STANDARD 17)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

find_package(zero CONFIG REQUIRED)

add_executable(pangolin main.cpp ptrace/tracee.cpp ptrace/executor.cpp)
target_link_libraries(pangolin zero::zero $<$<BOOL:${STATIC_BUILD}>:-static-pie>)