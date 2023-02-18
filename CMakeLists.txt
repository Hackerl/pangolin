cmake_minimum_required(VERSION 3.17)
project(pangolin)

set(CMAKE_CXX_STANDARD 17)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

include(FetchContent)

FetchContent_Declare(
        zero
        GIT_REPOSITORY https://github.com/Hackerl/zero
        GIT_TAG df739d44cacc95cf10251c0dbede56bc1f0b18bb
)

FetchContent_MakeAvailable(zero)

add_executable(pangolin main.cpp ptrace/tracee.cpp ptrace/executor.cpp)
target_link_libraries(pangolin zero $<$<BOOL:${STATIC_BUILD}>:-static-pie>)