cmake_minimum_required(VERSION 3.17)
project(pangolin)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include(FetchContent)

FetchContent_Declare(
        zero
        GIT_REPOSITORY https://github.com/Hackerl/zero
        GIT_TAG cbbab7d2176e3a679aa58387383c8cf6e902986a
)

FetchContent_MakeAvailable(zero)

add_executable(pangolin main.cpp ptrace/tracee.cpp ptrace/executor.cpp inject/injector.cpp)
target_link_libraries(pangolin zero $<$<BOOL:${STATIC_BUILD}>:-static-pie>)