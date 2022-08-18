cmake_minimum_required(VERSION 3.0)
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
        GIT_TAG 2ee1ee881dc5a0912dcd0a9a2eb4d2fd82ecd012
)

FetchContent_MakeAvailable(zero)

add_executable(pangolin main.cpp ptrace/tracee.cpp ptrace/executor.cpp inject/injector.cpp)
target_link_libraries(pangolin zero $<$<BOOL:${STATIC_BUILD}>:-static-pie>)