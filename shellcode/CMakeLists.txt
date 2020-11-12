cmake_minimum_required(VERSION 3.0)
project(shellcode C)

set(CMAKE_C_STANDARD 99)

include_directories(crt)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_C_FLAGS "-fno-common -fno-stack-protector \
        -fomit-frame-pointer -fno-exceptions -fno-asynchronous-unwind-tables \
        -fno-unwind-tables -fno-builtin -nostdlib")

add_library(spread SHARED spread/spread.h spread/spread.c)
add_library(shrink SHARED shrink/shrink.h shrink/shrink.c)
add_library(loader SHARED loader/loader.h loader/loader.c loader/elf_loader.h loader/elf_loader.c)