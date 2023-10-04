cmake_minimum_required(VERSION 3.25)
project(process_hollowing)

set(CMAKE_CXX_STANDARD 23)

add_executable(process_hollowing main/main.cpp process/shellcode.h process/process.hpp process/process.hpp)
