cmake_minimum_required(VERSION 3.29)
project(digdocproject C)

set(CMAKE_C_STANDARD 11)

if (APPLE)
    include_directories(/usr/local/Cellar/libcoap/4.3.5/include)
endif()

add_executable(digdocproject main.c)
