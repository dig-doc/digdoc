cmake_minimum_required(VERSION 3.29)
project(digdocproject C)

set(LIBCOAP_DIR "${CMAKE_SOURCE_DIR}/libcoap-main")

add_subdirectory(${LIBCOAP_DIR})

add_executable(digdocproject main.c)

target_link_libraries(digdocproject PRIVATE coap-3)
target_include_directories(digdocproject PRIVATE ${LIBCOAP_DIR}/include)
