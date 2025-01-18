cmake_minimum_required(VERSION 3.26)
project(digdoc C)

add_executable(digdoc main.c)

target_link_libraries(digdoc PRIVATE coap-3-gnutls ldns)
