cmake_minimum_required(VERSION 3.26)
project(digdoc C)

# Option to enable testing
option(LOCAL_TESTING "Enable local testing" OFF)

add_executable(digdoc main.c)

target_link_libraries(digdoc PRIVATE coap-3 ldns)

if(LOCAL_TESTING)
    add_executable(local_test_server testing/local_test_server.c)
    target_link_libraries(local_test_server PRIVATE ldns)
    install(TARGETS
            local_test_server)
endif ()

install(TARGETS
        digdoc)
