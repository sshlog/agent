cmake_minimum_required(VERSION 3.14)

# 1. Fetch Catch2 (Standard Modern Approach)

CPMAddPackage("gh:catchorg/Catch2#v3.12.0")

# 2. Define the Test Executable
add_executable(integration_tests integration_tests.cpp)

# 3. Link dependencies
target_link_libraries(integration_tests 
    PRIVATE 
    sshlog
    Catch2::Catch2WithMain
    yyjson
)
target_include_directories(integration_tests PRIVATE ../)

# 4. Register with CTest
include(CTest)
add_test(NAME IntegrationTests COMMAND integration_tests)