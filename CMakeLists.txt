cmake_minimum_required(VERSION 3.17)
project(fetchDNS)

set(CMAKE_CXX_STANDARD 14)

link_libraries(ws2_32.lib IPHLPAPI.LIB)

add_executable(fetchDNS main.cpp fetch.cpp fetch.h)