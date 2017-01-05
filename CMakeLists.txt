cmake_minimum_required(VERSION 3.6)
project(pcap_sniff)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c network.h)
add_executable(pcap_sniff ${SOURCE_FILES})