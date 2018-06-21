cmake_minimum_required(VERSION 3.10)
project(cpp_tmp_crypto)

set(CMAKE_CXX_STANDARD 11)

include_directories(include)
add_library(cpp_tmp_crypto library.cpp include/library.h)