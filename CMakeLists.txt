cmake_minimum_required(VERSION 3.10)
project(cryptomaic)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

include_directories(${OPENSSL_INCLUDE_DIR})

add_library(${PROJECT_NAME} src/cryptomagic.cpp src/cryptomagic.h src/context.cpp src/context.h)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)