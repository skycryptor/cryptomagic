cmake_minimum_required(VERSION 3.10)
project(cryptomaic)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

include_directories(${OPENSSL_INCLUDE_DIR})

add_library(${PROJECT_NAME} src/CryptoMagic.cpp src/CryptoMagic.h src/Context.cpp src/Context.h src/cryptography/EC.cpp src/cryptography/EC.h src/cryptography/BigNumber.cpp src/cryptography/BigNumber.h src/helpers/ErrorWrapper.cpp src/helpers/ErrorWrapper.h src/defines.h src/cryptography/Point.cpp src/cryptography/Point.h)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

add_executable(mgic src/testing.cpp)
target_link_libraries(mgic ${PROJECT_NAME} OpenSSL::Crypto )