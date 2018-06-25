cmake_minimum_required(VERSION 3.10)
project(cryptomaic)

set(CMAKE_CXX_STANDARD 11)

set(OPENSSL_ROOT_DIR /usr/local/opt/openssl/)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

include_directories(${OPENSSL_INCLUDE_DIR} src include)

set(CRYPTOMAGIC_SOURCES src/CryptoMagic.cpp src/CryptoMagic.h src/Context.cpp src/Context.h src/cryptography/EC.cpp src/cryptography/EC.h src/cryptography/BigNumber.cpp src/cryptography/BigNumber.h src/helpers/ErrorWrapper.cpp src/helpers/ErrorWrapper.h src/defines.h src/cryptography/Point.cpp src/cryptography/Point.h)

add_library(${PROJECT_NAME} ${CRYPTOMAGIC_SOURCES})
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -j4)
add_executable(cm_bignumber_test src/tests/bignumber.cpp)
target_link_libraries(cm_bignumber_test ${PROJECT_NAME} OpenSSL::Crypto)
add_test(NAME BigNumbers COMMAND cm_bignumber_test --use-colour=yes)