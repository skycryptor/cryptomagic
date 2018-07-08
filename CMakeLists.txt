cmake_minimum_required(VERSION 3.10)
project(cryptomaic)

set(CMAKE_CXX_STANDARD 11)

set(OPENSSL_ROOT_DIR /usr/local/opt/openssl/)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

include_directories(${OPENSSL_INCLUDE_DIR} src src/include include)

set(CRYPTOMAGIC_SOURCES src/CryptoMagic.cpp src/include/CryptoMagic.h src/Context.cpp src/include/Context.h src/BigNumber.cpp src/include/BigNumber.h src/ErrorWrapper.cpp src/include/ErrorWrapper.h src/include/defines.h src/Point.cpp src/include/Point.h src/include/BigNumberRaw.h src/BigNumberRaw.cpp src/include/PointRaw.h src/PointRaw.cpp src/include/PublicKey.h src/PublicKey.cpp src/PrivateKey.cpp src/include/PrivateKey.h src/include/Capsule.h src/Capsule.cpp src/include/helpers.h src/helpers.cpp src/include/ReEncryptionKey.h src/ReEncryptionKey.cpp include/CryptoMagic_C.h src/CryptoMagic_C.cpp src/KeyPair.cpp src/include/KeyPair.h)
set(PROJECT_TESTS ${PROJECT_NAME}_tests)
add_library(${PROJECT_NAME} ${CRYPTOMAGIC_SOURCES})
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -j4)
add_executable(${PROJECT_TESTS} src/tests/tests.cpp src/tests/bignumber.cpp src/tests/re_encryption.cpp src/tests/c_interface.cpp)
target_link_libraries(${PROJECT_TESTS} ${PROJECT_NAME} OpenSSL::Crypto)
add_test(NAME ${PROJECT_TESTS} COMMAND ${PROJECT_TESTS} --use-colour=yes)
