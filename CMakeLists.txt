cmake_minimum_required(VERSION 3.10)
project(cryptomaic)

set(CMAKE_CXX_STANDARD 11)

set(OPENSSL_ROOT_DIR /usr/local/opt/openssl/)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

include_directories(${OPENSSL_INCLUDE_DIR} src src/include include)

set(CRYPTOMAGIC_SOURCES src/CryptoMagic.cpp src/include/CryptoMagic.h src/Context.cpp src/include/Context.h src/BigNumber.cpp src/include/BigNumber.h src/ErrorWrapper.cpp src/include/ErrorWrapper.h src/include/defines.h src/Point.cpp src/include/Point.h src/include/BigNumberRaw.h src/BigNumberRaw.cpp src/include/PointRaw.h src/PointRaw.cpp src/include/PublicKey.h src/PublicKey.cpp src/PrivateKey.cpp src/include/PrivateKey.h src/include/Capsule.h src/Capsule.cpp src/include/helpers.h src/helpers.cpp)

add_library(${PROJECT_NAME} ${CRYPTOMAGIC_SOURCES})
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -j4)
add_executable(cm_bignumber_test src/tests/bignumber.cpp)
target_link_libraries(cm_bignumber_test ${PROJECT_NAME} OpenSSL::Crypto)
add_test(NAME BigNumbers COMMAND cm_bignumber_test --use-colour=yes)