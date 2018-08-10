cmake_minimum_required(VERSION 3.1)
project(cryptomagic)
include(${CMAKE_ROOT}/Modules/ExternalProject.cmake)

set(MBED_TLS_VERSION 2.7.5)

ExternalProject_Add(mbed_tls
  URL https://github.com/ARMmbed/mbedtls/archive/mbedtls-${MBED_TLS_VERSION}.tar.gz
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/mbed_tls
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/mbed_tls/build
)
ExternalProject_Get_Property(mbed_tls install_dir)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include_directories(src src/include ${install_dir}/build/include include)

set(CRYPTOMAGIC_SOURCES src/CryptoMagic.cpp src/include/CryptoMagic.h src/Context.cpp src/include/Context.h src/BigNumber.cpp src/include/BigNumber.h src/ErrorWrapper.cpp src/include/ErrorWrapper.h src/include/defines.h src/Point.cpp src/include/Point.h src/include/BigNumberRaw.h src/BigNumberRaw.cpp src/include/PointRaw.h src/PointRaw.cpp src/include/PublicKey.h src/PublicKey.cpp src/PrivateKey.cpp src/include/PrivateKey.h src/include/Capsule.h src/Capsule.cpp src/include/helpers.h src/helpers.cpp src/include/ReEncryptionKey.h src/ReEncryptionKey.cpp include/CryptoMagic_C.h src/CryptoMagic_C.cpp src/KeyPair.cpp src/include/KeyPair.h)
set(PROJECT_TESTS ${PROJECT_NAME}_tests)
add_library(${PROJECT_NAME} ${CRYPTOMAGIC_SOURCES})
target_link_libraries(${PROJECT_NAME})
add_dependencies(${PROJECT_NAME} mbed_tls)

add_custom_target(lib ALL
  COMMAND ar -x ${install_dir}/build/lib/libmbedcrypto.a
  COMMAND ar -x $<TARGET_FILE:${PROJECT_NAME}>
  COMMAND ar -qc $<TARGET_FILE:${PROJECT_NAME}> *.o
  COMMAND rm -f *.o
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
  DEPENDS mbed_tls ${PROJECT_NAME}
)

enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -j4)
add_executable(${PROJECT_TESTS} src/tests/tests.cpp src/tests/bignumber.cpp src/tests/re_encryption.cpp src/tests/c_interface.cpp)
target_link_libraries(${PROJECT_TESTS} ${PROJECT_NAME})
add_test(NAME ${PROJECT_TESTS} COMMAND ${PROJECT_TESTS} --use-colour=yes)
add_dependencies(${PROJECT_TESTS} lib)
