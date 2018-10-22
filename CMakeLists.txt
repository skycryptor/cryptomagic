cmake_minimum_required(VERSION 3.1)
project(ProxyLib)
include(${CMAKE_ROOT}/Modules/ExternalProject.cmake)

set(MBED_TLS_VERSION 2.7.5)

ExternalProject_Add(mbed_tls
  URL https://github.com/ARMmbed/mbedtls/archive/mbedtls-${MBED_TLS_VERSION}.tar.gz
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/mbed_tls
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/mbed_tls/build
  CMAKE_CACHE_ARGS -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=true
)
ExternalProject_Get_Property(mbed_tls install_dir)

link_directories(${CMAKE_CURRENT_BINARY_DIR}/mbed_tls/build/lib)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include_directories(src src/include ${install_dir}/build/include include  ${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

set(PROXYLIB_SOURCES
    src/MBED_TLS_VersionInfo.cpp
    src/VersionInfoMap.cpp
    src/ECScalar.cpp
    src/ProxyLibException.cpp
    src/ECPoint.cpp
    src/Hasher.cpp
    src/Proxy_C.cpp)

set(PROJECT_TESTS ${PROJECT_NAME}_tests)
add_library(${PROJECT_NAME} ${PROXYLIB_SOURCES})
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

add_executable(big_number_test
               src/tests/big_number_test.cpp
               src/tests/test_main.cpp
              )

# Standard linking to gtest stuff.
target_link_libraries(big_number_test gtest gtest_main ${PROJECT_NAME} pthread)
add_dependencies(big_number_test mbed_tls)

add_test(big_number_test big_number_test)

add_executable(re_encryption_test
               src/tests/re_encryption_test.cpp
               src/tests/test_main.cpp
              )

# Standard linking to gtest stuff.
target_link_libraries(re_encryption_test gtest gtest_main ${PROJECT_NAME} pthread)
add_dependencies(re_encryption_test mbed_tls)

add_test(re_encryption_test re_encryption_test)

add_executable(c_interface_test
               src/tests/c_interface_test.cpp
               src/tests/test_main.cpp
              )

# Standard linking to gtest stuff.
target_link_libraries(c_interface_test gtest gtest_main ${PROJECT_NAME} pthread mbedtls mbedcrypto mbedx509)
add_dependencies(c_interface_test mbed_tls)

add_test(c_interface_test c_interface_test)

