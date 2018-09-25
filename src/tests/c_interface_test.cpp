#include "gtest/gtest.h"

#include <cstring>
#include "catch/catch.hpp"
#include "Proxy_C.h"
#include "iostream"

using namespace std;

TEST(CInterfaceTest1, C_interface_test_1) {
  proxylib_init();
  // making new CryptoMagic object
  void *cm = proxylib_new();
  void *sk = proxylib_generate_private_key(cm);
  void *pk = proxylib_get_public_key(sk);

  char *symmetricKey1; int symmetricKeyLen1;
  char *symmetricKey2; int symmetricKeyLen2;

  void *capsule = proxylib_encapsulate(cm, pk, &symmetricKey1, &symmetricKeyLen1);
  proxylib_decapsulate(cm, capsule, sk, &symmetricKey2, &symmetricKeyLen2);

  ASSERT_EQ(symmetricKeyLen1, symmetricKeyLen2);
  ASSERT_EQ(strncmp(symmetricKey1, symmetricKey2, symmetricKeyLen1), 0);

  free(symmetricKey1);
  free(symmetricKey2);
  proxylib_capsule_free(capsule);
  proxylib_public_key_free(pk);
  proxylib_private_key_free(sk);
  proxylib_clear(cm);
}

