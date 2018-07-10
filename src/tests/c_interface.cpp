//
// Created by tigran on 7/8/18.
//

#include "catch/catch.hpp"
#include "CryptoMagic_C.h"
#include "iostream"
#include <string.h>

using namespace std;

TEST_CASE( "C interface test1" ) {
  cryptomagic_init();
  // making new CryptoMagic object
  void *cm = cryptomagic_new();
  void *sk = cryptomagic_generate_private_key(cm);
  void *pk = cryptomagic_get_public_key(sk);

  char *symmetricKey1; int symmetricKeyLen1;
  char *symmetricKey2; int symmetricKeyLen2;

  void *capsule = cryptomagic_encapsulate(cm, pk, &symmetricKey1, &symmetricKeyLen1);
  cryptomagic_decapsulate_original(cm, capsule, sk, &symmetricKey2, &symmetricKeyLen2);

  REQUIRE( symmetricKeyLen1 == symmetricKeyLen2 );
  REQUIRE( strncmp(symmetricKey1, symmetricKey2, symmetricKeyLen1) == 0 );

  free(symmetricKey1);
  free(symmetricKey2);
  cryptomagic_capsule_free(capsule);
  cryptomagic_public_key_free(pk);
  cryptomagic_private_key_free(sk);
  cryptomagic_clear(cm);
}
