#include <include/helpers.h>

#include <iostream>

#include "catch/catch.hpp"
#include "CryptoMagic.h"
#include "PrivateKey.h"
#include "Point.h"
#include "BigNumber.h"

using namespace std;
using namespace SkyCryptor;

TEST_CASE( "Re-encryption key generation" ) {
  Proxy<Point, BigNumber> cm;
  auto privateKeyA = PrivateKey::generate();
  auto publicKeyA = privateKeyA.get_publicKey();
  auto privateKeyB = PrivateKey::generate();
  auto publicKeyB = privateKeyB.get_publicKey();
  auto g = Point::get_generator();

  // Encapsulate
  vector<char> symmetric_key;
  Capsule capsule = cm.encapsulate(publicKeyA, symmetric_key);

  // Testing from bytes to bytes
  auto capsule_data = capsule.to_bytes();
  capsule = Capsule::from_bytes(capsule_data);

  // Decapsulating from original
  vector<char> symmetric_key_decapsulate = cm.decapsulate_original(capsule, privateKeyA);

  REQUIRE( symmetric_key_decapsulate.size() == Context.get_default().get_key_length() );
  REQUIRE( symmetric_key == symmetric_key_decapsulate );

  // Getting re-encryption Key!
  auto rkAB = cm.get_re_encryption_key(privateKeyA, publicKeyB);

  // Getting re-encryption capsule
  auto reCapsule = cm.get_re_encryption_capsule(capsule, rkAB);
  auto symmetricKeyRE = cm.decapsulate_re_encrypted(reCapsule, privateKeyB);

  REQUIRE( symmetricKeyRE == symmetric_key );
}

