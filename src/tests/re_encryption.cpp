//
// Created by Tigran on 7/5/18.
//

#include "catch/catch.hpp"
#include "CryptoMagic.h"
#include "PrivateKey.h"
#include "iostream"

using namespace std;
using namespace SkyCryptor;

TEST_CASE( "Re-encryption key generation" ) {
  CryptoMagic cm;
  auto privateKeyA = PrivateKey::generate(cm.getContext());
  auto publicKeyA = privateKeyA.get_publicKey();
  auto privateKeyB = PrivateKey::generate(cm.getContext());
  auto publicKeyB = privateKeyB.get_publicKey();
  auto g = Point::get_generator(cm.getContext());

  // Encapsulate
  vector<char> symmetric_key;
  Capsule capsule = cm.encapsulate(publicKeyA, symmetric_key);

  // Decapsulating from original
  vector<char> symmetric_key_decapsulate = cm.decapsulate_original(capsule, privateKeyA);

  REQUIRE( symmetric_key_decapsulate.size() == cm.getContext()->get_key_length() );
  REQUIRE( symmetric_key == symmetric_key_decapsulate );

  // Getting re-encryption Key!
  auto rkAB = cm.get_re_encryption_key(privateKeyA, publicKeyB);

  // Getting re-encryption capsule
  auto reCapsule = cm.get_re_encryption_capsule(capsule, rkAB);
  auto symmetricKeyRE = cm.decapsulate_re_encrypted(reCapsule, privateKeyB);

//  REQUIRE( symmetricKeyRE == symmetric_key );
}
