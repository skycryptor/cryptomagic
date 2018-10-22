#include "gtest/gtest.h"

#include <iostream>

#include "catch/catch.hpp"
#include "Proxy.h"
#include "PrivateKey.h"
#include "ECPoint.h"
#include "ECScalar.h"

using namespace std;
using namespace SkyCryptor;

TEST(KeyGeneration, key_generation ) {
  Proxy<ECPoint, ECScalar> cm;
  PrivateKey<ECPoint, ECScalar> privateKeyA = PrivateKey<ECPoint, ECScalar>::generate();
  PublicKey<ECPoint, ECScalar> publicKeyA = privateKeyA.get_public_key();
  PrivateKey<ECPoint, ECScalar> privateKeyB = PrivateKey<ECPoint, ECScalar>::generate();
  PublicKey<ECPoint, ECScalar> publicKeyB = privateKeyB.get_public_key();
  ECPoint g = ECPoint::get_generator();

  // Encapsulate
  vector<char> symmetric_key;
  Capsule<ECPoint, ECScalar> capsule = cm.encapsulate(publicKeyA, symmetric_key);

  // Testing from bytes to bytes
  std::vector<char> capsule_data;
  capsule.to_bytes(capsule_data);
  capsule = Capsule<ECPoint, ECScalar>::from_bytes(capsule_data);

  // Decapsulating from original
  vector<char> symmetric_key_decapsulate = cm.decapsulate_original(capsule, privateKeyA);

  ASSERT_EQ( symmetric_key_decapsulate.size(), VersionInfoMap::get_current_version()->get_key_length() );
  ASSERT_EQ( symmetric_key, symmetric_key_decapsulate );

  // Getting re-encryption Key!
  auto rkAB = cm.get_re_encryption_key(privateKeyA, publicKeyB);

  // Getting re-encryption capsule
  auto reCapsule = cm.get_re_encryption_capsule(capsule, rkAB);
  auto symmetricKeyRE = cm.decapsulate_re_encrypted(reCapsule, privateKeyB);

  ASSERT_EQ(symmetricKeyRE, symmetric_key);
}

