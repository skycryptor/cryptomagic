#include "gtest/gtest.h"
#include <include/helpers.h>

#include <iostream>

#include "catch/catch.hpp"
#include "Proxy.h"
#include "PrivateKey.h"
#include "Point.h"
#include "BigNumber.h"

using namespace std;
using namespace SkyCryptor;

TEST(KeyGeneration, key_generation ) {
  Proxy<Point, BigNumber> cm;
  PrivateKey<Point, BigNumber> privateKeyA = PrivateKey<Point, BigNumber>::generate();
  PublicKey<Point, BigNumber> publicKeyA = privateKeyA.get_public_key();
  PrivateKey<Point, BigNumber> privateKeyB = PrivateKey<Point, BigNumber>::generate();
  PublicKey<Point, BigNumber> publicKeyB = privateKeyB.get_public_key();
  Point g = Point::get_generator();

  // Encapsulate
  vector<char> symmetric_key;
  Capsule<Point, BigNumber> capsule = cm.encapsulate(publicKeyA, symmetric_key);

  // Testing from bytes to bytes
  std::vector<char> capsule_data;
  capsule.to_bytes(capsule_data);
  capsule = Capsule<Point, BigNumber>::from_bytes(capsule_data);

  // Decapsulating from original
  vector<char> symmetric_key_decapsulate = cm.decapsulate_original(capsule, privateKeyA);

  ASSERT_EQ( symmetric_key_decapsulate.size(), Context::get_default().get_key_length() );
  ASSERT_EQ( symmetric_key, symmetric_key_decapsulate );

  // Getting re-encryption Key!
  auto rkAB = cm.get_re_encryption_key(privateKeyA, publicKeyB);

  // Getting re-encryption capsule
  auto reCapsule = cm.get_re_encryption_capsule(capsule, rkAB);
  auto symmetricKeyRE = cm.decapsulate_re_encrypted(reCapsule, privateKeyB);

  ASSERT_EQ(symmetricKeyRE, symmetric_key);
}

