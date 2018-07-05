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

  auto rk = cm.get_re_encryption_key(privateKeyA, publicKeyB);

  auto bnZero = BigNumber::from_integer(0, cm.getContext());
  auto rk_bn = rk.get_rk_number();

  REQUIRE_FALSE( rk_bn == bnZero );
}