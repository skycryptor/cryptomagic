//
// Created by Tigran on 7/5/18.
//

#include "catch/catch.hpp"
#include "CryptoMagic.h"
#include "PrivateKey.h"
#include "iostream"

using namespace SkyCryptor;
using namespace std;

TEST_CASE( "Encapsulating Public Key from random PrivateKey" ) {
  CryptoMagic cm;
  auto SK = PrivateKey::generate(cm.getContext());
  auto publicKey = SK.get_publicKey();

  string symmetric_key;
  Capsule capsule = cm.encapsulate(publicKey, symmetric_key);

  REQUIRE( symmetric_key.length() > 0 );
  REQUIRE( symmetric_key.length() <= cm.getContext()->get_key_length() );
}