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

  vector<char> symmetric_key;
  Capsule capsule = cm.encapsulate(publicKey, symmetric_key);

  vector<char> symmetric_key_decapsulate = cm.decapsulate_original(capsule, SK);

  REQUIRE( symmetric_key.size() == cm.getContext()->get_key_length() );
  REQUIRE( symmetric_key_decapsulate.size() == cm.getContext()->get_key_length() );
}