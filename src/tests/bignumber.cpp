//
// Created by Tigran on 6/26/18.
//

#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
#include "cryptography/BigNumber.h"
#include "iostream"

using namespace CryptoMagic;

TEST_CASE( "BigNumber from_integer" ) {
  Context ctx = Context::getDefault();
  auto bn1 = BigNumber::from_integer(10, &ctx);
  auto bn2 = BigNumber::from_integer(10, &ctx);
  bool isEqual = bn1 == bn2;
  REQUIRE( isEqual );
}