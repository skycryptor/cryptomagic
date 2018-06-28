//
// Created by Tigran on 6/26/18.
//

#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
#include "cryptography/BigNumber.h"
#include "cryptography/Point.h"
#include "iostream"

using namespace CryptoMagic;

TEST_CASE( "BigNumber from_integer" ) {
  Context ctx = Context::getDefault();
  auto bn1 = BigNumber::from_integer(5, &ctx);
  auto bn2 = BigNumber::from_integer(5, &ctx);
  auto bn3 = BigNumber::from_integer(10, &ctx);
  auto bn4 = BigNumber::from_integer(25, &ctx);
  auto bn5 = BigNumber::from_integer(50, &ctx);

  REQUIRE( (bn1 == bn2) );
  REQUIRE( ((bn1 + bn2) == bn3) );
  REQUIRE( ((bn1 * bn2) == bn4) );
  REQUIRE( ((bn1 * bn3) == bn5) );
  REQUIRE( ((bn5 / bn2) == bn3) );
}

TEST_CASE( "BigNumber and Point actions" ) {
  Context ctx = Context::getDefault();
  auto bn1 = BigNumber::from_integer(1, &ctx);
  auto p1 = Point::generate_random(&ctx);
  if (p1.hasError()) {
    cout << p1.getErrorMessage() << endl;
  }

  REQUIRE( ((p1 * bn1) == p1) );
}