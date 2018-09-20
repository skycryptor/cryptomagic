#include "catch/catch.hpp"
#include "BigNumber.h"
#include "Point.h"

#include <iostream>

using namespace SkyCryptor;
using namespace std;

TEST_CASE( "BigNumber from_integer" ) {
  auto bn1 = BigNumber::from_integer(5);
  auto bn2 = BigNumber::from_integer(5);
  auto bn3 = BigNumber::from_integer(10);
  auto bn4 = BigNumber::from_integer(25);
  auto bn5 = BigNumber::from_integer(50);

  REQUIRE( bn1 == bn2 );
  REQUIRE( (bn1 + bn2) == bn3 );
  REQUIRE( (bn2 * bn3) == bn5 );
  REQUIRE( (bn5 / bn3) == bn2 );
  REQUIRE( (bn3 * (~bn3)) == (bn2 * (~bn2)) );
  REQUIRE( (bn3 - bn2)== bn1 );
  REQUIRE( (~(bn1 * bn2)) == ((~bn1) * (~bn2)) );
}

TEST_CASE( "BigNumber and Point actions" ) {
  auto bn1 = BigNumber::from_integer(1);
  auto p1 = Point::generate_random();
  if (p1.hasError()) {
    cout << p1.getErrorMessage() << endl;
  }

  REQUIRE( p1 * bn1 == p1 );
}

TEST_CASE( "Testing invert function for BigNumber class" ) {
  auto bn1 = BigNumber::from_integer(1);
  auto bn2 = BigNumber::generate_random();
  auto bn3 = ~bn2;
  auto bn4 = bn2 * bn3;

  REQUIRE( bn4 == bn1 );
}

TEST_CASE( "Testing DH Key exchange" ) {
  auto g = Point::get_generator();
  auto aSK = BigNumber::generate_random();
  auto bSK = BigNumber::generate_random();
  auto aPK = g * aSK;
  auto bPK = g * bSK;
  auto SK1 = bPK * aSK;
  auto SK2 = aPK * bSK;

  REQUIRE( SK1 == SK2 );
}
