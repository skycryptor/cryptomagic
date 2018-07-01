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
//  Context ctx = Context::getDefault();
//  auto bn1 = BigNumber::from_integer(5, &ctx);
//  auto bn2 = BigNumber::from_integer(5, &ctx);
//  auto bn3 = BigNumber::from_integer(10, &ctx);
//  auto bn4 = BigNumber::from_integer(25, &ctx);
//  auto bn5 = BigNumber::from_integer(50, &ctx);
//
//  REQUIRE( ((*bn1) == (*bn2)) );
//  REQUIRE( (((*bn1) + (*bn2)) == (*bn3)) );
//  REQUIRE( ((*bn1 * *bn2) == *bn4) );
//  REQUIRE( ((*bn1 * *bn3) == *bn5) );
//  REQUIRE( ((*bn5 / *bn2) == *bn3) );
}

TEST_CASE( "BigNumber and Point actions" ) {
  while (1) {
    Context ctx = Context::getDefault();
    auto bn1 = BigNumber::from_integer(1, &ctx);
    Point p1 = Point::generate_random(&ctx);
    if (p1.hasError()) {
      cout << p1.getErrorMessage() << endl;
    }

    REQUIRE( (p1.mul(bn1.get()) == p1) );
  }
}

//TEST_CASE( "Testing invert function for BigNumber class" ) {
//  Context ctx = Context::getDefault();
//  BigNumber *bn1 = BigNumber::from_integer(1, &ctx);
//  BigNumber *bn2 = BigNumber::generate_random(&ctx);
//  auto bn3 = ~(*bn2);
//  auto bn4 = (*bn2) * bn3;
//
//  REQUIRE( (bn4 == (*bn1)) );
//  delete bn1;
//  delete bn2;
//}
//
//TEST_CASE( "Testing DH Key exchange" ) {
//  Context ctx = Context::getDefault();
//  auto g = Point::get_generator(&ctx);
//  auto *aSK = BigNumber::generate_random(&ctx);
//  auto *bSK = BigNumber::generate_random(&ctx);
//  auto aPK = g * *aSK;
//  auto bPK = g * *bSK;
//  auto SK1 = bPK * *aSK;
//  auto SK2 = aPK * *bSK;
//
//  cout << "SK1: " << SK1.toHex() << "\nSK2: " << SK2.toHex() << endl;
//
//  REQUIRE( (SK1 == SK2) );
//}

// Hash function for BN and Point
// BigNumber -> Point, Point -> BigNumber convert functions
// Make BigNumber * Point also