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
  int i = 0;
  while (i < 20000000) {
    Context ctx = Context::getDefault();
    auto bn1 = shared_ptr<BigNumber>(BigNumber::from_integer(5, &ctx));
    auto bn2 = shared_ptr<BigNumber>(BigNumber::from_integer(5, &ctx));
    auto bn3 = shared_ptr<BigNumber>(BigNumber::from_integer(10, &ctx));
    auto bn4 = shared_ptr<BigNumber>(BigNumber::from_integer(25, &ctx));
    auto bn5 = shared_ptr<BigNumber>(BigNumber::from_integer(50, &ctx));

    REQUIRE( bn1->eq(bn2.get()) );
    REQUIRE( bn1->add(bn2.get())->eq(bn3.get()) );
    REQUIRE( bn2->mul(bn3.get())->eq(bn5.get()) );
    REQUIRE( bn2->div(bn3.get())->eq(bn1->sub(bn2.get())) );

    i++;
  }
}

//TEST_CASE( "BigNumber and Point actions" ) {
//  while (1) {
//    Context ctx = Context::getDefault();
//    auto bn1 = BigNumber::from_integer(1, &ctx);
//    Point p1 = Point::generate_random(&ctx);
//    if (p1.hasError()) {
//      cout << p1.getErrorMessage() << endl;
//    }
//
//    REQUIRE( (p1.mul(bn1.get()) == p1) );
//  }
//}

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