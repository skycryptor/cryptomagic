#include "gtest/gtest.h"
#include "BigNumber.h"
#include "Point.h"

#include <iostream>

using namespace SkyCryptor;
using namespace std;

TEST( BigNumberTest, big_number_primitives_test ) {
  auto bn1 = BigNumber::from_integer(5);
  auto bn2 = BigNumber::from_integer(5);
  auto bn3 = BigNumber::from_integer(10);
  auto bn4 = BigNumber::from_integer(25);
  auto bn5 = BigNumber::from_integer(50);

  ASSERT_EQ( bn1,  bn2 );
  ASSERT_EQ( (bn1 + bn2) , bn3 );
  ASSERT_EQ( (bn2 * bn3) , bn5 );
  ASSERT_EQ( (bn5 / bn3) , bn2 );
  ASSERT_EQ( (bn3 * (~bn3)), (bn2 * (~bn2)) );
  ASSERT_EQ( (bn3 - bn2), bn1 );
  ASSERT_EQ( (~(bn1 * bn2)), ((~bn1) * (~bn2)) );
}

TEST(BigNumberAndPointActions, big_number_and_point_actions) {
  auto bn1 = BigNumber::from_integer(1);
  auto p1 = Point::generate_random();
  if (p1.hasError()) {
    cout << p1.getErrorMessage() << endl;
  }

  ASSERT_EQ(p1 * bn1, p1);
}

TEST(Invert, invert) {
  BigNumber bn1 = BigNumber::from_integer(1);
  BigNumber bn2 = BigNumber::generate_random();
  BigNumber bn3 = ~bn2;
  BigNumber bn4 = bn2 * bn3;

  ASSERT_EQ(bn4 , bn1);
}

TEST(DH_KEY_EXCHANGE, dh_key_exchange ) {
  auto g = Point::get_generator();
  auto aSK = BigNumber::generate_random();
  auto bSK = BigNumber::generate_random();
  auto aPK = g * aSK;
  auto bPK = g * bSK;
  auto SK1 = bPK * aSK;
  auto SK2 = aPK * bSK;

  ASSERT_EQ(SK1, SK2);
}
