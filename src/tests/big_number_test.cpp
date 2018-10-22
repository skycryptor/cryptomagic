#include "gtest/gtest.h"
#include "ECScalar.h"
#include "ECPoint.h"

#include <iostream>

using namespace SkyCryptor;
using namespace std;

TEST( ECScalarTest, big_number_primitives_test ) {
  auto bn1 = ECScalar::from_integer(5);
  auto bn2 = ECScalar::from_integer(5);
  auto bn3 = ECScalar::from_integer(10);
  auto bn4 = ECScalar::from_integer(25);
  auto bn5 = ECScalar::from_integer(50);

  ASSERT_EQ( bn1,  bn2 );
  ASSERT_EQ( (bn1 + bn2) , bn3 );
  ASSERT_EQ( (bn2 * bn3) , bn5 );
  ASSERT_EQ( (bn5 / bn3) , bn2 );
  ASSERT_EQ( (bn3 * (~bn3)), (bn2 * (~bn2)) );
  ASSERT_EQ( (bn3 - bn2), bn1 );
  ASSERT_EQ( (~(bn1 * bn2)), ((~bn1) * (~bn2)) );
}

TEST(ECScalarAndECPointActions, big_number_and_point_actions) {
  auto bn1 = ECScalar::from_integer(1);
  auto p1 = ECPoint::generate_random();

  ASSERT_EQ(p1 * bn1, p1);
}

TEST(Invert, invert) {
  ECScalar bn1 = ECScalar::from_integer(1);
  ECScalar bn2 = ECScalar::generate_random();
  ECScalar bn3 = ~bn2;
  ECScalar bn4 = bn2 * bn3;

  ASSERT_EQ(bn4 , bn1);
}

TEST(DH_KEY_EXCHANGE, dh_key_exchange ) {
  auto g = ECPoint::get_generator();
  auto aSK = ECScalar::generate_random();
  auto bSK = ECScalar::generate_random();
  auto aPK = g * aSK;
  auto bPK = g * bSK;
  auto SK1 = bPK * aSK;
  auto SK2 = aPK * bSK;

  ASSERT_EQ(SK1, SK2);
}
