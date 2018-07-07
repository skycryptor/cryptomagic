//
// Created by Tigran on 7/4/18.
//

#include "PrivateKey.h"

namespace SkyCryptor {

  PrivateKey::PrivateKey(BigNumber &bn, Context *ctx) : bigNumber(bn) {
    context = ctx;
  }

  PrivateKey::PrivateKey(Context *ctx) : bigNumber(ctx) {
    bigNumber = BigNumber::generate_random(ctx);
    context = ctx;
  }

  PublicKey PrivateKey::get_publicKey() {
    // Making public key out of given/initialized bigNumber and context
    auto g = Point::get_generator(context);
    auto point = bigNumber * g;
    return PublicKey(point, context);
  }

  PrivateKey PrivateKey::generate(Context *ctx) {
    auto bn = BigNumber::generate_random(ctx);
    return PrivateKey(bn, ctx);
  }

  Point PrivateKey::operator*(const Point &other) const {
    return other * bigNumber;
  }

  BigNumber PrivateKey::operator*(const BigNumber &other) const {
    return bigNumber * other;
  }

  PrivateKey::PrivateKey(const PrivateKey& privateKey) : bigNumber(privateKey.bigNumber) {
    context = privateKey.context;
  }

  BigNumber PrivateKey::getBigNumber() {
    return bigNumber;
  }
}
