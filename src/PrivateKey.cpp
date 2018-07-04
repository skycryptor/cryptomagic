//
// Created by Tigran on 7/4/18.
//

#include "PrivateKey.h"

namespace CryptoMagic {

  PrivateKey::PrivateKey(BigNumber &bn, Context *ctx) : bigNumber(bn), publicKey(ctx) {
    context = ctx;

    // Making public key out of given/initialized bigNumber and context
    auto g = Point::get_generator(ctx);
    auto point = bigNumber * g;
    publicKey = PublicKey(point, ctx);
  }

  PrivateKey::PrivateKey(Context *ctx) : bigNumber(ctx), publicKey(ctx) {
    bigNumber = BigNumber::generate_random(ctx);
    context = ctx;
  }

  PublicKey PrivateKey::get_publicKey() {
    return publicKey;
  }

  PrivateKey PrivateKey::generate(Context *ctx) {
    auto bn = BigNumber::generate_random(ctx);
    return PrivateKey(bn, ctx);
  }
}