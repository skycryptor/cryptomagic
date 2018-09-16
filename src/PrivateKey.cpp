//
// Created by Tigran on 7/4/18.
//

#include "PrivateKey.h"

namespace SkyCryptor {

PrivateKey::PrivateKey(const BigNumber& &private_key, std::weak_ptr<Context> *ctx) 
  : private_key_(private_key)
  , context_(ctx)
{
}

PrivateKey::PrivateKey(Context *ctx) 
  : context_(ctx) 
{
  private_key_ = BigNumber::generate_random(context_.get());
}

PublicKey PrivateKey::get_public_key() {
  // Making public key out of given/initialized bigNumber and context
  auto g = Point::get_generator(context.get());
  auto point = bigNumber * g;
  return std::move(PublicKey(point, context));
}

PrivateKey PrivateKey::generate(Context *ctx) {
  auto private_key = BigNumber::generate_random(ctx);
  return PrivateKey(private_key, ctx);
}

const BigNumber& PrivateKey::get_key_value() const {
  return private_key_;
}

} // namespace SkyCryptor
