//
// Created by tigran on 7/6/18.
//

#include "KeyPair.h"

namespace SkyCryptor {

KeyPair::KeyPair(const PrivateKey& privateKey, 
                 std::weak_ptr<Context> ctx)
    : privateKey(privateKey)
    , publicKey(privateKey.get_publicKey())
    , context_(ctx)
{

}

KeyPair::KeyPair(const PrivateKey& privateKey, 
                 const PublicKey& publicKey, 
                 std::weak_ptr<Context> ctx) 
    : privateKey(privateKey)
    , publicKey(publicKey)
    , context_(ctx)
{

}

KeyPair KeyPair::generate(std::weak_ptr<Context> ctx) {
  auto sk = PrivateKey::generate(ctx);
  return std::move(KeyPair(std::move(sk), ctx));
}

const PublicKey& KeyPair::get_public_key() const {
  return public_key_;
}

const PrivateKey& KeyPair::get_private_key() const {
  return private_key_;
}

} // namespace SkyCryptor
