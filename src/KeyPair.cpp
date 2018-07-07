//
// Created by tigran on 7/6/18.
//

#include "KeyPair.h"

namespace SkyCryptor {

  KeyPair::KeyPair(PrivateKey& privateKey, Context *ctx) : privateKey(privateKey), publicKey(ctx) {
    publicKey = privateKey.get_publicKey();
    context = ctx;
  }

  KeyPair::KeyPair(PrivateKey &privateKey, PublicKey &publicKey, Context *ctx) : privateKey(privateKey), publicKey(publicKey) {
    context = ctx;
  }

  KeyPair KeyPair::generate(Context *ctx) {
    auto sk = PrivateKey::generate(ctx);
    return KeyPair(sk, ctx);
  }

  PublicKey KeyPair::getPublicKey() {
    return publicKey;
  }

  PrivateKey KeyPair::getPrivateKey() {
    return privateKey;
  }
}
