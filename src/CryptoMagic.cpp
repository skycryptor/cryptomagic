#include "CryptoMagic.h"

#include "helpers.h"

namespace SkyCryptor {

  CryptoMagic::CryptoMagic(Context ctx) {
    context = ctx;
  }

  Context *CryptoMagic::CryptoMagic::getContext() {
    return &context;
  }

  void CryptoMagic::setContext(const Context &ctx) {
    context = ctx;
  }

  Capsule CryptoMagic::encapsulate(PublicKey &pk, string &symmetric_key_out) const {
    Context *ctx = (Context *)&context;
    auto rand_u = BigNumber::generate_random(ctx);
    auto rand_r = BigNumber::generate_random(ctx);
    auto g = Point::get_generator(ctx);

    // Calculating parts E, V
    auto point_E = rand_r * g;
    auto point_V = rand_u * g;

    vector<Point> tmpHash = {point_E, point_V};
    string hash = Point::hash(ctx, tmpHash);
    auto hash_bn = BigNumber::from_bytes((unsigned char*)hash.c_str(), hash.length(), ctx);

    // Calculating part S from BN hashing
    auto part_S = rand_u + (rand_r * hash_bn);

    // Making symmetric key
    auto point_symmetric = (rand_u + rand_u) * pk;
    string symmetric_key = KDF(point_symmetric, ctx);

    // setting output byte buffer
    symmetric_key_out.assign(symmetric_key);

    return Capsule(point_E, point_V, part_S);
  }
}
