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

  Capsule CryptoMagic::encapsulate(PublicKey &pk, vector<char> &symmetric_key_out) const {
    auto ctx = (Context *)&context;
    auto rand_u = BigNumber::generate_random(ctx);
    auto rand_r = BigNumber::generate_random(ctx);
    auto g = Point::get_generator(ctx);

    // Calculating parts E, V
    auto point_E = rand_r * g;
    auto point_V = rand_u * g;

    vector<Point> tmpHash = {point_E, point_V};
    vector<char> hash = Point::hash(ctx, tmpHash);
    auto hash_bn = BigNumber::from_bytes((unsigned char*)&hash[0], hash.size(), ctx);

    // Calculating part S from BN hashing
    auto part_S = rand_u + (rand_r * hash_bn);

    // Making symmetric key
    auto point_symmetric = (rand_u + rand_r) * pk;
    vector<char> symmetric_key = KDF(point_symmetric, ctx);

    // setting output byte buffer
    symmetric_key_out.assign(symmetric_key.begin(), symmetric_key.end());

    return Capsule(point_E, point_V, part_S);
  }

  vector<char> CryptoMagic::decapsulate_original(Capsule &capsule, PrivateKey &privateKey) {
    auto ctx = (Context *)&context;
    auto symmetric_key = privateKey * (capsule.get_particleE() * capsule.get_particleV());
    return KDF(symmetric_key, ctx);
  }

  ReEncryptionKey CryptoMagic::get_re_encryption_key(PrivateKey &privateKeyA, PublicKey &publicKeyB) {
    auto ctx = (Context *)&context;
    auto tmp_privateKey = PrivateKey::generate(ctx);
    auto tmp_publicKey = tmp_privateKey.get_publicKey();
    auto tmp_publicKeyPoint = tmp_publicKey.getPoint();
    auto publicKeyPointB = publicKeyB.getPoint();
    vector<Point> points_for_hash = {
        tmp_publicKeyPoint,
        publicKeyPointB,
        tmp_privateKey * publicKeyPointB
    };
    auto tmp_hash_bytes = Point::hash(ctx, points_for_hash);
    auto hash_bn = BigNumber::from_bytes((unsigned char*)&tmp_hash_bytes[0], tmp_hash_bytes.size(), ctx);
    auto rk = privateKeyA * (~hash_bn);

    return ReEncryptionKey(rk, tmp_publicKeyPoint);
  }
}
