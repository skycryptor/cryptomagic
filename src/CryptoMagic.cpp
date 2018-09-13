#include "CryptoMagic.h"

#include "helpers.h"
#include "KeyPair.h"

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

  Capsule CryptoMagic::encapsulate(PublicKey &pk, std::vector<char> &symmetric_key_out) const {
    auto ctx = (Context *)&context;
    // generating 2 random key pairs
    auto kp1 = KeyPair::generate(ctx);
    auto kp2 = KeyPair::generate(ctx);

    // getting private keys out of generated KeyPair
    auto skU = kp1.getPrivateKey().getBigNumber();
    auto skR = kp2.getPrivateKey().getBigNumber();

    // getting public key points
    auto point_E = kp1.getPublicKey().getPoint();
    auto point_V = kp2.getPublicKey().getPoint();

    std::vector<Point> tmpHash = {point_E, point_V};
    std::vector<char> hash = Point::hash(ctx, tmpHash);
    auto hash_bn = BigNumber::from_bytes((unsigned char*)&hash[0], hash.size(), ctx);

    // Calculating part S from BN hashing
    auto part_S = skU + (skR * hash_bn);

    // Making symmetric key
    auto point_symmetric = (skU + skR) * pk;
    std::vector<char> symmetric_key = KDF(point_symmetric, ctx);

    // setting output byte buffer
    symmetric_key_out.assign(symmetric_key.begin(), symmetric_key.end());

    return Capsule(point_E, point_V, part_S, ctx);
  }

  std::vector<char> CryptoMagic::decapsulate_original(Capsule &capsule, PrivateKey &privateKey) {
    auto ctx = (Context *)&context;
    auto symmetric_key = privateKey * (capsule.get_particleE() + capsule.get_particleV());
    return KDF(symmetric_key, ctx);
  }

  ReEncryptionKey CryptoMagic::get_re_encryption_key(PrivateKey &privateKeyA, PublicKey &publicKeyB) {
    auto ctx = (Context *)&context;
    auto tmp_privateKey = PrivateKey::generate(ctx);
    auto tmp_publicKey = tmp_privateKey.get_publicKey();
    auto tmp_publicKeyPoint = tmp_publicKey.getPoint();
    auto publicKeyPointB = publicKeyB.getPoint();
    std::vector<Point> points_for_hash = {
        tmp_publicKeyPoint,
        publicKeyPointB,
        tmp_privateKey * publicKeyPointB
    };
    auto tmp_hash_bytes = Point::hash(ctx, points_for_hash);
    auto hash_bn = BigNumber::from_bytes((unsigned char*)&tmp_hash_bytes[0], tmp_hash_bytes.size(), ctx);
    auto rk = privateKeyA * (~hash_bn);

    return ReEncryptionKey(rk, tmp_publicKeyPoint);
  }

  Capsule CryptoMagic::get_re_encryption_capsule(Capsule &capsuleOriginal, ReEncryptionKey &reEncryptionKey) {
    auto ctx = &context;
    auto primeE = reEncryptionKey * capsuleOriginal.get_particleE();
    auto primeV = reEncryptionKey * capsuleOriginal.get_particleV();

    // TODO: we should definitely change this, and figure out how to calculate primeS
    auto primeS = BigNumber::from_integer(1, ctx) * capsuleOriginal.get_particleS();

    auto primeXG = reEncryptionKey.get_rk_point();
    return Capsule(primeE, primeV, primeS, primeXG, ctx, true);
  }

  std::vector<char> CryptoMagic::decapsulate_re_encrypted(Capsule &re_encrypted_capsule, PrivateKey &privateKey) {
    auto ctx = (Context *)&context;
    auto primeXG = re_encrypted_capsule.get_particleXG();
    auto primeE = re_encrypted_capsule.get_particleE();
    auto primeV = re_encrypted_capsule.get_particleV();
    std::vector<Point> points_for_hash = {
      primeXG,
      privateKey.get_publicKey().getPoint(),
      privateKey * primeXG
    };
    auto tmp_hash_bytes = Point::hash(ctx, points_for_hash);
    auto hash_bn = BigNumber::from_bytes((unsigned char*)&tmp_hash_bytes[0], tmp_hash_bytes.size(), ctx);
    auto tmp_kdf_point = hash_bn * (primeE + primeV);
    return KDF(tmp_kdf_point, ctx);
  }
}
