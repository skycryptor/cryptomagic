#include "Hasher.h"
#include "KeyPair.h"
#include "VersionInfo.h"
#include "VersionInfoMap.h"

namespace SkyCryptor {

template<class POINT_TYPE, class NUMBER_TYPE>
Capsule<POINT_TYPE, NUMBER_TYPE> Proxy<POINT_TYPE, NUMBER_TYPE>::encapsulate(
    const PublicKey<POINT_TYPE, NUMBER_TYPE>& pk, 
    std::vector<char>& symmetric_key_out) const {
  // generating 2 random key pairs
  KeyPair<POINT_TYPE, NUMBER_TYPE> kp1 = std::move(KeyPair<POINT_TYPE, NUMBER_TYPE>::generate());
  KeyPair<POINT_TYPE, NUMBER_TYPE> kp2 = std::move(KeyPair<POINT_TYPE, NUMBER_TYPE>::generate());

  // getting private keys out of generated KeyPair<POINT_TYPE, NUMBER_TYPE>
  NUMBER_TYPE skU = kp1.get_private_key().get_key_value();
  NUMBER_TYPE skR = kp2.get_private_key().get_key_value();

  // getting public key points
  POINT_TYPE point_E = kp1.get_public_key().get_point();
  POINT_TYPE point_V = kp2.get_public_key().get_point();

  std::vector<POINT_TYPE> tmpHash = {point_E, point_V};
  std::vector<char> hash = POINT_TYPE::hash(tmpHash);
  auto hash_bn = NUMBER_TYPE::from_bytes((unsigned char*)&hash[0], hash.size());

  // Calculating part S from BN hashing
  auto part_S = skU + (skR * hash_bn);

  // Making symmetric key
  POINT_TYPE point_symmetric = (skU + skR) * pk.get_point();
  std::vector<char> symmetric_key = Hasher::get_default().SHA_256(*VersionInfoMap::get_current_version(), point_symmetric);

  // setting output byte buffer
  symmetric_key_out.assign(symmetric_key.begin(), symmetric_key.end());

  return Capsule<POINT_TYPE, NUMBER_TYPE>(point_E, point_V, part_S);
}

template<class POINT_TYPE, class NUMBER_TYPE>
std::vector<char> Proxy<POINT_TYPE, NUMBER_TYPE>::decapsulate_original(
    const Capsule<POINT_TYPE, NUMBER_TYPE>& capsule, 
    const PrivateKey<POINT_TYPE, NUMBER_TYPE>& private_key) {
  auto symmetric_key = private_key.get_key_value() * 
      (capsule.get_E() + capsule.get_V());
  return Hasher::get_default().SHA_256(*VersionInfoMap::get_current_version(), symmetric_key);
}

template<class POINT_TYPE, class NUMBER_TYPE>
ReEncryptionKey<POINT_TYPE, NUMBER_TYPE> Proxy<POINT_TYPE, NUMBER_TYPE>::get_re_encryption_key(
    const PrivateKey<POINT_TYPE, NUMBER_TYPE>& private_key_A, 
    const PublicKey<POINT_TYPE, NUMBER_TYPE>& public_key_B) {
  auto tmp_private_key = PrivateKey<POINT_TYPE, NUMBER_TYPE>::generate();
  auto tmp_public_key = tmp_private_key.get_public_key();
  const POINT_TYPE& tmp_public_key_point = tmp_public_key.get_point();
  const POINT_TYPE& public_key_point_B = public_key_B.get_point();
  std::vector<POINT_TYPE> points_for_hash = {
      tmp_public_key_point,
      public_key_point_B,
      tmp_private_key.get_key_value() * public_key_point_B
  };
  auto tmp_hash_bytes = POINT_TYPE::hash(points_for_hash);
  auto hash_bn = NUMBER_TYPE::from_bytes(
      (unsigned char*)&tmp_hash_bytes[0], tmp_hash_bytes.size());
  auto rk = private_key_A.get_key_value() * (~hash_bn);

  return ReEncryptionKey<POINT_TYPE, NUMBER_TYPE>(rk, tmp_public_key_point);
}

template<class POINT_TYPE, class NUMBER_TYPE>
Capsule<POINT_TYPE, NUMBER_TYPE> Proxy<POINT_TYPE, NUMBER_TYPE>::get_re_encryption_capsule(
    const Capsule<POINT_TYPE, NUMBER_TYPE>& capsule_original, 
    const ReEncryptionKey<POINT_TYPE, NUMBER_TYPE>& re_encryption_key) {
  POINT_TYPE prime_E = re_encryption_key.get_rk_number() * capsule_original.get_E();
  POINT_TYPE prime_V = re_encryption_key.get_rk_number() * capsule_original.get_V();

  // TODO: we should definitely change this, and figure out how to calculate primeS
  NUMBER_TYPE prime_S = NUMBER_TYPE::from_integer(1) * capsule_original.get_S();

  return Capsule<POINT_TYPE, NUMBER_TYPE>(
      prime_E, prime_V, prime_S, re_encryption_key.get_rk_point(), true);
}

template<class POINT_TYPE, class NUMBER_TYPE>
std::vector<char> Proxy<POINT_TYPE, NUMBER_TYPE>::decapsulate_re_encrypted(
    const Capsule<POINT_TYPE, NUMBER_TYPE>& re_encrypted_capsule, 
    const PrivateKey<POINT_TYPE, NUMBER_TYPE>& private_key) {
  POINT_TYPE prime_XG = re_encrypted_capsule.get_XG();
  POINT_TYPE prime_E = re_encrypted_capsule.get_E();
  POINT_TYPE prime_V = re_encrypted_capsule.get_V();
  std::vector<POINT_TYPE> points_for_hash = {
    prime_XG,
    private_key.get_public_key().get_point(),
    private_key.get_key_value() * prime_XG
  };
  auto tmp_hash_bytes = POINT_TYPE::hash(points_for_hash);
  auto hash_bn = NUMBER_TYPE::from_bytes(
    (unsigned char*)&tmp_hash_bytes[0], tmp_hash_bytes.size());
  auto tmp_kdf_point = hash_bn * (prime_E + prime_V);
  return Hasher::get_default().SHA_256(*VersionInfoMap::get_current_version(), tmp_kdf_point);
}

} // namespace SkyCryptor

