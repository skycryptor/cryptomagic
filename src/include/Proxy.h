#ifndef _CRYPTOMAGIC_PROXY_H__
#define _CRYPTOMAGIC_PROXY_H__

#include "Context.h"
#include "Capsule.h"
#include "PublicKey.h"
#include "PrivateKey.h"
#include "ReEncryptionKey.h"

namespace SkyCryptor {

/**
 * \brief Proxy base class for handling library crypto operations and main functionality
 * Each initialized Proxy object should contain Context which will define
 * base parameters for crypto operations and configurations
 */
template<class POINT_TYPE, class NUMBER_TYPE>
class Proxy {
public:

  Proxy() = default;
  ~Proxy() = default;

  /**
   * \brief Making capsule out of given PublicKey<POINT_TYPE, NUMBER_TYPE> and given crypto Context and also returning
   * symmetric key wrapped as a string object
   *
   * @param pk "Alice" Public Key
   * @param[out] symmetric_key_out
   * @return Capsule<POINT_TYPE, NUMBER_TYPE>
   */
  Capsule<POINT_TYPE, NUMBER_TYPE> encapsulate(const PublicKey<POINT_TYPE, NUMBER_TYPE>& pk, std::vector<char>& symmetric_key_out) const;

  /**
   * \brief Decapsulate given capsule with private key,
   * NOTE: Provided private key, should be the original key from which Public Key capsule is created
   * @param capsule
   * @param privateKey
   * @return
   */
  std::vector<char> decapsulate_original(
      const Capsule<POINT_TYPE, NUMBER_TYPE>& capsule, 
      const PrivateKey<POINT_TYPE, NUMBER_TYPE>& privateKey);

  /**
   * \brief Getting re-encryption key out of Private key (Alice) and public key (Bob) using random private key generation
   * @param privateKeyA
   * @param publicKeyB
   * @return
   */
  ReEncryptionKey<POINT_TYPE, NUMBER_TYPE> get_re_encryption_key(
      const PrivateKey<POINT_TYPE, NUMBER_TYPE>& private_key_A, 
      const PublicKey<POINT_TYPE, NUMBER_TYPE>& public_key_B);

  /**
   * \brief Getting re-encryption capsule from given original capsule and re-encryption key
   * @param capsuleOriginal
   * @param reEncryptionKey
   * @return
   */
  Capsule<POINT_TYPE, NUMBER_TYPE> get_re_encryption_capsule(
      const Capsule<POINT_TYPE, NUMBER_TYPE>& capsuleOriginal,
      const ReEncryptionKey<POINT_TYPE, NUMBER_TYPE>& reEncryptionKey);

  /**
   * \brief Decapsulating given capsule with provided private key
   * @param re_encrypted_capsule
   * @param privateKey
   * @return
   */
  std::vector<char> decapsulate_re_encrypted(
      const Capsule<POINT_TYPE, NUMBER_TYPE>& re_encrypted_capsule, 
      const PrivateKey<POINT_TYPE, NUMBER_TYPE>& privateKey);

};

} // namespace SkyCryptor

// Include template function implementations.
#include "Proxy.hpp"

#endif
