#ifndef _PROXYLIB_PRIVATE_KEY_H__
#define _PROXYLIB_PRIVATE_KEY_H__

#include "PublicKey.h"
#include <memory>

namespace SkyCryptor {

/**
 * \brief Base private key containing implementation for EC Private keys
 */
template<class POINT_TYPE, class NUMBER_TYPE>
class PrivateKey {

public:
  /**
   * \brief Main constructor for making PublicKey object
   * @param bn NUMBER_TYPE for private key representation
   */
  PrivateKey(const NUMBER_TYPE& private_key);

  /**
   * \brief By providing only Crypto context we are making random Private Key
   * @param context
   */
  explicit PrivateKey();

  PrivateKey(const PrivateKey<POINT_TYPE, NUMBER_TYPE>& privateKey) = default;
  ~PrivateKey() = default;

  /**
   * \brief Getting generated PublicKey
   * NOTE: we can re-generate public key with #generate_publicKey()
   * @return PublicKey
   */
  PublicKey<POINT_TYPE, NUMBER_TYPE> get_public_key() const;

  /**
   * \brief Generating PrivateKey using NUMBER_TYPE random generator
   * This function will make PrivateKey object and will assign it inside given Context
   * @param context
   * @return PrivateKey
   */
  static PrivateKey<POINT_TYPE, NUMBER_TYPE> generate();

  /**
   * \brief Getting the big number which is representing this Private Key.
   */
  const NUMBER_TYPE& get_key_value() const;

private:

  /// Private key bigNumber representation
  NUMBER_TYPE private_key_;

};

} // namespace SkyCryptor

// Include template function implementations.
#include "PrivateKey.hpp"

#endif //_PROXYLIB_PRIVATE_KEY_H__
