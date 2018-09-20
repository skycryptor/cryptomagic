#ifndef _PROXYLIB_PRIVATE_KEY_H__
#define _PROXYLIB_PRIVATE_KEY_H__

#include "PublicKey.h"
#include <memory>

namespace SkyCryptor {

/**
 * \brief Base private key containing implementation for EC Private keys
 */
template<class NUMBER_TYPE>
class PrivateKey {

public:
  /**
   * \brief Main constructor for making PublicKey object
   * @param bn NUMBER_TYPE for private key representation
   * @param context Cryptographic context pointer
   */
  PrivateKey(NUMBER_TYPE& bn, Context *context);

  /**
   * \brief By providing only Crypto context we are making random Private Key
   * this is the same as calling static generate(context) function
   * @param context
   */
  explicit PrivateKey(Context *context);

  PrivateKey(const PrivateKey& privateKey) = default;
  ~PrivateKey() = default;

  /**
   * \brief Getting generated PublicKey
   * NOTE: we can re-generate public key with #generate_publicKey()
   * @return PublicKey
   */
  PublicKey get_public_key() const;

  /**
   * \brief Generating PrivateKey using NUMBER_TYPE random generator
   * This function will make PrivateKey object and will assign it inside given Context
   * @param context
   * @return PrivateKey
   */
  static PrivateKey generate(const Context& context);

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
