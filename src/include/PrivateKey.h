//
// Created by Tigran on 7/4/18.
//

#ifndef CRYPTOMAIC_PRIVATEKEY_H
#define CRYPTOMAIC_PRIVATEKEY_H

#include "BigNumber.h"
#include "PublicKey.h"
#include <memory>

namespace SkyCryptor {

/**
 * \brief Base private key containing implementation for EC Private keys
 */
class PrivateKey {

public:
  /**
   * \brief Main constructor for making PublicKey object
   * @param bn BigNumber for private key representation
   * @param ctx Cryptographic context pointer
   */
  PrivateKey(BigNumber& bn, Context *ctx);

  /**
   * \brief By providing only Crypto context we are making random Private Key
   * this is the same as calling static generate(ctx) function
   * @param ctx
   */
  explicit PrivateKey(Context *ctx);

  PrivateKey(const PrivateKey& privateKey) = default;
  ~PrivateKey() = default;

  /**
   * \brief Getting generated PublicKey
   * NOTE: we can re-generate public key with #generate_publicKey()
   * @return PublicKey
   */
  PublicKey get_public_key();

  /**
   * \brief Generating PrivateKey using BigNumber random generator
   * This function will make PrivateKey object and will assign it inside given Context
   * @param ctx
   * @return PrivateKey
   */
  static PrivateKey generate(Context *ctx);

  /**
   * \brief Getting the big number which is representing this Private Key.
   */
  const BigNumber& get_key_value() const;

private:

  /// Private key bigNumber representation
  BigNumber private_key_;

  /// Keeping crypto context for making decision based on specific context parameters
  /// NOTE: this class is not taking responsibility for deleting Context pointer
  std::weak_ptr<Context> context_;

};

} // namespace SkyCryptor

#endif //CRYPTOMAIC_PRIVATEKEY_H
