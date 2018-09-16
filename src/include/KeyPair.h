//
// Created by tigran on 7/6/18.
//

#ifndef CRYPTOMAIC_KEYPAIR_H
#define CRYPTOMAIC_KEYPAIR_H

#include <memory>

#include "PublicKey.h"
#include "PrivateKey.h"

namespace SkyCryptor {

/**
 * \brief Key Pair for public and Private Keys
 * This class used as a combination of Public and Private keys, and can do some actions with both of them
 */
class KeyPair {
public:
  /**
   * \brief If we want to get KeyPair and generate public key out of given private key.
   * using this constructor, because only PrivateKey is enough to have a key pair
   * @param privateKey
   */
  explicit KeyPair(const PrivateKey& privateKey, 
                   std::weak_ptr<Context> ctx);

  /**
   * \brief Getting key KeyPair class object from given public and private keys
   * @param privateKey
   * @param publicKey
   */
  KeyPair(const PrivateKey& privateKey, 
          const PublicKey& publicKey, 
          std::weak_ptr<Context> ctx);

  ~KeyPair() = default;

  /**
   * \brief Generating random KeyPair with their private and public keys
   * This is using Private key generator and getting public key out of generated private key
   * @param ctx
   * @return
   */
  static KeyPair generate(std::weak_ptr<Context> ctx);

  /**
   * \brief Getting public key
   * @return
   */
  const PublicKey& get_public_key() const;

  /**
   * Getting private key
   * @return
   */
  const PrivateKey& get_private_key() const;

private:

  /// Public key definition as a private class member
  PublicKey public_key_;

  /// Private key definition as a private class member
  PrivateKey private_key_;

  /// Context pointer for having our crypto context available here
  /// NOTE: this class is not taking responsibility to free up this pointer
  std::weak_ptr<Context> context_;

};

} // namespace SkyCryptor 

#endif //CRYPTOMAIC_KEYPAIR_H
