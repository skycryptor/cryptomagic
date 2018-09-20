#ifndef _PROXYLIB_KEY_PAIR_H__
#define _PROXYLIB_KEY_PAIR_H__

#include <memory>

#include "PublicKey.h"
#include "PrivateKey.h"

namespace SkyCryptor {

/**
 * \brief Key Pair for public and Private Keys
 * This class used as a combination of Public and Private keys, and can do some actions with both of them
 */
template<class POINT_TYPE, class NUMBER_TYPE>
class KeyPair {
public:
  /**
   * \brief If we want to get KeyPair and generate public key out of given private key.
   * using this constructor, because only PrivateKey<NUMBER_TYPE> is enough to have a key pair
   * @param privateKey
   */
  explicit KeyPair(const PrivateKey<NUMBER_TYPE>& privateKey, 
                   std::weak_ptr<Context> ctx);

  /**
   * \brief Getting key KeyPair class object from given public and private keys
   * @param privateKey
   * @param publicKey
   */
  KeyPair(const PrivateKey<NUMBER_TYPE>& privateKey, 
          const PublicKey<POINT_TYPE, NUMBER_TYPE>& publicKey, 
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
  const PublicKey<POINT_TYPE, NUMBER_TYPE>& get_public_key() const;

  /**
   * Getting private key
   * @return
   */
  const PrivateKey<NUMBER_TYPE>& get_private_key() const;

private:

  /// Public key definition as a private class member
  PublicKey<POINT_TYPE, NUMBER_TYPE> public_key_;

  /// Private key definition as a private class member
  PrivateKey<NUMBER_TYPE> private_key_;

  /// Context pointer for having our crypto context available here
  /// NOTE: this class is not taking responsibility to free up this pointer
  std::weak_ptr<Context> context_;

};

} // namespace SkyCryptor 

// Include template function implementations.
#include "KeyPair.hpp"

#endif //_PROXYLIB_KEY_PAIR_H__
