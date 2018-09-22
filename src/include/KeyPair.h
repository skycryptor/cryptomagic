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
   * using this constructor, because only PrivateKey<POINT_TYPE, NUMBER_TYPE> is enough to have a key pair
   * @param privateKey
   */
  explicit KeyPair(const PrivateKey<POINT_TYPE, NUMBER_TYPE>& private_key);

  /**
   * \brief Getting key KeyPair class object from given public and private keys
   * @param privateKey
   * @param publicKey
   */
  KeyPair(const PrivateKey<POINT_TYPE, NUMBER_TYPE>& private_key,
          const PublicKey<POINT_TYPE, NUMBER_TYPE>& public_key);

  ~KeyPair() = default;

  /**
   * \brief Generating random KeyPair with their private and public keys
   * This is using Private key generator and getting public key out of generated private key
   * @param ctx
   * @return
   */
  static KeyPair<POINT_TYPE, NUMBER_TYPE> generate();

  /**
   * \brief Getting public key
   * @return
   */
  const PublicKey<POINT_TYPE, NUMBER_TYPE>& get_public_key() const;

  /**
   * Getting private key
   * @return
   */
  const PrivateKey<POINT_TYPE, NUMBER_TYPE>& get_private_key() const;

private:

  /// Public key definition as a private class member
  PublicKey<POINT_TYPE, NUMBER_TYPE> public_key_;

  /// Private key definition as a private class member
  PrivateKey<POINT_TYPE, NUMBER_TYPE> private_key_;

};

} // namespace SkyCryptor 

// Include template function implementations.
#include "KeyPair.hpp"

#endif //_PROXYLIB_KEY_PAIR_H__
