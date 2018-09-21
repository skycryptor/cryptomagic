#ifndef _PROXYLIB_PUBLIC_KEY_H__
#define _PROXYLIB_PUBLIC_KEY_H__

#include <memory>

namespace SkyCryptor {

/**
 * \brief PublicKey class is a base implementation for keeping EC Public Key as an object
 */
template<class POINT_TYPE, class NUMBER_TYPE>
class PublicKey {

public:
  /**
   * Main constructor for making PublicKey object
   * @param ec_point Elliptic curve point for this public Key
   */
  PublicKey(const POINT_TYPE& ec_point);

  /**
   * \brief Making PublicKey with NULL point to fill it later on
   */
  PublicKey();

  /**
   * \brief Making public key object from existing one
   * @param pk
   */
  PublicKey(const PublicKey& pk) = default;
  ~PublicKey() = default;

  /**
   * Getting point from this public key
   * @return
   */
  const POINT_TYPE& get_point() const;

  /**
   * \brief Checking if we have an equal PublicKeys or not
   * @param publicKey
   * @return true if POINT_TYPEs are equal
   */
  bool operator==(const PublicKey& publicKey) const;

private:
  /// EC POINT_TYPE for this public key
  POINT_TYPE point_;

};

} // namespace SkyCryptor

// Include template function implementations.
#include "PublicKey.hpp"

#endif // _PROXYLIB_PUBLIC_KEY_H__
