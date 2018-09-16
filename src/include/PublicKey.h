//
// Created by Tigran on 7/4/18.
//

#ifndef CRYPTOMAIC_PUBLICKEY_H
#define CRYPTOMAIC_PUBLICKEY_H

#include <memory>
#include "BigNumber.h"
#include "Point.h"
#include "Context.h"

namespace SkyCryptor {

/**
 * \brief PublicKey class is a base implementation for keeping EC Public Key as an object
 */
class PublicKey {

public:
  /**
   * Main constructor for making PublicKey object
   * @param ec_point Elliptic curve point for this public Key
   * @param ctx Cryptographic context pointer
   */
  PublicKey(const Point &ec_point, std::weak_ptr<Context> ctx);

  /**
   * \brief Making PublicKey with NULL point to fill it later on
   * @param ctx
   */
  PublicKey(Context *ctx);

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
  const Point& get_point() const;

  /**
   * \brief Checking if we have an equal PublicKeys or not
   * @param publicKey
   * @return true if Points are equal
   */
  bool operator==(const PublicKey& publicKey) const;

private:
  /// EC Point for this public key
  Point point_;

  /// Keeping crypto context for making decision based on specific context parameters
  /// NOTE: this class is not taking responsibility for deleting Context pointer
  std::weak_ptr<Context> context_;

};

} // namespace SkyCryptor

#endif // CRYPTOMAIC_PUBLICKEY_H
