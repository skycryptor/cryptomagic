//
// Created by Tigran on 7/4/18.
//

#ifndef CRYPTOMAIC_PUBLICKEY_H
#define CRYPTOMAIC_PUBLICKEY_H

#include "Point.h"
#include "Context.h"

namespace CryptoMagic {

  /**
   * PublicKey class is a base implementation for keeping EC Public Key as an object
   */
  class PublicKey {
    /// EC Point for this public key
    Point point;
    /// Keeping crypto context for making decision based on specific context parameters
    /// NOTE: this class is not taking responsibility for deleting Context pointer
    Context *context;
   public:
    /**
     * Main constructor for making PublicKey object
     * @param ec_point Elliptic curve point for this public Key
     * @param ctx Cryptographic context pointer
     */
    PublicKey(Point& ec_point, Context *ctx);
    PublicKey(Context *ctx);
    ~PublicKey() = default;

    /**
     * Checking if we have an equal PublicKeys or not
     * @param publicKey
     * @return true if Points are equal
     */
    bool operator==(const PublicKey& publicKey) const;

    /**
     * Checking if our PublicKey point is equal to given one
     * @param point
     * @return true if Points are equal
     */
    bool operator==(const Point& point) const;
  };
}

#endif //CRYPTOMAIC_PUBLICKEY_H
