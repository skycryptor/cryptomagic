//
// Created by Tigran on 7/4/18.
//

#ifndef CRYPTOMAIC_PUBLICKEY_H
#define CRYPTOMAIC_PUBLICKEY_H

#include <memory>
#include "BigNumber.h"
#include "Point.h"
#include "Context.h"

using std::shared_ptr;
using std::make_shared;

namespace SkyCryptor {
  class BigNumber;
  class Point;

  /**
   * \brief PublicKey class is a base implementation for keeping EC Public Key as an object
   */
  class PublicKey {
    /// EC Point for this public key
    shared_ptr<Point> point;
    /// Keeping crypto context for making decision based on specific context parameters
    /// NOTE: this class is not taking responsibility for deleting Context pointer
    Context *context;
   public:
    /**
     * Main constructor for making PublicKey object
     * @param ec_point Elliptic curve point for this public Key
     * @param ctx Cryptographic context pointer
     */
    PublicKey(const Point &ec_point, Context *ctx);
    /**
     * \brief Making PublicKey with NULL point to fill it later on
     * @param ctx
     */
    explicit PublicKey(Context *ctx);
    /**
     * \brief Making public key object from existing one
     * @param pk
     */
    PublicKey(const PublicKey& pk);
    ~PublicKey() = default;

    /**
     * Getting point from this public key
     * @return
     */
    Point getPoint() const;

    /**
     * \brief Checking if we have an equal PublicKeys or not
     * @param publicKey
     * @return true if Points are equal
     */
    bool operator==(const PublicKey& publicKey) const;

    /**
     * \brief Checking if our PublicKey point is equal to given one
     * @param point
     * @return true if Points are equal
     */
    bool operator==(const Point& point) const;

    /**
     * MUL for PublicKey with given BigNumber which returns a Point for later usage
     * @param point
     * @return
     */
    Point operator*(const BigNumber& other) const;
  };
}

#endif //CRYPTOMAIC_PUBLICKEY_H
