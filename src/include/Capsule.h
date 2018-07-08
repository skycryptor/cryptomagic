//
// Created by Tigran on 7/4/18.
//

#ifndef CRYPTOMAIC_CAPSULE_H
#define CRYPTOMAIC_CAPSULE_H

#include "Point.h"

namespace SkyCryptor {

  /**
   * \brief Combination of parameters as a definition for cryptographic capsule
   * Each capsule contains E(Point), V(Point), s(BigNumber)
   */
  class Capsule {
    /// Defining Capsule particles
    Point particleE;
    Point particleV;
    BigNumber particleS;
    Point particleXG;

    /// Keeping crypto context available for capsule
    /// NOTE: this class is not taking responsibility for cleaning up this pointer
    Context *context;

   public:
    /**
     * \brief Making capsule with given particles
     * @param E
     * @param V
     * @param S
     * @param ctx
     */
    Capsule(Point& E, Point& V, BigNumber& S, Context *ctx);
    /**
     * \brief Making capsule with particles and public key to be encoded with it
     * @param E
     * @param V
     * @param S
     * @param XG
     * @param ctx
     */
    Capsule(Point& E, Point& V, BigNumber& S, Point& XG, Context *ctx);
    /**
     * \brief Copy constructor from another capsule
     * @param other
     */
    Capsule(const Capsule& other);
    ~Capsule() = default;

    /**
     * Getting particle E as a Point
     * @return
     */
    Point get_particleE() const;

    /**
     * Getting particle V as a Point
     * @return
     */
    Point get_particleV() const;

    /**
     * Getting particle S as a BigNumber
     * @return
     */
    BigNumber get_particleS() const;

    /**
     * Getting particle XG
     * @return
     */
    Point get_particleXG() const;
  };
}

#endif //CRYPTOMAIC_CAPSULE_H
