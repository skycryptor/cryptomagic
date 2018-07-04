//
// Created by Tigran on 7/4/18.
//

#ifndef CRYPTOMAIC_CAPSULE_H
#define CRYPTOMAIC_CAPSULE_H

#include "Point.h"

namespace CryptoMagic {

  /**
   * \brief Combination of parameters as a definition for cryptographic capsule
   * Each capsule contains E(Point), V(Point), s(BigNumber)
   */
  class Capsule {
    /// Defining Capsule particles
    Point particleE;
    Point particleV;
    BigNumber particleS;

   public:
    /**
     * \brief Making capsule with given particles
     * @param E
     * @param V
     * @param S
     */
    Capsule(Point E, Point V, BigNumber S);
    ~Capsule() = default;
  };
}

#endif //CRYPTOMAIC_CAPSULE_H
