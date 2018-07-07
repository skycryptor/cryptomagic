//
// Created by Tigran on 7/4/18.
//

#include "Capsule.h"

namespace SkyCryptor {

  Capsule::Capsule(Point& E, Point& V, BigNumber& S, Context *ctx)
    : particleE(E), particleV(V), particleS(S), particleXG(ctx) {}

  Point Capsule::get_particleE() const {
    return particleE;
  }

  Point Capsule::get_particleV() const {
    return particleV;
  }

  BigNumber Capsule::get_particleS() const {
    return particleS;
  }

  Capsule::Capsule(Point &E, Point &V, BigNumber &S, Point &XG, Context *ctx)
    : particleE(E), particleV(V), particleS(S), particleXG(XG) {}

  Point Capsule::get_particleXG() const {
    return particleXG;
  }
}
