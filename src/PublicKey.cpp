//
// Created by Tigran on 7/4/18.
//

#include "PublicKey.h"

namespace CryptoMagic {

  PublicKey::PublicKey(Point &ec_point, Context *ctx) : point(ctx) {
    point = ec_point;
    context = ctx;
  }

  PublicKey::PublicKey(Context *ctx) : point(ctx) {
    context = ctx;
  }

  bool PublicKey::operator==(const PublicKey &publicKey) const {
    return point == publicKey.point;
  }

  bool PublicKey::operator==(const Point &point) const {
    return this->point == point;
  }

}