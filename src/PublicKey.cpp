//
// Created by Tigran on 7/4/18.
//

#include "PublicKey.h"

namespace SkyCryptor {

  PublicKey::PublicKey(const Point &ec_point, Context *ctx) {
    point = std::make_shared<Point>(ec_point);
    context = ctx;
  }

  PublicKey::PublicKey(Context *ctx) {
    point = std::make_shared<Point>(ctx);
    context = ctx;
  }

  bool PublicKey::operator==(const PublicKey &publicKey) const {
    return (*point) == (*publicKey.point);
  }

  bool PublicKey::operator==(const Point &point) const {
    return (*this->point) == point;
  }

  Point PublicKey::getPoint() const {
    return (*point);
  }

  Point PublicKey::operator*(const BigNumber &other) const {
    return (*point) * other;
  }

  PublicKey::PublicKey(const PublicKey &pk) {
    context = pk.context;
    point = pk.point;
  }
}
