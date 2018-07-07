//
// Created by Tigran on 7/5/18.
//

#include "ReEncryptionKey.h"
#include "iostream"

namespace SkyCryptor {

  ReEncryptionKey::ReEncryptionKey(const BigNumber &bn, const Point &point) : rk_number(bn), rk_point(point) {
  }

  BigNumber ReEncryptionKey::get_rk_number() {
    return rk_number;
  }

  Point ReEncryptionKey::get_rk_point() {
    return rk_point;
  }

  Point ReEncryptionKey::operator*(const Point &point) const {
    return point * rk_number;
  }
}
