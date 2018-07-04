//
// Created by Tigran on 7/4/18.
//

#include "PointRaw.h"

namespace CryptoMagic {

  PointRaw::~PointRaw() {
    if (ec_point != nullptr) {
      EC_POINT_free(ec_point);
    }
  }

  EC_POINT *PointRaw::get_ec_point() {
    return ec_point;
  }

  void PointRaw::set_ec_point(EC_POINT *p) {
    if (ec_point != nullptr) {
      EC_POINT_free(ec_point);
    }
    ec_point = p;
  }

}