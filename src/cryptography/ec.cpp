//
// Created by Tigran on 6/21/18.
//

#include "ec.h"

namespace CryptoMagic {

  EllipticCurve::EllipticCurve(int ec_group) {
    curve_group = ec_group;
  }

  EllipticCurve::EllipticCurve(string ec_group_name) {
    curve_group = OBJ_txt2nid(ec_group_name.c_str());
  }

  EllipticCurve::~EllipticCurve() {
    if (private_key != nullptr) {
      EVP_PKEY_free(private_key);
    }

    if (ec_key != nullptr) {
      EC_KEY_free(ec_key);
    }
  }

  void EllipticCurve::generateKeys() {

  }

  bool EllipticCurve::validateGroup() {
    if (ec_key == nullptr) {
      ec_key = EC_KEY_new_by_curve_name(curve_group);
    }

    return ec_key == NULL;
  }

}