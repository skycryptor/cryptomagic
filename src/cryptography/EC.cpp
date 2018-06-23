//
// Created by Tigran on 6/21/18.
//

#include "EC.h"

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

  bool EllipticCurve::generateKeys() {
    if (!this->validateGroup()) {
      // TODO: define an error message
      return false;
    }

    if (!EC_KEY_generate_key(ec_key)) {
      // TODO: define an error message
      return false;
    }

    private_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(private_key, ec_key)) {
      // TODO: define an error message
      return false;
    }

    auto sA = EVP_PKEY_new();
    auto sB = EVP_PKEY_new();

    auto pA = EC_KEY_get0_public_key((EC_KEY*)sA);
    auto pB = EC_KEY_get0_public_key((EC_KEY*)sB);


    return true;
  }

  bool EllipticCurve::validateGroup() {
    if (curve_group != 0 && ec_key == nullptr) {
      ec_key = EC_KEY_new_by_curve_name(curve_group);
      // For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag
      EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
    }

    return ec_key == nullptr;
  }

}