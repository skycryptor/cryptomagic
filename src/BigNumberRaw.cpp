//
// Created by Tigran on 7/3/18.
//

#include "BigNumberRaw.h"

namespace SkyCryptor {

  BigNumberRaw::~BigNumberRaw() {
    if (bignum != nullptr) {
      BN_free(bignum);
    }

    if (ec_order != nullptr) {
      BN_free(ec_order);
    }

    if (bnCtx != nullptr) {
      BN_CTX_free(bnCtx);
    }
  }

  BIGNUM *BigNumberRaw::get_bignum() {
    return bignum;
  }

  void BigNumberRaw::set_bignum(BIGNUM *bn) {
    // if we have defined already BN, freeing up before assigning new one
    if (bignum != nullptr) {
      BN_free(bignum);
    }

    bignum = bn;
  }

  BIGNUM *BigNumberRaw::get_ec_order() {
    return ec_order;
  }

  void BigNumberRaw::set_ec_order(BIGNUM *order) {
    // if we have defined already ec_order, freeing up before assigning new one
    if (ec_order != nullptr) {
      BN_free(ec_order);
    }

    ec_order = order;
  }

  BN_CTX *BigNumberRaw::get_bnCtx() {
    return bnCtx;
  }

  void BigNumberRaw::set_bnCtx(BN_CTX *ctx) {
    // if we have defined already bnCtx, freeing up before assigning new one
    if (bnCtx != nullptr) {
      BN_CTX_free(bnCtx);
    }
    bnCtx = ctx;
  }
};