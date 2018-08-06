//
// Created by Tigran on 7/3/18.
//

#include <include/BigNumberRaw.h>

#include "BigNumberRaw.h"

namespace SkyCryptor {

  BigNumberRaw::~BigNumberRaw() {
    if (bignum != nullptr) {
      mbedtls_mpi_free(bignum);
    }
  }

  BIGNUM *BigNumberRaw::get_bignum() {
    return bignum;
  }

  void BigNumberRaw::set_bignum(BIGNUM *bn) {
    // if we have defined already BN, freeing up before assigning new one
    if (bignum != nullptr) {
      mbedtls_mpi_free(bignum);
    }

    bignum = bn;
  }
};
