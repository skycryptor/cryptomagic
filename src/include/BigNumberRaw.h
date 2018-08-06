//
// Created by Tigran on 7/3/18.
//

#ifndef CRYPTOMAIC_BIGNUMBERRAW_H
#define CRYPTOMAIC_BIGNUMBERRAW_H

#include "defines.h"
#include <mbedtls/bignum.h>

namespace SkyCryptor {
  class BigNumberRaw {
   private:
    // bignumber pointer
    BIGNUM *bignum = nullptr;

   public:
    BigNumberRaw() = default;
    ~BigNumberRaw();

    BIGNUM * get_bignum();
    void set_bignum(BIGNUM * bn);
  };
}

#endif //CRYPTOMAIC_BIGNUMBERRAW_H
