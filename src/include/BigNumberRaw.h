//
// Created by Tigran on 7/3/18.
//

#ifndef _CRYPTOMAGIC_BIG_NUMBER_RAW_H__
#define _CRYPTOMAGIC_BIG_NUMBER_RAW_H__

#include "defines.h"
#include <mbedtls/bignum.h>
#include "stdlib.h"

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

#endif // _CRYPTOMAGIC_BIG_NUMBER_RAW_H__
