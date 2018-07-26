//
// Created by Tigran on 7/3/18.
//

#ifndef CRYPTOMAIC_BIGNUMBERRAW_H
#define CRYPTOMAIC_BIGNUMBERRAW_H

#include <openssl/bn.h>
#include <openssl/ec.h>

namespace SkyCryptor {
  class BigNumberRaw {
   private:
    // OpenSSL bignumber parameter
    BIGNUM *bignum = nullptr;
    // EC order
    BIGNUM *ec_order = nullptr;
    // BigNumber context for making OpenSSL BIGNUM operations
    BN_CTX *bnCtx = nullptr;

   public:
    BigNumberRaw() = default;
    ~BigNumberRaw();

    BIGNUM * get_bignum();
    void set_bignum(BIGNUM * bn);

    BIGNUM * get_ec_order();
    void set_ec_order(BIGNUM * order);

    BN_CTX * get_bnCtx();
    void set_bnCtx(BN_CTX * ctx);
  };
}

#endif //CRYPTOMAIC_BIGNUMBERRAW_H
