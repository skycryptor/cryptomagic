//
// Created by Tigran on 6/23/18.
//

#include "BigNumber.h"
#include "iostream"
#include <arpa/inet.h>

namespace CryptoMagic {

  BIGNUM * BigNumber::BNZero = nullptr;

  BigNumber::BigNumber(BIGNUM *bn, Context *ctx) {
    this->bignum = bn;
    this->ctx = ctx;

    // Making order out of EC
    ec_order = BN_new();
    bnCtx = BN_CTX_new();
    int res = EC_GROUP_get_order(ctx->get_ec_group(), ec_order, bnCtx);

    // if we got an error during EC order generation
    // then just setting ec_order to null for checking error later on
    if (res != 1) {
      BN_free(ec_order);
      ec_order = nullptr;
    }

    // Making zero static variable
    if (BigNumber::BNZero == nullptr) {
      BigNumber::BNZero = BN_new();
      unsigned int zeroInt = 0;
      zeroInt = htonl(zeroInt);
      BN_bin2bn((const unsigned char*)&zeroInt, 4, BigNumber::BNZero);
    }
  }

  BigNumber::~BigNumber() {
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

  BigNumber *BigNumber::generate_random(Context *ctx) {
    auto bn = new BigNumber(nullptr, ctx);
    bn->bignum = BN_new();
    int res = BN_rand_range(bn->bignum, bn->ec_order);
    if (res != 1) {
      return nullptr;
    }

    // if we got big number not inside EC group range let's try again
    if (!bn->isFromECGroup()) {
      // clearing created big number and trying again
      delete bn;
      return BigNumber::generate_random(ctx);
    }

    return bn;
  }

  BigNumber *BigNumber::from_bytes(unsigned char *buffer, Context *ctx) {
    auto bn = new BigNumber(nullptr, ctx);
    bn->bignum = BN_new();
    BN_bin2bn((const unsigned char*)&buffer, 4, bn->bignum);
    return nullptr;
  }

  BigNumber *BigNumber::from_integer(int num, Context *ctx) {
    unsigned int beConverted = htonl((unsigned int)num);
    return BigNumber::from_bytes((unsigned char *)&beConverted, ctx);
  }

  bool BigNumber::isFromECGroup() {
    return BN_cmp(bignum, BigNumber::BNZero) ==1 && BN_cmp(bignum, ec_order) == -1;
  }

  string BigNumber::toHex() {
    char *hexStr = BN_bn2hex(bignum);
    string hex = string(hexStr);
    delete hexStr;
    return hex;
  }
}