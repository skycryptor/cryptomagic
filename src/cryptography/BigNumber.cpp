//
// Created by Tigran on 6/23/18.
//

#include "BigNumber.h"
#include "iostream"
#include <arpa/inet.h>
#include "defines.h"

namespace CryptoMagic {

  BIGNUM * BigNumber::BNZero = nullptr;

  BigNumber::BigNumber(BIGNUM *bn, Context *ctx) {
    bignum = bn;
    context = ctx;

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
      bignum = nullptr;
    }

    if (ec_order != nullptr) {
      BN_free(ec_order);
      ec_order = nullptr;
    }

    if (bnCtx != nullptr) {
      BN_CTX_free(bnCtx);
      bnCtx = nullptr;
    }
  }

  BigNumber *BigNumber::generate_random(Context *ctx) {
    auto bn = new BigNumber(BN_new(), ctx);
    int res = BN_rand_range(bn->bignum, bn->ec_order);
    if (res != 1) {
      bn->setOpenSSLError(ERROR_BIGNUMBER_RANDOM_GENERATION);
      return bn;
    }

    // if we got big number not inside EC group range let's try again
    if (!bn->isFromECGroup()) {
      return BigNumber::generate_random(ctx);
    }

    return bn;
  }

  BigNumber *BigNumber::from_bytes(unsigned char *buffer, int len, Context *ctx) {
    return new BigNumber(BN_bin2bn((const unsigned char*)&buffer, len, NULL), ctx);
  }

  BigNumber *BigNumber::from_integer(unsigned long num, Context *ctx) {
    auto bn = new BigNumber(BN_new(), ctx);
    BN_set_word(bn->bignum, num);
    return bn;
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
  string BigNumber::toBytes() {
    auto binData = new char[BN_num_bytes(bignum)];
    BN_bn2bin(bignum, (unsigned char*) binData);
    auto buffer = string(binData);
    delete[] binData;
    return buffer;
  }

  bool BigNumber::eq(BigNumber *bn2) {
    return BN_cmp(bignum, bn2->bignum) == 0;
  }

  bool BigNumber::eq(BigNumber *bn1, BigNumber *bn2) {
    return BN_cmp(bn1->bignum, bn2->bignum) == 0;
  }

  BigNumber *BigNumber::mul(BigNumber *bn2) {
    auto tmpBn = bignum;
    bignum = BN_new();
    int res = BN_mod_mul(bignum, tmpBn, bn2->bignum, ec_order, bnCtx);
    if (res != 1) {
      this->setOpenSSLError(ERROR_BIGNUMBER_MUL);
    }
    BN_free(tmpBn);
    return this;
  }

  BigNumber *BigNumber::mul(BigNumber *bn1, BigNumber *bn2) {
    auto bn = new BigNumber(BN_new(), bn1->context);
    int res = BN_mod_mul(bn->bignum, bn1->bignum, bn2->bignum, bn1->ec_order, bn1->bnCtx);
    if (res != 1) {
      bn->setOpenSSLError(ERROR_BIGNUMBER_MUL);
    }

    return bn;
  }

  BigNumber * BigNumber::inv() {
    auto tmpBn = bignum;
    bignum = BN_new();
    BN_mod_inverse(bignum, tmpBn, ec_order, bnCtx);
    BN_free(tmpBn);
    return this;
  }

  BigNumber *BigNumber::inv(BigNumber *bn) {
    auto bn2 = new BigNumber(BN_new(), bn->context);
    BN_mod_inverse(bn2->bignum, bn->bignum, bn->ec_order, bn->bnCtx);
    return bn2;
  }

  BigNumber * BigNumber::div(BigNumber* bn2) {
    auto tmpInv = BigNumber::inv(bn2);
    // inverting and multiplying to get div
    this->mul(tmpInv);
    delete tmpInv;
    return this;
  }

  BigNumber *BigNumber::div(BigNumber* bn1, BigNumber* bn2) {
    auto tmpInv = BigNumber::inv(bn2);
    auto bn = BigNumber::mul(bn1, tmpInv);
    delete tmpInv;
    return bn;
  }

  BigNumber * BigNumber::add(BigNumber *bn2) {
    auto tmpBn = bignum;
    bignum = BN_new();
    int res = BN_mod_add(bignum, tmpBn, bn2->bignum, ec_order, bnCtx);
    if (res != 1) {
      this->setOpenSSLError(ERROR_BIGNUMBER_ADD);
    }
    BN_free(tmpBn);
    return this;
  }

  BigNumber *BigNumber::add(BigNumber *bn1, BigNumber *bn2) {
    auto bn = new BigNumber(BN_new(), bn1->context);
    int res = BN_mod_add(bn->bignum, bn1->bignum, bn2->bignum, bn1->ec_order, bn1->bnCtx);
    if (res != 1) {
      bn->setOpenSSLError(ERROR_BIGNUMBER_ADD);
    }
    return bn;
  }

  BigNumber * BigNumber::sub(BigNumber *bn2) {
    auto tmpBn = bignum;
    bignum = BN_new();
    int res = BN_mod_sub(bignum, tmpBn, bn2->bignum, ec_order, bnCtx);
    if (res != 1) {
      this->setOpenSSLError(ERROR_BIGNUMBER_SUBTRACK);
    }
    BN_free(tmpBn);
    return this;
  }

  BigNumber *BigNumber::sub(BigNumber *bn1, BigNumber *bn2) {
    auto bn = new BigNumber(BN_new(), bn1->context);
    int res = BN_mod_sub(bn->bignum, bn1->bignum, bn2->bignum, bn1->ec_order, bn1->bnCtx);
    if (res != 1) {
      bn->setOpenSSLError(ERROR_BIGNUMBER_SUBTRACK);
    }
    return bn;
  }

  BigNumber * BigNumber::mod(BigNumber *bn2) {
    auto tmpBn = bignum;
    bignum = BN_new();
    int res = BN_nnmod(bignum, tmpBn, bn2->bignum, bnCtx);
    if (res != 1) {
      this->setOpenSSLError(ERROR_BIGNUMBER_MODULUS);
    }
    BN_free(tmpBn);
    return this;
  }

  BigNumber *BigNumber::mod(BigNumber *bn1, BigNumber *bn2) {
    auto bn = new BigNumber(BN_new(), bn1->context);
    int res = BN_nnmod(bn->bignum, bn1->bignum, bn2->bignum, bn1->bnCtx);
    if (res != 1) {
      bn->setOpenSSLError(ERROR_BIGNUMBER_MODULUS);
    }
    return bn;
  }

  BIGNUM *BigNumber::getRawBigNum() {
    return this->bignum;
  }

  BN_CTX *BigNumber::getRawBnCtx() {
    if (this->bnCtx != nullptr) {
      BN_CTX_free(this->bnCtx);
    }
    this->bnCtx = BN_CTX_new();
    return this->bnCtx;
  }

}