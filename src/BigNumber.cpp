//
// Created by Tigran on 6/23/18.
//

#include "BigNumber.h"
#include "iostream"
#include <arpa/inet.h>
#include "defines.h"

namespace SkyCryptor {

  BIGNUM * BigNumber::BNZero = nullptr;

  BigNumber::BigNumber(BIGNUM *bn, Context *ctx) {
    bn_raw->set_bignum(bn);
    context = ctx;

    // Making order out of EC
    bn_raw->set_ec_order(BN_new());
    bn_raw->set_bnCtx(BN_CTX_new());
    int res = EC_GROUP_get_order(ctx->get_ec_group(), bn_raw->get_ec_order(), bn_raw->get_bnCtx());

    // if we got an error during EC order generation
    // then just setting ec_order to null for checking error later on
    if (res != 1) {
      this->setOpenSSLError(ERROR_INITIALIZING_EC_GROUP_ORDER);
    }

    // Making zero static variable
    if (BigNumber::BNZero == nullptr) {
      BigNumber::BNZero = BN_new();
      unsigned int zeroInt = 0;
      zeroInt = htonl(zeroInt);
      BN_bin2bn((const unsigned char*)&zeroInt, 4, BigNumber::BNZero);
    }
  }

  BigNumber::BigNumber(const BigNumber &bn) {
    *this = bn;
  }

  BigNumber BigNumber::generate_random(Context *ctx) {
    BigNumber bn(BN_new(), ctx);
    int res = BN_rand_range(bn.bn_raw->get_bignum(), bn.bn_raw->get_ec_order());
    if (res != 1) {
      bn.setOpenSSLError(ERROR_BIGNUMBER_RANDOM_GENERATION);
      return bn;
    }

    // if we got big number not inside EC group range let's try again
    if (!bn.isFromECGroup()) {
      return BigNumber::generate_random(ctx);
    }

    return bn;
  }

  BigNumber BigNumber::from_bytes(unsigned char *buffer, int len, Context *ctx) {
    return BigNumber(BN_bin2bn((const unsigned char*)buffer, len, NULL), ctx);
  }

  BigNumber BigNumber::from_integer(unsigned long num, Context *ctx) {
    BigNumber bn(BN_new(), ctx);
    BN_set_word(bn.bn_raw->get_bignum(), num);
    return bn;
  }

  bool BigNumber::isFromECGroup() const {
    return BN_cmp(bn_raw->get_bignum(), BigNumber::BNZero) ==1 && BN_cmp(bn_raw->get_bignum(), bn_raw->get_ec_order()) == -1;
  }

  string BigNumber::toHex() const {
    char *hexStr = BN_bn2hex(bn_raw->get_bignum());
    string hex = string(hexStr);
    delete hexStr;
    return hex;
  }

  Point BigNumber::toPoint() const {
    EC_POINT *raw_p = EC_POINT_new(context->get_ec_group());
    EC_POINT_bn2point(context->get_ec_group(), bn_raw->get_bignum(), raw_p, bn_raw->get_bnCtx());
    return Point(raw_p, context);
  }

  vector<char> BigNumber::toBytes() {
    vector<char> ret(BN_num_bytes(bn_raw->get_bignum()));
    BN_bn2bin(bn_raw->get_bignum(), (unsigned char*) &ret[0]);
    return ret;
  }

  BIGNUM *BigNumber::getRawBigNum() const {
    return this->bn_raw->get_bignum();
  }

  BN_CTX *BigNumber::getRawBnCtx() const {
    if (bn_raw->get_bnCtx() == nullptr) {
      bn_raw->set_bnCtx(BN_CTX_new());
    }
    return bn_raw->get_bnCtx();
  }

  bool BigNumber::operator==(const BigNumber &other) const {
    return BN_cmp(bn_raw->get_bignum(), other.bn_raw->get_bignum()) == 0;
  }

  BigNumber BigNumber::operator*(const BigNumber &other) const {
    BigNumber bn(BN_new(), context);
    int res = BN_mod_mul(bn.bn_raw->get_bignum(), bn_raw->get_bignum(), other.bn_raw->get_bignum(), bn_raw->get_ec_order(), bn_raw->get_bnCtx());
    if (res != 1) {
      bn.setOpenSSLError(ERROR_BIGNUMBER_MUL);
    }
    return bn;
  }

  Point BigNumber::operator*(const Point &other) {
    return other * (*this);
  }

  Point BigNumber::operator*(const PublicKey &other) {
    return other * (*this);
  }

  BigNumber BigNumber::operator~() const {
    BigNumber bn(BN_new(), context);
    BN_mod_inverse(bn.bn_raw->get_bignum(), bn_raw->get_bignum(), bn_raw->get_ec_order(), bn_raw->get_bnCtx());
    return bn;
  }

  BigNumber BigNumber::operator/(const BigNumber &other) {
    return (*this) * (~other);
  }

  BigNumber BigNumber::operator+(const BigNumber &other) {
    BigNumber bn(BN_new(), context);
    int res = BN_mod_add(bn.bn_raw->get_bignum(), bn_raw->get_bignum(), other.bn_raw->get_bignum(), bn_raw->get_ec_order(), bn_raw->get_bnCtx());
    if (res != 1) {
      bn.setOpenSSLError(ERROR_BIGNUMBER_ADD);
    }
    return bn;
  }

  BigNumber BigNumber::operator-(const BigNumber &other) {
    BigNumber bn(BN_new(), context);
    int res = BN_mod_sub(bn.bn_raw->get_bignum(), bn_raw->get_bignum(), other.bn_raw->get_bignum(), bn_raw->get_ec_order(), bn_raw->get_bnCtx());
    if (res != 1) {
      bn.setOpenSSLError(ERROR_BIGNUMBER_SUBTRACK);
    }
    return bn;
  }

  BigNumber BigNumber::operator%(const BigNumber &other) {
    BigNumber bn(BN_new(), context);
    int res = BN_nnmod(bn.bn_raw->get_bignum(), bn_raw->get_bignum(), other.bn_raw->get_bignum(), bn_raw->get_bnCtx());
    if (res != 1) {
      bn.setOpenSSLError(ERROR_BIGNUMBER_MODULUS);
    }
    return bn;
  }
}
