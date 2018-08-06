//
// Created by Tigran on 6/23/18.
//

#include <arpa/inet.h>
#include <mbedtls/bignum.h>
#include "BigNumber.h"
#include "defines.h"

namespace SkyCryptor {

  BIGNUM * BigNumber::BNZero = nullptr;

  BigNumber::BigNumber(BIGNUM *bn, Context *ctx) {
    if (bn == nullptr) {
      BIGNUM *bnRaw;
      mbedtls_mpi_init(bnRaw);
      bn = bnRaw;
    }
    bn_raw->set_bignum(bn);
    context = ctx;

    // Making zero static variable
    if (BigNumber::BNZero == nullptr) {
      mbedtls_mpi_init(BigNumber::BNZero);
      mbedtls_mpi_lset(BigNumber::BNZero, 0);
    }
  }

  BigNumber::BigNumber(const BigNumber &bn) {
    *this = bn;
  }

  BigNumber BigNumber::generate_random(Context *ctx) {
    BigNumber bn(ctx);
    int res = mbedtls_mpi_fill_random(bn.getRawBigNum(), ctx->get_key_length(), nullptr, nullptr);
    if (res != 0) {
      // TODO: make error reporting!!
      return bn;
    }

    // if we got big number not inside EC group range let's try again
    if (!bn.isFromECGroup()) {
      return BigNumber::generate_random(ctx);
    }

    return bn;
  }

  BigNumber BigNumber::from_bytes(unsigned char *buffer, int len, Context *ctx) {
    BigNumber bn(ctx);
    int res = mbedtls_mpi_read_binary(bn.getRawBigNum(), (const unsigned char*)buffer, len);
    if (res != 0) {
      // TODO: define error case!!
    }

    return bn;
  }

  BigNumber BigNumber::from_integer(unsigned long num, Context *ctx) {
    BigNumber bn(ctx);
    int res = mbedtls_mpi_lset(bn.getRawBigNum(), num);
    if (res != 0) {
      // TODO: define error case!!
    }
    return bn;
  }

  bool BigNumber::isFromECGroup() const {
    return mbedtls_mpi_cmp_abs(bn_raw->get_bignum(), BigNumber::BNZero) ==1 && mbedtls_mpi_cmp_abs(bn_raw->get_bignum(), context->get_ec_order()) == -1;
  }

  Point BigNumber::toPoint() const {
    EC_POINT *raw_p = EC_POINT_new(context->get_ec_group());
    EC_POINT_bn2point(context->get_ec_group(), bn_raw->get_bignum(), raw_p, bn_raw->get_bnCtx());
    return Point(raw_p, context);
  }

  vector<char> BigNumber::toBytes() {
    vector<char> ret(mbedtls_mpi_size(bn_raw->get_bignum()));
    int res = mbedtls_mpi_write_binary(bn_raw->get_bignum(), (unsigned char*)&ret[0], ret.size());
    if (res != 0) {
      // TODO: handle error case!!
    }
    return ret;
  }

  BIGNUM *BigNumber::getRawBigNum() const {
    return this->bn_raw->get_bignum();
  }

  bool BigNumber::operator==(const BigNumber &other) const {
    return mbedtls_mpi_cmp_mpi(bn_raw->get_bignum(), other.bn_raw->get_bignum()) == 0;
  }

  BigNumber BigNumber::operator*(const BigNumber &other) const {
    BigNumber bn(context);
    int res = mbedtls_mpi_mul_mpi(bn.bn_raw->get_bignum(), bn_raw->get_bignum(), other.bn_raw->get_bignum());
    if (res != 0) {
      // TODO: handle error case!!
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
    BigNumber bn(context);
    int res = mbedtls_mpi_inv_mod(bn.bn_raw->get_bignum(), bn_raw->get_bignum(), context->get_ec_order());
    if (res != 0) {
      // TODO: handle error case!!
    }
    return bn;
  }

  BigNumber BigNumber::operator/(const BigNumber &other) {
    return (*this) * (~other);
  }

  BigNumber BigNumber::operator+(const BigNumber &other) {
    BigNumber bn(BN_new(), context);
    int res = mbedtls_mpi_add_mpi(bn.bn_raw->get_bignum(), bn_raw->get_bignum(), other.bn_raw->get_bignum());
    if (res != 1) {
      // TODO: handle error case!!
    }
    return bn;
  }

  BigNumber BigNumber::operator-(const BigNumber &other) {
    BigNumber bn(BN_new(), context);
    int res = mbedtls_mpi_sub_mpi(bn.bn_raw->get_bignum(), bn_raw->get_bignum(), other.bn_raw->get_bignum());
    if (res != 1) {
      // TODO: handle error case!!
    }
    return bn;
  }

  BigNumber BigNumber::operator%(const BigNumber &other) {
    BigNumber bn(BN_new(), context);
    int res = mbedtls_mpi_mod_mpi(bn.bn_raw->get_bignum(), bn_raw->get_bignum(), other.bn_raw->get_bignum());
    if (res != 1) {
      // TODO: handle error case!!
    }
    return bn;
  }
}
