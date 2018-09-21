#include <arpa/inet.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "Point.h"
#include "BigNumber.h"
#include "defines.h"
#include "Context.h"

namespace SkyCryptor {

BigNumber::BigNumber(const BIGNUM& bn)
  : bn_raw_(bn)
{
}

const BigNumber& BigNumber::get_zero() {
  static BIGNUM* BNZero;
  // Making zero static variable
  if (BNZero == nullptr) {
    BNZero = (BIGNUM*) malloc(sizeof(BIGNUM));
    mbedtls_mpi_init(BNZero);
    mbedtls_mpi_lset(BNZero, 0);
  } 
  return *BNZero;
}

BigNumber BigNumber::generate_random() {
  BigNumber bn;
  mbedtls_ctr_drbg_context ctr_drbg_context_;
  mbedtls_entropy_context entropy_context_;
  mbedtls_ctr_drbg_init(&ctr_drbg_context_);
  mbedtls_entropy_init(&entropy_context_);
  mbedtls_ctr_drbg_seed(&ctr_drbg_context_, mbedtls_entropy_func, &entropy_context_, NULL, 0);
  int res = mbedtls_mpi_fill_random(
      &bn.bn_raw_, 
      30, // TODO(martun): figure out what's this 30.
      mbedtls_ctr_drbg_random, 
      &ctr_drbg_context_);
  if (res != 0) {
    // TODO: make error reporting!!
    return bn;
  }

  // if we got big number not inside EC group range let's try again
  if (!bn.is_from_EC_group()) {
    return BigNumber::generate_random();
  }

  return bn;
}

BigNumber BigNumber::from_bytes(unsigned char *buffer, int len) {
  BigNumber bn;
  int res = mbedtls_mpi_read_binary(&bn.bn_raw_, (const unsigned char*)buffer, len);
  if (res != 0) {
    // TODO: define error case!!
  }

  return bn;
}

BigNumber BigNumber::from_integer(uint32_t num) {
  BigNumber bn;
  int res = mbedtls_mpi_lset(&bn.bn_raw_, num);
  if (res != 0) {
    // TODO: define error case!!
  }
  return bn;
}

bool BigNumber::is_from_EC_group() const {
  return mbedtls_mpi_cmp_abs(&bn_raw_, &get_zero().bn_raw_) == 1 && 
         mbedtls_mpi_cmp_abs(&bn_raw_, &get_ec_order().bn_raw_) == -1;
}

std::vector<char> BigNumber::to_bytes() const {
  std::vector<char> ret(mbedtls_mpi_size(&bn_raw_));
  int res = mbedtls_mpi_write_binary(
      &bn_raw_, (unsigned char*)&ret[0], ret.size());
  if (res != 0) {
    // TODO: handle error case!!
  }
  return ret;
}

bool BigNumber::operator==(const BigNumber &other) const {
  return mbedtls_mpi_cmp_mpi(&bn_raw_, &other.bn_raw_) == 0;
}

const BigNumber& BigNumber::get_ec_order() {
  static BigNumber ec_order(Context::get_default().get_ec_order());
  return ec_order;
}

BigNumber BigNumber::operator*(const BigNumber &other) const {
  BigNumber bn;
  int res = mbedtls_mpi_mul_mpi(
      &bn.bn_raw_, &bn_raw_, &other.bn_raw_);
  if (res != 0) {
    // TODO: handle error case!!
  }
  return bn % get_ec_order();
}

Point BigNumber::operator*(const Point &other) const {
  return other * (*this);
}

// TODO(martun): maybe create a function named "inverse".
BigNumber BigNumber::operator~() const {
  BigNumber bn;
  int res = mbedtls_mpi_inv_mod(
      &bn.bn_raw_, &bn_raw_, &get_ec_order().bn_raw_);
  if (res != 0) {
    // TODO: handle error case!!
  }
  return bn;
}

BigNumber BigNumber::operator/(const BigNumber& other) const {
  return ((*this) * (~other)) % get_ec_order();
}

BigNumber BigNumber::operator+(const BigNumber& other) const {
  BigNumber bn;
  int res = mbedtls_mpi_add_mpi(
      &bn.bn_raw_, &bn_raw_, &other.bn_raw_);
  if (res != 1) {
    // TODO: handle error case!!
  }
  return bn % get_ec_order();
}

BigNumber BigNumber::operator-(const BigNumber& other) const {
  BigNumber bn;
  int res = mbedtls_mpi_sub_mpi(
      &bn.bn_raw_, &bn_raw_, &other.bn_raw_);
  if (res != 1) {
    // TODO: handle error case!!
  }
  return bn % get_ec_order();
}

BigNumber BigNumber::operator%(const BigNumber& other) const {
  return (*this) % other.bn_raw_;
}

} // namespace SkyCryptor
