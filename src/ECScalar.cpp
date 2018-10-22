#include <arpa/inet.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "ECPoint.h"
#include "ECScalar.h"
#include "defines.h"
#include "VersionInfo.h"
#include "VersionInfoMap.h"

namespace SkyCryptor {

ECScalar::ECScalar() {
  bn_raw_ = (BIGNUM *)malloc(sizeof(BIGNUM));
  mbedtls_mpi_init(bn_raw_);
}

ECScalar::ECScalar(uint32_t value) {
  bn_raw_ = (BIGNUM *)malloc(sizeof(BIGNUM));
  mbedtls_mpi_init(bn_raw_);
  int res = mbedtls_mpi_lset(bn_raw_, value);
  if (res != 0) {
    // TODO: define error case!!
  }
}

ECScalar::ECScalar(const ECScalar& bn) {
  bn_raw_ = (BIGNUM *)malloc(sizeof(BIGNUM));
  mbedtls_mpi_init(bn_raw_);

  mbedtls_mpi_copy(bn_raw_, bn.bn_raw_);
}

ECScalar::~ECScalar() {
  delete bn_raw_;
}

ECScalar::ECScalar(const BIGNUM& bn)
{
  if (bn_raw_ != nullptr) {
     mbedtls_mpi_free(bn_raw_);
  }
  bn_raw_ = (BIGNUM *)malloc(sizeof(BIGNUM));
  mbedtls_mpi_init(bn_raw_);
  
	mbedtls_mpi_copy(bn_raw_, &bn); 
}

const ECScalar& ECScalar::get_zero() {
  static ECScalar BNZero(0);
  return BNZero;
}

ECScalar ECScalar::generate_random() {
  ECScalar bn;
  mbedtls_ctr_drbg_context ctr_drbg_context_;
  mbedtls_entropy_context entropy_context_;
  mbedtls_ctr_drbg_init(&ctr_drbg_context_);
  mbedtls_entropy_init(&entropy_context_);
  mbedtls_ctr_drbg_seed(&ctr_drbg_context_, mbedtls_entropy_func, &entropy_context_, NULL, 0);
  int res = mbedtls_mpi_fill_random(
      bn.bn_raw_, 
      30, // TODO(martun): figure out what's this 30.
      mbedtls_ctr_drbg_random, 
      &ctr_drbg_context_);
  if (res != 0) {
    // TODO: make error reporting!!
    return bn;
  }

  // if we got big number not inside EC group range let's try again
  if (!bn.is_from_EC_group()) {
    return ECScalar::generate_random();
  }

  return bn;
}

ECScalar ECScalar::from_bytes(unsigned char *buffer, int len) {
  ECScalar bn;
  int res = mbedtls_mpi_read_binary(bn.bn_raw_, (const unsigned char*)buffer, len);
  if (res != 0) {
    // TODO: define error case!!
  }

  return bn;
}

ECScalar ECScalar::from_integer(uint32_t num) {
  ECScalar bn;
  int res = mbedtls_mpi_lset(bn.bn_raw_, num);
  if (res != 0) {
    // TODO: define error case!!
  }
  return bn;
}

bool ECScalar::is_from_EC_group() const {
  return mbedtls_mpi_cmp_abs(bn_raw_, get_zero().bn_raw_) == 1 && 
         mbedtls_mpi_cmp_abs(bn_raw_, get_ec_order().bn_raw_) == -1;
}

std::vector<char> ECScalar::to_bytes() const {
  std::vector<char> ret(mbedtls_mpi_size(bn_raw_));
  int res = mbedtls_mpi_write_binary(
      bn_raw_, (unsigned char*)&ret[0], ret.size());
  if (res != 0) {
    // TODO: handle error case!!
  }
  return ret;
}

bool ECScalar::operator==(const ECScalar &other) const {
  return mbedtls_mpi_cmp_mpi(bn_raw_, other.bn_raw_) == 0;
}

const ECScalar& ECScalar::get_ec_order() {
  static ECScalar ec_order(VersionInfoMap::get_current_version()->get_ec_order());
  return ec_order;
}

ECScalar ECScalar::operator*(const ECScalar &other) const {
  ECScalar bn;
  int res = mbedtls_mpi_mul_mpi(
      bn.bn_raw_, bn_raw_, other.bn_raw_);
  if (res != 0) {
    // TODO: handle error case!!
  }
  return bn % get_ec_order();
}

ECPoint ECScalar::operator*(const ECPoint &other) const {
  return other * (*this);
}

// TODO(martun): maybe create a function named "inverse".
ECScalar ECScalar::operator~() const {
  ECScalar bn;
  int res = mbedtls_mpi_inv_mod(
      bn.bn_raw_, bn_raw_, get_ec_order().bn_raw_);
  if (res != 0) {
    // TODO: handle error case!!
  }
  return bn;
}

ECScalar ECScalar::operator/(const ECScalar& other) const {
  return ((*this) * (~other)) % get_ec_order();
}

ECScalar ECScalar::operator+(const ECScalar& other) const {
  ECScalar bn;
  int res = mbedtls_mpi_add_mpi(
      bn.bn_raw_, bn_raw_, other.bn_raw_);
  if (res != 1) {
    // TODO: handle error case!!
  }
  return bn % get_ec_order();
}

ECScalar ECScalar::operator-(const ECScalar& other) const {
  ECScalar bn;
  int res = mbedtls_mpi_sub_mpi(
      bn.bn_raw_, bn_raw_, other.bn_raw_);
  if (res != 1) {
    // TODO: handle error case!!
  }
  return bn % get_ec_order();
}

ECScalar ECScalar::operator%(const ECScalar& other) const {
  ECScalar bn;
  int res = mbedtls_mpi_mod_mpi(bn.bn_raw_, bn_raw_, other.bn_raw_);
  if (res != 1) {
    // TODO: handle error case!!
  }
  return bn;
}

} // namespace SkyCryptor
