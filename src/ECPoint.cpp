#include <cstring>
#include <vector>

#include "ECPoint.h"
#include "defines.h"
#include "Hasher.h"
#include "ECScalar.h"
#include "VersionInfo.h"
#include "VersionInfoMap.h"

namespace SkyCryptor {

ECPoint::ECPoint(EC_POINT *point) {
  ec_point_ = (EC_POINT*)malloc(sizeof(EC_POINT));
  mbedtls_ecp_point_init(ec_point_);

  if (point != nullptr) {
    mbedtls_ecp_copy(ec_point_, point);
  }
}

ECPoint::ECPoint() {
  ec_point_ = (EC_POINT*)malloc(sizeof(EC_POINT));
  mbedtls_ecp_point_init(ec_point_);
}

ECPoint::~ECPoint() {
  if (ec_point_ != nullptr) {
    mbedtls_ecp_point_free(ec_point_);
  }
}

ECPoint::ECPoint(const ECPoint &p) {
  ec_point_ = (EC_POINT*)malloc(sizeof(EC_POINT));
  mbedtls_ecp_point_init(ec_point_);
  mbedtls_ecp_copy(ec_point_, p.ec_point_);
}

ECPoint ECPoint::get_generator() {
  ECPoint p;
  int res = mbedtls_ecp_copy(
      p.ec_point_, &VersionInfoMap::get_current_version()->get_ec_group()->G);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return p;
}

ECPoint ECPoint::generate_random() {
  // TODO(martun): generate a random point in a simpler way.
  ECPoint g = ECPoint::get_generator();
  ECScalar randBN = ECScalar::generate_random();

  return g * randBN;
}

std::vector<char> ECPoint::to_bytes() const {
  if (ec_point_ == nullptr) {
    return std::vector<char>(0);
  }

  char byte_buffer[500];
  size_t buffer_len;
  auto ec_group = VersionInfoMap::get_current_version()->get_ec_group();
  int res = mbedtls_ecp_point_write_binary(
      ec_group,
      ec_point_, 
      MBEDTLS_ECP_PF_UNCOMPRESSED, 
      &buffer_len, 
      (unsigned char*)byte_buffer,
      sizeof(byte_buffer));

  if (res != 0) {
    // TODO: make error handling here!!
    return std::vector<char>(0);
  }
  return std::vector<char>(byte_buffer, byte_buffer + buffer_len);
}

ECPoint ECPoint::from_bytes(const std::vector<char>& bytes) {
  return ECPoint::from_bytes(&bytes[0], bytes.size());
}

ECPoint ECPoint::from_bytes(const char *bytes, int len) {
  ECPoint p;
  int res = mbedtls_ecp_point_read_binary(
      VersionInfoMap::get_current_version()->get_ec_group(), 
      p.ec_point_, 
      (unsigned char*)bytes, len);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return p;
}

std::vector<char> ECPoint::hash(const std::vector<ECPoint>& points) {
  std::vector<std::vector<char>> point_hashes;
  for(auto &p : points) {
    point_hashes.push_back(p.to_bytes());
  }

  return Hasher::get_default().SHA_256(point_hashes);
}

bool ECPoint::operator==(const ECPoint& other) const {
  int res = mbedtls_ecp_point_cmp(other.ec_point_, ec_point_);
  return res == 0;
}

ECPoint ECPoint::operator*(const ECScalar &other) const {
  ECPoint p;
  int res = mbedtls_ecp_mul(
      VersionInfoMap::get_current_version()->get_ec_group(), 
      p.ec_point_, 
      other.bn_raw_, 
      ec_point_,
      nullptr, 
      nullptr);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return p;
}

ECPoint ECPoint::operator+(const ECPoint &other) const {
  auto one = ECScalar::from_integer(1);
  ECPoint p;
  // TODO(martun): change this to use mbedtls_ecp_add.
  int res = mbedtls_ecp_muladd(
      VersionInfoMap::get_current_version()->get_ec_group(), 
      p.ec_point_, 
      one.bn_raw_,
      ec_point_, 
      one.bn_raw_, 
      other.ec_point_);
  if (res != 0) {
    // TODO: make error handling here!!
  }

  return p;
}

} // namespace SkyCryptor

