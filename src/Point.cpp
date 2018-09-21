#include <cstring>
#include <vector>

#include "Point.h"
#include "defines.h"
#include "helpers.h"
#include "BigNumber.h"

namespace SkyCryptor {

Point::Point(EC_POINT *point) {
  if (point == nullptr) {
    ec_point_ = (EC_POINT*)malloc(sizeof(EC_POINT));
    mbedtls_ecp_point_init(ec_point_);
  } else {
    ec_point_ = point;
  }
}

Point::Point() {
  ec_point_ = (EC_POINT*)malloc(sizeof(EC_POINT));
  mbedtls_ecp_point_init(ec_point_);
}

Point::~Point() {
  if (ec_point_ != nullptr) {
    mbedtls_ecp_point_free(ec_point_);
  }
}

Point::Point(const Point &p) {
  if (ec_point_ != nullptr) {
    mbedtls_ecp_point_free(ec_point_);
  }
  mbedtls_ecp_copy(ec_point_, p.ec_point_);
}

Point Point::get_generator() {
  Point p;
  int res = mbedtls_ecp_copy(
      p.ec_point_, &Context::get_default().get_ec_group()->G);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return p;
}

Point Point::generate_random() {
  // TODO(martun): generate a random point in a simpler way.
  Point g = Point::get_generator();
  BigNumber randBN = BigNumber::generate_random();
  if (randBN.hasError()) {
    // TODO: make error handling here!!
    return g;
  }

  return g * randBN;
}

std::vector<char> Point::to_bytes() const {
  if (ec_point_ == nullptr) {
    return std::vector<char>(0);
  }

  char byte_buffer[500];
  size_t buffer_len;
  int res = mbedtls_ecp_point_write_binary(
      Context::get_default().get_ec_group(), 
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

Point Point::from_bytes(const std::vector<char>& bytes) {
  return Point::from_bytes(&bytes[0], bytes.size());
}

Point Point::from_bytes(const char *bytes, int len) {
  Point p;
  int res = mbedtls_ecp_point_read_binary(
      Context::get_default().get_ec_group(), 
      p.ec_point_, 
      (unsigned char*)bytes, len);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return p;
}

std::vector<char> Point::hash(const std::vector<Point>& points) {
  std::vector<std::vector<char>> point_hashes;
  for(auto &p : points) {
    point_hashes.push_back(p.to_bytes());
  }

  return HASH(Context::get_default(), point_hashes);
}

bool Point::operator==(const Point& other) const {
  int res = mbedtls_ecp_point_cmp(other.ec_point_, ec_point_);
  return res == 0;
}

Point Point::operator*(const BigNumber &other) const {
  Point p;
  int res = mbedtls_ecp_mul(
      Context::get_default().get_ec_group(), 
      ec_point_, 
      &other.bn_raw_, 
      ec_point_,
      nullptr, 
      nullptr);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return p;
}

Point Point::operator+(const Point &other) const {
  auto one = BigNumber::from_integer(1);
  Point p;
  // TODO(martun): change this to use mbedtls_ecp_add.
  int res = mbedtls_ecp_muladd(
      Context::get_default().get_ec_group(), 
      ec_point_, 
      &one.bn_raw_,
      ec_point_, 
      &one.bn_raw_, 
      other.ec_point_);
  if (res != 0) {
    // TODO: make error handling here!!
  }

  return p;
}

} // namespace SkyCryptor

