#include <cstring>
#include <vector>

#include "Point.h"
#include "defines.h"
#include "helpers.h"
#include "BigNumber.h"

namespace SkyCryptor {

Point::Point(EC_POINT *point) {
  if (point == nullptr) {
    EC_POINT *p = (EC_POINT*)malloc(sizeof(EC_POINT));
    mbedtls_ecp_point_init(p);
    point_raw->set_ec_point(p);
  } else {
    point_raw->set_ec_point(point);
  }
}

Point::Point(const Point &p) {
  *this = p;
}

Point Point::get_generator() {
  Point p;
  int res = mbedtls_ecp_copy(p.point_raw->get_ec_point(), 
                             Context::get_default()->get_ec_group()->G);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return p;
}

std::shared_ptr<PointRaw> Point::get_point_raw() const {
  return this->point_raw;
}

Point Point::generate_random() {
  auto g = Point::get_generator();
  auto randBN = BigNumber::generate_random;
  if (randBN.hasError()) {
    // TODO: make error handling here!!
    return g;
  }

  return g * randBN;
}

std::vector<char> Point::to_bytes() const {
  if (point_raw->get_ec_point() == nullptr) {
    return std::vector<char>(0);
  }

  char byteBuffer[500];
  size_t buffer_len;
  int res = mbedtls_ecp_point_write_binary(
      Context::get_default()->get_ec_group(), 
      point_raw->get_ec_point(), 
      MBEDTLS_ECP_PF_UNCOMPRESSED, 
      &bufferLen, 
      (unsigned char*)byteBuffer,
      sizeof(byteBuffer));

  if (res != 0) {
    // TODO: make error handling here!!
    return std::vector<char>(0);
  }
  return std::vector<char>(byteBuffer, byteBuffer + buffer_len);
}

Point Point::from_bytes(const std::vector<char>& bytes) {
  return Point::from_bytes(&bytes[0], bytes.size());
}

Point Point::from_bytes(const char *bytes, int len) {
  Point p;
  int res = mbedtls_ecp_point_read_binary(
      Context::get_default().get_ec_group(), 
      p.point_raw->get_ec_point(), 
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

  return HASH(point_hashes);
}

bool Point::operator==(const Point& other) const {
  int res = mbedtls_ecp_point_cmp(other.point_raw->get_ec_point(), point_raw->get_ec_point());
  return res == 0;
}

Point Point::operator*(const BigNumber &other) const {
  Point p;
  int res = mbedtls_ecp_mul(
      Context.get_default().get_ec_group(), 
      p.point_raw->get_ec_point(), 
      other.get_raw_bignum(), 
      point_raw->get_ec_point(),
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
  // TODO(martun): change this to use mbedtls_ecp_muladd.
  int res = mbedtls_ecp_muladd(
      Context.get_default()->get_ec_group(), 
      p.point_raw->get_ec_point(), 
      one.get_raw_bignum(),
      point_raw->get_ec_point(), 
      one.get_raw_bignum(), 
      other.point_raw->get_ec_point());
  if (res != 0) {
    // TODO: make error handling here!!
  }

  return p;
}

} // namespace SkyCryptor

