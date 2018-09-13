//
// Created by Tigran on 6/25/18.
//

#include <cstring>
#include <vector>

#include "Point.h"
#include "defines.h"
#include "helpers.h"
#include "BigNumber.h"

namespace SkyCryptor {

Point::Point(EC_POINT *point, Context *ctx) {
  if (point == nullptr) {
    EC_POINT *p = (EC_POINT*)malloc(sizeof(EC_POINT));
    mbedtls_ecp_point_init(p);
    point_raw->set_ec_point(p);
  } else {
    point_raw->set_ec_point(point);
  }
  context = ctx;
}

Point::Point(const Point &p) {
  *this = p;
}

Point Point::get_generator(Context *ctx) {
  Point p(ctx);
  int res = mbedtls_ecp_copy(p.point_raw->get_ec_point(), &ctx->get_ec_group()->G);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return p;
}

std::shared_ptr<PointRaw> Point::get_point_raw() const {
  return this->point_raw;
}

Point Point::generate_random(Context *ctx) {
  auto g = Point::get_generator(ctx);
  auto randBN = BigNumber::generate_random(ctx);
  if (randBN.hasError()) {
    // TODO: make error handling here!!
    return g;
  }

  return g * randBN;
}

std::vector<char> Point::toBytes() const {
  if (point_raw->get_ec_point() == nullptr) {
    return std::vector<char>(0);
  }

  char byteBuffer[500];
  size_t bufferLen;
  int res = mbedtls_ecp_point_write_binary(context->get_ec_group(), point_raw->get_ec_point(), MBEDTLS_ECP_PF_UNCOMPRESSED, &bufferLen, (unsigned char*)byteBuffer,
                                           sizeof(byteBuffer));
  if (res != 0) {
    // TODO: make error handling here!!
    return std::vector<char>(0);
  }
  return std::vector<char>(byteBuffer, byteBuffer + bufferLen);
}

Point Point::from_bytes(const std::vector<char>& bytes, Context *ctx) {
  return Point::from_bytes(&bytes[0], bytes.size(), ctx);
}

Point Point::from_bytes(const char *bytes, int len, Context *ctx) {
  Point p(ctx);
  int res = mbedtls_ecp_point_read_binary(ctx->get_ec_group(), p.point_raw->get_ec_point(), (unsigned char*)bytes, len);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return p;
}

std::vector<char> Point::hash(Context *ctx, std::vector<Point>& points) {
  std::vector<std::vector<char>> point_hashes;
  for(auto &p : points) {
    point_hashes.push_back(p.toBytes());
  }

  return HASH(ctx, point_hashes);
}

bool Point::operator==(const Point& other) const {
  int res = mbedtls_ecp_point_cmp(other.point_raw->get_ec_point(), point_raw->get_ec_point());
  return res == 0;
}

Point Point::operator*(const BigNumber &other) const {
  Point p(context);
  int res = mbedtls_ecp_mul(context->get_ec_group(), p.point_raw->get_ec_point(), other.getRawBigNum(), point_raw->get_ec_point(),
                  nullptr, nullptr);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return p;
}

Point Point::operator+(const Point &other) const {
  auto bn = BigNumber::from_integer(1, context);
  Point p(context);
  int res = mbedtls_ecp_muladd(context->get_ec_group(), p.point_raw->get_ec_point(), bn.getRawBigNum(),
    point_raw->get_ec_point(), bn.getRawBigNum(), other.point_raw->get_ec_point());
  if (res != 0) {
    // TODO: make error handling here!!
  }

  return p;
}

} // namespace SkyCryptor


