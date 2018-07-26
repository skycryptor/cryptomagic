//
// Created by Tigran on 6/25/18.
//

#include <cstring>
#include "Point.h"
#include "defines.h"
#include "helpers.h"

namespace SkyCryptor {

  Point::Point(EC_POINT *point, Context *ctx) {
    point_raw->set_ec_point(point);
    context = ctx;
  }

  Point::Point(const Point &p) {
    *this = p;
  }

  Point Point::get_generator(Context *ctx) {
    Point p(EC_POINT_new(ctx->get_ec_group()), ctx);
    int res = EC_POINT_copy(p.point_raw->get_ec_point(), EC_GROUP_get0_generator(ctx->get_ec_group()));
    if (res != 1) {
      p.setOpenSSLError(ERROR_POINT_COPY);
    }

    return p;
  }

  shared_ptr<PointRaw> Point::get_point_raw() const {
    return this->point_raw;
  }

  Point Point::generate_random(Context *ctx) {
    auto g = Point::get_generator(ctx);
    auto randBN = BigNumber::generate_random(ctx);
    if (randBN.hasError()) {
      g.setFromError(randBN);
      return g;
    }

    return g * randBN;
  }

  vector<char> Point::toBytes() const {
    if (point_raw->get_ec_point() == nullptr) {
      return vector<char>(0);
    }

    BigNumber bn(context);
    char *hexStr = EC_POINT_point2hex(context->get_ec_group(), point_raw->get_ec_point(), POINT_CONVERSION_COMPRESSED, bn.getRawBnCtx());
    auto ret = vector<char>(hexStr, hexStr + strlen(hexStr));
    free(hexStr);
    return ret;
  }

  Point Point::from_bytes(const vector<char>& bytes, Context *ctx) {
    return Point::from_bytes(&bytes[0], ctx);
  }

  Point Point::from_bytes(const char *bytes, Context *ctx) {
    BigNumber bn(ctx);
    Point p(EC_POINT_new(ctx->get_ec_group()), ctx);
    EC_POINT_hex2point(ctx->get_ec_group(), bytes, p.point_raw->get_ec_point(), bn.getRawBnCtx());
    return p;
  }

  vector<char> Point::hash(Context *ctx, vector<Point>& points) {
    vector<vector<char>> point_hashes;
    point_hashes.reserve(points.size());
    for(auto &p : points) {
      point_hashes.push_back(p.toBytes());
    }

    return HASH(ctx, point_hashes);
  }

  BigNumber Point::toBigNumber() {
    BigNumber bn(BN_new(), context);
    EC_POINT_point2bn(context->get_ec_group(), point_raw->get_ec_point(), POINT_CONVERSION_UNCOMPRESSED, bn.getRawBigNum(), bn.getRawBnCtx());
    return bn;
  }

  bool Point::operator==(const Point& other) const {
    BigNumber bn(context);
    int res = EC_POINT_cmp(context->get_ec_group(), point_raw->get_ec_point(), other.point_raw->get_ec_point(), bn.getRawBnCtx());
    return res == 0;
  }

  Point Point::operator*(const BigNumber &other) const {
    Point p(EC_POINT_new(context->get_ec_group()), context);
    int res = EC_POINT_mul(context->get_ec_group(), p.point_raw->get_ec_point(), NULL, point_raw->get_ec_point(), other.getRawBigNum(), other.getRawBnCtx());
    if (res != 1) {
      p.setOpenSSLError(ERROR_POINT_MUL);
    }
    return p;
  }

  Point Point::operator*(const Point &other) const {
    BigNumber bn(BN_new(), context);
    EC_POINT_point2bn(context->get_ec_group(), point_raw->get_ec_point(), POINT_CONVERSION_UNCOMPRESSED, bn.getRawBigNum(), bn.getRawBnCtx());
    return (*this) * bn;
  }

  Point Point::operator+(const Point &other) const {
    Point p(EC_POINT_new(context->get_ec_group()), context);
    BigNumber bn(context);
    int res = EC_POINT_add(context->get_ec_group(), p.point_raw->get_ec_point(), point_raw->get_ec_point(), other.point_raw->get_ec_point(), bn.getRawBnCtx());
    if (res != 1) {
      p.setOpenSSLError(ERROR_POINT_ADD);
    }
    return p;
  }

  Point Point::operator~() const {
    Point p(context);
    BigNumber bn(context);
    p.point_raw->set_ec_point(EC_POINT_dup(point_raw->get_ec_point(), context->get_ec_group()));
    int res = EC_POINT_invert(context->get_ec_group(), p.point_raw->get_ec_point(), bn.getRawBnCtx());
    if (res != 1) {
      p.setOpenSSLError(ERROR_POINT_INVERT);
    }
    return p;
  }

  Point Point::operator-(const Point &other) const {
    return (*this) + (~other);
  }
}


