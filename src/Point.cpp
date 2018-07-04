//
// Created by Tigran on 6/25/18.
//

#include "Point.h"
#include "defines.h"

namespace CryptoMagic {

  Point::Point(EC_POINT *point, Context *ctx) {
    point_raw->set_ec_point(point);
    context = ctx;
  }

  Point Point::get_generator(Context *ctx) const {
    Point p(EC_POINT_new(ctx->get_ec_group()), ctx);
    int res = EC_POINT_copy(p.point_raw->get_ec_point(), EC_GROUP_get0_generator(ctx->get_ec_group()));
    if (res != 1) {
      p.setOpenSSLError(ERROR_POINT_COPY);
    }

    return p;
  }

  Point Point::generate_random(Context *ctx) const {
    auto g = Point::get_generator(ctx);
    auto randBN = BigNumber::generate_random(ctx);
    if (randBN.hasError()) {
      g.setFromError(randBN);
      return g;
    }

    return g * randBN;
  }

  void Point::toHex(string& result_out) {
    BigNumber bn(context);
    char *hexStr = EC_POINT_point2hex(context->get_ec_group(), point_raw->get_ec_point(), POINT_CONVERSION_UNCOMPRESSED, bn.getRawBnCtx());
    result_out.assign(hexStr);
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


