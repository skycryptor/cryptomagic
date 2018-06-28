//
// Created by Tigran on 6/25/18.
//

#include "Point.h"
#include "defines.h"

namespace CryptoMagic {

  Point::Point(EC_POINT *point, Context *ctx) {
    ec_point = point;
    context = ctx;
  }

  Point::~Point() {
    if (ec_point != nullptr) {
      EC_POINT_free(ec_point);
    }
  }

  Point Point::get_generator(Context *ctx) {
    Point p(ctx);
    p.ec_point = EC_POINT_new(ctx->get_ec_group());
    int res = EC_POINT_copy(p.ec_point, EC_GROUP_get0_generator(ctx->get_ec_group()));
    if (res != 1) {
      p.setOpenSSLError(ERROR_POINT_COPY);
    }

    return p;
  }

  Point Point::generate_random(Context *ctx) {
    Point randP(ctx);
    Point g = Point::get_generator(ctx);
    BigNumber randBN = BigNumber::from_integer(10, ctx);
    if (randBN.hasError()) {
      randP.setFromError(randBN);
      return randP;
    }

    return g * randBN;
  }

  bool Point::operator==(Point &rhs) {
    BigNumber bn(context);
    int res = EC_POINT_cmp(context->get_ec_group(), ec_point, rhs.ec_point, bn.getRawBnCtx());
    return res == 0;
  }

  Point Point::operator*(BigNumber &rhs) {
    Point p(context);
    p.ec_point = EC_POINT_new(context->get_ec_group());
    int res = EC_POINT_mul(context->get_ec_group(), p.ec_point, NULL, ec_point, rhs.getRawBigNum(), rhs.getRawBnCtx());
    if (res != 1) {
      p.setOpenSSLError(ERROR_POINT_MUL);
    }

    return p;
  }

  Point Point::operator+(Point &rhs) {
    Point p(context);
    BigNumber bn(context);
    p.ec_point = EC_POINT_new(context->get_ec_group());
    int res = EC_POINT_add(context->get_ec_group(), p.ec_point, ec_point, rhs.ec_point, bn.getRawBnCtx());
    if (res != 1) {
      p.setOpenSSLError(ERROR_POINT_ADD);
    }

    return p;
  }

  Point Point::operator~() {
    Point p(context);
    BigNumber bn(context);
    p.ec_point = EC_POINT_dup(ec_point, context->get_ec_group());
    int res = EC_POINT_invert(context->get_ec_group(), p.ec_point, bn.getRawBnCtx());
    if (res != 1) {
      p.setOpenSSLError(ERROR_POINT_INVERT);
    }

    return p;
  }

  Point Point::operator-(Point &rhs) {
    auto p = ~rhs;
    // if we got an error, let's just send it back to operation
    if (p.hasError()) {
      return p;
    }

    return (*this) + p;
  }

  Point Point::operator*(Point &rhs) {
    BigNumber bn(BN_new(), context);
    EC_POINT_point2bn(context->get_ec_group(), ec_point, POINT_CONVERSION_UNCOMPRESSED, bn.getRawBigNum(), bn.getRawBnCtx());
    return rhs * bn;
  }

}


