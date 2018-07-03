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

  Point *Point::get_generator(Context *ctx) {
    auto p = new Point(EC_POINT_new(ctx->get_ec_group()), ctx);
    int res = EC_POINT_copy(p->ec_point, EC_GROUP_get0_generator(ctx->get_ec_group()));
    if (res != 1) {
      p->setOpenSSLError(ERROR_POINT_COPY);
    }

    return p;
  }

  Point *Point::generate_random(Context *ctx) {
    auto g = Point::get_generator(ctx);
    auto randBN = BigNumber::generate_random(ctx);
    if (randBN->hasError()) {
      g->setFromError(*randBN);
      delete randBN;
      return g;
    }

    g->mul(randBN);
    delete randBN;
    return g;
  }

  string Point::toHex() {
    BigNumber bn(context);
    char *hexStr = EC_POINT_point2hex(context->get_ec_group(), ec_point, POINT_CONVERSION_UNCOMPRESSED, bn.getRawBnCtx());
    string hex = string(hexStr);
    delete hexStr;
    return hex;
  }

  bool Point::eq(Point *p1) {
    BigNumber bn(context);
    int res = EC_POINT_cmp(context->get_ec_group(), ec_point, p1->ec_point, bn.getRawBnCtx());
    return res == 0;
  }

  bool Point::eq(Point *p1, Point *p2) {
    return p1->eq(p2);
  }

  Point *Point::mul(BigNumber *bn) {
    auto tmpP = ec_point;
    ec_point = EC_POINT_new(context->get_ec_group());
    int res = EC_POINT_mul(context->get_ec_group(), ec_point, NULL, tmpP, bn->getRawBigNum(), bn->getRawBnCtx());
    if (res != 1) {
      this->setOpenSSLError(ERROR_POINT_MUL);
    }
    EC_POINT_free(tmpP);
    return this;
  }

  Point *Point::mul(Point *p, BigNumber *bn) {
    auto p2 = new Point(EC_POINT_new(p->context->get_ec_group()), p->context);
    int res = EC_POINT_mul(p->context->get_ec_group(), p2->ec_point, NULL, p->ec_point, bn->getRawBigNum(), bn->getRawBnCtx());
    if (res != 1) {
      p2->setOpenSSLError(ERROR_POINT_MUL);
    }

    return p2;
  }

  Point *Point::mul(Point *p2) {
    BigNumber bn(BN_new(), context);
    EC_POINT_point2bn(context->get_ec_group(), ec_point, POINT_CONVERSION_UNCOMPRESSED, bn.getRawBigNum(), bn.getRawBnCtx());
    return this->mul(&bn);
  }

  Point *Point::mul(Point *p, Point *p2) {
    BigNumber bn(BN_new(), p->context);
    EC_POINT_point2bn(p->context->get_ec_group(), p->ec_point, POINT_CONVERSION_UNCOMPRESSED, bn.getRawBigNum(), bn.getRawBnCtx());
    return Point::mul(p, &bn);
  }

  Point *Point::add(Point *p2) {
    auto tmpP = ec_point;
    BigNumber bn(context);
    ec_point = EC_POINT_new(context->get_ec_group());
    int res = EC_POINT_add(context->get_ec_group(), ec_point, tmpP, p2->ec_point, bn.getRawBnCtx());
    if (res != 1) {
      this->setOpenSSLError(ERROR_POINT_ADD);
    }
    EC_POINT_free(tmpP);
    return this;
  }

  Point *Point::add(Point *p1, Point *p2) {
    auto p = new Point(EC_POINT_new(p1->context->get_ec_group()), p1->context);
    BigNumber bn(p1->context);
    int res = EC_POINT_add(p1->context->get_ec_group(), p->ec_point, p1->ec_point, p2->ec_point, bn.getRawBnCtx());
    return p;
  }

  Point *Point::inv() {
    BigNumber bn(context);
    int res = EC_POINT_invert(context->get_ec_group(), ec_point, bn.getRawBnCtx());
    if (res != 1) {
      this->setOpenSSLError(ERROR_POINT_INVERT);
    }

    return this;
  }

  Point *Point::inv(Point *p2) {
    auto p = new Point(p2->context);
    p->ec_point = EC_POINT_dup(p2->ec_point, p2->context->get_ec_group());
    return p->inv();
  }

  Point *Point::sub(Point *p2) {
    auto tmpP = Point::inv(p2);
    this->add(tmpP);
    delete tmpP;
    return this;
  }

  Point *Point::sub(Point *p1, Point *p2) {
    auto tmpP = Point::inv(p2);
    auto p = Point::add(p1, tmpP);
    delete tmpP;
    return p;
  }
}


