//
// Created by Tigran on 6/25/18.
//

#ifndef CRYPTOMAIC_POINT_H
#define CRYPTOMAIC_POINT_H

#include "BigNumber.h"
#include "Context.h"
#include "openssl/ec.h"
#include "helpers/ErrorWrapper.h"

namespace CryptoMagic {

  // Elliptic curve Point class implementation based on OpenSSL EC_POINT interface
  class Point: public ErrorWrapper {
   private:
    EC_POINT *ec_point = nullptr;
    // Cryptographic context for big number operations
    // NOTE: this class not taking any ownership for this pointer
    Context *context = nullptr;

   public:
    Point(EC_POINT *point, Context *ctx);
    explicit Point(Context *ctx) : Point(nullptr, ctx) {};
    ~Point();

    // Getting Generator Point from provided context based Elliptic curve
    static Point *get_generator(Context *ctx);
    // Generating random point for context based Elliptic curve
    static Point *generate_random(Context *ctx);

    // Getting BigNumber as a string/byte array
    string toHex();

    // Equality operator for Point == Point
    bool eq(Point *p2);
    static bool eq(Point *p1, Point *p2);

    // MUL Operator for Point * BigNumber = Point
    Point *mul(BigNumber *bn);
    static Point *mul(Point *p, BigNumber *bn);

    // MUL Operator for Point * Point = Point
    Point *mul(Point *p2);
    static Point *mul(Point *p, Point *p2);

    // ADD Operator for Point + Point = Point
    Point *add(Point *p2);
    static Point *add(Point *p1, Point *p2);

    // Invert Operator for ~Point = Point
    Point *inv();
    static Point *inv(Point *p2);

    // SUB operator for Point - Point = Point
    Point *sub(Point *p2);
    static Point *sub(Point *p1, Point *p2);
  };

}

#endif //CRYPTOMAIC_POINT_H
