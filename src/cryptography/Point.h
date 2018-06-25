//
// Created by Tigran on 6/25/18.
//

#ifndef CRYPTOMAIC_POINT_H
#define CRYPTOMAIC_POINT_H

#include "BigNumber.h"
#include "../Context.h"
#include "openssl/ec.h"
#include "../helpers/ErrorWrapper.h"

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
    static Point get_generator(Context *ctx);
    // Generating random point for context based Elliptic curve
    static Point generate_random(Context *ctx);

    // Equality operator for Point == Point
    bool operator==(Point& rhs);
    // MUL Operator for Point * BigNumber = Point
    Point operator*(BigNumber& rhs);
    // ADD Operator for Point + Point = Point
    Point operator+(Point &rhs);
    // Invert Operator for ~Point = Point
    Point operator~();
    // SUB operator for Point - Point = Point
    Point operator-(Point& rhs);
  };

}

#endif //CRYPTOMAIC_POINT_H
