//
// Created by Tigran on 6/25/18.
//

#ifndef CRYPTOMAIC_POINT_H
#define CRYPTOMAIC_POINT_H

#include "memory"
#include "BigNumber.h"
#include "PointRaw.h"
#include "Context.h"
#include "ErrorWrapper.h"

using std::shared_ptr;
using std::make_shared;

namespace CryptoMagic {
  class BigNumber;

  // Elliptic curve Point class implementation based on OpenSSL EC_POINT interface
  class Point: public ErrorWrapper {
   private:
    shared_ptr<PointRaw> point_raw = make_shared<PointRaw>();
    // Cryptographic context for big number operations
    // NOTE: this class not taking any ownership for this pointer
    Context *context = nullptr;

   public:
    Point(EC_POINT *point, Context *ctx);
    explicit Point(Context *ctx) : Point(nullptr, ctx) {};
    virtual ~Point() = default;

    // Getting Generator Point from provided context based Elliptic curve
    static Point get_generator(Context *ctx);
    // Generating random point for context based Elliptic curve
    static Point generate_random(Context *ctx);

    // Getting BigNumber as a string/byte array
    string toHex() const;

    // Converting Point to BigNumber
    BigNumber toBigNumber();

    // Equality operator for Point == Point
    bool operator==(const Point& other) const;

    // MUL Operator for Point * BigNumber = Point
    Point operator*(const BigNumber& other) const;
    // MUL Operator for Point * Point = Point
    Point operator*(const Point& other) const;

    // ADD Operator for Point + Point = Point
    Point operator+(const Point& other) const;

    // Invert Operator for ~Point = Point
    Point operator~() const;

    // SUB operator for Point - Point = Point
    Point operator-(const Point& other) const;
  };

}

#endif //CRYPTOMAIC_POINT_H