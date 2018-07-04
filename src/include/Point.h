//
// Created by Tigran on 6/25/18.
//

#ifndef CRYPTOMAIC_POINT_H
#define CRYPTOMAIC_POINT_H

#include "memory"
#include "vector"
#include "BigNumber.h"
#include "PointRaw.h"
#include "Context.h"
#include "ErrorWrapper.h"

using std::shared_ptr;
using std::make_shared;
using std::vector;

namespace CryptoMagic {
  class BigNumber;

  /**
   * \brief Elliptic curve Point class implementation based on OpenSSL EC_POINT interface
   */
  class Point: public ErrorWrapper {
   private:
    shared_ptr<PointRaw> point_raw = make_shared<PointRaw>();
    // Cryptographic context for big number operations
    // NOTE: this class not taking any ownership for this pointer
    Context *context = nullptr;

   public:
    /**
     * \brief Making Point object out of given raw point and Context
     * NOTE: raw could be NULL, and then defined later on
     * @param point
     * @param ctx
     */
    Point(EC_POINT *point, Context *ctx);
    explicit Point(Context *ctx) : Point(nullptr, ctx) {};
    /**
     * \brief Copying existing point
     * @param p
     */
    Point(const Point& p);
    virtual ~Point() = default;

    /**
     * \brief Getting raw point for using raw values defined in encryption backend
     * @return
     */
    shared_ptr<PointRaw> get_point_raw() const;

    /**
     * \brief Getting Generator Point from provided context based Elliptic curve
     * @param ctx
     * @return
     */
    static Point get_generator(Context *ctx);

    /**
     * \brief Converting serialized bytes to Point object
     * NOTE: Serialization is done using Point -> Hex conversation
     * @param bytes
     * @return
     */
    static Point from_bytes(const string& bytes, Context *ctx);

    /**
     * \brief Generating random point for context based Elliptic curve
     * @param ctx
     * @return
     */
    static Point generate_random(Context *ctx);

    /**
     * \brief Hashing our Point object as a BigNumber
     * @param ctx crypto context for hashing
     * @param points vector of points to be hashed
     * @param ...
     * @return
     */
    static string hash(Context *ctx, vector<Point>& points);

    /**
     * \brief Getting bytes from our Point object
     * @return
     */
    string toBytes() const;

    /**
     * \brief Converting Point to BigNumber
     * @return
     */
    BigNumber toBigNumber();

    /**
     * \brief Equality operator for Point == Point
     * @param other
     * @return
     */
    bool operator==(const Point& other) const;

    /**
     * \brief MUL Operator for Point * BigNumber = Point
     * @param other
     * @return
     */
    Point operator*(const BigNumber& other) const;
    /**
     * \brief MUL Operator for Point * Point = Point
     * @param other
     * @return
     */
    Point operator*(const Point& other) const;

    /**
     * \brief ADD Operator for Point + Point = Point
     * @param other
     * @return
     */
    Point operator+(const Point& other) const;

    /**
     * \brief Invert Operator for ~Point = Point
     * @return
     */
    Point operator~() const;

    /**
     * \brief SUB operator for Point - Point = Point
     * @param other
     * @return
     */
    Point operator-(const Point& other) const;
  };

}

#endif //CRYPTOMAIC_POINT_H
