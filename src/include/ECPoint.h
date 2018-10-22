#ifndef __PROXYLIB_POINT_H__
#define __PROXYLIB_POINT_H__

#include <memory>
#include <vector>
#include "ProxyLibException.h"
#include <mbedtls/ecp.h>
#include "defines.h"

namespace SkyCryptor {

class ECScalar;

/**
 * \brief Elliptic curve ECPoint class implementation based on OpenSSL EC_POINT interface
 */
class ECPoint {
friend class ECScalar;

public:

  /**
   * \brief Making ECPoint object out of given raw point, rakes ownership of the passed pointer. 
   * NOTE: raw could be NULL, and then defined later on
   * @param point
   * @param ctx
   */
  ECPoint(EC_POINT* point);

  ECPoint();

  /**
   * \brief Copying existing point
   * @param p
   */
  ECPoint(const ECPoint& p);

  virtual ~ECPoint();

  /**
   * \brief Getting Generator ECPoint based on Elliptic curve.
   * @param ctx
   * @return
   */
  static ECPoint get_generator();

  /**
   * \brief Converting serialized bytes to ECPoint object
   * NOTE: Serialization is done using ECPoint -> Hex conversion.
   * @param bytes
   * @return
   */
  static ECPoint from_bytes(const std::vector<char>& bytes);
  static ECPoint from_bytes(const char *bytes, int len);

  /**
   * \brief Generating random point for context based Elliptic curve
   * @param ctx
   * @return
   */
  static ECPoint generate_random();

  /**
   * \brief Hashing our ECPoint object as a ECScalar
   * @param points std::vector of points to be hashed
   * @param ...
   * @return
   */
  // TODO(martun): move this out of this class, move to some hasher class.
  static std::vector<char> hash(const std::vector<ECPoint>& points);

  /**
   * \brief Getting bytes from our ECPoint object
   * @return
   */
  std::vector<char> to_bytes() const;

  /**
   * \brief Equality operator for ECPoint == ECPoint
   * @param other
   * @return
   */
  bool operator==(const ECPoint& other) const;

  /**
   * \brief MUL Operator for ECPoint * ECScalar = ECPoint
   * @param other
   * @return
   */
  ECPoint operator*(const ECScalar& other) const;

  /**
   * \brief ADD Operator for ECPoint + ECPoint = ECPoint
   * @param other
   * @return
   */
  ECPoint operator+(const ECPoint& other) const;

private:
  // Raw pointer for OpenSSL object
  EC_POINT *ec_point_;

};

} // namespace SkyCryptor

#endif // __PROXYLIB_POINT_H__
