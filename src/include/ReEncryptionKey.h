//
// Created by Tigran on 7/5/18.
//

#ifndef _CRYPTOMAGIC_RE_ENCRYPTION_KEY_H__
#define _CRYPTOMAGIC_RE_ENCRYPTION_KEY_H__

#include "BigNumber.h"
#include "Point.h"

namespace SkyCryptor {

/**
 * \brief Base definition for re-encryption key
 */
class ReEncryptionKey {
public:
  /**
   * \brief Setting up Re encryption key using bignumber and point
   * @param bn
   * @param point
   */
  ReEncryptionKey(const BigNumber& bn, const Point& point);
  ReEncryptionKey(const ReEncryptionKey& rkk);
  ~ReEncryptionKey() = default;

  /**
   * \brief Getting RK number
   * @return
   */
  BigNumber get_rk_number();

  /**
   * Getting RK point
   * @return
   */
  Point get_rk_point();

  /**
   * \brief making operator for having ReEncryptionKey * Point = Point
   * @param point
   * @return
   */
  Point operator*(const Point& point) const;

  /**
   * \brief converting our re-encryption key to bytes
   * @return
   */
  std::vector<char> toBytes();

  /**
   * \brief Making re-encryption key from encoded bytes using provided raw bytes pointer
   * @param buffer
   * @param length
   * @param ctx
   * @return
   */
  static ReEncryptionKey fromBytes(const char *buffer, int length, Context *ctx);

  /**
   * \brief Making re-encryption key from encoded bytes using provided bytes std::vector
   * @param buffer
   * @param ctx
   * @return
   */
  static ReEncryptionKey fromBytes(std::vector<char> buffer, Context *ctx);

private:

  BigNumber rk_number;
  Point rk_point;

};

} // namespace SkyCryptor

#endif // _CRYPTOMAGIC_RE_ENCRYPTION_KEY_H__
