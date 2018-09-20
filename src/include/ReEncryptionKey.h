//
// Created by Tigran on 7/5/18.
//

#ifndef _CRYPTOMAGIC_RE_ENCRYPTION_KEY_H__
#define _CRYPTOMAGIC_RE_ENCRYPTION_KEY_H__

#include "NUMBER_TYPE.h"
#include "POINT_TYPE.h"

namespace SkyCryptor {

/**
 * \brief Base definition for re-encryption key
 */
template<class POINT_TYPE, class NUMBER_TYPE>
class ReEncryptionKey {

public:
  /**
   * \brief Setting up Re encryption key using bignumber and point
   * @param bn
   * @param point
   */
  ReEncryptionKey(const NUMBER_TYPE& bn, const POINT_TYPE& point);
  ReEncryptionKey(const ReEncryptionKey& rkk) = default;
  ~ReEncryptionKey() = default;

  /**
   * \brief Getting RK number
   * @return
   */
  const NUMBER_TYPE& get_rk_number() const;

  /**
   * Getting RK point
   * @return
   */
  const POINT_TYPE& get_rk_point() const;

  /**
   * \brief converting our re-encryption key to bytes
   * @return
   */
  std::vector<char> to_bytes() const;

  /**
   * \brief Making re-encryption key from encoded bytes using provided raw bytes pointer
   * @param buffer
   * @param length
   * @param ctx
   * @return
   */
  static ReEncryptionKey from_bytes(const char *buffer, int length, Context *ctx);

  /**
   * \brief Making re-encryption key from encoded bytes using provided bytes std::vector
   * @param buffer
   * @param ctx
   * @return
   */
  static ReEncryptionKey from_bytes(const std::vector<char>& buffer, Context *ctx);

private:

  NUMBER_TYPE rk_number_; // rename rk

  // value of x * g, I.E. temporary public key.
  POINT_TYPE rk_point_; // TODO(martun): rename to internal_public_key

};

} // namespace SkyCryptor

// Include template function implementations.
#include "ReEncryptionKey.hpp"

#endif // _CRYPTOMAGIC_RE_ENCRYPTION_KEY_H__
