//
// Created by Tigran on 7/5/18.
//

#ifndef CRYPTOMAIC_REENCRYPTIONKEY_H
#define CRYPTOMAIC_REENCRYPTIONKEY_H

#include "BigNumber.h"

namespace SkyCryptor {

  /**
   * \brief Base definition for re-encryption key
   */
  class ReEncryptionKey {
    BigNumber rk_number;
    Point rk_point;

   public:
    /**
     * \brief Setting up Re encryption key using bignumber and point
     * @param bn
     * @param point
     */
    ReEncryptionKey(const BigNumber& bn, const Point& point);
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
  };
}

#endif //CRYPTOMAIC_REENCRYPTIONKEY_H
