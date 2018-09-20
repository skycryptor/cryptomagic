#ifndef _PROXYLIB_BIG_NUMBER_H__
#define _PROXYLIB_BIG_NUMBER_H__

#include <memory>
#include <vector>

#include "Context.h"
#include "ErrorWrapper.h"

namespace SkyCryptor {

class BigNumberRaw;
class Point;

/// \brief Generic implementation for BigNumber
class BigNumber : public ErrorWrapper {

public:
  /// keeping zero bignum initiated and allocated for later usage
  /// this will be created on first BigNumber constructor work at any time
  /// then just we will be checking if it's created or not
  static BIGNUM *BNZero;

  /**
   * \brief Making BigNumber object from given raw big number.
   * @param bn
   */
  BigNumber(BIGNUM *bn);
  BigNumber() = default;

  /**
   * \brief Copying BigNumber object from existing one
   * @param bn
   */
  BigNumber(const BigNumber& bn) = default;
  virtual ~BigNumber() = default;

  /**
   * \brief Generate random BigNumber.
   * @return
   */
  static BigNumber generate_random();

  /**
   * \brief Get BigNumber from integer
   * @param num
   * @return
   */
  static BigNumber from_integer(uint32_t num);

  /**
   * \brief Get BigNumber from big endian ordered bytes
   * @param buffer
   * @param len
   * @return
   */
  static BigNumber from_bytes(unsigned char *buffer, int len);

  /**
   * \brief Getting BIGNUM bytes from existing OpenSSL BIGNUM
   * @return vector of bytes
   */
  std::vector<char> to_bytes() const;

  /**
   * \brief Getting reference to OpenSSL BIGNUM
   * /TODO(martun): try to get rid of this function.
   * @return
   */
  BIGNUM* get_raw_bignum() const;

  /**
   * \brief Checking if BigNumbers are equal
   * @param other
   * @return
   */
  bool operator==(const BigNumber& other) const;

  /**
   * \brief MUL operator for BigNumber * BigNumber = BigNumber
   * @param other
   * @return
   */
  BigNumber operator*(const BigNumber& other) const;

  /**
   * \brief MUL operator for BigNumber * Point = Point
   * @param other
   * @return
   */
  Point operator*(const Point& other) const;

  /**
   * \brief Inverting current BigNumber: ~BigNumber = BigNumber
   * @return
   */
  BigNumber operator~() const;

  /**
   * \brief DIV operator for BigNumbers: BigNumber / BigNumber = BigNumber
   * @param other
   * @return
   */
  BigNumber operator/(const BigNumber& other) const;

  /**
   * \brief ADD operator implementation: BigNumber + BigNumber = BigNumber
   * @param other
   * @return
   */
  BigNumber operator+(const BigNumber& other) const;

  /**
   * \brief SUB operator implementation: BigNumber - BigNumber = BigNumber
   * @param other
   * @return
   */
  BigNumber operator-(const BigNumber& other) const;

  /**
   * \brief MOD operator implementation: BigNumber % BigNumber = BigNumber
   * @param other
   * @return
   */
  BigNumber operator%(const BigNumber& other) const;

  /**
   * \brief MOD operator implementation: BigNumber % BIGNUM = BigNumber
   * @param other
   * @return
   */
  //  BigNumber operator%(BIGNUM * other);

  /**
   * \brief Checking if number is in current EC group
  *  /TODO(martun): check what this means.
   * @return
   */
  bool is_from_EC_group() const;

  static uint32_t get_ec_order();

private:
  /// Shared pointer for raw big number implementation
  /// This is based on specific Crypto backend choosed compile time
  std::shared_ptr<BigNumberRaw> bn_raw_;

};

} // namespace SkyCryptor

#endif // _PROXYLIB_BIG_NUMBER_H__
