#ifndef _PROXYLIB_EC_SCALAR_H__
#define _PROXYLIB_EC_SCALAR_H__

#include <memory>
#include <vector>
#include <mbedtls/ecp.h>

#include "ProxyLibException.h"

namespace SkyCryptor {

class ECScalarRaw;
class ECPoint;

/// \brief Generic implementation for ECScalar
class ECScalar {
friend class ECPoint;
public:

  /**
   * \brief Making ECScalar object from given raw big number.
   * @param bn
   */
  ECScalar(const mbedtls_mpi& bn);
  ECScalar();
  /// \brief Creating a bignumber from an integer value.
  ECScalar(uint32_t value);
  ~ECScalar();

  // Returns a reference to a static object which contains number 0.
  static const ECScalar& get_zero();

  /**
   * \brief Copying ECScalar object from existing one
   * @param bn
   */
  ECScalar(const ECScalar& bn);

  /**
   * \brief Generate random ECScalar.
   * @return
   */
  static ECScalar generate_random();

  /**
   * \brief Get ECScalar from integer
   * @param num
   * @return
   */
  static ECScalar from_integer(uint32_t num);

  /**
   * \brief Get ECScalar from big endian ordered bytes
   * @param buffer
   * @param len
   * @return
   */
  static ECScalar from_bytes(unsigned char *buffer, int len);

  /**
   * \brief Getting mbedtls_mpi bytes from existing OpenSSL mbedtls_mpi
   * @return vector of bytes
   */
  std::vector<char> to_bytes() const;

  /**
   * \brief Checking if ECScalars are equal
   * @param other
   * @return
   */
  bool operator==(const ECScalar& other) const;

  /**
   * \brief MUL operator for ECScalar * ECScalar = ECScalar
   * @param other
   * @return
   */
  ECScalar operator*(const ECScalar& other) const;

  /**
   * \brief MUL operator for ECScalar * ECPoint = ECPoint
   * @param other
   * @return
   */
  ECPoint operator*(const ECPoint& other) const;

  /**
   * \brief Inverting current ECScalar: ~ECScalar = ECScalar
   * @return
   */
  ECScalar operator~() const;

  /**
   * \brief DIV operator for ECScalars: ECScalar / ECScalar = ECScalar
   * @param other
   * @return
   */
  ECScalar operator/(const ECScalar& other) const;

  /**
   * \brief ADD operator implementation: ECScalar + ECScalar = ECScalar
   * @param other
   * @return
   */
  ECScalar operator+(const ECScalar& other) const;

  /**
   * \brief SUB operator implementation: ECScalar - ECScalar = ECScalar
   * @param other
   * @return
   */
  ECScalar operator-(const ECScalar& other) const;

  /**
   * \brief MOD operator implementation: ECScalar % ECScalar = ECScalar
   * @param other
   * @return
   */
  ECScalar operator%(const ECScalar& other) const;

  /**
   * \brief Checking if number is in current EC group
  *  /TODO(martun): check what this means.
   * @return
   */
  bool is_from_EC_group() const;

  static const ECScalar& get_ec_order();

private:

  mbedtls_mpi* bn_raw_;

};

} // namespace SkyCryptor

#endif // _PROXYLIB_EC_SCALAR_H__
