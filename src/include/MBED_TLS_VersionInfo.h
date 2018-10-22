#ifndef _PROXYLIB_MBED_TLS_VERSION_INFO_H__
#define _PROXYLIB_MBED_TLS_VERSION_INFO_H__

#include <string>
#include <cstdint>
#include <memory>

#include "defines.h"
#include "VersionInfo.h"

namespace SkyCryptor {

/**
 * \brief MBED_TLS_VersionInfo is defining various values which match a given version ID. 
 */
class MBED_TLS_VersionInfo : public VersionInfo {
public:

  /**
   * @returns A singleton instance of a current Version Info. 
   */
  static MBED_TLS_VersionInfo& get_current();

  /**
   * \brief Defining MBED_TLS_VersionInfo from given Elliptic curve name
   * @param ec_name
   */
  MBED_TLS_VersionInfo(const std::string& elliptic_curve_name,
              int32_t group_id, 
              uint32_t key_length,
              uint32_t sha256_iteration_count);

  ~MBED_TLS_VersionInfo();

  /**
   * \brief Getting EC NID from OpenSSL numerical definition
   * @return
   */
  int32_t get_ec_nid();

  /**
   * \brief Getting raw pointer for EC group from OpenSSL definition
   * @return
   */
  EC_GROUP* get_ec_group() const;

  /**
   * \brief Getting key length
   * @return
   */
  uint32_t get_key_length() const;

  /**
   * Getting iteration count for crypto operations
   * @return
   */
  uint32_t get_iteration_count() const;

  /**
   * \brief Getting EC order from defined elliptic curve
   * @return
   */
   const mbedtls_mpi& get_ec_order() const;

private:

  /// Keeping current elliptic curve name as a context
  std::string elliptic_curve_name_;

  /// EC NID.
  int32_t ec_nid_;

  /// Eliptic Curve group.
  std::unique_ptr<mbedtls_ecp_group> ec_group_;

  /// Defining key length for using it for functions like KDF
  const uint32_t key_length_;

  // Iteration number for crypto functions like KDF
  const uint32_t sha256_iteration_count_;

};

} // namespace SkyCryptor

#endif //_PROXYLIB_MBED_TLS_VERSION_INFO_H__
