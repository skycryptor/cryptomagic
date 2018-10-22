#ifndef _PROXYLIB_VERSION_INFO_H__
#define _PROXYLIB_VERSION_INFO_H__

#include <string>
#include <cstdint>
#include <memory>

#include "defines.h"

namespace SkyCryptor {

/**
 * \brief Generic VersionInfo for all possible future versions. 
 */
class VersionInfo {
public:

  /**
   * \brief Getting EC NID from OpenSSL numerical definition
   * @return
   */
  virtual int32_t get_ec_nid() = 0;

  /**
   * \brief Getting raw pointer for EC group from OpenSSL definition
   * @return
   */
  virtual EC_GROUP* get_ec_group() const = 0;

  /**
   * \brief Getting key length
   * @return
   */
  virtual uint32_t get_key_length() const = 0;

  /**
   * Getting iteration count for crypto operations
   * @return
   */
  virtual uint32_t get_iteration_count() const = 0;

  /**
   * \brief Getting EC order from defined elliptic curve
   * @return
   */
  virtual const mbedtls_mpi& get_ec_order() const = 0;

};

} // namespace SkyCryptor

#endif //_PROXYLIB_VERSION_INFO_H__
