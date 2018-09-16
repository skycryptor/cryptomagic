//
// Created by Tigran on 6/21/18.
//

#ifndef CRYPTOMAIC_CONTEXT_H
#define CRYPTOMAIC_CONTEXT_H

#include <string>
#include <cstdint>
#include "defines.h"

namespace SkyCryptor {

/**
 * \brief Context is defining main context for cryptographic operations and configurations
 * Each CryptoMagic entry point object should contain context for having
 * consistent crypto operations configurations and algorithm definitions
 */
class Context {
public:

  /**
   * \brief Making default Context from defined EC name
   * @return
   */
  static Context& get_default();

  /**
   * \brief Defining context from given Elliptic curve name
   * @param ec_name
   */
  Context(int32_t group_id, uint32_t key_length = 128, uint32_t iteration_count = 1000);

  ~Context();

  /**
   * \brief Getting EC NID from OpenSSL numerical definition
   * @return
   */
  int32_t get_ec_nid();

  /**
   * \brief Getting raw pointer for EC group from OpenSSL definition
   * @return
   */
  EC_GROUP* get_ec_group();

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
   const BIGNUM& get_ec_order();

private:

  /// Keeping current elliptic curve name as a context
  std::string elliptic_curve_name_;

  /// EC NID from OpenSSL definitions
  int32_t ec_nid_;

  /// Making EC group from OpenSSL
  std::unique_ptr<EC_GROUP> ec_group_;

  /// Defining key length for using it for functions like KDF
  const uint32_t key_length_;

  /// Iteration number for crypto functions like KDF
  const uint32_t iteration_count_;

};

} // namespace SkyCryptor

#endif //CRYPTOMAIC_CONTEXT_H
