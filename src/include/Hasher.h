#ifndef _PROXYLIB_HASHER_H__
#define _PROXYLIB_HASHER_H__

#include <string>
#include "ECPoint.h"
#include "VersionInfo.h"

namespace SkyCryptor {

class Hasher {
public: 
  static Hasher& get_default();
  Hasher(const int32_t& sha256_digest_byte_length, const int32_t& iteration_count);

  /**
   * \brief Running KDF cryptographic function with defined Context and given shared_key Point
   * @param shared_key
   * @return
   */
  std::vector<char> KDF(const VersionInfo& ctx, const ECPoint& shared_key);

  /**
   * \brief Implementing hash function with given byte array parts and crypto context
   * NOTE: byte array list could be N size, all of them would be hashed together
   * @param part
   * @param ...
   * @return
   */
  std::vector<char> SHA_256(const std::vector<std::vector<char>>& parts);
  std::vector<char> SHA_256(const VersionInfo& version_info, const ECPoint& shared_key);

private:

  int32_t sha256_digest_byte_length_;
  int32_t iteration_count_;

};

} // namespace SkyCryptor

#endif //_PROXYLIB_HASHER_H__
