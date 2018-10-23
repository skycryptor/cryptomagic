#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>

#include <vector>

#include "defines.h"
#include "Hasher.h"
#include "VersionInfo.h"
#include "VersionInfoMap.h"

namespace SkyCryptor {

Hasher& Hasher::get_default() {
  static Hasher hasher(VersionInfoMap::get_current_version()->get_key_length(), 
                       VersionInfoMap::get_current_version()->get_iteration_count());
  return hasher;
}

Hasher::Hasher(const int32_t& sha256_digest_byte_length, const int32_t& iteration_count)
  : sha256_digest_byte_length_(sha256_digest_byte_length)
  , iteration_count_(iteration_count) 
{

}

std::vector<char> Hasher::KDF(const VersionInfo& version_info, const ECPoint& shared_key) {
  auto point_bytes = shared_key.to_bytes();
  std::vector<char> digest(version_info.get_key_length());
  mbedtls_md_context_t sha_context;
  mbedtls_md_init( &sha_context );
  mbedtls_md_setup( &sha_context, mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), 1);
  int res = mbedtls_pkcs5_pbkdf2_hmac(
      &sha_context, (const unsigned char*)&point_bytes[0],
      point_bytes.size(), nullptr, 0,
      version_info.get_iteration_count(), version_info.get_key_length(), 
      (unsigned char*)&digest[0]);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return digest;
}

std::vector<char> Hasher::SHA_256(const VersionInfo& version_info, const ECPoint& shared_key) {
  auto key_bytes = shared_key.to_bytes();
  std::vector<char> digest(SHA256_DIGEST_LENGTH);
  mbedtls_sha256_context shaCtx;
  mbedtls_sha256_init(&shaCtx);
  mbedtls_sha256_starts_ret(&shaCtx, 0);
  mbedtls_sha256_update_ret(&shaCtx, (unsigned char*)&key_bytes[0], key_bytes.size());
  mbedtls_sha256_finish_ret(&shaCtx, (unsigned char*)&digest[0]);
  return digest;
}

std::vector<char> Hasher::SHA_256(const std::vector<std::vector<char>>& parts) {
  std::vector<char> digest(SHA256_DIGEST_LENGTH);
  mbedtls_sha256_context shaCtx;
  mbedtls_sha256_init(&shaCtx);
  mbedtls_sha256_starts_ret(&shaCtx, 0);
  for(auto &p : parts) {
    mbedtls_sha256_update_ret(&shaCtx, (unsigned char*)&p[0], p.size());
  }
  mbedtls_sha256_finish_ret(&shaCtx, (unsigned char*)&digest[0]);
  return digest;
}

} // namespace SkyCryptor

