//
// Created by Tigran on 7/4/18.
//

#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>

#include <vector>

#include "defines.h"
#include "helpers.h"

namespace SkyCryptor {

std::vector<char> KDF(const Context& context, const Point& shared_key) {
  auto point_bytes = shared_key.to_bytes();
  std::vector<char> digest(context.get_key_length());
  mbedtls_md_context_t sha_context;
  mbedtls_md_init( &sha_context );
  mbedtls_md_setup( &sha_context, mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), 1);
  int res = mbedtls_pkcs5_pbkdf2_hmac(
      &sha_context, (const unsigned char*)&point_bytes[0], point_bytes.size(), nullptr, 0,
      context.get_iteration_count(), context.get_key_length(), (unsigned char*)&digest[0]);
  if (res != 0) {
    // TODO: make error handling here!!
  }
  return digest;
}

std::vector<char> HASH(const Context& context, const std::vector<std::vector<char>>& parts) {
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
