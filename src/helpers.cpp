//
// Created by Tigran on 7/4/18.
//

#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>

#include <vector>

#include "defines.h"
#include "helpers.h"

namespace SkyCryptor {

std::vector<char> KDF(const Point& shared_key, const Context& context) {
  auto point_bytes = shared_key.toBytes();
  std::vector<char> digest(ctx->get_key_length());
  mbedtls_md_context_t sha_ctx;
  mbedtls_md_init( &sha_ctx );
  mbedtls_md_setup( &sha_ctx, mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), 1);
  int res = mbedtls_pkcs5_pbkdf2_hmac(
      &sha_ctx, (const unsigned char*)&point_bytes[0], point_bytes.size(), nullptr, 0,
      context->get_iteration_count(), context->get_key_length(), (unsigned char*)&digest[0]);
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
