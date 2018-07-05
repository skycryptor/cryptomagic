//
// Created by Tigran on 7/4/18.
//

#include "helpers.h"
#include "openssl/evp.h"
#include "openssl/sha.h"

namespace SkyCryptor {

  vector<char> KDF(Point& shared_key, Context *ctx) {
    auto point_bytes = shared_key.toBytes();
    vector<char> digest(ctx->get_key_length());
    PKCS5_PBKDF2_HMAC(&point_bytes[0], (int)point_bytes.size(), NULL, 0, ctx->get_iteration_count(), EVP_sha256(), ctx->get_key_length(), (unsigned char*)&digest[0]);
    return digest;
  }

  vector<char> HASH(Context *ctx, vector<vector<char>>& parts) {
    vector<char> digest(SHA256_DIGEST_LENGTH);
    SHA256_CTX shaCtx;
    SHA256_Init(&shaCtx);
    for(auto &p : parts) {
      SHA256_Update(&shaCtx, &p[0], p.size());
    }

    SHA256_Final((unsigned char*)&digest[0], &shaCtx);
    return digest;
  }
}
