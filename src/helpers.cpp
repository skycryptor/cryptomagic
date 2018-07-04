//
// Created by Tigran on 7/4/18.
//

#include "helpers.h"
#include "openssl/evp.h"
#include "openssl/sha.h"

namespace CryptoMagic {

  string KDF(Point& shared_key, Context *ctx) {
    string point_bytes = shared_key.toBytes();
    char digest[ctx->get_key_length()];
    PKCS5_PBKDF2_HMAC(point_bytes.c_str(), (int)point_bytes.length(), NULL, 0, ctx->get_iteration_count(), EVP_sha256(), ctx->get_key_length(), (unsigned char*)digest);
    return string(digest);
  }

  string HASH(Context *ctx, vector<string>& parts) {
    char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX shaCtx;
    SHA256_Init(&shaCtx);
    for(auto &p : parts) {
      SHA256_Update(&shaCtx, p.c_str(), p.length());
    }

    SHA256_Final((unsigned char*)digest, &shaCtx);
    return string(digest);
  }
}
