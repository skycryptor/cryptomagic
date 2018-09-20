//
// Created by Tigran on 6/21/18.
//

#include "Context.h"

namespace SkyCryptor {

Context::Context(int32_t group_id, uint32_t key_length, uint32_t iteration_count) 
  : ec_group_(new EC_GROUP())
  , ec_nid_(group_id)
  , key_length_(key_length)
  , iteration_count_(iteration_count)
{
  mbedtls_ecp_group_init(ec_group_.get());
  int res = mbedtls_ecp_group_load(ec_group_.get(), (mbedtls_ecp_group_id)group_id);
  if (res != 0) {
    throw std::runtime_error("Problem with creation of context.");
  }
}


Context::~Context() {
  if (ec_group_ != nullptr) {
    mbedtls_ecp_group_free(ec_group_.get());
  }
}

int32_t Context::get_ec_nid() {
  return ec_nid_;
}

EC_GROUP* Context::get_ec_group() {
  return ec_group_.get();
}

std::shared_ptr<Context> Context::get_default() {
  static std::shared_ptr<Context> ctx = std::make_shared<Context>(MBEDTLS_ECP_DP_SECP256K1);
  return ctx;
}

uint32_t Context::get_key_length() const {
  return key_length_;
}

uint32_t Context::get_iteration_count() const {
  return iteration_count_;
}

const BIGNUM& Context::get_ec_order() const {
  return ec_group_->N;
}

} // namespace SkyCryptor

