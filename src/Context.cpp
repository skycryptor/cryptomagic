//
// Created by Tigran on 6/21/18.
//

#include "Context.h"

namespace SkyCryptor {

  Context::Context(int group_id) {
    ec_nid = group_id;
    mbedtls_ecp_group_init(ec_group);
    int res = mbedtls_ecp_group_load(ec_group, (mbedtls_ecp_group_id)group_id);
    if (res != 0) {
      // TODO: think about error reporting!!
    }
  }


  Context::~Context() {
    if (ec_group != nullptr) {
      mbedtls_ecp_group_free(ec_group);
    }
  }

  int Context::get_ec_nid() {
    return ec_nid;
  }

  EC_GROUP *Context::get_ec_group() {
    return ec_group;
  }

  Context Context::getDefault() {
    return Context(MBEDTLS_ECP_DP_SECP256K1);
  }

  unsigned int Context::get_key_length() {
    return key_length;
  }

  void Context::set_key_length(unsigned int len) {
    key_length = len;
  }

  unsigned int Context::get_iteration_count() {
    return iteration_count;
  }

  void Context::get_iteration_count(unsigned int iter) {
    iteration_count = iter;
  }

  BIGNUM *Context::get_ec_order() {
    return &ec_group->N;
  }
}
