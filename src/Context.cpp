//
// Created by Tigran on 6/21/18.
//

#include "Context.h"
#include <openssl/objects.h>


namespace CryptoMagic {

  Context::Context(const char * ec_name) {
    elliptic_curve_name = ec_name;
    ec_nid = OBJ_txt2nid(elliptic_curve_name.c_str());
    if (ec_nid != 0) {
      ec_group = EC_GROUP_new_by_curve_name(ec_nid);
      if (ec_group == NULL) {
        ec_group = nullptr;
      }
    }
  }

  string Context::get_elliptic_curve_name() {
    return elliptic_curve_name;
  }

  Context::~Context() {
    if (ec_group != nullptr) {
      EC_GROUP_free(ec_group);
    }
  }

  int Context::get_ec_nid() {
    return ec_nid;
  }

  EC_GROUP *Context::get_ec_group() {
    return ec_group;
  }

  Context Context::getDefault() {
    return Context("secp256k1");
  }

}
