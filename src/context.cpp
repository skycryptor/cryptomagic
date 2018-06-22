//
// Created by Tigran on 6/21/18.
//

#include "context.h"


namespace CryptoMagic {

  string Context::get_elliptic_curve_name() {
    return elliptic_curve_name;
  }

  void Context::set_elliptic_curve_name(string &ec_name) {
    elliptic_curve_name = ec_name;
  }

  void Context::set_elliptic_curve_name(char *ec_name) {
    elliptic_curve_name = string(ec_name);
  }

  int Context::get_rsa_key_size() {
    return rsa_key_size;
  }

  void Context::set_rsa_key_size(int size) {
    rsa_key_size = size;
  }

}
