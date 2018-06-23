//
// Created by Tigran on 6/21/18.
//

#ifndef CRYPTOMAIC_CONTEXT_H
#define CRYPTOMAIC_CONTEXT_H

#include "string"
#include "openssl/ec.h"

using namespace std;

namespace CryptoMagic {

  /**
   * Context is defining main context for cryptographic operations and configurations
   * Each CryptoMagic entry point object should contain context for having
   * consistent crypto operations configurations and algorithm definitions
   */
  class Context {
   private:
    // Keeping current elliptic curve name as a context
    string elliptic_curve_name;
    // EC NID from OpenSSL definitions
    int ec_nid = 0;
    // Making EC group from OpenSSL
    EC_GROUP *ec_group = nullptr;

   public:
    explicit Context(const char * ec_name);
    ~Context();

    string get_elliptic_curve_name();
    int get_ec_nid();
    EC_GROUP *get_ec_group();

    static Context getDefault();
  };

}

#endif //CRYPTOMAIC_CONTEXT_H
