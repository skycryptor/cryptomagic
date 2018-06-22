//
// Created by Tigran on 6/21/18.
//

#ifndef CRYPTOMAIC_CONTEXT_H
#define CRYPTOMAIC_CONTEXT_H

#include "string"

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
    string elliptic_curve_name = "secp256k1";

    // keeping RSA key size inside context
    int rsa_key_size = 2048;

   public:
    Context() = default;
    ~Context() = default;

    string get_elliptic_curve_name();
    void set_elliptic_curve_name(string &ec_name);
    void set_elliptic_curve_name(char *ec_name);

    int get_rsa_key_size();
    void set_rsa_key_size(int size);
  };

}

#endif //CRYPTOMAIC_CONTEXT_H
