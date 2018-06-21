//
// Created by Tigran on 6/21/18.
//

#ifndef CRYPTOMAIC_EC_H
#define CRYPTOMAIC_EC_H

#include "string"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

using namespace std;

namespace CryptoMagic {

  /**
   * EllipticCurve contains main functionality for handling Elliptic Curve cryptography needed for CryptoMagic
   * It needs some context configuration like curve type example: "secp256k1"
   */
  class EllipticCurve {
   private:
    // Elliptic curve group for processing operations with it
    // 0 - means that curve_group is undefined or not found if it still 0 after providing a name
    int curve_group = 0;

    // Elliptic curve main key reference for crypto operations
    EC_KEY *ec_key = nullptr;

    // Private key generated or provided before any crypto operation
    EVP_PKEY *private_key = nullptr;

   public:
    EllipticCurve(int ec_group);
    EllipticCurve(string ec_group_name);
    ~EllipticCurve();

    // Validating provided group information
    // NOTE: this should be called right after constructor
    // otherwise all other crypto operations will return an error if group is invalid
    bool validateGroup();

    // Generating private/public keys using already provided EC group information
    // TODO: make error handling for this case with error code and text
    bool generateKeys();
  };

}

#endif //CRYPTOMAIC_EC_H
