//
// Created by Tigran on 6/23/18.
//

#ifndef CRYPTOMAIC_BIGNUMBER_H
#define CRYPTOMAIC_BIGNUMBER_H

#include "openssl/bn.h"
#include "openssl/ec.h"
#include "../Context.h"
#include "../helpers/ErrorWrapper.h"

namespace CryptoMagic {
  /**
   * Generic implementation for BigNumber actions
   */
  class BigNumber : public ErrorWrapper {
   private:
    // OpenSSL bignumber parameter
    BIGNUM *bignum = nullptr;
    // Cryptographic context for big number operations
    // NOTE: this class not taking any ownership for this pointer
    Context *ctx = nullptr;
    // EC order
    BIGNUM *ec_order = nullptr;
    // BigNumber context for making OpenSSL BIGNUM operations
    BN_CTX *bnCtx = nullptr;

    // keeping zero bignum initiated and allocated for later usage
    // this will be created on first BigNumber constructor work at any time
    // then just we will be checking if it's created or not
    static BIGNUM *BNZero;

    // checking if number is in current EC group
    bool isFromECGroup();

   public:
    BigNumber(BIGNUM *bn, Context *ctx);
    explicit BigNumber(Context *ctx) : BigNumber(nullptr, ctx) {}
    ~BigNumber();

    // Generate random BigNumber
    static BigNumber generate_random(Context *ctx);
    // Get BigNumber from integer
    static BigNumber from_integer(int num, Context *ctx);
    // Get BigNumber from big endian ordered bytes
    static BigNumber from_bytes(unsigned char *buffer, Context *ctx);

    // Getting BigNumber as a string/byte array
    string toHex();
    // Getting BIGNUM bytes from existing OpenSSL BIGNUM
    string toBytes();

    // Checking if BigNumbers are equal
    bool operator==(const BigNumber& rhs);
    // MUL operator for BigNumbers, it returns another BigNumber as a result
    BigNumber operator*(const BigNumber& rhs);
    // Inverting current BigNumber and returning inverted one
    BigNumber operator~();
    // DIV operator for BigNumbers, it returns another BigNumber as a result
    BigNumber operator/(BigNumber& rhs);
    // ADD operator implementation, it returns another BigNumber as a result
    BigNumber operator+(const BigNumber& rhs);
    // SUB operator implementation, it returns another BigNumber as a result
    BigNumber operator-(const BigNumber& rhs);
    // MOD operator implementation, it returns another BigNumber as a result
    BigNumber operator%(const BigNumber& rhs);
  };
}

#endif //CRYPTOMAIC_BIGNUMBER_H
