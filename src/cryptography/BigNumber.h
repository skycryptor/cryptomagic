//
// Created by Tigran on 6/23/18.
//

#ifndef CRYPTOMAIC_BIGNUMBER_H
#define CRYPTOMAIC_BIGNUMBER_H

#include "memory"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "Context.h"
#include "helpers/ErrorWrapper.h"

using std::unique_ptr;

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
    Context *context = nullptr;
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
    virtual ~BigNumber();

    // Generate random BigNumber
    static BigNumber *generate_random(Context *ctx);
    // Get BigNumber from integer
    static BigNumber *from_integer(unsigned long num, Context *ctx);
    // Get BigNumber from big endian ordered bytes
    static BigNumber *from_bytes(unsigned char *buffer, int len, Context *ctx);

    // Getting BigNumber as a string/byte array
    string toHex();
    // Getting BIGNUM bytes from existing OpenSSL BIGNUM
    string toBytes();
    // Getting reference to OpenSSL BIGNUM
    BIGNUM *getRawBigNum();
    // Getting reference to OpenSSL BN_CTX to make context based operations with it
    BN_CTX *getRawBnCtx();

    // Checking if BigNumbers are equal
    bool eq(BigNumber *bn2);
    static bool eq(BigNumber *bn1, BigNumber *bn2);

    // MUL operator for BigNumbers, it returns another BigNumber as a result
    BigNumber *mul(BigNumber *bn2);
    static BigNumber *mul(BigNumber *bn1, BigNumber *bn2);

    // Inverting current BigNumber and returning inverted one
    BigNumber *inv();
    static BigNumber *inv(BigNumber *bn);

    // DIV operator for BigNumbers, it returns another BigNumber as a result
    BigNumber *div(BigNumber *bn2);
    static BigNumber *div(BigNumber *bn1, BigNumber *bn2);

    // ADD operator implementation, it returns another BigNumber as a result
    BigNumber *add(BigNumber *bn2);
    static BigNumber *add(BigNumber *bn1, BigNumber *bn2);

    // SUB operator implementation, it returns another BigNumber as a result
    BigNumber *sub(BigNumber *bn2);
    static BigNumber *sub(BigNumber *bn1, BigNumber *bn2);

    // MOD operator implementation, it returns another BigNumber as a result
    BigNumber *mod(BigNumber *bn2);
    static BigNumber *mod(BigNumber *bn1, BigNumber *bn2);
  };
}

#endif //CRYPTOMAIC_BIGNUMBER_H
