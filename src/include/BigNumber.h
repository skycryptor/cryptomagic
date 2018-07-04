//
// Created by Tigran on 6/23/18.
//

#ifndef CRYPTOMAIC_BIGNUMBER_H
#define CRYPTOMAIC_BIGNUMBER_H

#include "memory"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "Context.h"
#include "ErrorWrapper.h"
#include "BigNumberRaw.h"
#include "Point.h"

using std::shared_ptr;
using std::make_shared;

namespace CryptoMagic {
  class Point;

  /**
   * Generic implementation for BigNumber actions
   */
  class BigNumber : public ErrorWrapper {
   private:

    // Cryptographic context for big number operations
    // NOTE: this class not taking any ownership for this pointer
    Context *context = nullptr;

    // Shared pointer for raw big number implementation
    // This is based on specific Crypto backend choosed compile time
    shared_ptr<BigNumberRaw> bn_raw = make_shared<BigNumberRaw>();

    // keeping zero bignum initiated and allocated for later usage
    // this will be created on first BigNumber constructor work at any time
    // then just we will be checking if it's created or not
    static BIGNUM *BNZero;

    // checking if number is in current EC group
    bool isFromECGroup() const;

   public:
    BigNumber(BIGNUM *bn, Context *ctx);
    explicit BigNumber(Context *ctx) : BigNumber(nullptr, ctx) {}
    virtual ~BigNumber() = default;

    // Generate random BigNumber
    static BigNumber generate_random(Context *ctx);
    // Get BigNumber from integer
    static BigNumber from_integer(unsigned long num, Context *ctx);
    // Get BigNumber from big endian ordered bytes
    static BigNumber from_bytes(unsigned char *buffer, int len, Context *ctx);

    // Getting BigNumber as a string/byte array
    string toHex() const;

    // Convert BigNumber to Point
    Point toPoint() const;

    // Doxygen.
    /** \brief Getting BIGNUM bytes from existing OpenSSL BIGNUM
     * @param[out] result_out Serialized string to fill up.
     * @return nothing.
     */
    void toBytes(string& result_out);

    // Getting reference to OpenSSL BIGNUM
    BIGNUM *getRawBigNum() const;
    // Getting reference to OpenSSL BN_CTX to make context based operations with it
    BN_CTX *getRawBnCtx() const;

    // Checking if BigNumbers are equal
    bool operator==(const BigNumber& other) const;

    // MUL operator for BigNumbers, it returns another BigNumber as a result
    BigNumber operator*(const BigNumber& other);
    Point operator*(const Point& other);

    // Inverting current BigNumber and returning inverted one
    BigNumber operator~() const;

    // DIV operator for BigNumbers, it returns another BigNumber as a result
    BigNumber operator/(const BigNumber& other);

    // ADD operator implementation, it returns another BigNumber as a result
    BigNumber operator+(const BigNumber& other);

    // SUB operator implementation, it returns another BigNumber as a result
    BigNumber operator-(const BigNumber& other);

    // MOD operator implementation, it returns another BigNumber as a result
    BigNumber operator%(const BigNumber& other);
  };
}

#endif //CRYPTOMAIC_BIGNUMBER_H
