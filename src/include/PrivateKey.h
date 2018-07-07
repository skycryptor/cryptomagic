//
// Created by Tigran on 7/4/18.
//

#ifndef CRYPTOMAIC_PRIVATEKEY_H
#define CRYPTOMAIC_PRIVATEKEY_H

#include "BigNumber.h"
#include "PublicKey.h"

namespace SkyCryptor {

  /**
   * \brief Base private key containing implementation for EC Private keys
   */
  class PrivateKey {
    /// Private key bigNumber representation
    BigNumber bigNumber;
    /// Keeping crypto context for making decision based on specific context parameters
    /// NOTE: this class is not taking responsibility for deleting Context pointer
    Context *context;

   public:
    /**
     * \brief Main constructor for making PublicKey object
     * @param bn BigNumber for private key representation
     * @param ctx Cryptographic context pointer
     */
    PrivateKey(BigNumber& bn, Context *ctx);
    /**
     * \brief By providing only Crypto context we are making random Private Key
     * this is the same as calling static generate(ctx) function
     * @param ctx
     */
    explicit PrivateKey(Context *ctx);

    /**
     * \brief this is an implementation for copying existing private key as an object
     * @param privateKey
     */
    PrivateKey(const PrivateKey& privateKey);
    ~PrivateKey() = default;

    /**
     * \brief Getting generated PublicKey
     * NOTE: we can re-generate public key with #generate_publicKey()
     * @return PublicKey
     */
    PublicKey get_publicKey();

    /**
     * \brief Generating PrivateKey using BigNumber random generator
     * This function will make PrivateKey object and will assign it inside given Context
     * @param ctx
     * @return PrivateKey
     */
    static PrivateKey generate(Context *ctx);

    /**
     * \brief Getting big number which is representing this Private Key
     * @return
     */
    BigNumber getBigNumber();

    /**
     * \brief MUL operator for having PrivateKey * Point = Point
     * @param other
     * @return
     */
    Point operator*(const Point& other) const;

    /**
     * MUL operator with BigNumber: PrivateKey * BigNumber = BigNumber
     * @param other
     * @return
     */
    BigNumber operator*(const BigNumber& other) const;
  };

}

#endif //CRYPTOMAIC_PRIVATEKEY_H
