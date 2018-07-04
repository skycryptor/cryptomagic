//
// Created by Tigran on 7/4/18.
//

#ifndef CRYPTOMAIC_PRIVATEKEY_H
#define CRYPTOMAIC_PRIVATEKEY_H

#include "BigNumber.h"
#include "PublicKey.h"

namespace CryptoMagic {

  /**
   * Base private key containing implementation for EC Private keys
   */
  class PrivateKey {
    /// Private key bigNumber representation
    BigNumber bigNumber;
    /// Keeping public key for having it specifically for this Private Key
    PublicKey publicKey;
    /// Keeping crypto context for making decision based on specific context parameters
    /// NOTE: this class is not taking responsibility for deleting Context pointer
    Context *context;

   public:
    /**
     * Main constructor for making PublicKey object
     * @param bn BigNumber for private key representation
     * @param ctx Cryptographic context pointer
     */
    PrivateKey(BigNumber& bn, Context *ctx);
    PrivateKey(Context *ctx);
    ~PrivateKey() = default;

    /**
     * Getting generated PublicKey
     * NOTE: we can re-generate public key with #generate_publicKey()
     * @return PublicKey
     */
    PublicKey get_publicKey();

    /**
     * Generating PrivateKey using BigNumber random generator
     * This function will make PrivateKey object and will assign it inside given Context
     * @param ctx
     * @return PrivateKey
     */
    static PrivateKey generate(Context *ctx);
  };

}

#endif //CRYPTOMAIC_PRIVATEKEY_H
