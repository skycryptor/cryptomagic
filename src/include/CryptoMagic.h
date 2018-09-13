#ifndef CRYPTOMAGIC_CRYPTOMAGIC_H
#define CRYPTOMAGIC_CRYPTOMAGIC_H

#include "Context.h"
#include "BigNumber.h"
#include "Point.h"
#include "Capsule.h"
#include "PublicKey.h"
#include "PrivateKey.h"
#include "ReEncryptionKey.h"

namespace SkyCryptor {

  /**
   * \brief CryptoMagic base class for handling library crypto operations and main functionality
   * Each initialized CryptoMagic object should contain Context which will define
   * base parameters for crypto operations and configurations
   */
  class CryptoMagic {
   private:
    // defining main context for all cryptographic operations inside current CryptoMagic object
    Context context = Context::getDefault();

   public:
    CryptoMagic() = default;
    /**
     * \brief Making CryptoMagic object with defined context
     * @param ctx
     */
    explicit CryptoMagic(Context ctx);
    ~CryptoMagic() = default;

    // Getting current defined context as a reference
    Context *getContext();

    /**
     * \brief Setting context for this CryptoMagic object
     *  NOTE: crypto operations will start receiving this context parameters after calling this setter function
     * @param ctx
     */
    void setContext(const Context& ctx);

    /**
     * \brief Making capsule out of given PublicKey and given crypto Context and also returning
     * symmetric key wrapped as a string object
     *
     * @param pk "Alice" Public Key
     * @param[out] symmetric_key_out
     * @return Capsule
     */
    Capsule encapsulate(PublicKey& pk, std::vector<char>& symmetric_key_out) const;

    /**
     * \brief Decapsulate given capsule with private key,
     * NOTE: Provided private key, should be the original key from which Public Key capsule is created
     * @param capsule
     * @param privateKey
     * @return
     */
    std::vector<char> decapsulate_original(Capsule& capsule, PrivateKey& privateKey);

    /**
     * \brief Getting re-encryption key out of Private key (Alice) and public key (Bob) using random private key generation
     * @param privateKeyA
     * @param publicKeyB
     * @return
     */
    ReEncryptionKey get_re_encryption_key(PrivateKey& privateKeyA, PublicKey& publicKeyB);

    /**
     * \brief Getting re-encryption capsule from given original capsule and re-encryption key
     * @param capsuleOriginal
     * @param reEncryptionKey
     * @return
     */
    Capsule get_re_encryption_capsule(Capsule& capsuleOriginal, ReEncryptionKey& reEncryptionKey);

    /**
     * \brief Decapsulating given capsule with provided private key
     * @param re_encrypted_capsule
     * @param privateKey
     * @return
     */
    std::vector<char> decapsulate_re_encrypted(Capsule& re_encrypted_capsule, PrivateKey& privateKey);
  };

}

#endif
