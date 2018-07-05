#ifndef CRYPTOMAGIC_CRYPTOMAGIC_H
#define CRYPTOMAGIC_CRYPTOMAGIC_H

#include "Context.h"
#include "BigNumber.h"
#include "Point.h"
#include "Capsule.h"
#include "PublicKey.h"

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
    Capsule encapsulate(PublicKey& pk, string& symmetric_key_out) const;
  };

}

#endif