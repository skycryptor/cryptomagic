#ifndef CRYPTOMAGIC_CRYPTOMAGIC_H
#define CRYPTOMAGIC_CRYPTOMAGIC_H

#include "Context.h"

namespace CryptoMagic {

  /**
   * CryptoMagic base class for handling library crypto operations and main functionality
   * Each initialized CryptoMagic object should contain Context which will define
   * base parameters for crypto operations and configurations
   */
  class CryptoMagic {
   private:
    // defining main context for all cryptographic operations inside current CryptoMagic object
    Context context;

   public:
    CryptoMagic(Context ctx);
    ~CryptoMagic() = default;

    // Getting current defined context as a reference
    Context *getContext();
    // Setting context for this CryptoMagic object
    // NOTE: crypto operations will start receiving this context parameters after calling this setter function
    void setContext(Context ctx);
  };

}

#endif