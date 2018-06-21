#ifndef CRYPTOMAGIC_CRYPTOMAGIC_H
#define CRYPTOMAGIC_CRYPTOMAGIC_H

#include "context.h"

namespace CryptoMagic {

  /**
   * CryptoMagic base class for handling library crypto operations and main functionality
   * Each initialized CryptoMagic object should contain CMContext which will define
   * base parameters for crypto operations and configurations
   */
  class CryptoMagic {
   private:
    // defining main context for all cryptographic operations inside current CryptoMagic object
    CMContext context;

   public:
    CryptoMagic(CMContext ctx);
    ~CryptoMagic() = default;

    // Getting current defined context as a reference
    CMContext *getContext();
    // Setting context for this CryptoMagic object
    // NOTE: crypto operations will start receiving this context parameters after calling this setter function
    void setContext(CMContext ctx);
  };

}

#endif