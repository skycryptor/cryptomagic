#include "cryptomagic.h"

namespace CryptoMagic {

  CryptoMagic::CryptoMagic(Context ctx) {
    context = ctx;
  }

Context *CryptoMagic::CryptoMagic::getContext() {
    return &context;
  }

  void CryptoMagic::setContext(Context ctx) {
    context = ctx;
  }
}
