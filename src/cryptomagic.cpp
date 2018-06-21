#include "cryptomagic.h"

namespace CryptoMagic {

  CryptoMagic::CryptoMagic(CMContext ctx) {
    context = ctx;
  }

  CMContext *CryptoMagic::CryptoMagic::getContext() {
    return &context;
  }

  void CryptoMagic::setContext(CMContext ctx) {
    context = ctx;
  }
}
