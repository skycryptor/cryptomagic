//
// Created by Tigran on 7/6/18.
//

#include "CryptoMagic_C.h"
#include "CryptoMagic.h"

using namespace SkyCryptor;

void cryptomagic_init() {
  // TODO: probably make some OpenSSL init functions or something similar
}

void * cryptomagic_new() {
  auto cm = new CryptoMagic();
  return (void*) cm;
}

void cryptomagic_clear(void *cm_ptr) {
  auto cm = (CryptoMagic*) cm_ptr;
  delete cm;
}