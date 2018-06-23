//
// Created by Tigran on 6/23/18.
//

#include "cryptography/BigNumber.h"
#include "iostream"

using namespace CryptoMagic;
using namespace std;

int main() {
  while (true) {
    auto ctx = Context::getDefault();
    auto bn = BigNumber::generate_random(&ctx);
    cout<< bn->toHex() << endl;
    delete bn;
  }
}