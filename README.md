# Skycryptor for C++
Skycryptor, SAS, is a Paris, France, based cybersecurity company and a graduate of the Techstars Paris 2017 accelerator program.

We provide "Encryption & Key Management" service in operation with open sourced libraries with support for Javascript, Python, Go, Rust, Java, C++ languages.

Our goal is to enable developers to build ’privacy by design’, end-to-end secured applications, without any technical complexities.

This C++ library is our main low level algorithmic implementation, which is embedded in all our other SDK libraries and web services.

# C Interface
Most of the programming languages and low level API's don't have C++ integration capability, so for being platform and programing
language agnostic, we are providing low level C interface for using Skycryptor's encryption on any platform and with any programming language.

[`inculde/CryptoMagic_C.h`](inculde/CryptoMagic_C.h) is a single header file which contains all our API functions for having fully functional
proxy re-encryption and key management system for your application.

```cpp
#include "CryptoMagic_C.h"
....
....
cryptomagic_init();
void * cm = cryptomagic_new();
.....
.....
cryptomagic_clean(cm);
```  
As a low level interface, we are providing memory allocation and de-allocation functions for each object.

# Building
For building project as a static library, you will need to `install OpenSSL`, because currently we are using OpenSSL as a cryptographic backend.
```bash
mkdir build
cd build && cmake ..
make
```
