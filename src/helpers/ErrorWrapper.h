//
// Created by Tigran on 6/25/18.
//

#ifndef CRYPTOMAIC_ERRORWRAPPER_H
#define CRYPTOMAIC_ERRORWRAPPER_H

#include "string"

using namespace std;

namespace CryptoMagic {

  class ErrorWrapper {
   protected:
    bool has_error = false;
    string error_message = "";
    int error_code = 0;
    unsigned long openssl_error_code = 0;

    // Setting las error from OpenSSL
    void setOpenSSLErrorMessage();

    // Setting error from given CryptoMagic code and OpenSSL message
    void setOpenSSLError(int code);

   public:
    ErrorWrapper() = default;
    virtual ~ErrorWrapper() = default;

    // Checking if we have an error or not
    bool hasError();
    // Getting error message
    string getErrorMessage();
    // Getting error code
    int getErrorCode();
  };

}

#endif //CRYPTOMAIC_ERRORWRAPPER_H
