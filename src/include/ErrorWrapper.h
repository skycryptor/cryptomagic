//
// Created by Tigran on 6/25/18.
//

#ifndef _CRYPTOMAGIC_ERROR_WRAPPER_H__
#define _CRYPTOMAGIC_ERROR_WRAPPER_H__

#include <string>

namespace SkyCryptor {

class ErrorWrapper {
public:

  ErrorWrapper() = default;
  virtual ~ErrorWrapper() = default;

  // Checking if we have an error or not
  bool hasError();

  // Getting error message
  std::string getErrorMessage();

  // Getting error code
  int getErrorCode();

protected:

  // Setting las error from OpenSSL
  void setOpenSSLErrorMessage();

  // Setting error from given CryptoMagic code and OpenSSL message
  void setOpenSSLError(int code);

  // Setting error parameters from another error extended object
  void setFromError(const ErrorWrapper& err);

protected:

  bool has_error = false;
  std::string error_message = "";
  int error_code = 0;
  unsigned long openssl_error_code = 0;

};

}

#endif //_CRYPTOMAGIC_ERROR_WRAPPER_H__
