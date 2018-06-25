//
// Created by Tigran on 6/25/18.
//

#include <openssl/err.h>
#include "ErrorWrapper.h"

namespace CryptoMagic {

  bool ErrorWrapper::hasError() {
    return has_error;
  }

  string ErrorWrapper::getErrorMessage() {
    return error_message;
  }

  int ErrorWrapper::getErrorCode() {
    return error_code;
  }

  void ErrorWrapper::setOpenSSLErrorMessage() {
    openssl_error_code = ERR_get_error();
    error_message = string(ERR_error_string(openssl_error_code, NULL));
  }

  void ErrorWrapper::setOpenSSLError(int code) {
    // setting message
    setOpenSSLErrorMessage();
    this->has_error = true;
    this->error_code = code;
  }

}