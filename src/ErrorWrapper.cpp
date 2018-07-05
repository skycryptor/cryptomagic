//
// Created by Tigran on 6/25/18.
//

#include <openssl/err.h>
#include "ErrorWrapper.h"

namespace SkyCryptor {

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
    has_error = true;
    error_code = code;
  }

  void ErrorWrapper::setFromError(ErrorWrapper &err) {
    error_code = err.error_code;
    has_error = err.has_error;
    openssl_error_code = err.openssl_error_code;
    error_message = err.error_message;
  }

}