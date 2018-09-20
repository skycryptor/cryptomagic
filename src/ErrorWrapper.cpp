#include "ErrorWrapper.h"

namespace SkyCryptor {

bool ErrorWrapper::hasError() {
  return has_error;
}

std::string ErrorWrapper::getErrorMessage() {
  return error_message;
}

int ErrorWrapper::getErrorCode() {
  return error_code;
}

void ErrorWrapper::setOpenSSLErrorMessage() {
  // TODO: NEED RE-DESIGN ERROR REPORTING!!!
  // openssl_error_code = ERR_get_error();
  // error_message = string(ERR_error_string(openssl_error_code, NULL));
}

void ErrorWrapper::setOpenSSLError(int code) {
  // setting message
  setOpenSSLErrorMessage();
  has_error = true;
  error_code = code;
}

void ErrorWrapper::setFromError(const ErrorWrapper& err) {
  error_code = err.error_code;
  has_error = err.has_error;
  openssl_error_code = err.openssl_error_code;
  error_message = err.error_message;
}

} // namespace SkyCryptor
