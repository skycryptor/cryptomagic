#include "ProxyLibException.h"

namespace SkyCryptor {

ProxyLibException::ProxyLibException(const char* message)
  : error_message_(message)
{

}

ProxyLibException::ProxyLibException(const std::string& message)
  : error_message_(message)
{

}

ProxyLibException::~ProxyLibException() throw () 
{
}

const char* ProxyLibException::what() const throw (){
   return error_message_.c_str();
}

const std::string& ProxyLibException::getErrorMessage() const {
  return error_message_;
}

int ProxyLibException::getErrorCode() {
  return error_code_;
}

void ProxyLibException::setOpenSSLError(int code) {
  // setting message
  error_code_ = code;
}

} // namespace SkyCryptor
