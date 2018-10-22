#ifndef _CRYPTOMAGIC_ERROR_WRAPPER_H__
#define _CRYPTOMAGIC_ERROR_WRAPPER_H__

#include <string>

namespace SkyCryptor {

class ProxyLibException : public std::exception {
public:

  /** Constructor (C strings).
   *  @param message C-style string error message.
   *                 The string contents are copied upon construction.
   *                 Hence, responsibility for deleting the char* lies
   *                 with the caller. 
   */
  explicit ProxyLibException(const char* message);

  /** Constructor (C++ STL strings).
   *  @param message The error message.
   */
  explicit ProxyLibException(const std::string& message);

  /** Destructor.
   * Virtual to allow for subclassing.
   */
  virtual ~ProxyLibException() throw ();

  /** Returns a pointer to the (constant) error description.
   *  @return A pointer to a const char*. The underlying memory
   *          is in posession of the Exception object. Callers must
   *          not attempt to free the memory.
   */
  virtual const char* what() const throw ();

  // Getting error code
  int getErrorCode();

  // Setting error from given ProxyLib code and OpenSSL message
  void setOpenSSLError(int code);

  const std::string& getErrorMessage() const;

protected:

  int error_code_ = 0;
  std::string error_message_;
  unsigned long openssl_error_code_ = 0;

};

}

#endif //_CRYPTOMAGIC_ERROR_WRAPPER_H__
