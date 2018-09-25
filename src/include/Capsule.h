#ifndef _PROXYLIB_CAPSULE_H__
#define _PROXYLIB_CAPSULE_H__

namespace SkyCryptor {

/**
 * \brief Combination of parameters as a definition for cryptographic capsule
 * Each capsule contains E(POINT_TYPE), V(POINT_TYPE), s(NUMBER_TYPE)
 */
template<class POINT_TYPE, class NUMBER_TYPE>
class Capsule {
public:

  /**
   * \brief Making capsule with given particles
   * @param E
   * @param V
   * @param S
   */
  Capsule(const POINT_TYPE& E, 
          const POINT_TYPE& V, 
          const NUMBER_TYPE& S, 
          bool is_re_encripted = false);

  /**
   * \brief Making capsule with particles and public key to be encoded with it
   * @param E
   * @param V
   * @param S
   * @param XG
   */
  Capsule(const POINT_TYPE& E, 
          const POINT_TYPE& V, 
          const NUMBER_TYPE& S, 
          const POINT_TYPE& XG, 
          bool is_re_encripted = false);

  /**
   * \brief Copy constructor from another capsule
   * @param other
   */
  Capsule(const Capsule& other);
  ~Capsule() = default;

  /**
   * Getting particle E as a POINT_TYPE
   * @return
   */
  const POINT_TYPE& get_E() const;

  /**
   * Getting particle V as a POINT_TYPE
   * @return
   */
  const POINT_TYPE& get_V() const;

  /**
   * Getting particle S as a NUMBER_TYPE
   * @return
   */
  const NUMBER_TYPE& get_S() const;

  /**
   * Getting particle XG
   * @return
   */
  const POINT_TYPE& get_XG() const;

  /**
   * \brief Setting capsule as re-encryption capsule
   */
  void set_re_encrypted();

  /**
   * \brief Checking if we have re-encryption capsule or not
   * @return
   */
  bool is_re_encrypted() const;

  /**
   * \brief Serializing capsule to bytes
   * \param[out] bytes_out - Serialized byte array of current capsule. 
   * @return
   */
  void to_bytes(std::vector<char>& bytes_out) const;

  /**
   * \brief Getting Capsule from encoded bytes
   * @param buffer
   * @param length
   * @return
   */
  static Capsule<POINT_TYPE, NUMBER_TYPE> from_bytes(const char *buffer, int length);
  static Capsule<POINT_TYPE, NUMBER_TYPE> from_bytes(const std::vector<char>& buffer);

private:

  /// Defining Capsule particles
  POINT_TYPE E_;
  POINT_TYPE V_;
  NUMBER_TYPE S_;
  POINT_TYPE XG_;

  bool re_encrypted_;
};

} // namespace SkyCryptor

// Include template function implementations.
#include "Capsule.hpp"

#endif //_PROXYLIB_CAPSULE_H__
