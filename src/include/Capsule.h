//
// Created by Tigran on 7/4/18.
//

#ifndef CRYPTOMAIC_CAPSULE_H
#define CRYPTOMAIC_CAPSULE_H

#include "Point.h"

namespace SkyCryptor {

/**
 * \brief Combination of parameters as a definition for cryptographic capsule
 * Each capsule contains E(Point), V(Point), s(BigNumber)
 */
class Capsule {
public:

  /**
   * \brief Making capsule with given particles
   * @param E
   * @param V
   * @param S
   * @param ctx
   */
  Capsule(const Point& E, 
          const Point& V, 
          const BigNumber& S, 
          std::weak_ptr<Context> ctx,
          bool isReEncription = false);

  /**
   * \brief Making capsule with particles and public key to be encoded with it
   * @param E
   * @param V
   * @param S
   * @param XG
   * @param ctx
   */
  Capsule(const Point& E, 
          const Point& V, 
          const BigNumber& S, 
          const Point& XG, 
          std::weak_ptr<Context> ctx, 
          bool isReEncription = false);

  /**
   * \brief Copy constructor from another capsule
   * @param other
   */
  Capsule(const Capsule& other);
  ~Capsule() = default;

  /**
   * Getting particle E as a Point
   * @return
   */
  const Point& get_particle_E() const;

  /**
   * Getting particle V as a Point
   * @return
   */
  const Point& get_particle_V() const;

  /**
   * Getting particle S as a BigNumber
   * @return
   */
  const BigNumber get_particle_S() const;

  /**
   * Getting particle XG
   * @return
   */
  const Point get_particle_XG() const;

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
  void to_byte_array(std::vector<char>& bytes_out) const;

  /**
   * \brief Getting Capsule from encoded bytes
   * @param buffer
   * @param length
   * @param ctx
   * @return
   */
  static Capsule from_bytes(const char *buffer, int length, Context *ctx);
  static Capsule from_bytes(const std::vector<char>& buffer, Context *ctx);

private:

  /// Defining Capsule particles
  Point E_;
  Point V_;
  BigNumber S_;
  Point XG_;

  /// Keeping crypto context available for capsule
  /// NOTE: this class is not taking responsibility for cleaning up this pointer
  std::weak_ptr<Context> context;

  bool re_encrypted_ = false;

};

} // namespace SkyCryptor

#endif //CRYPTOMAIC_CAPSULE_H
