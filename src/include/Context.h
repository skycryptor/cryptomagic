//
// Created by Tigran on 6/21/18.
//

#ifndef CRYPTOMAIC_CONTEXT_H
#define CRYPTOMAIC_CONTEXT_H

#include <string>
#include <openssl/ec.h>

using namespace std;

namespace SkyCryptor {

  /**
   * \brief Context is defining main context for cryptographic operations and configurations
   * Each CryptoMagic entry point object should contain context for having
   * consistent crypto operations configurations and algorithm definitions
   */
  class Context {
   private:
    /// Keeping current elliptic curve name as a context
    string elliptic_curve_name;
    /// EC NID from OpenSSL definitions
    int ec_nid = 0;
    /// Making EC group from OpenSSL
    EC_GROUP *ec_group = nullptr;

    /// Defining key length for using it for functions like KDF
    unsigned int key_length = 128;
    /// Iteration number for crypto functions like KDF
    unsigned int iteration_count = 1000;

   public:
    /**
     * \brief Defining context from given Elliptic curve name
     * @param ec_name
     */
    explicit Context(const char * ec_name);
    ~Context();

    /**
     * \brief Making default Context from defined EC name
     * @return
     */
    static Context getDefault();

    /**
     * \brief Getting EC Name as a string
     * @return
     */
    string get_elliptic_curve_name();

    /**
     * \brief Getting EC NID from OpenSSL numerical definition
     * @return
     */
    int get_ec_nid();

    /**
     * \brief Getting raw pointer for EC group from OpenSSL definition
     * @return
     */
    EC_GROUP *get_ec_group();

    /**
     * \brief Getting key length
     * @return
     */
    unsigned int get_key_length();

    /**
     * \brief Setting key length
     * @param len
     */
    void set_key_length(unsigned int len);

    /**
     * Getting iteration count for crypto operations
     * @return
     */
    unsigned int get_iteration_count();

    /**
     * Setting iteration count for crypto operations
     * @return
     */
    void get_iteration_count(unsigned int iter);
  };

}

#endif //CRYPTOMAIC_CONTEXT_H
