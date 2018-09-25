//
// Created by Tigran on 7/4/18.
//

#ifndef CRYPTOMAIC_HELPERS_H
#define CRYPTOMAIC_HELPERS_H

#include <string>
#include "Point.h"
#include "Context.h"

using std::string;

namespace SkyCryptor {

/**
 * \brief Running KDF cryptographic function with defined Context and given shared_key Point
 * @param shared_key
 * @return
 */
std::vector<char> KDF(const Context& ctx, const Point& shared_key);

/**
 * \brief Implementing hash function with given byte array parts and crypto context
 * NOTE: byte array list could be N size, all of them would be hashed together
 * @param ctx
 * @param part
 * @param ...
 * @return
 */
std::vector<char> HASH(const Context& ctx, const std::vector<std::vector<char>>& parts);

}

#endif //CRYPTOMAIC_HELPERS_H
