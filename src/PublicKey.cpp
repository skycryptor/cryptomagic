//
// Created by Tigran on 7/4/18.
//

#include "PublicKey.h"

namespace SkyCryptor {

PublicKey::PublicKey(const Point &ec_point, Context *ctx)
    : point_(ctx)
    , context_(ctx)
{
}

PublicKey::PublicKey(std::weak_ptr<Context> ctx) 
    : point_(*ctx) // Martun: this will generate a random point???
    , context_(ctx)
{
}

bool PublicKey::operator==(const PublicKey &publicKey) const {
  return point == publicKey;
}

const Point& PublicKey::get_point() const {
  return point;
}

PublicKey::PublicKey(const PublicKey &pk) {
  context = pk.context;
  point = pk.point;
}

} // namespace SkyCryptor
