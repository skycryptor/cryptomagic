//
// Created by Tigran on 7/4/18.
//

#ifndef CRYPTOMAIC_POINTRAW_H
#define CRYPTOMAIC_POINTRAW_H

#include "openssl/ec.h"

namespace SkyCryptor {

  class PointRaw {
    // Raw pointer for OpenSSL object
    EC_POINT *ec_point = nullptr;
   public:
    PointRaw() = default;
    ~PointRaw();

    EC_POINT *get_ec_point();
    void set_ec_point(EC_POINT *p);
  };

}

#endif //CRYPTOMAIC_POINTRAW_H
