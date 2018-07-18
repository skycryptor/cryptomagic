//
// Created by Tigran on 7/5/18.
//

#include "ReEncryptionKey.h"
#include <netinet/in.h>
#include "string.h"

namespace SkyCryptor {

  ReEncryptionKey::ReEncryptionKey(const BigNumber &bn, const Point &point) : rk_number(bn), rk_point(point) {
  }

  ReEncryptionKey::ReEncryptionKey(const ReEncryptionKey &rkk) : rk_number(rkk.rk_number), rk_point(rkk.rk_point) {
  }

  BigNumber ReEncryptionKey::get_rk_number() {
    return rk_number;
  }

  Point ReEncryptionKey::get_rk_point() {
    return rk_point;
  }

  Point ReEncryptionKey::operator*(const Point &point) const {
    return point * rk_number;
  }

  vector<char> ReEncryptionKey::toBytes() {
    auto rk_number_bytes = rk_number.toBytes();
    auto rk_number_size = htonl((int)rk_number_bytes.size());
    auto rk_point_bytes = rk_point.toBytes();
    auto rk_point_size = htonl((int)rk_point_bytes.size());
    auto total_vec_len = 4 + rk_number_bytes.size() + 4 + rk_point_bytes.size();
    vector<char> ret(total_vec_len);
    int buffer_index = 0;
    memcpy(&ret[buffer_index], &rk_number_size, 4);
    buffer_index += 4;
    ret.insert(ret.begin() + buffer_index, rk_number_bytes.begin(), rk_number_bytes.end());
    buffer_index += rk_number_bytes.size();

    memcpy(&ret[buffer_index], &rk_point_size, 4);
    buffer_index += 4;
    ret.insert(ret.begin() + buffer_index, rk_point_bytes.begin(), rk_point_bytes.end());
    buffer_index += rk_point_bytes.size();
    return ret;
  }

  ReEncryptionKey ReEncryptionKey::fromBytes(const char *buffer, int length, Context *ctx) {
    int rk_number_size;
    int buffer_index = 0;
    memcpy(&rk_number_size, &buffer[buffer_index], 4);
    buffer_index += 4;
    rk_number_size = ntohl(rk_number_size);
    auto rk_number = BigNumber::from_bytes((unsigned char*)&buffer[buffer_index], rk_number_size, ctx);
    buffer_index += rk_number_size;

    int rk_point_size;
    memcpy(&rk_point_size, &buffer[buffer_index], 4);
    buffer_index += 4;
    rk_point_size = ntohl(rk_point_size);
    auto rk_point = Point::from_bytes(&buffer[buffer_index], ctx);

    return ReEncryptionKey(rk_number, rk_point);
  }

  ReEncryptionKey ReEncryptionKey::fromBytes(vector<char> buffer, Context *ctx) {
    return ReEncryptionKey::fromBytes(&buffer[0], buffer.size(), ctx);
  }
}
