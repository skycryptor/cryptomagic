//
// Created by Tigran on 7/5/18.
//

#include <netinet/in.h>
#include <cstring>
#include <vector>

#include "ReEncryptionKey.h"

namespace SkyCryptor {

template<class POINT_TYPE, class NUMBER_TYPE>
ReEncryptionKey<POINT_TYPE, NUMBER_TYPE>::ReEncryptionKey(
    const NUMBER_TYPE& rk_number, const POINT_TYPE& rk_point) 
  : rk_number_(rk_number)
  , rk_point_(rk_point) 
{
}

template<class POINT_TYPE, class NUMBER_TYPE>
const NUMBER_TYPE& ReEncryptionKey<POINT_TYPE, NUMBER_TYPE>::get_rk_number() const {
  return rk_number_;
}

template<class POINT_TYPE, class NUMBER_TYPE>
const POINT_TYPE& ReEncryptionKey<POINT_TYPE, NUMBER_TYPE>::get_rk_point() const {
  return rk_point_;
}

template<class POINT_TYPE, class NUMBER_TYPE>
std::vector<char> ReEncryptionKey<POINT_TYPE, NUMBER_TYPE>::to_bytes() const {
  auto rk_number_bytes = rk_number_.to_bytes();
  auto rk_number_size = htonl((int)rk_number_bytes.size());
  auto rk_point_bytes = rk_point_.to_bytes();
  auto rk_point_size = htonl((int)rk_point_bytes.size());
  auto total_vec_len = 4 + rk_number_bytes.size() + 4 + rk_point_bytes.size();
  std::vector<char> ret(total_vec_len);
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

template<class POINT_TYPE, class NUMBER_TYPE>
ReEncryptionKey<POINT_TYPE, NUMBER_TYPE> ReEncryptionKey<POINT_TYPE, NUMBER_TYPE>::from_bytes(
    const char *buffer, int length) {
  int rk_number_size;
  int buffer_index = 0;
  memcpy(&rk_number_size, &buffer[buffer_index], 4);
  buffer_index += 4;
  rk_number_size = ntohl(rk_number_size);
  auto rk_number = NUMBER_TYPE::from_bytes(
      (unsigned char*)&buffer[buffer_index], rk_number_size);
  buffer_index += rk_number_size;

  int rk_point_size;
  memcpy(&rk_point_size, &buffer[buffer_index], 4);
  buffer_index += 4;
  rk_point_size = ntohl(rk_point_size);
  auto rk_point = POINT_TYPE::from_bytes(&buffer[buffer_index], length);

  return ReEncryptionKey(rk_number, rk_point);
}

template<class POINT_TYPE, class NUMBER_TYPE>
ReEncryptionKey<POINT_TYPE, NUMBER_TYPE> ReEncryptionKey<POINT_TYPE, NUMBER_TYPE>::from_bytes(
      const std::vector<char>& buffer) {
  return ReEncryptionKey<POINT_TYPE, NUMBER_TYPE>::from_bytes(&buffer[0], buffer.size());
}

} // namespace SkyCryptor
