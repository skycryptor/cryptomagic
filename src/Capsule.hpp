//
// Created by Tigran on 7/4/18.
//

#include <netinet/in.h>
#include <cstring>
#include <map>
#include <iostream>

#include "NUMBER_TYPE.h"
#include "Capsule.h"

namespace SkyCryptor {

template<class POINT_TYPE, class NUMBER_TYPE>
Capsule::Capsule(POINT_TYPE& E, POINT_TYPE& V, NUMBER_TYPE& S)
  : E_(E)
  , V_(V)
  , S_(S)
  , re_encrypted_(false)
{

}

template<class POINT_TYPE, class NUMBER_TYPE>
Capsule::Capsule(
    const POINT_TYPE& E, 
    const POINT_TYPE& V, 
    const NUMBER_TYPE& S, 
    const POINT_TYPE& XG,
    bool is_re_encrypted)
    : E(E)
    , V(V)
    , S(S)
    , XG(XG) 
    , re_encrypted_(is_re_encrypted)
{

}

template<class POINT_TYPE, class NUMBER_TYPE>
Capsule::Capsule(const Capsule &other)
  : E(other.E)
  , V(other.V)
  , XG(other.XG)
  , S(other.S)
  , re_encrypted_(other.re_encrypted_)
{
}

template<class POINT_TYPE, class NUMBER_TYPE>
const POINT_TYPE& Capsule::get_E() const {
  return E;
}

template<class POINT_TYPE, class NUMBER_TYPE>
const POINT_TYPE& Capsule::get_V() const {
  return V;
}

template<class POINT_TYPE, class NUMBER_TYPE>
const NUMBER_TYPE& Capsule::get_S() const {
  return S;
}

template<class POINT_TYPE, class NUMBER_TYPE>
const POINT_TYPE& Capsule::get_XG() const {
  return XG;
}

template<class POINT_TYPE, class NUMBER_TYPE>
void Capsule::set_re_encrypted() {
  re_encrypted_ = true;
}

template<class POINT_TYPE, class NUMBER_TYPE>
bool Capsule::is_re_encrypted() const {
  return re_encrypted_;
}

template<class POINT_TYPE, class NUMBER_TYPE>
std::vector<char> Capsule::to_bytes() const {
  auto pE = E.to_bytes();
  auto pE_len = htonl(pE.size());

  auto pXG = XG.to_bytes();
  auto pV = V.to_bytes();

  auto pS = S.to_bytes();
  auto pS_len = htonl(pS.size());

  std::vector<char> ret(4 + pE.size() + pV.size() + 4 + pS.size() + 1 + pXG.size());
  int mem_index = 0;

  memcpy(&ret[mem_index], &pE_len, 4);
  mem_index += 4;

  memcpy(&ret[mem_index], &pE[0], pE.size());
  mem_index += pE.size();

  memcpy(&ret[mem_index], &pV[0], pV.size());
  mem_index += pV.size();

  memcpy(&ret[mem_index], &pS_len, 4);
  mem_index += 4;
  memcpy(&ret[mem_index], &pS[0], pS.size());
  mem_index += pS.size();

  if (!reEncrypted) {
    ret[mem_index] = (char) 0;
  } else {
    ret[mem_index] = (char) 1;
    mem_index += 1;
    memcpy(&ret[mem_index], &pXG[0], pXG.size());
    mem_index += pXG.size();
  }

  return ret;
}

template<class POINT_TYPE, class NUMBER_TYPE>
Capsule Capsule::from_bytes(const char *buffer, int length) {
  const char *tmp = buffer;

  // Getting Particle E
  int point_len;
  memcpy(&point_len, tmp, 4);
  tmp += 4;
  point_len = ntohl(point_len);
  std::vector<char> pE_buffer(tmp, tmp + point_len);
  auto pE = POINT_TYPE::from_bytes(pE_buffer);
  tmp += point_len;

  // Getting Particle V
  std::vector<char> pV_buffer(tmp, tmp + point_len);
  auto pV = POINT_TYPE::from_bytes(pV_buffer);
  tmp += point_len;

  // Getting Particle S
  int partS_len;
  memcpy(&partS_len, tmp, 4);
  tmp += 4;
  partS_len = ntohl(partS_len);
  auto pS = NUMBER_TYPE::from_bytes((unsigned char*)tmp, partS_len);
  tmp += partS_len;

  // Getting boolean for re-encryption indicator
  bool is_re_encrypted = *tmp == 1;
  tmp += 1;
  POINT_TYPE pXG;
  if (is_re_encrypted) {
    std::vector<char> pXG_buffer(tmp, tmp + point_len);
    pXG = POINT_TYPE::from_bytes(pXG_buffer);
    tmp += point_len;
  }

  return Capsule(pE, pV, pS, pXG, is_re_encrypted);
}

template<class POINT_TYPE, class NUMBER_TYPE>
Capsule Capsule::from_bytes(const std::vector<char>& buffer) {
  return Capsule::from_bytes(&buffer[0], buffer.size());
}

} // namespace SkyCryptor
