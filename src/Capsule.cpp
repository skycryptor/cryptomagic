//
// Created by Tigran on 7/4/18.
//

#include <netinet/in.h>
#include <cstring>
#include <map>
#include <iostream>
#include "Capsule.h"

namespace SkyCryptor {

  Capsule::Capsule(Point& E, Point& V, BigNumber& S, Context *ctx)
    : particleE(E), particleV(V), particleS(S), particleXG(ctx) {
    context = ctx;
  }

  Capsule::Capsule(Point &E, Point &V, BigNumber &S, Point &XG, Context *ctx, bool isReEncryption)
    : particleE(E), particleV(V), particleS(S), particleXG(XG) {
    context = ctx;
    reEncrypted = isReEncryption;
  }

  Capsule::Capsule(const Capsule &other)
    : particleE(other.particleE), particleV(other.particleV), particleXG(other.particleXG), particleS(other.particleS) {
    context = other.context;
    reEncrypted = other.reEncrypted;
  }

  Point Capsule::get_particleE() const {
    return particleE;
  }

  Point Capsule::get_particleV() const {
    return particleV;
  }

  BigNumber Capsule::get_particleS() const {
    return particleS;
  }

  Point Capsule::get_particleXG() const {
    return particleXG;
  }

  void Capsule::setReEncrypted() {
    reEncrypted = true;
  }

  bool Capsule::isreEncrypted() {
    return reEncrypted;
  }

  vector<char> Capsule::toBytes() {
    auto pE = particleE.toBytes();
    auto pE_len = htonl(pE.size());

    auto pXG = particleXG.toBytes();
    auto pV = particleV.toBytes();

    auto pS = particleS.toBytes();
    auto pS_len = htonl(pS.size());

    vector<char> ret(4 + pE.size() + pV.size() + 4 + pS.size() + 1 + pXG.size());
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

    if (!pXG.empty()) {
      ret[mem_index] = (char) 1;
    } else {
      ret[mem_index] = (char) 0;
      mem_index += 1;
      memcpy(&ret[mem_index], &pXG[0], pXG.size());
      mem_index += pXG.size();
    }

    return ret;
  }

  Capsule Capsule::from_bytes(const char *buffer, int length, Context *ctx) {
    const char *tmp = buffer;

    // Getting Particle E
    int point_len;
    memcpy(&point_len, tmp, 4);
    tmp += 4;
    point_len = ntohl(point_len);
    vector<char> pE_buffer(tmp, tmp + point_len);
    auto pE = Point::from_bytes(pE_buffer, ctx);
    tmp += point_len;

    // Getting Particle V
    vector<char> pV_buffer(tmp, tmp + point_len);
    auto pV = Point::from_bytes(pV_buffer, ctx);
    tmp += point_len;

    // Getting Particle S
    int partS_len;
    memcpy(&partS_len, tmp, 4);
    tmp += 4;
    partS_len = ntohl(partS_len);
    auto pS = BigNumber::from_bytes((unsigned char*)tmp, partS_len, ctx);
    tmp += partS_len;

    // Getting boolean for re-encryption indicator
    bool isReEncrypted = *tmp == 1;
    tmp += 1;
    Point pXG(ctx);
    if (isReEncrypted) {
      vector<char> pXG_buffer(tmp, tmp + point_len);
      pXG = Point::from_bytes(pXG_buffer, ctx);
      tmp += point_len;
    }

    return Capsule(pE, pV, pS, pXG, ctx, isReEncrypted);
  }

  Capsule Capsule::from_bytes(vector<char> buffer, Context *ctx) {
    return Capsule::from_bytes(&buffer[0], buffer.size(), ctx);
  }
}
