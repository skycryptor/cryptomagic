//
// Created by Tigran on 7/4/18.
//

#include <netinet/in.h>
#include <cstring>
#include <map>
#include "Capsule.h"

namespace SkyCryptor {

  Capsule::Capsule(Point& E, Point& V, BigNumber& S, Context *ctx)
    : particleE(E), particleV(V), particleS(S), particleXG(ctx) {
    context = ctx;
  }

  Capsule::Capsule(Point &E, Point &V, BigNumber &S, Point &XG, Context *ctx, bool isReEncription)
    : particleE(E), particleV(V), particleS(S), particleXG(XG) {
    context = ctx;
    reEncription = isReEncription;
  }

  Capsule::Capsule(const Capsule &other)
    : particleE(other.particleE), particleV(other.particleV), particleXG(other.particleXG), particleS(other.particleS) {
    context = other.context;
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

  void Capsule::setReEncription() {
    reEncription = true;
  }

  bool Capsule::isReEncryption() {
    return reEncription;
  }

  vector<char> Capsule::toBytes() {
    auto pE = particleE.toBytes();
    auto pE_len = htonl(pE.size());

    auto pV = particleV.toBytes();
    auto pV_len = htonl(pV.size());

    auto pS = particleS.toBytes();
    auto pS_len = htonl(pS.size());

    auto pXG = particleXG.toBytes();
    auto pXG_len = htonl(pXG.size());
    vector<char> ret(1 + pE.size() +  4 + pV.size() + 4 + pS.size() + 4 + pXG.size() + 4);
    int mem_index = 0;
    // 1 byte for keeping ReEncryption boolean
    ret[mem_index] = (char) (reEncription ? 1 : 0);
    mem_index += 1;
    memcpy(&ret[mem_index], &pE_len, 4);
    mem_index += 4;
    memcpy(&ret[mem_index], &pE[0], 4);
    mem_index += pE.size();

    memcpy(&ret[mem_index], &pV_len, 4);
    mem_index += 4;
    memcpy(&ret[mem_index], &pV[0], 4);
    mem_index += pV.size();

    memcpy(&ret[mem_index], &pS_len, 4);
    mem_index += 4;
    memcpy(&ret[mem_index], &pS[0], 4);
    mem_index += pS.size();

    memcpy(&ret[mem_index], &pXG_len, 4);
    mem_index += 4;
    memcpy(&ret[mem_index], &pXG[0], 4);
    mem_index += pXG.size();

    return ret;
  }

  Capsule Capsule::from_bytes(const char *buffer, int length, Context *ctx) {
    const char *tmp = buffer;

    // Getting boolean for re-encryption indicator
    bool isReEncrypted = tmp[0] == 1;
    tmp += 1;

    // Getting Particle E
    int partE_len;
    memcpy(&partE_len, tmp, 4);
    tmp += 4;
    partE_len = ntohl(partE_len);
    vector<char> pE_buffer(tmp, tmp + partE_len);
    auto pE = Point::from_bytes(pE_buffer, ctx);
    tmp += partE_len;

    // Getting Particle V
    int partV_len;
    memcpy(&partV_len, tmp, 4);
    tmp += 4;
    partV_len = ntohl(partV_len);
    vector<char> pV_buffer(tmp, tmp + partV_len);
    auto pV = Point::from_bytes(pV_buffer, ctx);
    tmp += partV_len;

    // Getting Particle S
    int partS_len;
    memcpy(&partS_len, tmp, 4);
    tmp += 4;
    partS_len = ntohl(partS_len);
    auto pS = BigNumber::from_bytes((unsigned char*)tmp, partS_len, ctx);
    tmp += partS_len;

    // Getting Particle XG
    int partXG_len;
    memcpy(&partXG_len, tmp, 4);
    tmp += 4;
    partXG_len = ntohl(partXG_len);
    vector<char> pXG_buffer(tmp, tmp + partXG_len);
    auto pXG = Point::from_bytes(pXG_buffer, ctx);
    tmp += partXG_len;

    return Capsule(pE, pV, pS, pXG, ctx, isReEncrypted);
  }
}
