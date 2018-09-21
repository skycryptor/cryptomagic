//
// Created by Tigran on 7/6/18.
//

#include <vector>

#include "Proxy_C.h"
#include "Proxy.h"
#include "Point.h"
#include "BigNumber.h"
#include "cstring"

using namespace SkyCryptor;

void proxylib_init() {
}

void * proxylib_new() {
  auto cm = new Proxy<Point, BigNumber>();
  return (void*) cm;
}

void proxylib_clear(void *cm_ptr) {
  auto cm = (Proxy<Point, BigNumber>*) cm_ptr;
  delete cm;
}

void *proxylib_generate_private_key(void *cm_ptr) {
  auto cm = (Proxy<Point, BigNumber>*) cm_ptr;
  return new PrivateKey<BigNumber>(PrivateKey<BigNumber>::generate(cm->getContext()));
}

void proxylib_private_key_free(void *private_key_ptr) {
  auto sk = (PrivateKey<BigNumber>*) private_key_ptr;
  delete sk;
}

void *proxylib_get_public_key(void *private_key_ptr) {
  auto sk = (PrivateKey<BigNumber>*) private_key_ptr;
  return new PublicKey<Point,BigNumber>(sk->get_public_key());
}

void proxylib_public_key_free(void *public_key_ptr) {
  auto pk = (PublicKey<Point,BigNumber>*) public_key_ptr;
  delete pk;
}

void *proxylib_encapsulate(
    void *cm_ptr, 
    void *public_key_ptr, 
    char **symmetric_key_out, 
    int *symmetric_key_len) {
  auto cm = (Proxy<Point, BigNumber>*) cm_ptr;
  auto pk = (PublicKey<Point,BigNumber>*) public_key_ptr;
  std::vector<char> symmetricKey;
  Capsule<Point, BigNumber> c = cm->encapsulate((*pk), symmetricKey);
  *symmetric_key_out = (char*)malloc(symmetricKey.size());
  *symmetric_key_len = (int)symmetricKey.size();
  memcpy(*symmetric_key_out, &symmetricKey[0], symmetricKey.size());
  return new Capsule<Point, BigNumber>(c);
}

void proxylib_capsule_free(void *capsule_ptr) {
  auto capsule = (Capsule<Point, BigNumber>*) capsule_ptr;
  delete capsule;
}

void proxylib_decapsulate(void * cm_ptr, void *capsule_ptr, void *private_key_ptr, char **symmetric_key_out, int *symmetric_key_len) {
  auto cm = (Proxy<Point, BigNumber>*) cm_ptr;
  auto sk = (PrivateKey<BigNumber>*) private_key_ptr;
  auto capsule = (Capsule<Point, BigNumber>*) capsule_ptr;
  std::vector<char> symmetricKey = capsule->is_re_encrypted() ?
                              cm->decapsulate_re_encrypted(*capsule, *sk)
                              : cm->decapsulate_original(*capsule, *sk);
  *symmetric_key_out = (char*)malloc(symmetricKey.size());
  *symmetric_key_len = (int)symmetricKey.size();
  memcpy(*symmetric_key_out, &symmetricKey[0], symmetricKey.size());
}

void proxylib_private_key_to_bytes(void *private_key_ptr, char **buffer, int *length) {
  auto sk = (PrivateKey<BigNumber>*) private_key_ptr;
  auto bytesVec = sk->getBigNumber().to_bytes();
  *buffer = (char*)malloc(bytesVec.size());
  *length = bytesVec.size();
  memcpy(*buffer, &bytesVec[0], bytesVec.size());
}

void proxylib_public_key_to_bytes(void *public_key_ptr, char **buffer, int *length) {
  auto pk = (PublicKey<Point,BigNumber>*) public_key_ptr;
  auto bytesVec = pk->getPoint().to_bytes();
  *buffer = (char*)malloc(bytesVec.size());
  *length = bytesVec.size();
  memcpy(*buffer, &bytesVec[0], bytesVec.size());
}

void *proxylib_private_key_from_bytes(void * cm_ptr, const char *buffer, int length) {
  auto cm = (Proxy<Point, BigNumber>*) cm_ptr;
  auto bn = BigNumber::from_bytes((unsigned char*) buffer, length, cm->getContext());
  return new PrivateKey<BigNumber>(bn, cm->getContext());
}

void *proxylib_public_key_from_bytes(void *cm_ptr, char *buffer, int length) {
  auto cm = (Proxy<Point, BigNumber>*) cm_ptr;
  std::vector<char> bytesVec(buffer, buffer + length);
  auto point = Point::from_bytes(bytesVec);
  return new PublicKey<Point,BigNumber>(point);
}

void proxylib_capsule_to_bytes(void *capsule, char **buffer, int *length) {
  auto c = (Capsule<Point, BigNumber>*) capsule;
  auto capsule_buffer = c->to_bytes();
  *buffer = (char*)malloc(capsule_buffer.size());
  *length = capsule_buffer.size();
  memcpy(*buffer, &capsule_buffer[0], capsule_buffer.size());
}

void *proxylib_capsule_from_bytes(void * cm_ptr, char *buffer, int length) {
  auto cm = (Proxy<Point, BigNumber>*) cm_ptr;
  auto capsule = Capsule<Point, BigNumber>::from_bytes(buffer, length, cm->getContext());
  return new Capsule<Point, BigNumber>(capsule);
}

void *proxylib_get_re_encryption_key(void * cm_ptr, void *skA_ptr, void *pkB_ptr) {
  auto cm = (Proxy<Point, BigNumber>*) cm_ptr;
  auto skA = (PrivateKey<BigNumber>*) skA_ptr;
  auto pkA = (PublicKey<Point,BigNumber>*) pkB_ptr;
  auto rkk = cm->get_re_encryption_key(*skA, *pkA);
  return new ReEncryptionKey<Point, BigNumber>(rkk);
}

void *proxylib_get_re_encryption_from_bytes(void *cm_ptr, char *buffer, int length) {
  auto cm = (Proxy<Point, BigNumber>*) cm_ptr;
  auto rkk = ReEncryptionKey<Point, BigNumber>::from_bytes(buffer, length, cm->getContext());
  return new ReEncryptionKey<Point, BigNumber>(rkk);
}

void proxylib_re_encryption_key_free(void *rkk_ptr) {
  auto rkk = (ReEncryptionKey<Point, BigNumber>*) rkk_ptr;
  delete rkk;
}

void *proxylib_get_re_encryption_capsule(void *cm_ptr, void *capsule_ptr, void *rkAB_ptr) {
  auto cm = (Proxy<Point, BigNumber>*) cm_ptr;
  auto capsule = (Capsule<Point, BigNumber>*) capsule_ptr;
  auto rkAB = (ReEncryptionKey<Point, BigNumber>*) rkAB_ptr;
  auto re_capsule = cm->get_re_encryption_capsule(*capsule, *rkAB);
  return new Capsule<Point, BigNumber>(re_capsule);
}

void proxylib_re_encryption_to_bytes(void * rkk_ptr, char **buffer, int *length) {
  auto rkk = (ReEncryptionKey<Point, BigNumber>*)rkk_ptr;
  auto bytes_vec = rkk->to_bytes();
  *length = bytes_vec.size();
  *buffer = (char*)malloc(*length);
  memcpy(*buffer, &bytes_vec[0], *length);
}

