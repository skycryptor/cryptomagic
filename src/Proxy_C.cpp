//
// Created by Tigran on 7/6/18.
//

#include <vector>

#include "Proxy_C.h"
#include "Proxy.h"
#include "ECPoint.h"
#include "ECScalar.h"
#include "cstring"

using namespace SkyCryptor;

void proxylib_init() {
}

void * proxylib_new() {
  auto cm = new Proxy<ECPoint, ECScalar>();
  return (void*) cm;
}

void proxylib_clear(void *cm_ptr) {
  auto cm = (Proxy<ECPoint, ECScalar>*) cm_ptr;
  delete cm;
}

void *proxylib_generate_private_key(void *cm_ptr) {
  return new PrivateKey<ECPoint, ECScalar>(PrivateKey<ECPoint, ECScalar>::generate());
}

void proxylib_private_key_free(void *private_key_ptr) {
  auto sk = (PrivateKey<ECPoint, ECScalar>*) private_key_ptr;
  delete sk;
}

void *proxylib_get_public_key(void *private_key_ptr) {
  auto sk = (PrivateKey<ECPoint, ECScalar>*) private_key_ptr;
  return new PublicKey<ECPoint,ECScalar>(sk->get_public_key());
}

void proxylib_public_key_free(void *public_key_ptr) {
  auto pk = (PublicKey<ECPoint,ECScalar>*) public_key_ptr;
  delete pk;
}

void *proxylib_encapsulate(
    void *cm_ptr, 
    void *public_key_ptr, 
    char **symmetric_key_out, 
    int *symmetric_key_len) {
  auto cm = (Proxy<ECPoint, ECScalar>*) cm_ptr;
  auto pk = (PublicKey<ECPoint,ECScalar>*) public_key_ptr;
  std::vector<char> symmetricKey;
  Capsule<ECPoint, ECScalar> c = cm->encapsulate((*pk), symmetricKey);
  *symmetric_key_out = (char*)malloc(symmetricKey.size());
  *symmetric_key_len = (int)symmetricKey.size();
  memcpy(*symmetric_key_out, &symmetricKey[0], symmetricKey.size());
  return new Capsule<ECPoint, ECScalar>(c);
}

void proxylib_capsule_free(void *capsule_ptr) {
  auto capsule = (Capsule<ECPoint, ECScalar>*) capsule_ptr;
  delete capsule;
}

void proxylib_decapsulate(void * cm_ptr, void *capsule_ptr, void *private_key_ptr, char **symmetric_key_out, int *symmetric_key_len) {
  auto cm = (Proxy<ECPoint, ECScalar>*) cm_ptr;
  auto sk = (PrivateKey<ECPoint, ECScalar>*) private_key_ptr;
  auto capsule = (Capsule<ECPoint, ECScalar>*) capsule_ptr;
  std::vector<char> symmetricKey = capsule->is_re_encrypted() ?
                              cm->decapsulate_re_encrypted(*capsule, *sk)
                              : cm->decapsulate_original(*capsule, *sk);
  *symmetric_key_out = (char*)malloc(symmetricKey.size());
  *symmetric_key_len = (int)symmetricKey.size();
  memcpy(*symmetric_key_out, &symmetricKey[0], symmetricKey.size());
}

void proxylib_private_key_to_bytes(void *private_key_ptr, char **buffer, int *length) {
  auto sk = (PrivateKey<ECPoint, ECScalar>*) private_key_ptr;
  auto bytesVec = sk->get_key_value().to_bytes();
  *buffer = (char*)malloc(bytesVec.size());
  *length = bytesVec.size();
  memcpy(*buffer, &bytesVec[0], bytesVec.size());
}

void proxylib_public_key_to_bytes(void *public_key_ptr, char **buffer, int *length) {
  PublicKey<ECPoint,ECScalar>* pk = (PublicKey<ECPoint,ECScalar>*) public_key_ptr;
  auto bytesVec = pk->get_point().to_bytes();
  *buffer = (char*)malloc(bytesVec.size());
  *length = bytesVec.size();
  memcpy(*buffer, &bytesVec[0], bytesVec.size());
}

void *proxylib_private_key_from_bytes(void * cm_ptr, const char *buffer, int length) {
  auto bn = ECScalar::from_bytes((unsigned char*) buffer, length);
  return new PrivateKey<ECPoint, ECScalar>(bn);
}

void *proxylib_public_key_from_bytes(void *cm_ptr, char *buffer, int length) {
  auto cm = (Proxy<ECPoint, ECScalar>*) cm_ptr;
  std::vector<char> bytesVec(buffer, buffer + length);
  auto point = ECPoint::from_bytes(bytesVec);
  return new PublicKey<ECPoint,ECScalar>(point);
}

void proxylib_capsule_to_bytes(void *capsule, char **buffer, int *length) {
  auto c = (Capsule<ECPoint, ECScalar>*) capsule;
  std::vector<char> capsule_buffer;
  c->to_bytes(capsule_buffer);
  *buffer = (char*)malloc(capsule_buffer.size());
  *length = capsule_buffer.size();
  memcpy(*buffer, &capsule_buffer[0], capsule_buffer.size());
}

void *proxylib_capsule_from_bytes(void * cm_ptr, char *buffer, int length) {
  auto cm = (Proxy<ECPoint, ECScalar>*) cm_ptr;
  auto capsule = Capsule<ECPoint, ECScalar>::from_bytes(buffer, length);
  return new Capsule<ECPoint, ECScalar>(capsule);
}

void *proxylib_get_re_encryption_key(void * cm_ptr, void *skA_ptr, void *pkB_ptr) {
  auto cm = (Proxy<ECPoint, ECScalar>*) cm_ptr;
  auto skA = (PrivateKey<ECPoint, ECScalar>*) skA_ptr;
  auto pkA = (PublicKey<ECPoint,ECScalar>*) pkB_ptr;
  auto rkk = cm->get_re_encryption_key(*skA, *pkA);
  return new ReEncryptionKey<ECPoint, ECScalar>(rkk);
}

void *proxylib_get_re_encryption_from_bytes(void *cm_ptr, char *buffer, int length) {
  auto rkk = ReEncryptionKey<ECPoint, ECScalar>::from_bytes(buffer, length);
  return new ReEncryptionKey<ECPoint, ECScalar>(rkk);
}

void proxylib_re_encryption_key_free(void *rkk_ptr) {
  auto rkk = (ReEncryptionKey<ECPoint, ECScalar>*) rkk_ptr;
  delete rkk;
}

void *proxylib_get_re_encryption_capsule(void *cm_ptr, void *capsule_ptr, void *rkAB_ptr) {
  auto cm = (Proxy<ECPoint, ECScalar>*) cm_ptr;
  auto capsule = (Capsule<ECPoint, ECScalar>*) capsule_ptr;
  auto rkAB = (ReEncryptionKey<ECPoint, ECScalar>*) rkAB_ptr;
  auto re_capsule = cm->get_re_encryption_capsule(*capsule, *rkAB);
  return new Capsule<ECPoint, ECScalar>(re_capsule);
}

void proxylib_re_encryption_to_bytes(void * rkk_ptr, char **buffer, int *length) {
  auto rkk = (ReEncryptionKey<ECPoint, ECScalar>*)rkk_ptr;
  auto bytes_vec = rkk->to_bytes();
  *length = bytes_vec.size();
  *buffer = (char*)malloc(*length);
  memcpy(*buffer, &bytes_vec[0], *length);
}

