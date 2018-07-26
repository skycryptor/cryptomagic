//
// Created by Tigran on 7/6/18.
//

#include "CryptoMagic_C.h"
#include "CryptoMagic.h"
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace SkyCryptor;

void cryptomagic_init() {
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
}

void * cryptomagic_new() {
  auto cm = new CryptoMagic();
  return (void*) cm;
}

void cryptomagic_clear(void *cm_ptr) {
  auto cm = (CryptoMagic*) cm_ptr;
  delete cm;
}

void *cryptomagic_generate_private_key(void *cm_ptr) {
  auto cm = (CryptoMagic*) cm_ptr;
  return new PrivateKey(PrivateKey::generate(cm->getContext()));
}

void cryptomagic_private_key_free(void *private_key_ptr) {
  auto sk = (PrivateKey*) private_key_ptr;
  delete sk;
}

void *cryptomagic_get_public_key(void *private_key_ptr) {
  auto sk = (PrivateKey*) private_key_ptr;
  return new PublicKey(sk->get_publicKey());
}

void cryptomagic_public_key_free(void *public_key_ptr) {
  auto pk = (PublicKey*) public_key_ptr;
  delete pk;
}

void *cryptomagic_encapsulate(void *cm_ptr, void *public_key_ptr, char **symmetric_key_out, int *symmetric_key_len) {
  auto cm = (CryptoMagic*) cm_ptr;
  auto pk = (PublicKey*) public_key_ptr;
  vector<char> symmetricKey;
  Capsule c = cm->encapsulate((*pk), symmetricKey);
  *symmetric_key_out = (char*)malloc(symmetricKey.size());
  *symmetric_key_len = (int)symmetricKey.size();
  memcpy(*symmetric_key_out, &symmetricKey[0], symmetricKey.size());
  return new Capsule(c);
}

void cryptomagic_capsule_free(void *capsule_ptr) {
  auto capsule = (Capsule*) capsule_ptr;
  delete capsule;
}

void cryptomagic_decapsulate(void * cm_ptr, void *capsule_ptr, void *private_key_ptr, char **symmetric_key_out, int *symmetric_key_len) {
  auto cm = (CryptoMagic*) cm_ptr;
  auto sk = (PrivateKey*) private_key_ptr;
  auto capsule = (Capsule*) capsule_ptr;
  vector<char> symmetricKey = capsule->isreEncrypted() ?
                              cm->decapsulate_re_encrypted(*capsule, *sk)
                              : cm->decapsulate_original(*capsule, *sk);
  *symmetric_key_out = (char*)malloc(symmetricKey.size());
  *symmetric_key_len = (int)symmetricKey.size();
  memcpy(*symmetric_key_out, &symmetricKey[0], symmetricKey.size());
}

void cryptomagic_private_key_to_bytes(void *private_key_ptr, char **buffer, int *length) {
  auto sk = (PrivateKey*) private_key_ptr;
  auto bytesVec = sk->getBigNumber().toBytes();
  *buffer = (char*)malloc(bytesVec.size());
  *length = bytesVec.size();
  memcpy(*buffer, &bytesVec[0], bytesVec.size());
}

void cryptomagic_public_key_to_bytes(void *public_key_ptr, char **buffer, int *length) {
  auto pk = (PublicKey*) public_key_ptr;
  auto bytesVec = pk->getPoint().toBytes();
  *buffer = (char*)malloc(bytesVec.size());
  *length = bytesVec.size();
  memcpy(*buffer, &bytesVec[0], bytesVec.size());
}

void *cryptomagic_private_key_from_bytes(void * cm_ptr, const char *buffer, int length) {
  auto cm = (CryptoMagic*) cm_ptr;
  auto bn = BigNumber::from_bytes((unsigned char*) buffer, length, cm->getContext());
  return new PrivateKey(bn, cm->getContext());
}

void *cryptomagic_public_key_from_bytes(void *cm_ptr, char *buffer, int length) {
  auto cm = (CryptoMagic*) cm_ptr;
  vector<char> bytesVec(buffer, buffer + length);
  auto point = Point::from_bytes(bytesVec, cm->getContext());
  return new PublicKey(point, cm->getContext());
}

void cryptomagic_capsule_to_bytes(void *capsule, char **buffer, int *length) {
  auto c = (Capsule*) capsule;
  auto capsule_buffer = c->toBytes();
  *buffer = (char*)malloc(capsule_buffer.size());
  *length = capsule_buffer.size();
  memcpy(*buffer, &capsule_buffer[0], capsule_buffer.size());
}

void *cryptomagic_capsule_from_bytes(void * cm_ptr, char *buffer, int length) {
  auto cm = (CryptoMagic*) cm_ptr;
  auto capsule = Capsule::from_bytes(buffer, length, cm->getContext());
  return new Capsule(capsule);
}

void *cryptomagic_get_re_encryption_key(void * cm_ptr, void *skA_ptr, void *pkB_ptr) {
  auto cm = (CryptoMagic*) cm_ptr;
  auto skA = (PrivateKey*) skA_ptr;
  auto pkA = (PublicKey*) pkB_ptr;
  auto rkk = cm->get_re_encryption_key(*skA, *pkA);
  return new ReEncryptionKey(rkk);
}

void *cryptomagic_get_re_encryption_from_bytes(void *cm_ptr, char *buffer, int length) {
  auto cm = (CryptoMagic*) cm_ptr;
  auto rkk = ReEncryptionKey::fromBytes(buffer, length, cm->getContext());
  return new ReEncryptionKey(rkk);
}

void cryptomagic_re_encryption_key_free(void *rkk_ptr) {
  auto rkk = (ReEncryptionKey*) rkk_ptr;
  delete rkk;
}

void *cryptomagic_get_re_encryption_capsule(void *cm_ptr, void *capsule_ptr, void *rkAB_ptr) {
  auto cm = (CryptoMagic*) cm_ptr;
  auto capsule = (Capsule*) capsule_ptr;
  auto rkAB = (ReEncryptionKey*) rkAB_ptr;
  auto re_capsule = cm->get_re_encryption_capsule(*capsule, *rkAB);
  return new Capsule(re_capsule);
}

void cryptomagic_re_encryption_to_bytes(void * rkk_ptr, char **buffer, int *length) {
  auto rkk = (ReEncryptionKey*)rkk_ptr;
  auto bytes_vec = rkk->toBytes();
  *length = bytes_vec.size();
  *buffer = (char*)malloc(*length);
  memcpy(*buffer, &bytes_vec[0], *length);
}
