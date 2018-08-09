//
// Created by Tigran on 6/25/18.
//

#ifndef CRYPTOMAIC_DEFINES_H
#define CRYPTOMAIC_DEFINES_H

#include <mbedtls/ecp.h>

// Defining Error Codes for CryptoMagic
#define ERROR_BIGNUMBER_RANDOM_GENERATION 600
#define ERROR_BIGNUMBER_MUL 601
#define ERROR_BIGNUMBER_ADD 602
#define ERROR_BIGNUMBER_SUBTRACK 603
#define ERROR_BIGNUMBER_MODULUS 604
#define ERROR_POINT_MUL 605
#define ERROR_POINT_ADD 606
#define ERROR_POINT_INVERT 607
#define ERROR_POINT_COPY 608
#define ERROR_INITIALIZING_EC_GROUP_ORDER 609

#define SHA256_DIGEST_LENGTH 32

typedef mbedtls_mpi BIGNUM;
typedef mbedtls_ecp_group EC_GROUP;
typedef mbedtls_ecp_point EC_POINT;

#endif //CRYPTOMAIC_DEFINES_H
