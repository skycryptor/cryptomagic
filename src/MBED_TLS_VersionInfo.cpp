#include "MBED_TLS_VersionInfo.h"

namespace SkyCryptor {

MBED_TLS_VersionInfo::MBED_TLS_VersionInfo(const std::string& elliptic_curve_name, 
                         int32_t group_id, 
                         uint32_t key_length, 
                         uint32_t sha256_iteration_count) 
  : ec_group_(new mbedtls_ecp_group())
  , ec_nid_(group_id)
  , elliptic_curve_name_(elliptic_curve_name)
  , key_length_(key_length)
  , sha256_iteration_count_(sha256_iteration_count)
{
  mbedtls_ecp_group_init(ec_group_.get());
  int res = mbedtls_ecp_group_load(ec_group_.get(), (mbedtls_ecp_group_id)group_id);
  if (res != 0) {
    throw std::runtime_error("Problem with creation of context.");
  }
}


MBED_TLS_VersionInfo::~MBED_TLS_VersionInfo() {
  if (ec_group_ != nullptr) {
    mbedtls_ecp_group_free(ec_group_.get());
  }
}

int32_t MBED_TLS_VersionInfo::get_ec_nid() {
  return ec_nid_;
}

EC_GROUP* MBED_TLS_VersionInfo::get_ec_group() const {
  return ec_group_.get();
}

MBED_TLS_VersionInfo& MBED_TLS_VersionInfo::get_current() {
  static MBED_TLS_VersionInfo ctx("MBEDTLS_ELIPTIC_CURVES", MBEDTLS_ECP_DP_SECP256K1, 128, 1000);
  return ctx;
}

uint32_t MBED_TLS_VersionInfo::get_key_length() const {
  return key_length_;
}

uint32_t MBED_TLS_VersionInfo::get_iteration_count() const {
  return sha256_iteration_count_;
}

const mbedtls_mpi& MBED_TLS_VersionInfo::get_ec_order() const {
  return ec_group_->N;
}

} // namespace SkyCryptor

