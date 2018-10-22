#include "VersionInfo.h"
#include "VersionInfoMap.h"
#include "MBED_TLS_VersionInfo.h"

namespace SkyCryptor {

VersionInfo* VersionInfoMap::get_current_version() {
  MBED_TLS_VersionInfo& version = MBED_TLS_VersionInfo::get_current();
  return &version;
}

} // namespace SkyCryptor

