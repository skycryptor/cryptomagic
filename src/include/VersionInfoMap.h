#ifndef _VERSION_INFO_MAP__
#define _VERSION_INFO_MAP__

#include "MBED_TLS_VersionInfo.h"

#include "VersionInfo.h"

namespace SkyCryptor {

class VersionInfoMap {
public: 
  static VersionInfo* get_current_version();
};

} // namespace SkyCryptor

#endif  // _VERSION_INFO_MAP__
