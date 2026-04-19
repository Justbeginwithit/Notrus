#ifndef NOTRUS_PROTOCOL_CORE_H
#define NOTRUS_PROTOCOL_CORE_H

#include <stdint.h>

typedef struct NotrusCoreProfile {
  const char *core_version;
  const char *signal_label;
  const char *mls_label;
  uint16_t mls_mti_ciphersuite_code;
} NotrusCoreProfile;

NotrusCoreProfile notrus_protocol_core_profile(void);
char *notrus_protocol_core_snapshot_json(void);
void notrus_protocol_core_free_string(char *value);

#endif
