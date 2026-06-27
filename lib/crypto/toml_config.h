#pragma once
#include <stdint.h>

typedef struct {
    uint16_t local_port;
    uint16_t local_port_alt;
    uint16_t remote_port;
    char     remote_addr[64];
    uint16_t discovery_port;
    int      discovery_enabled;
    int      multipath_enabled;
    int      path_count;
    char     identity_key_hex[128];
} config_t;

int config_load(config_t* cfg, const char* path);
int config_load_default(config_t* cfg);
void config_dump(const config_t* cfg);
