#pragma once
#include <stdint.h>

int lan_discovery_init(uint16_t port);
void lan_discovery_shutdown(void);
int lan_discovery_start(void);
void lan_discovery_stop(void);
void lan_discovery_trigger_scan(void);
