#pragma once
#include <stdint.h>
#include "config.h"

typedef struct {
    
    uint8_t addr[32];
    uint32_t addr_len;
    
    uint32_t len;
    
    uint8_t data[MAX_PACKET_SIZE];

} packet_buf_t;
