#pragma  once
#include <stdint.h>
#include "packet.h"
#include "config.h"

void pool_init(void);

packet_buf_t* pool_get(void);

void pool_return(packet_buf_t* p);

uint32_t pool_free_count(void);