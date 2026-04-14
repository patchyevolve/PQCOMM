#pragma once

#include <stdint.h>
#include <string.h>
#include "packet.h"
#define REPLAY_WINDOW_SIZE 64

typedef enum 
{
    SESSION_IDLE = 0,
    SESSION_HANDSHAKE,
    SESSION_VERIFY,
    SESSION_LOCKED
} session_state_t;

typedef struct
{
    uint64_t session_id;

    uint8_t addr[32];
    uint32_t addr_len;
    
    uint32_t last_seq;
    uint64_t recv_bitmap;

    session_state_t state;
} session_t;



