#pragma once

#include <stdint.h>
#include "packet.h"

typedef struct 
{
    //raw ref
    packet_buf_t* buf;

    //parsed header fields
    uint32_t magic;
    uint8_t version;
    uint8_t flags;

    uint64_t session_id;
    uint8_t channel_id;

    uint32_t seq;
    uint32_t length;

    //pointers
    uint8_t* payload;

} packet_view_t;
