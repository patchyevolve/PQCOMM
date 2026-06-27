#pragma once
#include <stdint.h>
#include "packet.h"
#include "config.h"

typedef struct {
    packet_buf_t* buf;
    uint32_t magic;
    uint8_t version;
    uint8_t flags;
    uint64_t session_id;
    uint8_t channel_id;
    uint32_t seq;
    uint32_t length;
    uint8_t* payload;

    /* phase 3: aead fields stripped during parse */
    uint8_t nonce[AEAD_NONCE_SIZE];
    uint8_t tag[AEAD_TAG_SIZE];
    uint8_t encrypted;

    /* phase 4: path index for multipath seq tracking */
    uint32_t path_idx;
} packet_view_t;
