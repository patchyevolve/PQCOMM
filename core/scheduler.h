#pragma once

#include "ring.h"
#include "packet.h"

typedef struct
{
    spsc_ring_t control;
    spsc_ring_t audio;
    spsc_ring_t chat;
    spsc_ring_t file;
    spsc_ring_t fake;

} tx_queues_t;

void tx_queues_init(tx_queues_t* q);

packet_buf_t* scheduler_next(tx_queues_t* q);