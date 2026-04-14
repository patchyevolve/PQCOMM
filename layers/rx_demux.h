#pragma once

#include "ring.h"
#include "packet.h"

typedef struct
{
    spsc_ring_t control;
    spsc_ring_t audio;
    spsc_ring_t chat;
    spsc_ring_t file;
    spsc_ring_t route;
} rx_queues_t;

void rx_queues_init(rx_queues_t* q);

int rx_demux_push(rx_queues_t* q, packet_buf_t* p, uint8_t channel);