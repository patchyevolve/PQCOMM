#pragma once
#include <stdint.h>
#include "ring.h"
#include "packet.h"

typedef void (*rx_handler_fn)(packet_buf_t* p, void* ctx);

typedef struct {
    volatile int running;
    spsc_ring_t* ring;
    rx_handler_fn handler;
    void* ctx;

#ifdef _WIN32
    HANDLE thread;
#else
    pthread_t thread;
#endif
} rx_worker_t;

int rx_worker_start(rx_worker_t* w, spsc_ring_t* ring,
                    rx_handler_fn handler, void* ctx);
void rx_worker_stop(rx_worker_t* w);
