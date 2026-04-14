#pragma once

#ifdef _WIN32
#include <windows.h>
#endif

#include "udp.h"
#include "ring.h"


typedef struct 
{
    udp_socket_t* sock;
    spsc_ring_t* rx_ring;
    volatile int running;

#ifdef _WIN32
    HANDLE thread;
#endif

} rx_thread_t;

int rx_thread_start (rx_thread_t* ctx, udp_socket_t* sock, spsc_ring_t* ring);

void rx_thread_stop(rx_thread_t* ctx);