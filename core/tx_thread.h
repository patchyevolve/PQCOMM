#pragma once

#ifdef _WIN32
#include <windows.h>
#endif

#include "udp.h"
#include "ring.h"
#include "scheduler.h"

typedef struct
{
    udp_socket_t* sock;
    tx_queues_t* queues;
    volatile int running;

#ifdef _WIN32
    HANDLE thread;
#endif

} tx_thread_t;

int tx_thread_start(tx_thread_t* ctx, udp_socket_t* sock, tx_queues_t* queues);

void tx_thread_stop(tx_thread_t* ctx);

