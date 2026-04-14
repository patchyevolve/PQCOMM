#pragma once

#include "udp.h"

#define IO_EVENT_READ   1
#define IO_EVENT_WRITE  2

typedef struct
{
    udp_socket_t* sock;

    int events;   // requested
    int revents;  // returned

} io_event_t;

typedef struct io_poll_t
{
    udp_socket_t* socks[64];   // same as MAX_SOCKS
    int events[64];
    int count;
} io_poll_t;

// lifecycle
int io_poll_init(io_poll_t* p);
void io_poll_destroy(io_poll_t* p);

// registration
int io_poll_add(io_poll_t* p, udp_socket_t* s, int events);

// wait
int io_poll_wait(
    io_poll_t* p,
    io_event_t* out,
    int max_events,
    int timeout_ms);