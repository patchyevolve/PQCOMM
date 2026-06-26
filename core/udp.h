#pragma once
#include <stdint.h>
#include "ring.h"

#ifdef _WIN32
typedef uintptr_t udp_fd_t;
#else
typedef int udp_fd_t;
#endif

typedef struct {
    udp_fd_t fd;
} udp_socket_t;

int udp_socket_create(udp_socket_t* s, uint16_t port);
int udp_socket_send(udp_socket_t* s, const void* data, uint32_t len,
                    const void* addr, uint32_t addr_len);
int udp_socket_recv(udp_socket_t* s, void* data, uint32_t max_len,
                    void* addr, uint32_t* addr_len);
void udp_socket_close(udp_socket_t* s);
int udp_rx_once(udp_socket_t* s, spsc_ring_t* rx_ring);
int udp_tx_once(udp_socket_t* s, spsc_ring_t* tx_ring);
