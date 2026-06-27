#pragma once
#include "packet_view.h"
#include "packet.h"
#include <stdint.h>
#include <netinet/in.h>

#define OFF_MAX_SOURCES 256
#define OFF_THRESHOLD 100
#define OFF_WINDOW_MS 1000

typedef struct {
    uint8_t addr[16];
    uint16_t port;
    uint32_t rate_count;
    uint64_t window_start_ms;
} off_source_t;

typedef struct {
    off_source_t sources[OFF_MAX_SOURCES];
    uint32_t count;
    uint32_t total_decoys;
    uint32_t total_noise;
    uint32_t reserve_pool;
} offensive_t;

extern offensive_t g_offensive;

void offensive_init(void);
int offensive_check(packet_view_t* p);
packet_buf_t* offensive_build_decoy(const struct sockaddr_in6* target);
void offensive_tick(uint64_t now_ms);
