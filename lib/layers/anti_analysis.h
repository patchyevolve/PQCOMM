#pragma once
#include "packet_view.h"
#include <stdint.h>

#define AA_MAX_SOURCES 256
#define AA_LRU_EVICT 64

typedef struct {
    uint8_t addr[16];
    uint16_t port;
    uint32_t score;
    uint64_t last_seen_ms;
    uint32_t bad_packets;
    uint32_t total_packets;
} aa_source_t;

typedef struct {
    aa_source_t sources[AA_MAX_SOURCES];
    uint32_t count;
    uint64_t last_evict_ms;
    uint64_t evict_interval_ms;
    uint32_t drops_medium;
    uint32_t drops_high;
    uint32_t delayed_packets;
} anti_analysis_t;

extern anti_analysis_t g_anti_analysis;

void anti_analysis_init(void);
int anti_analysis_check(packet_view_t* p);
