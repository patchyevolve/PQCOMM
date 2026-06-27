#pragma once
#include "packet_view.h"
#include <stdint.h>

#define KF_MAX_LIST 64

typedef struct {
    uint8_t addr[16];
    uint8_t valid;
} kf_addr_t;

typedef struct {
    kf_addr_t whitelist[KF_MAX_LIST];
    uint32_t whitelist_count;
    kf_addr_t blocklist[KF_MAX_LIST];
    uint32_t blocklist_count;
    uint16_t bound_port;
    uint32_t drops_port;
    uint32_t drops_size;
    uint32_t drops_blocked;
    uint32_t passes;
} kernel_filter_t;

extern kernel_filter_t g_kernel_filter;

void kernel_filter_init(void);
int kernel_filter_whitelist_add(const uint8_t* addr);
int kernel_filter_blocklist_add(const uint8_t* addr);
void kernel_filter_set_bound_port(uint16_t port);
int kernel_filter_check(packet_view_t* p);
