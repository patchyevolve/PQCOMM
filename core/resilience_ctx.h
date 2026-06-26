#pragma once
#include <stdint.h>
#include "config.h"

#define RESILIENCE_LOSS_WINDOW 64

typedef enum {
    PATH_UNKNOWN = 0,
    PATH_ACTIVE,
    PATH_DEGRADED,
    PATH_DOWN
} path_state_t;

typedef struct {
    uint32_t packets_sent;
    uint32_t packets_recv;
    uint32_t packets_lost;
    uint64_t rtt_ns;
    uint64_t rtt_min_ns;
    uint64_t rtt_max_ns;
    uint64_t jitter_ns;
    float loss_rate;
    path_state_t state;
    uint64_t last_activity_ms;
    uint64_t last_probe_ms;
    uint8_t loss_window[RESILIENCE_LOSS_WINDOW];
    uint32_t loss_window_pos;
} path_metrics_t;

typedef struct {
    path_metrics_t paths[RESILIENCE_MAX_PATHS];
    uint32_t path_count;
    uint32_t active_path;
    uint8_t multipath_enabled;
    uint32_t heartbeat_interval_ms;
    uint32_t reconnect_timeout_ms;
    uint32_t max_reconnect_attempts;
    uint64_t last_heartbeat_ms;
    uint64_t start_time_ms;
} resilience_t;

void resilience_init(resilience_t* r);
void resilience_record_tx(resilience_t* r, uint32_t path_idx);
void resilience_record_rx(resilience_t* r, uint32_t path_idx, uint64_t rtt_ns);
void resilience_record_loss(resilience_t* r, uint32_t path_idx);
uint32_t resilience_select_path(resilience_t* r);
int resilience_tick(resilience_t* r, uint64_t now_ms);
