#pragma once
#include <stdint.h>
#include "session.h"

typedef struct {
    uint32_t pool_free_min;
    uint32_t pool_free_current;
    uint32_t rx_thread_stalled;
    uint32_t tx_thread_stalled;
    uint32_t crypto_thread_stalled;
    uint32_t session_locked;
    uint32_t handshake_attempts;
    uint32_t handshake_successes;
    uint32_t handshake_failures;
    uint32_t total_drops;
    uint64_t uptime_ms;
    uint64_t sample_count;
} monitor_snapshot_t;

int monitor_start(void);
void monitor_stop(void);
void monitor_get_snapshot(monitor_snapshot_t* snap);
void monitor_mark_alive(const char* name);
