#include "monitor.h"
#include "pool.h"
#include "offensive.h"
#include "handshake.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#define MONITOR_INTERVAL_MS 2000
#define STALL_THRESHOLD_MS  5000

extern handshake_stats_t g_handshake_stats;

static pthread_t g_monitor_thread;
static volatile int g_monitor_running = 0;

typedef struct {
    char name[32];
    uint64_t last_tick_ms;
} liveness_entry_t;

#define MAX_LIVENESS_ENTRIES 8
static liveness_entry_t g_liveness[MAX_LIVENESS_ENTRIES];
static int g_liveness_count = 0;

static monitor_snapshot_t g_snapshot;
static pthread_mutex_t g_snap_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

void monitor_mark_alive(const char* name)
{
    uint64_t t = now_ms();
    for (int i = 0; i < g_liveness_count; i++) {
        if (strcmp(g_liveness[i].name, name) == 0) {
            g_liveness[i].last_tick_ms = t;
            return;
        }
    }
    if (g_liveness_count < MAX_LIVENESS_ENTRIES) {
        snprintf(g_liveness[g_liveness_count].name, sizeof(g_liveness[g_liveness_count].name), "%s", name);
        g_liveness[g_liveness_count].last_tick_ms = t;
        g_liveness_count++;
    }
}

static void sample(void)
{
    monitor_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));

    snap.pool_free_current = pool_free_count();
    snap.session_locked = 0;
    snap.handshake_attempts = g_handshake_stats.attempts_total;
    snap.handshake_successes = g_handshake_stats.successes;
    snap.handshake_failures = g_handshake_stats.failures_timeout +
                              g_handshake_stats.failures_identity +
                              g_handshake_stats.failures_replay +
                              g_handshake_stats.failures_state;

    uint64_t t = now_ms();
    for (int i = 0; i < g_liveness_count; i++) {
        if (t - g_liveness[i].last_tick_ms > STALL_THRESHOLD_MS) {
            if (strcmp(g_liveness[i].name, "rx-worker") == 0) snap.rx_thread_stalled++;
            if (strcmp(g_liveness[i].name, "tx-worker") == 0) snap.tx_thread_stalled++;
            if (strcmp(g_liveness[i].name, "crypto") == 0) snap.crypto_thread_stalled++;
        }
    }

    snap.total_drops = g_offensive.total_decoys;

    snap.uptime_ms = t;
    snap.sample_count++;

    static uint32_t prev_free = 0;
    if (prev_free > 0 && snap.pool_free_current < prev_free / 2)
        printf("[MONITOR] WARNING: pool pressure — free=%u (was %u)\n",
               snap.pool_free_current, prev_free);
    prev_free = snap.pool_free_current;

    if (snap.rx_thread_stalled || snap.tx_thread_stalled || snap.crypto_thread_stalled)
        printf("[MONITOR] WARNING: thread stall detected\n");

    pthread_mutex_lock(&g_snap_mutex);
    g_snapshot = snap;
    pthread_mutex_unlock(&g_snap_mutex);
}

static void* monitor_loop(void* arg)
{
    (void)arg;
    while (g_monitor_running) {
        sample();
        struct timespec ts = { .tv_sec = MONITOR_INTERVAL_MS / 1000,
                               .tv_nsec = (MONITOR_INTERVAL_MS % 1000) * 1000000 };
        nanosleep(&ts, NULL);
    }
    return NULL;
}

int monitor_start(void)
{
    if (g_monitor_running) return 0;
    g_monitor_running = 1;
    memset(g_liveness, 0, sizeof(g_liveness));
    g_liveness_count = 0;
    if (pthread_create(&g_monitor_thread, NULL, monitor_loop, NULL) != 0) {
        g_monitor_running = 0;
        return -1;
    }
    pthread_detach(g_monitor_thread);
    return 0;
}

void monitor_stop(void)
{
    g_monitor_running = 0;
}

void monitor_get_snapshot(monitor_snapshot_t* snap)
{
    if (!snap) return;
    pthread_mutex_lock(&g_snap_mutex);
    *snap = g_snapshot;
    pthread_mutex_unlock(&g_snap_mutex);
}
