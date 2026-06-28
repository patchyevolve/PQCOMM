#include "monitor.h"
#include "pool.h"
#include "offensive.h"
#include "handshake.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MONITOR_INTERVAL_MS 2000
#define STALL_THRESHOLD_MS  5000

extern handshake_stats_t g_handshake_stats;

#ifdef _WIN32
static HANDLE g_monitor_thread;
static CRITICAL_SECTION g_snap_mutex;
#else
static pthread_t g_monitor_thread;
static pthread_mutex_t g_snap_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static volatile int g_monitor_running = 0;

typedef struct {
    char name[32];
    uint64_t last_tick_ms;
} liveness_entry_t;

#define MAX_LIVENESS_ENTRIES 8
static liveness_entry_t g_liveness[MAX_LIVENESS_ENTRIES];
static int g_liveness_count = 0;

static monitor_snapshot_t g_snapshot;

void monitor_mark_alive(const char* name)
{
    uint64_t t = platform_now_ms();
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

static void snap_lock(void)
{
#ifdef _WIN32
    EnterCriticalSection(&g_snap_mutex);
#else
    pthread_mutex_lock(&g_snap_mutex);
#endif
}

static void snap_unlock(void)
{
#ifdef _WIN32
    LeaveCriticalSection(&g_snap_mutex);
#else
    pthread_mutex_unlock(&g_snap_mutex);
#endif
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

    uint64_t t = platform_now_ms();
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

    snap_lock();
    g_snapshot = snap;
    snap_unlock();
}

#ifdef _WIN32
static DWORD WINAPI monitor_loop(LPVOID arg)
#else
static void* monitor_loop(void* arg)
#endif
{
    (void)arg;
    while (g_monitor_running) {
        sample();
        platform_sleep_ms(MONITOR_INTERVAL_MS);
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int monitor_start(void)
{
    if (g_monitor_running) return 0;
    g_monitor_running = 1;
    memset(g_liveness, 0, sizeof(g_liveness));
    g_liveness_count = 0;

#ifdef _WIN32
    InitializeCriticalSection(&g_snap_mutex);
    g_monitor_thread = CreateThread(NULL, 0, monitor_loop, NULL, 0, NULL);
    if (!g_monitor_thread) {
        g_monitor_running = 0;
        return -1;
    }
#else
    if (pthread_create(&g_monitor_thread, NULL, monitor_loop, NULL) != 0) {
        g_monitor_running = 0;
        return -1;
    }
    pthread_detach(g_monitor_thread);
#endif
    return 0;
}

void monitor_stop(void)
{
    g_monitor_running = 0;
#ifdef _WIN32
    if (g_monitor_thread) {
        WaitForSingleObject(g_monitor_thread, 2000);
        CloseHandle(g_monitor_thread);
        g_monitor_thread = NULL;
    }
    DeleteCriticalSection(&g_snap_mutex);
#endif
}

void monitor_get_snapshot(monitor_snapshot_t* snap)
{
    if (!snap) return;
    snap_lock();
    *snap = g_snapshot;
    snap_unlock();
}
