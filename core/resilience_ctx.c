#include "resilience_ctx.h"
#include <string.h>

void resilience_init(resilience_t* r)
{
    if (!r) return;
    memset(r, 0, sizeof(resilience_t));
    r->path_count = 1;
    r->active_path = 0;
    r->heartbeat_interval_ms = 1000;
    r->reconnect_timeout_ms = 5000;
    r->max_reconnect_attempts = 3;
    for (uint32_t i = 0; i < RESILIENCE_MAX_PATHS; i++) {
        r->paths[i].state = PATH_UNKNOWN;
    }
}

static void update_loss_rate(path_metrics_t* p)
{
    uint32_t total = 0, lost = 0;
    for (uint32_t i = 0; i < RESILIENCE_LOSS_WINDOW; i++) {
        if (p->loss_window[i]) lost++;
        total++;
    }
    p->loss_rate = total > 0 ? (float)lost / (float)total : 0.0f;
}

void resilience_record_tx(resilience_t* r, uint32_t path_idx)
{
    if (!r || path_idx >= RESILIENCE_MAX_PATHS) return;
    r->paths[path_idx].packets_sent++;
}

void resilience_record_rx(resilience_t* r, uint32_t path_idx, uint64_t rtt_ns)
{
    if (!r || path_idx >= RESILIENCE_MAX_PATHS) return;
    path_metrics_t* p = &r->paths[path_idx];
    p->packets_recv++;
    p->loss_window[p->loss_window_pos % RESILIENCE_LOSS_WINDOW] = 0;
    p->loss_window_pos++;
    update_loss_rate(p);
    if (rtt_ns > 0) {
        if (p->rtt_min_ns == 0 || rtt_ns < p->rtt_min_ns)
            p->rtt_min_ns = rtt_ns;
        if (rtt_ns > p->rtt_max_ns)
            p->rtt_max_ns = rtt_ns;
        uint64_t prev = p->rtt_ns;
        p->rtt_ns = prev > 0 ? (prev * 7 + rtt_ns) / 8 : rtt_ns;
        p->jitter_ns = p->jitter_ns > 0
            ? (p->jitter_ns * 7 + (rtt_ns > prev ? rtt_ns - prev : prev - rtt_ns)) / 8
            : 0;
    }
    p->state = PATH_ACTIVE;
}

void resilience_record_loss(resilience_t* r, uint32_t path_idx)
{
    if (!r || path_idx >= RESILIENCE_MAX_PATHS) return;
    path_metrics_t* p = &r->paths[path_idx];
    p->packets_lost++;
    p->loss_window[p->loss_window_pos % RESILIENCE_LOSS_WINDOW] = 1;
    p->loss_window_pos++;
    update_loss_rate(p);
    if (p->loss_rate > 0.3f)
        p->state = PATH_DEGRADED;
    if (p->loss_rate > 0.5f)
        p->state = PATH_DOWN;
}

uint32_t resilience_select_path(resilience_t* r)
{
    if (!r || r->path_count == 0) return 0;
    if (!r->multipath_enabled) return r->active_path;
    uint32_t best = r->active_path;
    float best_loss = r->paths[best].loss_rate;
    for (uint32_t i = 0; i < r->path_count; i++) {
        if (r->paths[i].state == PATH_ACTIVE && r->paths[i].loss_rate < best_loss) {
            best = i;
            best_loss = r->paths[i].loss_rate;
        }
    }
    return best;
}

int resilience_tick(resilience_t* r, uint64_t now_ms)
{
    if (!r) return 0;
    int changed = 0;
    for (uint32_t i = 0; i < r->path_count; i++) {
        path_metrics_t* p = &r->paths[i];
        if (p->state == PATH_ACTIVE && now_ms - p->last_activity_ms > r->heartbeat_interval_ms * 3) {
            p->state = PATH_DEGRADED;
            changed = 1;
        }
        if (p->state == PATH_DEGRADED && now_ms - p->last_activity_ms > r->reconnect_timeout_ms) {
            p->state = PATH_DOWN;
            changed = 1;
        }
    }
    return changed;
}
