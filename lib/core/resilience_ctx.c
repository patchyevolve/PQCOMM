#include "resilience_ctx.h"
#include <string.h>
#include <time.h>

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
    r->fec_enabled = 1;
    r->fec_group_size = RESILIENCE_FEC_GROUP;
    r->fec_group_pos = 0;
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

int fec_tx_accumulate(resilience_t* r, const uint8_t* payload, uint32_t payload_len,
                      uint32_t seq, uint64_t session_id, uint8_t channel_id,
                      uint8_t* parity_out, uint32_t* parity_len, int* group_complete)
{
    if (!r || !payload || !parity_out || !parity_len || !group_complete) return -1;
    *group_complete = 0;
    *parity_len = 0;
    if (!r->fec_enabled || r->fec_group_size == 0) return 0;

    if (r->fec_group_pos == 0) {
        r->fec_group_start_seq = seq;
        r->fec_channel_id = channel_id;
        r->fec_parity_len = 0;
        memset(r->fec_parity_buf, 0, FEC_MAX_PAYLOAD);
        for (uint8_t i = 0; i < r->fec_group_size; i++)
            r->fec_buf_lens[i] = 0;
    }

    memcpy(r->fec_buf_ptrs[r->fec_group_pos], payload, payload_len < FEC_MAX_PAYLOAD ? payload_len : FEC_MAX_PAYLOAD);
    r->fec_buf_lens[r->fec_group_pos] = payload_len < FEC_MAX_PAYLOAD ? payload_len : FEC_MAX_PAYLOAD;

    for (uint32_t i = 0; i < payload_len && i < FEC_MAX_PAYLOAD; i++)
        r->fec_parity_buf[i] ^= payload[i];
    if (payload_len > r->fec_parity_len)
        r->fec_parity_len = payload_len;

    r->fec_group_pos++;

    if (r->fec_group_pos >= r->fec_group_size) {
        memcpy(parity_out, &r->fec_group_start_seq, 4);
        parity_out[4] = (uint8_t)r->fec_group_size;
        parity_out[5] = channel_id;
        memcpy(parity_out + 6, r->fec_parity_buf, r->fec_parity_len);
        *parity_len = 6 + r->fec_parity_len;
        *group_complete = 1;
        for (uint8_t i = 0; i < r->fec_group_size; i++)
            r->fec_buf_lens[i] = 0;
        r->fec_group_pos = 0;
        return 1;
    }

    return 0;
}

int fec_rx_track(resilience_t* r, uint32_t seq, const uint8_t* payload, uint32_t payload_len)
{
    if (!r || !payload) return -1;
    if (!r->fec_enabled || r->fec_group_size == 0) return 0;

    uint32_t group_pos = seq % r->fec_group_size;
    memcpy(r->fec_buf_ptrs[group_pos], payload, payload_len < FEC_MAX_PAYLOAD ? payload_len : FEC_MAX_PAYLOAD);
    r->fec_buf_lens[group_pos] = payload_len < FEC_MAX_PAYLOAD ? payload_len : FEC_MAX_PAYLOAD;
    r->fec_rx_seqs[group_pos] = seq;
    return 0;
}

void fec_rx_store_parity(resilience_t* r, const uint8_t* parity_wire, uint32_t wire_len)
{
    if (!r || !parity_wire || wire_len < 6) return;
    memcpy(&r->fec_rx_group_start_seq, parity_wire, 4);
    r->fec_rx_group_size = parity_wire[4];
    r->fec_rx_channel_id = parity_wire[5];
    r->fec_rx_parity_len = wire_len - 6;
    if (r->fec_rx_parity_len > FEC_MAX_PAYLOAD)
        r->fec_rx_parity_len = FEC_MAX_PAYLOAD;
    memcpy(r->fec_rx_parity, parity_wire + 6, r->fec_rx_parity_len);
    r->fec_rx_have_parity = 1;
}

static void fec_rx_clear_group(resilience_t* r)
{
    r->fec_rx_have_parity = 0;
    r->fec_rx_group_size = 0;
    for (uint8_t i = 0; i < RESILIENCE_FEC_GROUP; i++) {
        r->fec_buf_lens[i] = 0;
        r->fec_rx_seqs[i] = 0;
    }
}

int fec_rx_rebuild(resilience_t* r, uint8_t* out_payload, uint32_t* out_len, uint32_t* out_seq)
{
    if (!r || !out_payload || !out_len || !out_seq) return -1;
    if (!r->fec_rx_have_parity || r->fec_rx_group_size == 0) return 0;

    uint32_t filled = 0;
    uint32_t empty_slot = 0;
    int has_foreign = 0;
    for (uint8_t i = 0; i < r->fec_rx_group_size; i++) {
        uint32_t expected_seq = r->fec_rx_group_start_seq + i;
        if (r->fec_buf_lens[i] > 0 && r->fec_rx_seqs[i] == expected_seq) {
            filled++;
        } else if (r->fec_buf_lens[i] == 0) {
            empty_slot = i;
        } else {
            has_foreign = 1;
        }
    }

    /* all N received — clear and return */
    if (filled == r->fec_rx_group_size) {
        fec_rx_clear_group(r);
        return 0;
    }

    /* reconstruct only if exactly N-1 matching + no foreign data contaminating slots */
    if (filled != r->fec_rx_group_size - 1 || has_foreign) return 0;

    memcpy(out_payload, r->fec_rx_parity, r->fec_rx_parity_len);
    for (uint8_t i = 0; i < r->fec_rx_group_size; i++) {
        if (i == empty_slot || r->fec_buf_lens[i] == 0) continue;
        uint32_t expected_seq = r->fec_rx_group_start_seq + i;
        if (r->fec_rx_seqs[i] != expected_seq) continue;
        uint32_t xlen = r->fec_buf_lens[i] < r->fec_rx_parity_len ? r->fec_buf_lens[i] : r->fec_rx_parity_len;
        for (uint32_t j = 0; j < xlen; j++)
            out_payload[j] ^= r->fec_buf_ptrs[i][j];
    }

    *out_len = r->fec_rx_parity_len;
    *out_seq = r->fec_rx_group_start_seq + empty_slot;

    fec_rx_clear_group(r);
    return 1;
}
