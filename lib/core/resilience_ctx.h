#pragma once
#include <stdint.h>
#include "config.h"

#define RESILIENCE_LOSS_WINDOW 64
#define FEC_MAX_PAYLOAD 1400

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
    uint32_t last_seq;
    uint64_t recv_bitmap;
    uint16_t peer_port;
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

    /* FEC TX */
    uint8_t fec_enabled;
    uint8_t fec_group_size;
    uint8_t fec_group_pos;
    uint8_t fec_parity_buf[FEC_MAX_PAYLOAD];
    uint32_t fec_parity_len;
    uint32_t fec_group_start_seq;
    uint8_t fec_channel_id;
    uint8_t fec_buf_ptrs[RESILIENCE_FEC_GROUP][FEC_MAX_PAYLOAD];
    uint32_t fec_buf_lens[RESILIENCE_FEC_GROUP];

    /* FEC RX */
    uint8_t fec_rx_parity[FEC_MAX_PAYLOAD];
    uint32_t fec_rx_parity_len;
    uint32_t fec_rx_group_start_seq;
    uint8_t fec_rx_group_size;
    uint8_t fec_rx_channel_id;
    uint8_t fec_rx_have_parity;
    uint32_t fec_rx_seqs[RESILIENCE_FEC_GROUP];
} resilience_t;

void resilience_init(resilience_t* r);
void resilience_record_tx(resilience_t* r, uint32_t path_idx);
void resilience_record_rx(resilience_t* r, uint32_t path_idx, uint64_t rtt_ns);
void resilience_record_loss(resilience_t* r, uint32_t path_idx);
uint32_t resilience_select_path(resilience_t* r);
int resilience_tick(resilience_t* r, uint64_t now_ms);

/* FEC TX — accumulate data packet into current group */
int fec_tx_accumulate(resilience_t* r, const uint8_t* payload, uint32_t payload_len,
                      uint32_t seq, uint64_t session_id, uint8_t channel_id,
                      uint8_t* parity_out, uint32_t* parity_len, int* group_complete);

/* FEC RX — track a received data packet's ciphertext */
int fec_rx_track(resilience_t* r, uint32_t seq, const uint8_t* payload, uint32_t payload_len);

/* FEC RX — store a received parity packet's payload (wire format: group_start_seq(4) + group_size(1) + channel_id(1) + xor_parity(N)) */
void fec_rx_store_parity(resilience_t* r, const uint8_t* parity_wire, uint32_t wire_len);

/* FEC RX — attempt to reconstruct a missing packet from buffered data + parity */
int fec_rx_rebuild(resilience_t* r, uint8_t* out_payload, uint32_t* out_len, uint32_t* out_seq);
