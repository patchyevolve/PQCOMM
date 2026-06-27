#include "heartbeat.h"
#include "channel.h"
#include "pool.h"
#include "ring.h"
#include <stdio.h>
#include <string.h>

int heartbeat_send(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter, uint64_t now_ms)
{
    if (!sess || !txq || !seq_counter) return -1;
    if (sess->state != SESSION_LOCKED) return 0;

    packet_buf_t* p = pool_get();
    if (!p) return -1;

    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1, flags = 0, channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1 + 8 + 8;
    uint8_t opcode = CTRL_HEARTBEAT;

    memset(d, 0, 24);
    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &sess->session_id, sizeof(sess->session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    d[24] = opcode;
    memcpy(d + 25, &sess->session_id, 8);
    memcpy(d + 33, &now_ms, 8);

    p->len = 24 + payload_len;
    memcpy(p->addr, sess->addr, sizeof(sess->addr));
    p->addr_len = sess->addr_len;
    ring_push(&txq->control, p);

    sess->resilience.last_heartbeat_ms = now_ms;
    return 0;
}

int heartbeat_handle(packet_buf_t* p, session_t* sess, tx_queues_t* txq,
                     uint32_t* seq_counter, uint64_t now_ms)
{
    if (!p || !sess || p->len < 24 + 1) return 0;
    uint8_t opcode = p->data[24];

    if (opcode == CTRL_HEARTBEAT) {
        if (p->len < 24 + 17) return -1;
        uint64_t ts;
        memcpy(&ts, p->data + 33, 8);

        sess->last_heartbeat_rx_ms = now_ms;
        for (uint32_t i = 0; i < sess->resilience.path_count; i++)
            sess->resilience.paths[i].last_activity_ms = now_ms;

        packet_buf_t* ack = pool_get();
        if (!ack) return 0;
        uint8_t* d = ack->data;
        uint32_t magic = 0xAABBCCDD;
        uint8_t version = 1, flags = 0, channel = CH_CONTROL;
        uint32_t seq = (*seq_counter)++;
        uint32_t payload_len = 1 + 8 + 8;
        memset(d, 0, 24);
        memcpy(d + 0, &magic, sizeof(magic));
        memcpy(d + 4, &version, sizeof(version));
        memcpy(d + 5, &flags, sizeof(flags));
        memcpy(d + 6, &sess->session_id, sizeof(sess->session_id));
        memcpy(d + 14, &channel, sizeof(channel));
        memcpy(d + 15, &seq, sizeof(seq));
        memcpy(d + 19, &payload_len, sizeof(payload_len));
        d[24] = CTRL_HEARTBEAT_ACK;
        memcpy(d + 25, &sess->session_id, 8);
        memcpy(d + 33, &ts, 8);
        ack->len = 24 + payload_len;
        memcpy(ack->addr, p->addr, sizeof(p->addr));
        ack->addr_len = p->addr_len;
        ring_push(&txq->control, ack);
        return 1;
    }

    if (opcode == CTRL_HEARTBEAT_ACK) {
        sess->last_heartbeat_rx_ms = now_ms;
        for (uint32_t i = 0; i < sess->resilience.path_count; i++)
            sess->resilience.paths[i].last_activity_ms = now_ms;
        return 1;
    }

    return 0;
}

int heartbeat_tick(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter, uint64_t now_ms)
{
    if (!sess || sess->state != SESSION_LOCKED) return 0;

    if (now_ms - sess->resilience.last_heartbeat_ms >= sess->resilience.heartbeat_interval_ms) {
        heartbeat_send(sess, txq, seq_counter, now_ms);
        return 1;
    }

    for (uint32_t i = 0; i < sess->resilience.path_count; i++) {
        path_metrics_t* path = &sess->resilience.paths[i];
        if (path->state == PATH_ACTIVE &&
            now_ms - path->last_activity_ms > sess->resilience.heartbeat_interval_ms * 3) {
            path->state = PATH_DEGRADED;
            printf("[HEARTBEAT] path %u DEGRADED (no activity %lu ms)\n",
                   i, (unsigned long)(now_ms - path->last_activity_ms));
        }
        if (path->state == PATH_DEGRADED &&
            now_ms - path->last_activity_ms > sess->resilience.reconnect_timeout_ms) {
            path->state = PATH_DOWN;
            printf("[HEARTBEAT] path %u DOWN (timeout %lu ms)\n",
                   i, (unsigned long)(now_ms - path->last_activity_ms));
        }
    }

    return 0;
}
