#include "reconnect.h"
#include "channel.h"
#include "pool.h"
#include "ring.h"
#include "session.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

#define RECONNECT_RETRY_MS 2000

int reconnect_send_request(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter)
{
    if (!sess || !txq || !seq_counter) return -1;

    packet_buf_t* p = pool_get();
    if (!p) return -1;

    uint8_t* d = p->data;
    uint32_t magic = PROTO_MAGIC;
    uint8_t version = 1, flags = 0, channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1 + 8 + 8;
    uint8_t opcode = CTRL_RECONNECT;
    uint64_t last_seq_be = sess->last_seq;

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
    memcpy(d + 33, &last_seq_be, 8);

    p->len = 24 + payload_len;
    memcpy(p->addr, sess->addr, sizeof(sess->addr));
    p->addr_len = sess->addr_len;
    if (ring_push(&txq->control, p) != 0) pool_return(p);

    sess->reconnect_attempts++;
    sess->reconnect_start_ms = 0;
    printf("[RECONNECT] request sent (attempt %u)\n", sess->reconnect_attempts);
    return 0;
}

int reconnect_send_ack(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter, struct sockaddr_in6* dest)
{
    if (!sess || !txq || !seq_counter) return -1;

    packet_buf_t* p = pool_get();
    if (!p) return -1;

    uint8_t* d = p->data;
    uint32_t magic = PROTO_MAGIC;
    uint8_t version = 1, flags = 0, channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1 + 8;
    uint8_t opcode = CTRL_RECONNECT_ACK;

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

    p->len = 24 + payload_len;
    memcpy(p->addr, dest, sizeof(*dest));
    p->addr_len = sizeof(*dest);
    if (ring_push(&txq->control, p) != 0) pool_return(p);

    printf("[RECONNECT] ack sent\n");
    return 0;
}

int reconnect_handle(packet_buf_t* p, session_t* sess, tx_queues_t* txq,
                     uint32_t* seq_counter, uint64_t now_ms)
{
    (void)now_ms;
    if (!p || !sess || p->len < 24 + 1) return 0;
    uint8_t opcode = p->data[24];

    if (opcode == CTRL_RECONNECT) {
        uint64_t msg_session_id;
        memcpy(&msg_session_id, p->data + 25, 8);
        if (msg_session_id != sess->session_id) return 0;

        if (sess->state != SESSION_LOCKED) return 0;

        printf("[RECONNECT] received request from peer, session preserved\n");

        for (uint32_t i = 0; i < sess->resilience.path_count; i++) {
            sess->resilience.paths[i].state = PATH_ACTIVE;
            sess->resilience.paths[i].last_activity_ms = now_ms;
        }
        sess->reconnect_attempts = 0;
        sess->reconnect_pending = 0;

        reconnect_send_ack(sess, txq, seq_counter, (struct sockaddr_in6*)p->addr);
        return 1;
    }

    if (opcode == CTRL_RECONNECT_ACK) {
        uint64_t msg_session_id;
        memcpy(&msg_session_id, p->data + 25, 8);
        if (msg_session_id != sess->session_id) return 0;

        if (sess->state != SESSION_LOCKED) return 0;

        printf("[RECONNECT] ack received, session re-established\n");

        for (uint32_t i = 0; i < sess->resilience.path_count; i++) {
            sess->resilience.paths[i].state = PATH_ACTIVE;
            sess->resilience.paths[i].last_activity_ms = now_ms;
        }
        sess->reconnect_attempts = 0;
        sess->reconnect_pending = 0;
        return 1;
    }

    return 0;
}

int reconnect_tick(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter, uint64_t now_ms)
{
    if (!sess || sess->state != SESSION_LOCKED) return 0;

    int any_down = 0;
    for (uint32_t i = 0; i < sess->resilience.path_count; i++) {
        if (sess->resilience.paths[i].state == PATH_DOWN)
            any_down = 1;
    }
    if (!any_down) return 0;

    if (sess->reconnect_attempts >= sess->resilience.max_reconnect_attempts) {
        printf("[RECONNECT] max attempts (%u) reached, dropping session\n",
               sess->resilience.max_reconnect_attempts);
        session_zero_secrets(sess);
        sess->state = SESSION_IDLE;
        return -1;
    }

    if (sess->reconnect_start_ms == 0) {
        sess->reconnect_start_ms = now_ms;
        reconnect_send_request(sess, txq, seq_counter);
        return 1;
    }

    if (now_ms - sess->reconnect_start_ms >= RECONNECT_RETRY_MS) {
        reconnect_send_request(sess, txq, seq_counter);
        return 1;
    }

    return 0;
}
