#include "conn_request.h"
#include "pool.h"
#include "channel.h"
#include "handshake.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <netinet/in.h>

conn_request_table_t g_conn_requests = { 0 };

int conn_request_build(session_t* sess, tx_queues_t* txq, uint32_t* seq,
                        const char* username, const char* display_name)
{
    if (!sess || !txq || !seq || !username) return -1;

    uint32_t uname_len = (uint32_t)strlen(username);
    uint32_t dname_len = (uint32_t)strlen(display_name);
    if (uname_len > 31 || dname_len > 63) return -1;

    packet_buf_t* p = pool_get();
    if (!p) return -1;

    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t ver = 1, fl = 0, ch = CH_CONTROL;
    uint32_t seq_n = (*seq)++;

    uint32_t payload_len = 1 + 1 + uname_len + 1 + dname_len;
    memcpy(d + 0, &magic, 4);
    memcpy(d + 4, &ver, 1);
    memcpy(d + 5, &fl, 1);
    memcpy(d + 6, &sess->session_id, 8);
    memcpy(d + 14, &ch, 1);
    memcpy(d + 15, &seq_n, 4);
    memcpy(d + 19, &payload_len, 4);
    d[24] = CTRL_CONNECT_REQUEST;
    d[25] = (uint8_t)uname_len;
    memcpy(d + 26, username, uname_len);
    d[26 + uname_len] = (uint8_t)dname_len;
    memcpy(d + 27 + uname_len, display_name, dname_len);
    p->len = 24 + payload_len;

    memcpy(p->addr, sess->addr, sizeof(struct sockaddr_in6));
    p->addr_len = sizeof(struct sockaddr_in6);

    ring_push(&txq->control, p);
    return 0;
}

int conn_request_handle(packet_buf_t* p, session_t* sess, tx_queues_t* txq,
                        uint32_t* seq, int is_responder)
{
    (void)sess;
    if (!p || !txq) return -1;

    uint8_t opcode = p->data[24];

    if (opcode == CTRL_CONNECT_REQUEST) {
        if (!is_responder) return 0;

        uint8_t uname_len = p->data[25];
        if (uname_len > 31) return 0;

        struct sockaddr_in6* peer = (struct sockaddr_in6*)p->addr;

        pending_request_t* r = NULL;
        for (int i = 0; i < CONN_REQUEST_MAX_PENDING; i++) {
            if (!g_conn_requests.requests[i].active) {
                r = &g_conn_requests.requests[i];
                break;
            }
        }
        if (!r) return 0;

        memcpy(r->addr, &peer->sin6_addr, 16);
        r->port = ntohs(peer->sin6_port);
        memcpy(r->username, p->data + 26, uname_len);
        r->username[uname_len] = '\0';

        uint8_t dname_len = p->data[26 + uname_len];
        if (dname_len > 63) dname_len = 63;
        memcpy(r->display_name, p->data + 27 + uname_len, dname_len);
        r->display_name[dname_len] = '\0';

        r->timestamp_ms = (uint64_t)time(NULL) * 1000;
        r->active = 1;
        if (g_conn_requests.count < CONN_REQUEST_MAX_PENDING)
            g_conn_requests.count++;

        return 1;
    }

    if (opcode == CTRL_CONNECT_ACCEPT) {
        return 2;
    }

    if (opcode == CTRL_CONNECT_DECLINE) {
        return 3;
    }

    return 0;
}

int conn_request_send_accept(session_t* sess, tx_queues_t* txq, uint32_t* seq,
                              const struct sockaddr_in6* peer_addr)
{
    if (!sess || !txq || !seq || !peer_addr) return -1;

    packet_buf_t* p = pool_get();
    if (!p) return -1;

    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t ver = 1, fl = 0, ch = CH_CONTROL;
    uint32_t seq_n = (*seq)++;

    uint32_t payload_len = 1;
    memcpy(d + 0, &magic, 4);
    memcpy(d + 4, &ver, 1);
    memcpy(d + 5, &fl, 1);
    memcpy(d + 6, &sess->session_id, 8);
    memcpy(d + 14, &ch, 1);
    memcpy(d + 15, &seq_n, 4);
    memcpy(d + 19, &payload_len, 4);
    d[24] = CTRL_CONNECT_ACCEPT;
    p->len = 24 + payload_len;

    memcpy(p->addr, peer_addr, sizeof(*peer_addr));
    p->addr_len = sizeof(*peer_addr);

    ring_push(&txq->control, p);
    return 0;
}

int conn_request_send_decline(session_t* sess, tx_queues_t* txq, uint32_t* seq,
                               const struct sockaddr_in6* peer_addr,
                               const char* reason)
{
    if (!sess || !txq || !seq || !peer_addr) return -1;

    uint32_t reason_len = reason ? (uint32_t)strlen(reason) : 0;
    if (reason_len > 63) reason_len = 63;

    packet_buf_t* p = pool_get();
    if (!p) return -1;

    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t ver = 1, fl = 0, ch = CH_CONTROL;
    uint32_t seq_n = (*seq)++;

    uint32_t payload_len = 1 + 1 + reason_len;
    memcpy(d + 0, &magic, 4);
    memcpy(d + 4, &ver, 1);
    memcpy(d + 5, &fl, 1);
    memcpy(d + 6, &sess->session_id, 8);
    memcpy(d + 14, &ch, 1);
    memcpy(d + 15, &seq_n, 4);
    memcpy(d + 19, &payload_len, 4);
    d[24] = CTRL_CONNECT_DECLINE;
    d[25] = (uint8_t)reason_len;
    if (reason_len > 0) memcpy(d + 26, reason, reason_len);
    p->len = 24 + payload_len;

    memcpy(p->addr, peer_addr, sizeof(*peer_addr));
    p->addr_len = sizeof(*peer_addr);

    ring_push(&txq->control, p);
    return 0;
}

pending_request_t* conn_request_find(const struct sockaddr_in6* addr)
{
    if (!addr) return NULL;
    for (int i = 0; i < CONN_REQUEST_MAX_PENDING; i++) {
        if (g_conn_requests.requests[i].active &&
            memcmp(g_conn_requests.requests[i].addr, &addr->sin6_addr, 16) == 0 &&
            g_conn_requests.requests[i].port == ntohs(addr->sin6_port))
            return &g_conn_requests.requests[i];
    }
    return NULL;
}
