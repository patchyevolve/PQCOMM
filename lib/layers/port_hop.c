#include "port_hop.h"
#include "channel.h"
#include "scheduler.h"
#include "ring.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

int port_hop_send_request(session_t* sess, tx_queues_t* txq,
                          struct sockaddr_in6* peer_addr,
                          uint16_t new_port, uint32_t* seq_counter)
{
    packet_buf_t* p = pool_get();
    if (!p) return -1;

    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1, flags = 0;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1 + 2 + 8;
    uint8_t opcode = CTRL_PORT_HOP;
    uint16_t port_be = htons(new_port);

    memset(d, 0, 24);
    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &sess->session_id, sizeof(sess->session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    d[24] = opcode;
    memcpy(d + 25, &port_be, 2);
    memcpy(d + 27, &sess->session_id, 8);

    p->len = 24 + payload_len;
    memcpy(p->addr, peer_addr, sizeof(*peer_addr));
    p->addr_len = sizeof(*peer_addr);
    ring_push(&txq->control, p);

    sess->hop_target_port = new_port;
    printf("[PORT_HOP] request sent: hop to port %u\n", new_port);
    return 0;
}

int port_hop_send_ack(session_t* sess, tx_queues_t* txq,
                      struct sockaddr_in6* peer_addr,
                      uint32_t* seq_counter)
{
    packet_buf_t* p = pool_get();
    if (!p) return -1;

    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1, flags = 0;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1 + 8;
    uint8_t opcode = CTRL_PORT_HOP_ACK;

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
    memcpy(p->addr, peer_addr, sizeof(*peer_addr));
    p->addr_len = sizeof(*peer_addr);
    ring_push(&txq->control, p);

    printf("[PORT_HOP] ack sent\n");
    return 0;
}

int port_hop_handle(packet_buf_t* p, session_t* sess)
{
    if (!p || !sess || p->len < 25) return 0;
    uint8_t opcode = p->data[24];

    if (opcode == CTRL_PORT_HOP) {
        if (p->len < 24 + 11) return -1;
        uint16_t new_port;
        memcpy(&new_port, p->data + 25, 2);
        new_port = ntohs(new_port);

        printf("[PORT_HOP] received request: peer hopping to port %u\n", new_port);
        sess->hop_target_port = new_port;

        struct sockaddr_in6 new_addr;
        memcpy(&new_addr, sess->addr, sizeof(new_addr));
        new_addr.sin6_port = htons(new_port);
        session_register_path(sess, sess->resilience.path_count, &new_addr, sizeof(new_addr));
        if (sess->resilience.path_count < RESILIENCE_MAX_PATHS)
            sess->resilience.path_count++;
        memcpy(sess->addr, &new_addr, sizeof(new_addr));
        sess->addr_len = sizeof(new_addr);

        return 1;
    }

    if (opcode == CTRL_PORT_HOP_ACK) {
        if (p->len < 24 + 9) return -1;
        printf("[PORT_HOP] ack received: hop confirmed\n");
        return 2;
    }

    return 0;
}
