#include "relay.h"
#include "channel.h"
#include "pool.h"
#include "ring.h"
#include "packet.h"
#include "packet_view.h"
#include "packet_parse.h"
#include "session_enc.h"
#include <stdio.h>
#include <string.h>

int relay_forward_route(packet_buf_t* p, packet_view_t* view,
                        session_t* local_sess,
                        route_table_t* rt, uint32_t* seq_counter,
                        tx_queues_t* txq, struct sockaddr_in6* peer_addr)
{
    if (!p || !view || !local_sess || !rt) return 0;
    if (view->length < 1 + 8 + 1) return 0;

    uint8_t* route_payload = view->payload;
    uint8_t opcode = route_payload[0];
    if (opcode != CTRL_ROUTE_DATA) return 0;

    uint64_t dest_node_id;
    memcpy(&dest_node_id, route_payload + 1, 8);
    if (dest_node_id == RELAY_NODE_ID_UNKNOWN) return 0;

    route_entry_t* entry = route_table_find(rt, dest_node_id);
    if (!entry) {
        printf("[RELAY] no route to node %lu\n", (unsigned long)dest_node_id);
        return 1;
    }

    uint8_t inner_channel = route_payload[9];
    uint32_t inner_len = view->length - 1 - 8 - 1;
    if (inner_len > 1024) inner_len = 1024;
    uint8_t* inner_data = route_payload + 10;

    packet_buf_t* fwd = pool_get();
    if (!fwd) return 1;

    uint32_t magic = PROTO_MAGIC;
    uint8_t ver = 1, flags = 0;
    uint32_t seq = (*seq_counter)++;
    uint32_t plen = inner_len;

    memset(fwd->data, 0, 24);
    memcpy(fwd->data + 0, &magic, 4);
    memcpy(fwd->data + 4, &ver, 1);
    memcpy(fwd->data + 5, &flags, 1);
    memcpy(fwd->data + 6, &local_sess->session_id, 8);
    memcpy(fwd->data + 14, &inner_channel, 1);
    memcpy(fwd->data + 15, &seq, 4);
    memcpy(fwd->data + 19, &plen, 4);
    memcpy(fwd->data + 24, inner_data, inner_len);
    fwd->len = 24 + plen;

    packet_view_t fwd_view = { 0 };
    if (packet_parse(fwd, &fwd_view) != 0) {
        pool_return(fwd);
        return 1;
    }

    if (session_enc_apply(fwd, &fwd_view, local_sess) != 0) {
        pool_return(fwd);
        return 1;
    }

    memcpy(fwd->addr, peer_addr, sizeof(*peer_addr));
    fwd->addr_len = sizeof(*peer_addr);
    if (ring_push(&txq->chat, fwd) != 0) { pool_return(fwd); return 1; }

    printf("[RELAY] forwarded seq=%u to node %lu ch=%u (%u bytes)\n",
           seq, (unsigned long)dest_node_id, inner_channel, inner_len);
    return 1;
}

int relay_build_test_packet(session_t* sess, uint32_t* seq_counter,
                            uint64_t dest_node_id,
                            const char* message,
                            packet_buf_t** out)
{
    if (!sess || !seq_counter || !message || !out) return -1;

    packet_buf_t* p = pool_get();
    if (!p) return -1;

    uint32_t msg_len = (uint32_t)strlen(message) + 1;
    uint32_t route_hdr = 1 + 8 + 1;
    uint32_t plen = route_hdr + msg_len;
    uint32_t magic = PROTO_MAGIC;
    uint8_t ver = 1, flags = 0;
    uint8_t ch = CH_ROUTE;
    uint32_t seq = (*seq_counter)++;

    memset(p->data, 0, 24);
    memcpy(p->data + 0, &magic, 4);
    memcpy(p->data + 4, &ver, 1);
    memcpy(p->data + 5, &flags, 1);
    memcpy(p->data + 6, &sess->session_id, 8);
    memcpy(p->data + 14, &ch, 1);
    memcpy(p->data + 15, &seq, 4);
    memcpy(p->data + 19, &plen, 4);

    uint8_t* route = p->data + 24;
    route[0] = CTRL_ROUTE_DATA;
    memcpy(route + 1, &dest_node_id, 8);
    route[9] = CH_CHAT;
    memcpy(route + 10, message, msg_len);
    p->len = 24 + plen;

    packet_view_t view = { 0 };
    if (packet_parse(p, &view) != 0) {
        pool_return(p);
        return -1;
    }

    if (session_enc_apply(p, &view, sess) != 0) {
        pool_return(p);
        return -1;
    }

    *out = p;
    return 0;
}
