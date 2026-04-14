#include "pipeline_selftest.h"

#include <string.h>

#include "pool.h"
#include "channel.h"

static void build_test_header(packet_buf_t* p,
                              uint32_t magic,
                              uint8_t version,
                              uint8_t flags,
                              uint64_t session_id,
                              uint8_t channel,
                              uint32_t seq,
                              uint32_t length)
{
    uint8_t* d = p->data;
    memcpy(d + 0,  &magic, 4);
    memcpy(d + 4,  &version, 1);
    memcpy(d + 5,  &flags, 1);
    memcpy(d + 6,  &session_id, 8);
    memcpy(d + 14, &channel, 1);
    memcpy(d + 15, &seq, 4);
    memcpy(d + 19, &length, 4);
}

void pipeline_enqueue_phase1_selftests(spsc_ring_t* rx_ring)
{
    packet_buf_t* p;

    // 1) PARSE drop: too-short packet
    p = pool_get();
    if (p) {
        p->len = 8; // < header size (24)
        p->addr_len = 0;
        ring_push(rx_ring, p);
    }

    // 2) STATIC drop: bad magic with otherwise parseable header
    p = pool_get();
    if (p) {
        build_test_header(p, 0xDEADBEEF, 1, 0, 0, CH_CONTROL, 1, 1);
        p->data[24] = 0xAA;
        p->len = 25;
        p->addr_len = 0;
        ring_push(rx_ring, p);
    }

    // 3) SESSION drop: non-control before lock
    p = pool_get();
    if (p) {
        build_test_header(p, 0xAABBCCDD, 1, 0, 0, CH_AUDIO, 1, 1);
        p->data[24] = 0xBB;
        p->len = 25;
        p->addr_len = 0;
        ring_push(rx_ring, p);
    }
}

void pipeline_enqueue_seq_duplicate_probe(spsc_ring_t* rx_ring, session_t* sess)
{
    packet_buf_t* p1 = pool_get();
    packet_buf_t* p2 = pool_get();
    uint32_t test_seq = 5000;

    if (!p1 || !p2) {
        if (p1) pool_return(p1);
        if (p2) pool_return(p2);
        return;
    }

    build_test_header(p1, 0xAABBCCDD, 1, 0, sess->session_id, CH_CHAT, test_seq, 1);
    p1->data[24] = 'X';
    p1->len = 25;
    memcpy(p1->addr, sess->addr, sess->addr_len);
    p1->addr_len = sess->addr_len;

    build_test_header(p2, 0xAABBCCDD, 1, 0, sess->session_id, CH_CHAT, test_seq, 1);
    p2->data[24] = 'Y';
    p2->len = 25;
    memcpy(p2->addr, sess->addr, sess->addr_len);
    p2->addr_len = sess->addr_len;

    ring_push(rx_ring, p1); // first should pass
    ring_push(rx_ring, p2); // duplicate seq should drop
}
