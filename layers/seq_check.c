#include "seq_check.h"

#define W REPLAY_WINDOW_SIZE

int seq_check(session_t* s, packet_view_t* p)
{
    uint32_t seq = p->seq;
    if (seq == 0) return -1;

    if (s->last_seq == 0) {
        s->last_seq = seq;
        s->recv_bitmap = 1ULL;
        return 0;
    }

    if (seq > s->last_seq) {
        uint32_t diff = seq - s->last_seq;
        if (diff >= W)
            s->recv_bitmap = 0;
        else
            s->recv_bitmap <<= diff;

        s->recv_bitmap |= 1ULL;
        s->last_seq = seq;
        return 0;
    }

    uint32_t offset = s->last_seq - seq;
    if (offset >= W)
        return -1;

    if (s->recv_bitmap == 0)
        s->recv_bitmap = 1;

    uint64_t mask = (1ULL << offset);
    if (s->recv_bitmap & mask)
        return -1;

    s->recv_bitmap |= mask;
    return 0;
}
