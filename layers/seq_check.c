#include "seq_check.h"

#define W REPLAY_WINDOW_SIZE

int seq_check(session_t* s, packet_view_t* p)
{

    uint32_t seq = p->seq;

    if (seq == 0)
        return -1;

    // bootstrap
    if (s->last_seq == 0)
    {
        s->last_seq = seq;
        s->recv_bitmap = 1ULL; // mark current seq
        return 0;
    }

    if (seq > s->last_seq)
    {
        uint32_t diff = seq - s->last_seq;

        if (diff >= W)
        {
            // jump beyond window → reset
            s->recv_bitmap = 0;
        }
        else
        {
            s->recv_bitmap <<= diff;
        }

        s->recv_bitmap |= 1ULL;   // mark newest
        s->last_seq = seq;
        return 0;
    }

    // seq <= last_seq
    uint32_t offset = s->last_seq - seq;

    if (offset >= W)
    {
        // too old
        return -1;
    }

    if (s->recv_bitmap == 0)
        s->recv_bitmap = 1;

    uint64_t mask = (1ULL << offset);

    if (s->recv_bitmap & mask)
    {
        // duplicate
        return -1;
    }

    // mark as received
    s->recv_bitmap |= mask;

    return 0;
}