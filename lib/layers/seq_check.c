#include "seq_check.h"

#define W REPLAY_WINDOW_SIZE

static int seq_check_bitmap(uint32_t seq, uint32_t* last_seq, uint64_t* bitmap)
{
    if (seq == 0) return -1;

    if (*last_seq == 0) {
        *last_seq = seq;
        *bitmap = 1ULL;
        return 0;
    }

    if (seq > *last_seq) {
        uint32_t diff = seq - *last_seq;
        if (diff >= W)
            *bitmap = 0;
        else
            *bitmap <<= diff;

        *bitmap |= 1ULL;
        *last_seq = seq;
        return 0;
    }

    uint32_t offset = *last_seq - seq;
    if (offset >= W)
        return -1;

    if (*bitmap == 0)
        *bitmap = 1;

    uint64_t mask = (1ULL << offset);
    if (*bitmap & mask)
        return -1;

    *bitmap |= mask;
    return 0;
}

int seq_check(session_t* s, packet_view_t* p)
{
    uint32_t seq = p->seq;
    if (seq == 0) return -1;

    /* per-path seq when multipath enabled */
    if (s->resilience.multipath_enabled && p->path_idx < s->resilience.path_count) {
        path_metrics_t* path = &s->resilience.paths[p->path_idx];
        return seq_check_bitmap(seq, &path->last_seq, &path->recv_bitmap);
    }

    /* single-path: use session level */
    return seq_check_bitmap(seq, &s->last_seq, &s->recv_bitmap);
}
