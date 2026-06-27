#include "scheduler.h"

void tx_queues_init(tx_queues_t* q)
{
    ring_init(&q->control);
    ring_init(&q->audio);
    ring_init(&q->chat);
    ring_init(&q->file);
    ring_init(&q->video);
    ring_init(&q->fake);
}

packet_buf_t* scheduler_next(tx_queues_t* q)
{
    packet_buf_t* p;
    if ((p = ring_pop(&q->control))) return p;
    if ((p = ring_pop(&q->audio)))   return p;
    if ((p = ring_pop(&q->chat)))    return p;
    if ((p = ring_pop(&q->file)))    return p;
    if ((p = ring_pop(&q->video)))   return p;
    return ring_pop(&q->fake);
}
