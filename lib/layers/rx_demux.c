#include "rx_demux.h"
#include "channel.h"

void rx_queues_init(rx_queues_t* q)
{
    ring_init(&q->control);
    ring_init(&q->audio);
    ring_init(&q->chat);
    ring_init(&q->file);
    ring_init(&q->video);
    ring_init(&q->route);
}

int rx_demux_push(rx_queues_t* q, packet_buf_t* p, uint8_t channel)
{
    switch (channel) {
    case CH_CONTROL: return ring_push(&q->control, p);
    case CH_AUDIO:   return ring_push(&q->audio, p);
    case CH_CHAT:    return ring_push(&q->chat, p);
    case CH_FILE:    return ring_push(&q->file, p);
    case CH_VIDEO:   return ring_push(&q->video, p);
    case CH_ROUTE:   return ring_push(&q->route, p);
    default:         return -1;
    }
}