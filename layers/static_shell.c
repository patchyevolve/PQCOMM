#include "static_shell.h"
#include "channel.h"

#define PROTO_MAGIC  0xAABBCCDD
#define PROTO_VERSION 1
#define HEADER_MIN_SIZE 24

int static_check(packet_view_t* p)
{
    if(!p)
    {
        return -1;
    }

    // magic check
    if (p->magic != PROTO_MAGIC)
        return -1;

    // version check
    if (p->version != PROTO_VERSION)
        return -1;

    // length check
    if (p->length == 0)
        return -1;

    if (p->length > 1400)   // sanity bound (< MTU)
        return -1;

    // flags sanity (for now: only 0 allowed)
    if (p->flags != 0)
        return -1;

    if(p->channel_id < CH_CONTROL || p->channel_id > CH_ROUTE)
        return -1;

    if(p->seq == 0)
        return -1;

    return 0;
}