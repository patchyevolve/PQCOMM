#include "static_shell.h"
#include "channel.h"

#define PROTO_MAGIC   0xAABBCCDD
#define PROTO_VERSION 1

int static_check(packet_view_t* p)
{
    if (!p) return -1;

    if (p->magic != PROTO_MAGIC)
        return -1;
    if (p->version != PROTO_VERSION)
        return -1;
    if (p->length == 0 || p->length > 1400)
        return -1;
    uint8_t allowed_flags = PACKET_FLAG_ENCRYPTED | PACKET_FLAG_FEC_PARITY;
    if (p->flags & ~allowed_flags)
        return -1;
    if (p->channel_id < CH_CONTROL || p->channel_id > CH_ROUTE)
        return -1;
    if (p->seq == 0)
        return -1;

    return 0;
}
