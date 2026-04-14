#include "packet_view.h"
#include <string.h>

#define  HEADER_MIN_SIZE 24

int packet_parse(packet_buf_t* buf, packet_view_t* out)
{
    if(!buf || !out)
    {
        return -1;
    }

    if(buf->len < HEADER_MIN_SIZE)
    {
        return -1;
    }

    uint8_t* d = buf->data;

    out->buf = buf;

    //very temp layout
    memcpy(&out->magic,      d + 0,  4);
    memcpy(&out->version,    d + 4,  1);
    memcpy(&out->flags,      d + 5,  1);
    memcpy(&out->session_id, d + 6,  8);
    memcpy(&out->channel_id, d + 14, 1);
    memcpy(&out->seq,        d + 15, 4);
    memcpy(&out->length,     d + 19, 4);

    if (out->length > MAX_PACKET_SIZE - HEADER_MIN_SIZE)
        return -1;

    // packet must match exact size
    if (buf->len != HEADER_MIN_SIZE + out->length)
        return -1;

    out->payload = d + HEADER_MIN_SIZE;

    return 0;
}


