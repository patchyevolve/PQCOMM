#include "packet_view.h"
#include <string.h>

int packet_parse(packet_buf_t* buf, packet_view_t* out)
{
    if (!buf || !out)
        return -1;

    if (buf->len < HEADER_SIZE)
        return -1;

    uint8_t* d = buf->data;

    out->buf = buf;

    memcpy(&out->magic,      d + 0,  4);
    memcpy(&out->version,    d + 4,  1);
    memcpy(&out->flags,      d + 5,  1);
    memcpy(&out->session_id, d + 6,  8);
    memcpy(&out->channel_id, d + 14, 1);
    memcpy(&out->seq,        d + 15, 4);
    memcpy(&out->length,     d + 19, 4);

    if (out->length > MAX_PACKET_SIZE - HEADER_SIZE)
        return -1;

    if (buf->len != HEADER_SIZE + out->length)
        return -1;

    out->encrypted = (out->flags & PACKET_FLAG_ENCRYPTED) ? 1 : 0;

    uint32_t offset = HEADER_SIZE;

    if (out->encrypted) {
        if (out->length < AEAD_NONCE_SIZE + AEAD_TAG_SIZE)
            return -1;
        memcpy(out->nonce, d + offset, AEAD_NONCE_SIZE);
        offset += AEAD_NONCE_SIZE;
        out->length -= AEAD_NONCE_SIZE + AEAD_TAG_SIZE;
    }

    out->payload = d + offset;

    if (out->encrypted) {
        memcpy(out->tag, d + offset + out->length, AEAD_TAG_SIZE);
    }

    return 0;
}
