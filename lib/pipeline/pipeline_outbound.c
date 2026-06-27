#include "pipeline_outbound.h"
#include "packet_parse.h"
#include "session_enc.h"
#include "channel.h"
#include <string.h>

int pipeline_outbound_process(packet_buf_t* p, session_t* sess,
                              uint32_t seq, uint8_t channel,
                              const uint8_t* payload, uint32_t payload_len)
{
    if (!p || !sess) return -1;

    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1, flags = 0;
    uint32_t plen = payload_len;

    memset(d, 0, 24);
    memcpy(d + 0, &magic, 4);
    memcpy(d + 4, &version, 1);
    memcpy(d + 5, &flags, 1);
    memcpy(d + 6, &sess->session_id, 8);
    memcpy(d + 14, &channel, 1);
    memcpy(d + 15, &seq, 4);
    memcpy(d + 19, &plen, 4);
    if (payload && payload_len > 0)
        memcpy(d + 24, payload, payload_len);
    p->len = 24 + payload_len;

    if (channel != CH_CONTROL) {
        packet_view_t view = { 0 };
        if (packet_parse(p, &view) != 0) return -1;
        if (session_enc_apply(p, &view, sess) != 0) return -1;
    }

    return 0;
}
