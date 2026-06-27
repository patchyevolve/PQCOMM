#include "transport_api.h"
#include "packet.h"
#include "session.h"
#include <string.h>
#include <stdlib.h>

packet_buf_t* build_test_packet(uint32_t magic, uint8_t version, uint8_t flags,
                                 uint64_t session_id, uint8_t channel, uint32_t seq,
                                 const uint8_t* payload, uint32_t payload_len)
{
    packet_buf_t* p = (packet_buf_t*)malloc(sizeof(packet_buf_t));
    if (!p) return NULL;
    memset(p, 0, sizeof(*p));
    uint8_t* d = p->data;
    memcpy(d + 0, &magic, 4);
    memcpy(d + 4, &version, 1);
    memcpy(d + 5, &flags, 1);
    memcpy(d + 6, &session_id, 8);
    memcpy(d + 14, &channel, 1);
    memcpy(d + 15, &seq, 4);
    memcpy(d + 19, &payload_len, 4);
    if (payload && payload_len > 0)
        memcpy(d + 24, payload, payload_len);
    p->len = 24 + payload_len;
    return p;
}

void free_test_packet(packet_buf_t* p)
{
    free(p);
}
