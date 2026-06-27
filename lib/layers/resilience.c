#include "resilience.h"
#include "channel.h"
#include "pool.h"
#include <stdio.h>
#include <string.h>

static int try_rebuild(packet_view_t* p, session_t* sess)
{
    uint8_t recon_payload[FEC_MAX_PAYLOAD];
    uint32_t recon_len = 0;
    uint32_t recon_seq = 0;

    int ret = fec_rx_rebuild(&sess->resilience, recon_payload, &recon_len, &recon_seq);
    if (ret <= 0) return 0;

    packet_buf_t* rec = pool_get();
    if (!rec) return 0;

    uint8_t* d = rec->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t ver = 1;
    uint8_t fl = PACKET_FLAG_ENCRYPTED;
    uint8_t ch = sess->resilience.fec_rx_channel_id;
    uint64_t sid = sess->session_id;

    memset(d, 0, HEADER_SIZE);
    memcpy(d + 0, &magic, 4);
    memcpy(d + 4, &ver, 1);
    memcpy(d + 5, &fl, 1);
    memcpy(d + 6, &sid, 8);
    memcpy(d + 14, &ch, 1);
    memcpy(d + 15, &recon_seq, 4);
    uint32_t plen = recon_len;
    memcpy(d + 19, &plen, 4);
    memcpy(d + HEADER_SIZE, recon_payload, recon_len);
    rec->len = HEADER_SIZE + recon_len;
    memcpy(rec->addr, sess->addr, sizeof(sess->addr));
    rec->addr_len = sess->addr_len;

    sess->fec_recovered = rec;

    if (p) printf("[FEC] recovered seq=%u len=%u from parity\n", recon_seq, recon_len);
    return 1;
}

int resilience_check(packet_view_t* p, session_t* sess)
{
    if (!p || !sess) return -1;
    if (sess->state != SESSION_LOCKED) return 0;

    uint32_t path_idx = 0;
    resilience_record_rx(&sess->resilience, path_idx, 0);

    /* FEC: track data packets, attempt rebuild if parity already stored */
    if (sess->resilience.fec_enabled && p->encrypted && p->channel_id != CH_CONTROL) {
        uint32_t offset = HEADER_SIZE;
        uint32_t plen = p->buf->len > offset ? p->buf->len - offset : 0;
        fec_rx_track(&sess->resilience, p->seq, p->buf->data + offset, plen);
        try_rebuild(p, sess);
    }

    /* FEC: parity packet — store parity, attempt rebuild, then drop */
    if (p->flags & PACKET_FLAG_FEC_PARITY) {
        uint32_t offset = HEADER_SIZE;
        uint32_t plen = p->buf->len > offset ? p->buf->len - offset : 0;
        if (plen >= 6) {
            fec_rx_store_parity(&sess->resilience, p->buf->data + offset, plen);
            try_rebuild(p, sess);
        }
        pool_return(p->buf);
        return -1;
    }

    return 0;
}
