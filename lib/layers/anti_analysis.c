#include "anti_analysis.h"
#include "config.h"
#include "session.h"
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

anti_analysis_t g_anti_analysis;

void anti_analysis_init(void)
{
    memset(&g_anti_analysis, 0, sizeof(g_anti_analysis));
    g_anti_analysis.evict_interval_ms = 10000;
}

static int addr_port_match(aa_source_t* s, const uint8_t* addr, uint16_t port)
{
    for (int i = 0; i < 16; i++)
        if (s->addr[i] != addr[i]) return 0;
    return s->port == port;
}

static aa_source_t* aa_find_or_create(const uint8_t* addr, uint16_t port, uint64_t now_ms)
{
    anti_analysis_t* aa = &g_anti_analysis;

    for (uint32_t i = 0; i < aa->count; i++) {
        if (addr_port_match(&aa->sources[i], addr, port))
            return &aa->sources[i];
    }

    /* evict oldest if full */
    if (aa->count >= AA_MAX_SOURCES && now_ms - aa->last_evict_ms >= aa->evict_interval_ms) {
        uint32_t oldest = 0;
        uint64_t oldest_time = aa->sources[0].last_seen_ms;
        for (uint32_t i = 1; i < aa->count; i++) {
            if (aa->sources[i].last_seen_ms < oldest_time) {
                oldest = i;
                oldest_time = aa->sources[i].last_seen_ms;
            }
        }
        aa->sources[oldest] = aa->sources[aa->count - 1];
        aa->count--;
        aa->last_evict_ms = now_ms;
    }

    if (aa->count >= AA_MAX_SOURCES) return NULL;

    aa_source_t* s = &aa->sources[aa->count++];
    memset(s, 0, sizeof(*s));
    memcpy(s->addr, addr, 16);
    s->port = port;
    s->last_seen_ms = now_ms;
    return s;
}

int anti_analysis_check(packet_view_t* p)
{
    if (!p || !p->buf) return -1;

    uint64_t now_ms = (uint64_t)time(NULL) * 1000;

    /* extract source addr/port */
    uint8_t* src_addr = NULL;
    uint16_t src_port = 0;
    if (p->buf->addr_len >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6* sa = (struct sockaddr_in6*)p->buf->addr;
        src_addr = (uint8_t*)&sa->sin6_addr;
        src_port = ntohs(sa->sin6_port);
    } else if (p->buf->addr_len >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* sa = (struct sockaddr_in*)p->buf->addr;
        src_addr = (uint8_t*)&sa->sin_addr;
        src_port = ntohs(sa->sin_port);
    }

    if (!src_addr) return 0;

    aa_source_t* s = aa_find_or_create(src_addr, src_port, now_ms);
    if (!s) return 0;

    s->total_packets++;
    s->last_seen_ms = now_ms;

    /* score based on header anomalies */
    int is_bad = 0;

    /* bad magic */
    if (p->magic != 0xAABBCCDD) is_bad = 1;
    /* bad version */
    if (p->version != 1) is_bad = 1;
    /* bad flags */
    if (p->flags != 0 && p->flags != PACKET_FLAG_ENCRYPTED && p->flags != 0x02) is_bad = 1;
    /* channel range */ 
    if (p->channel_id < 1 || p->channel_id > 5) is_bad = 1;
    /* zero seq */
    if (p->seq == 0) is_bad = 1;

    if (is_bad) {
        s->bad_packets++;
        s->score = s->bad_packets * 10;
    } else {
        if (s->score > 0) s->score--;
    }

    /* actions by score threshold */
    if (s->score >= 100) {
        /* high: drop silently */
        g_anti_analysis.drops_high++;
        return -1;
    }

    if (s->score >= 50) {
        /* medium: delay by returning drop — caller can treat as transient */
        g_anti_analysis.drops_medium++;
        g_anti_analysis.delayed_packets++;
        return -1;
    }

    return 0;
}
