#include "offensive.h"
#include "config.h"
#include "packet.h"
#include "session.h"
#include "pool.h"
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

offensive_t g_offensive;

void offensive_init(void)
{
    memset(&g_offensive, 0, sizeof(g_offensive));
    g_offensive.reserve_pool = 64;
}

static off_source_t* off_find_or_create(const uint8_t* addr, uint16_t port)
{
    for (uint32_t i = 0; i < g_offensive.count; i++) {
        if (memcmp(g_offensive.sources[i].addr, addr, 16) == 0 &&
            g_offensive.sources[i].port == port)
            return &g_offensive.sources[i];
    }

    if (g_offensive.count >= OFF_MAX_SOURCES) {
        /* evict oldest */
        uint32_t oldest = 0;
        uint64_t oldest_time = g_offensive.sources[0].window_start_ms;
        for (uint32_t i = 1; i < g_offensive.count; i++) {
            if (g_offensive.sources[i].window_start_ms < oldest_time) {
                oldest = i;
                oldest_time = g_offensive.sources[i].window_start_ms;
            }
        }
        g_offensive.sources[oldest] = g_offensive.sources[g_offensive.count - 1];
        g_offensive.count--;
    }

    off_source_t* s = &g_offensive.sources[g_offensive.count++];
    memset(s, 0, sizeof(*s));
    memcpy(s->addr, addr, 16);
    s->port = port;
    s->window_start_ms = (uint64_t)time(NULL) * 1000;
    return s;
}

static int off_rate_limited(off_source_t* s)
{
    uint64_t now_ms = (uint64_t)time(NULL) * 1000;
    if (now_ms - s->window_start_ms > OFF_WINDOW_MS) {
        s->rate_count = 0;
        s->window_start_ms = now_ms;
    }
    s->rate_count++;
    return s->rate_count > OFF_THRESHOLD;
}

int offensive_check(packet_view_t* p)
{
    if (!p || !p->buf) return 0;

    /* extract source */
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

    off_source_t* s = off_find_or_create(src_addr, src_port);
    if (!s) return 0;

    /* rate limit: if source exceeds threshold, return pass (let later layers drop) */
    /* trust check: matched session + known channel — bypass offense per RULE-4 */
    if (p->session_id != 0 && p->channel_id >= 1 && p->channel_id <= 5 &&
        p->magic == 0xAABBCCDD && p->version == 1) {
        /* trusted packet — always bypass (RULE-4) */
        return 0;
    }

    if (off_rate_limited(s)) {
        /* source exceeds rate — drop but don't decoy (preserve resources) */
        return -1;
    }

    /* This is an unknown/untrusted packet. Let it through for anti-analysis scoring.
       Offensive action (decoy handshake, noise) is handled outside the fast path. */
    return 0;
}
