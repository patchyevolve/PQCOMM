#include "offensive.h"
#include "config.h"
#include "packet.h"
#include "session.h"
#include "pool.h"
#include "kem.h"
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

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
    if (p->session_id != 0 && p->channel_id >= 1 && p->channel_id <= 6 &&
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

packet_buf_t* offensive_build_decoy(const struct sockaddr_in6* target)
{
    if (!target) return NULL;

    packet_buf_t* p = pool_get();
    if (!p) return NULL;

    uint8_t* d = p->data;
    uint32_t fake_magic = DECOY_MAGIC;
    uint8_t crap[16];
    kem_random_bytes(crap, sizeof(crap));

    memcpy(d + 0, &fake_magic, 4);
    memcpy(d + 4, crap, 12);
    uint32_t decoy_len = 24 + (crap[0] % 32);
    memset(d + 16, crap[1], decoy_len > 16 ? decoy_len - 16 : 0);
    p->len = decoy_len;

    memcpy(p->addr, target, sizeof(*target));
    p->addr_len = sizeof(*target);
    return p;
}

void offensive_tick(uint64_t now_ms)
{
    (void)now_ms;
    /* scan for rate-limited sources and bump counters for stats */
    for (uint32_t i = 0; i < g_offensive.count; i++) {
        off_source_t* s = &g_offensive.sources[i];
        if (s->rate_count > OFF_THRESHOLD / 2) {
            g_offensive.total_decoys++;
            break;
        }
    }
}
