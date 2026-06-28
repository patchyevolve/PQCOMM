#include "kernel_filter.h"
#include "kernel_filter_bpf.h"
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "config.h"

kernel_filter_t g_kernel_filter;

void kernel_filter_init(void)
{
    memset(&g_kernel_filter, 0, sizeof(g_kernel_filter));
    g_kernel_filter.bound_port = 0;
}

static int addr_match(const uint8_t* a, const uint8_t* b)
{
    for (int i = 0; i < 16; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

int kernel_filter_whitelist_add(const uint8_t* addr)
{
    kernel_filter_t* kf = &g_kernel_filter;
    if (kf->whitelist_count >= KF_MAX_LIST) return -1;
    kf_addr_t* e = &kf->whitelist[kf->whitelist_count++];
    memcpy(e->addr, addr, 16);
    e->valid = 1;
    return 0;
}

int kernel_filter_blocklist_add(const uint8_t* addr)
{
    kernel_filter_t* kf = &g_kernel_filter;
    if (kf->blocklist_count >= KF_MAX_LIST) return -1;
    kf_addr_t* e = &kf->blocklist[kf->blocklist_count++];
    memcpy(e->addr, addr, 16);
    e->valid = 1;
    return 0;
}

void kernel_filter_set_bound_port(uint16_t port)
{
    g_kernel_filter.bound_port = port;
}

int kernel_filter_check(packet_view_t* p)
{
    kernel_filter_t* kf = &g_kernel_filter;
    if (!p || !p->buf) { kf->drops_size++; return -1; }

    /* size bounds check */
    if (p->buf->len < 24 || p->buf->len > MAX_PACKET_SIZE) {
        kf->drops_size++;
        return -1;
    }

    /* source address extraction from buf->addr (sockaddr_in6) */
    uint8_t* src_addr = NULL;
    uint16_t src_port = 0;
    if (p->buf->addr_len >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6* sa = (struct sockaddr_in6*)p->buf->addr;
        src_addr = (uint8_t*)&sa->sin6_addr;
        src_port = ntohs(sa->sin6_port);
    } else if (p->buf->addr_len >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* sa = (struct sockaddr_in*)p->buf->addr;
        /* map v4 to v6 */
        src_addr = (uint8_t*)&sa->sin_addr;
        src_port = ntohs(sa->sin_port);
    }

    /* whitelist check — if whitelist is non-empty, only whitelisted addrs pass */
    if (kf->whitelist_count > 0 && src_addr) {
        int whitelisted = 0;
        for (uint32_t i = 0; i < kf->whitelist_count; i++) {
            if (kf->whitelist[i].valid && addr_match(src_addr, kf->whitelist[i].addr)) {
                whitelisted = 1;
                break;
            }
        }
        if (!whitelisted) {
            kf->drops_blocked++;
            return -1;
        }
    }

    /* blocklist check */
    if (src_addr) {
        for (uint32_t i = 0; i < kf->blocklist_count; i++) {
            if (kf->blocklist[i].valid && addr_match(src_addr, kf->blocklist[i].addr)) {
                kf->drops_blocked++;
                return -1;
            }
        }
    }

    /* port binding check — if bound_port set, verify source port */
    if (kf->bound_port > 0 && src_port > 0 && src_port != kf->bound_port) {
        kf->drops_port++;
        return -1;
    }

    kf->passes++;
    return 0;
}

/* eBPF/XDP integration wrappers */

int kernel_filter_bpf_attach_iface(const char* ifname)
{
    if (kernel_filter_bpf_create_map() != 0) return -1;
    if (kernel_filter_bpf_load() != 0) return -1;
    if (kernel_filter_bpf_attach(ifname) != 0) return -1;
    return 0;
}

int kernel_filter_bpf_detach_iface(void)
{
    return kernel_filter_bpf_detach();
}

int kernel_filter_bpf_sync_state(void)
{
    kernel_filter_t* kf = &g_kernel_filter;
    uint32_t wl = kf->whitelist_count > 0 ? 1 : 0;
    uint32_t bl = kf->blocklist_count > 0 ? 1 : 0;
    return kernel_filter_bpf_sync(wl, bl);
}

int kernel_filter_bpf_loaded(void)
{
    return kernel_filter_bpf_is_attached();
}

void kernel_filter_bpf_cleanup(void)
{
    kernel_filter_bpf_shutdown();
}
