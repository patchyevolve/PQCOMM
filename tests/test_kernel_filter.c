#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "kernel_filter.h"

static void v4_in_v6(const uint8_t* v4, uint8_t* out)
{
    memset(out, 0, 16);
    out[10] = 0xFF;
    out[11] = 0xFF;
    memcpy(out + 12, v4, 4);
}

int test_kf_whitelist(void)
{
    kernel_filter_init();

    uint8_t allowed[16] = {0};
    allowed[15] = 1;
    kernel_filter_whitelist_add(allowed);

    /* packet_view_t with matching addr */
    packet_buf_t buf;
    memset(&buf, 0, sizeof(buf));
    buf.len = 24;
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_addr.s6_addr[15] = 1;
    memcpy(buf.addr, &sa, sizeof(sa));
    buf.addr_len = sizeof(sa);

    packet_view_t view;
    memset(&view, 0, sizeof(view));
    view.buf = &buf;

    if (kernel_filter_check(&view) != 0) return -1;

    /* different addr should fail */
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_addr.s6_addr[15] = 2;
    memcpy(buf.addr, &sa, sizeof(sa));

    if (kernel_filter_check(&view) == 0) return -2;

    return 0;
}

int test_kf_blocklist(void)
{
    kernel_filter_init();

    uint8_t blocked[16] = {0};
    blocked[15] = 10;
    kernel_filter_blocklist_add(blocked);

    packet_buf_t buf;
    memset(&buf, 0, sizeof(buf));
    buf.len = 24;
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_addr.s6_addr[15] = 10;
    memcpy(buf.addr, &sa, sizeof(sa));
    buf.addr_len = sizeof(sa);

    packet_view_t view;
    memset(&view, 0, sizeof(view));
    view.buf = &buf;

    if (kernel_filter_check(&view) == 0) return -1;

    /* non-blocked addr should pass */
    sa.sin6_addr.s6_addr[15] = 20;
    memcpy(buf.addr, &sa, sizeof(sa));

    if (kernel_filter_check(&view) != 0) return -2;

    return 0;
}

int test_kf_size(void)
{
    kernel_filter_init();

    packet_buf_t buf;
    memset(&buf, 0, sizeof(buf));
    buf.len = 10;

    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    memcpy(buf.addr, &sa, sizeof(sa));
    buf.addr_len = sizeof(sa);

    packet_view_t view;
    memset(&view, 0, sizeof(view));
    view.buf = &buf;

    if (kernel_filter_check(&view) == 0) return -1;

    return 0;
}

int test_kf_port(void)
{
    kernel_filter_init();
    kernel_filter_set_bound_port(9002);

    packet_buf_t buf;
    memset(&buf, 0, sizeof(buf));
    buf.len = 24;

    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(9002);
    memcpy(buf.addr, &sa, sizeof(sa));
    buf.addr_len = sizeof(sa);

    packet_view_t view;
    memset(&view, 0, sizeof(view));
    view.buf = &buf;

    if (kernel_filter_check(&view) != 0) return -1;

    /* wrong port should fail */
    sa.sin6_port = htons(9999);
    memcpy(buf.addr, &sa, sizeof(sa));

    if (kernel_filter_check(&view) == 0) return -2;

    return 0;
}
