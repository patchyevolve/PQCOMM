#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "offensive.h"

int test_off_trusted_bypass(void)
{
    offensive_init();

    packet_buf_t buf;
    memset(&buf, 0, sizeof(buf));
    buf.len = 24;

    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_addr.s6_addr[15] = 1;
    sa.sin6_port = htons(1234);
    memcpy(buf.addr, &sa, sizeof(sa));
    buf.addr_len = sizeof(sa);

    packet_view_t view;
    memset(&view, 0, sizeof(view));
    view.buf = &buf;
    view.magic = 0xAABBCCDD;
    view.version = 1;
    view.flags = 0x01;
    view.channel_id = 3;
    view.seq = 100;
    view.session_id = 12345;

    /* trusted packet bypasses offense per RULE-4 */
    if (offensive_check(&view) != 0) return -1;

    return 0;
}

int test_off_repeated_unknown(void)
{
    offensive_init();

    packet_buf_t buf;
    memset(&buf, 0, sizeof(buf));
    buf.len = 24;

    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_addr.s6_addr[15] = 2;
    sa.sin6_port = htons(1235);
    memcpy(buf.addr, &sa, sizeof(sa));
    buf.addr_len = sizeof(sa);

    packet_view_t view;
    memset(&view, 0, sizeof(view));
    view.buf = &buf;
    view.magic = 0;
    view.version = 0;
    view.channel_id = 0;
    view.seq = 0;

    /* first OFF_THRESHOLD packets should pass through (rate limit not hit yet) */
    int passed = 0;
    for (int i = 0; i < OFF_THRESHOLD; i++) {
        if (offensive_check(&view) == 0) passed++;
    }
    if (passed != OFF_THRESHOLD) return -1;

    /* next should be rate-limited (dropped) */
    if (offensive_check(&view) == 0) return -2;

    return 0;
}
