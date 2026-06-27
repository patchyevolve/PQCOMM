#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "anti_analysis.h"

int test_aa_clean_packet(void)
{
    anti_analysis_init();

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

    /* clean packet should pass */
    if (anti_analysis_check(&view) != 0) return -1;

    return 0;
}

int test_aa_bad_packet_scoring(void)
{
    anti_analysis_init();

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

    /* bad magic packets accumulate score */
    for (int i = 0; i < 15; i++) {
        view.magic = 0xDEADBEEF;
        view.version = 1;
        view.flags = 0;
        view.channel_id = 1;
        view.seq = i + 1;
        anti_analysis_check(&view);
    }

    /* score should now be 150 (15 * 10), which is >= 50 (medium) */
    /* the 10th+ call should return -1 */
    /* we already sent 15 bad, check that drops are registered */
    if (g_anti_analysis.drops_medium + g_anti_analysis.drops_high == 0) return -1;

    return 0;
}
