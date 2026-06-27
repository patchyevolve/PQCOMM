#include <string.h>
#include "route_table.h"

int test_route_table_add_find(void)
{
    route_table_t rt;
    route_table_init(&rt);

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;

    int ret = route_table_add(&rt, 42, 1001, &addr, sizeof(addr));
    if (ret != 0) return -1;

    ret = route_table_add(&rt, 99, 2002, &addr, sizeof(addr));
    if (ret != 0) return -2;

    route_entry_t* e = route_table_find(&rt, 42);
    if (!e) return -3;
    if (e->node_id != 42) return -4;
    if (e->session_id != 1001) return -5;

    e = route_table_find(&rt, 99);
    if (!e) return -6;
    if (e->node_id != 99) return -7;

    e = route_table_find(&rt, 999);
    if (e) return -8;

    return 0;
}

int test_route_table_remove(void)
{
    route_table_t rt;
    route_table_init(&rt);

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;

    route_table_add(&rt, 10, 500, &addr, sizeof(addr));
    route_table_add(&rt, 20, 600, &addr, sizeof(addr));
    route_table_add(&rt, 30, 700, &addr, sizeof(addr));

    if (rt.count != 3) return -1;

    int ret = route_table_remove(&rt, 20);
    if (ret != 0) return -2;

    if (rt.count != 2) return -3;
    if (route_table_find(&rt, 20)) return -4;
    if (!route_table_find(&rt, 10)) return -5;
    if (!route_table_find(&rt, 30)) return -6;

    ret = route_table_remove(&rt, 999);
    if (ret == 0) return -7;

    return 0;
}

int test_route_table_update_metrics(void)
{
    route_table_t rt;
    route_table_init(&rt);

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;

    route_table_add(&rt, 7, 300, &addr, sizeof(addr));
    route_table_update_metrics(&rt, 7, 0.05f, 500000);

    route_entry_t* e = route_table_find(&rt, 7);
    if (!e) return -1;
    if (e->loss_rate != 0.05f) return -2;
    if (e->rtt_ns != 500000) return -3;

    return 0;
}
