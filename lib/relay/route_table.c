#include "route_table.h"
#include <string.h>

void route_table_init(route_table_t* rt)
{
    memset(rt, 0, sizeof(route_table_t));
}

int route_table_add(route_table_t* rt, uint64_t node_id, uint64_t session_id,
                    struct sockaddr_in6* addr, uint32_t addr_len)
{
    if (!rt || node_id == 0) return -1;
    route_entry_t* existing = route_table_find(rt, node_id);
    if (existing) {
        existing->session_id = session_id;
        if (addr) {
            memcpy(&existing->addr, addr, sizeof(existing->addr));
            existing->addr_len = addr_len;
        }
        existing->loss_rate = 0.0f;
        existing->rtt_ns = 0;
        return 1;
    }
    if (rt->count >= MAX_ROUTES) return -1;
    route_entry_t* e = &rt->entries[rt->count++];
    e->node_id = node_id;
    e->session_id = session_id;
    if (addr) {
        memcpy(&e->addr, addr, sizeof(e->addr));
        e->addr_len = addr_len;
    }
    e->loss_rate = 0.0f;
    e->rtt_ns = 0;
    e->valid = 1;
    return 0;
}

int route_table_remove(route_table_t* rt, uint64_t node_id)
{
    if (!rt) return -1;
    for (uint32_t i = 0; i < rt->count; i++) {
        if (rt->entries[i].node_id == node_id) {
            rt->entries[i].valid = 0;
            rt->entries[i] = rt->entries[--rt->count];
            return 0;
        }
    }
    return -1;
}

route_entry_t* route_table_find(route_table_t* rt, uint64_t node_id)
{
    if (!rt) return NULL;
    for (uint32_t i = 0; i < rt->count; i++) {
        if (rt->entries[i].valid && rt->entries[i].node_id == node_id)
            return &rt->entries[i];
    }
    return NULL;
}

void route_table_update_metrics(route_table_t* rt, uint64_t node_id, float loss_rate, uint64_t rtt_ns)
{
    route_entry_t* e = route_table_find(rt, node_id);
    if (!e) return;
    e->loss_rate = e->loss_rate > 0.0f ? (e->loss_rate * 7.0f + loss_rate) / 8.0f : loss_rate;
    e->rtt_ns = e->rtt_ns > 0 ? (e->rtt_ns * 7 + rtt_ns) / 8 : rtt_ns;
}
