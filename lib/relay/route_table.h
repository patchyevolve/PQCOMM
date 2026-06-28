#pragma once
#include <stdint.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

#define MAX_ROUTES 16
#define RELAY_NODE_ID_UNKNOWN 0

typedef struct {
    uint64_t node_id;
    uint64_t session_id;
    struct sockaddr_in6 addr;
    uint32_t addr_len;
    float loss_rate;
    uint64_t rtt_ns;
    uint8_t valid;
} route_entry_t;

typedef struct {
    route_entry_t entries[MAX_ROUTES];
    uint32_t count;
} route_table_t;

void route_table_init(route_table_t* rt);
int route_table_add(route_table_t* rt, uint64_t node_id, uint64_t session_id,
                    struct sockaddr_in6* addr, uint32_t addr_len);
int route_table_remove(route_table_t* rt, uint64_t node_id);
route_entry_t* route_table_find(route_table_t* rt, uint64_t node_id);
void route_table_update_metrics(route_table_t* rt, uint64_t node_id, float loss_rate, uint64_t rtt_ns);
