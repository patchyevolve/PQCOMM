#include "transport_api.h"
#include <string.h>
#include <stdio.h>

int transport_init(const transport_config_t* config)
{
    (void)config;
    return 0;
}

void transport_shutdown(void)
{
}

int transport_connect(const char* addr_str, uint16_t port)
{
    (void)addr_str;
    (void)port;
    return -1;
}

int transport_disconnect(void)
{
    return -1;
}

int transport_send_chat(const char* text)
{
    (void)text;
    return -1;
}

void transport_get_connection_info(conn_info_t* info)
{
    memset(info, 0, sizeof(*info));
    info->state = CONN_IDLE;
}

int transport_poll_event(transport_event_t* ev)
{
    (void)ev;
    return 0;
}

int transport_port_hop(uint16_t new_port)
{
    (void)new_port;
    return -1;
}

int transport_set_fec_enabled(int enabled)
{
    (void)enabled;
    return -1;
}

int transport_discovery_scan(void)
{
    return -1;
}

int transport_get_peer_list(peer_entry_t* entries, int max_entries)
{
    (void)entries;
    (void)max_entries;
    return 0;
}
