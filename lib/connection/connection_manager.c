#include "connection_manager.h"
#include <string.h>
#include <stdio.h>

static peer_t g_peers[MAX_PEERS];
static int g_peer_count = 0;

int connection_manager_init(void)
{
    memset(g_peers, 0, sizeof(g_peers));
    g_peer_count = 0;
    return 0;
}

void connection_manager_shutdown(void)
{
}

int connection_manager_connect(const char* addr_str, uint16_t port)
{
    (void)addr_str;
    (void)port;
    return -1;
}

int connection_manager_disconnect(void)
{
    return -1;
}

peer_t* connection_manager_get_peers(int* count)
{
    if (count) *count = g_peer_count;
    return g_peers;
}
