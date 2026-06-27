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
    g_peer_count = 0;
}

static peer_t* find_peer(const char* addr_str, uint16_t port)
{
    for (int i = 0; i < g_peer_count; i++) {
        if (g_peers[i].port == port && strcmp(g_peers[i].addr_str, addr_str) == 0)
            return &g_peers[i];
    }
    return NULL;
}

int connection_manager_connect(const char* addr_str, uint16_t port)
{
    if (!addr_str) return -1;

    peer_t* p = find_peer(addr_str, port);
    if (p) {
        p->state = PEER_CONNECTING;
        p->is_online = 1;
        return 0;
    }

    if (g_peer_count >= MAX_PEERS) return -1;

    p = &g_peers[g_peer_count++];
    snprintf(p->addr_str, sizeof(p->addr_str), "%s", addr_str);
    p->port = port;
    p->state = PEER_CONNECTING;
    p->is_online = 1;
    p->last_seen_ms = 0;
    return 0;
}

int connection_manager_disconnect(void)
{
    for (int i = 0; i < g_peer_count; i++) {
        if (g_peers[i].state == PEER_LOCKED || g_peers[i].state == PEER_HANDSHAKE) {
            g_peers[i].state = PEER_DISCONNECTED;
            g_peers[i].is_online = 0;
        }
    }
    return 0;
}

void connection_manager_update_state(const char* addr_str, uint16_t port, peer_state_t state)
{
    peer_t* p = find_peer(addr_str, port);
    if (p) {
        p->state = state;
        if (state == PEER_LOCKED || state == PEER_HANDSHAKE)
            p->is_online = 1;
    }
}

peer_t* connection_manager_get_peers(int* count)
{
    if (count) *count = g_peer_count;
    return g_peers;
}

int connection_manager_peer_count(void)
{
    return g_peer_count;
}

void connection_manager_set_username(const char* addr_str, uint16_t port, const char* username)
{
    peer_t* p = find_peer(addr_str, port);
    if (p && username) {
        snprintf(p->username, sizeof(p->username), "%s", username);
    }
}

void connection_manager_mark_stale(uint64_t now_ms, uint64_t timeout_ms)
{
    for (int i = 0; i < g_peer_count; i++) {
        if (g_peers[i].is_online && g_peers[i].last_seen_ms > 0 &&
            (now_ms - g_peers[i].last_seen_ms) > timeout_ms &&
            g_peers[i].state != PEER_LOCKED && g_peers[i].state != PEER_HANDSHAKE) {
            g_peers[i].is_online = 0;
        }
    }
}

void connection_manager_update_last_seen(const char* addr_str, uint16_t port, uint64_t now_ms)
{
    peer_t* p = find_peer(addr_str, port);
    if (p) {
        p->last_seen_ms = now_ms;
        p->is_online = 1;
    }
}
