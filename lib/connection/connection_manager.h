#pragma once
#include <stdint.h>

#define MAX_PEERS 32

typedef enum {
    PEER_IDLE,
    PEER_CONNECTING,
    PEER_HANDSHAKE,
    PEER_LOCKED,
    PEER_DISCONNECTED
} peer_state_t;

typedef struct {
    char addr_str[64];
    uint16_t port;
    char username[32];
    peer_state_t state;
    uint8_t is_online;
    uint64_t last_seen_ms;
} peer_t;

int connection_manager_init(void);
void connection_manager_shutdown(void);
int connection_manager_connect(const char* addr_str, uint16_t port);
int connection_manager_disconnect(void);
void connection_manager_update_state(const char* addr_str, uint16_t port, peer_state_t state);
peer_t* connection_manager_get_peers(int* count);
int connection_manager_peer_count(void);
void connection_manager_set_username(const char* addr_str, uint16_t port, const char* username);
void connection_manager_mark_stale(uint64_t now_ms, uint64_t timeout_ms);
void connection_manager_update_last_seen(const char* addr_str, uint16_t port, uint64_t now_ms);
