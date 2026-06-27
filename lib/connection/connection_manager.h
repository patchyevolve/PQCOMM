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
    peer_state_t state;
    uint8_t is_online;
    uint64_t last_seen_ms;
} peer_t;

int connection_manager_init(void);
void connection_manager_shutdown(void);
int connection_manager_connect(const char* addr_str, uint16_t port);
int connection_manager_disconnect(void);
peer_t* connection_manager_get_peers(int* count);
