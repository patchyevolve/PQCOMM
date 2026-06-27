#pragma once
#include <stdint.h>

#define RESILIENCE_MAX_PATHS 4

typedef enum {
    CONN_IDLE,
    CONN_CONNECTING,
    CONN_HANDSHAKE,
    CONN_LOCKED,
    CONN_FAILED
} conn_state_t;

typedef struct {
    float loss_rate;
    uint64_t rtt_ns;
    uint32_t packets_sent;
    uint32_t packets_recv;
} path_info_t;

typedef struct {
    conn_state_t state;
    uint64_t session_id;
    char peer_addr[64];
    uint16_t peer_port;
    uint32_t uptime_ms;
    int fec_enabled;
    uint32_t fec_recovered_count;
    uint32_t path_count;
    path_info_t paths[RESILIENCE_MAX_PATHS];
} conn_info_t;

typedef struct {
    uint16_t local_port;
    uint16_t local_port_alt;
    uint16_t discovery_port;
    int discovery_enabled;
    int fec_enabled;
    uint8_t fec_group_size;
    uint8_t multipath_enabled;
    uint32_t path_count;
    uint32_t handshake_timeout_ms;
    uint32_t heartbeat_interval_ms;
    uint32_t reconnect_timeout_ms;
    uint32_t max_reconnect_attempts;
} transport_config_t;

typedef enum {
    EVENT_NONE,
    EVENT_CONNECTION_STATE_CHANGED,
    EVENT_CHAT_RECEIVED,
    EVENT_PEER_DISCOVERED,
    EVENT_STATS_UPDATE,
    EVENT_ERROR,
} transport_event_type_t;

typedef struct {
    transport_event_type_t type;
    uint64_t timestamp_ms;
    union {
        struct { conn_state_t old_state; conn_state_t new_state; } conn_state;
        struct { char text[1024]; uint16_t sender_port; } chat;
        struct { char addr[64]; uint16_t port; } peer;
        struct { char message[256]; } error;
        struct { conn_info_t info; } stats;
    } data;
} transport_event_t;

typedef struct {
    char addr[64];
    uint16_t port;
    uint8_t is_online;
    uint64_t last_seen_ms;
    uint8_t is_connected;
} peer_entry_t;

int transport_init(const transport_config_t* config);
void transport_shutdown(void);
int transport_connect(const char* addr_str, uint16_t port);
int transport_disconnect(void);
int transport_send_chat(const char* text);
void transport_get_connection_info(conn_info_t* info);
int transport_poll_event(transport_event_t* ev);
int transport_port_hop(uint16_t new_port);
int transport_set_fec_enabled(int enabled);
int transport_discovery_scan(void);
int transport_get_peer_list(peer_entry_t* entries, int max_entries);

int transport_engine_run_demo(void);
