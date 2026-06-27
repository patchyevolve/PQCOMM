/* ================================================================
 * SSM Secure Communication Transport — Public C API
 * Status: FROZEN — do not change function signatures or struct layouts
 * ================================================================
 *
 * Lifecycle:
 *   1. transport_init(config)         — one-time init, starts threads
 *   2. transport_connect(addr, port)  — initiate outbound connection
 *   3. transport_send_chat(text)      — send chat when locked
 *   4. transport_poll_event(ev)       — poll for events (non-blocking)
 *   5. transport_shutdown()           — cleanup
 *
 * Events are delivered via transport_poll_event(). Call in a loop.
 * All functions are thread-safe via the engine's lock-free design.
 */

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
    EVENT_CONNECT_REQUEST,
    EVENT_CONNECT_ACCEPTED,
    EVENT_CONNECT_DECLINED,
    EVENT_AUDIO_CALL_REQUEST,
    EVENT_AUDIO_CALL_ACCEPTED,
    EVENT_AUDIO_CALL_ENDED,
    EVENT_VIDEO_CALL_REQUEST,
    EVENT_VIDEO_CALL_ACCEPTED,
    EVENT_VIDEO_CALL_ENDED,
    EVENT_FILE_TRANSFER_REQUEST,
    EVENT_FILE_TRANSFER_PROGRESS,
    EVENT_FILE_TRANSFER_COMPLETE,
    EVENT_FILE_TRANSFER_FAILED,
    EVENT_TYPING,
    EVENT_DELIVERY_ACK,
    EVENT_READ_ACK,
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
        struct { char addr[64]; uint16_t port; char username[32]; char display_name[64]; } conn_req;
        struct { char peer_username[32]; } call_req;
        struct { char filename[256]; uint32_t total_size; uint32_t progress; } file;
        struct { char peer_username[32]; uint32_t seq; } typing;
        struct { uint32_t message_seq; } delivery_ack;
        struct { uint32_t message_seq; } read_ack;
    } data;
} transport_event_t;

typedef struct {
    char addr[64];
    uint16_t port;
    char username[32];
    uint8_t is_online;
    uint64_t last_seen_ms;
    uint8_t is_connected;
} peer_entry_t;

int transport_init(const transport_config_t* config);
void transport_shutdown(void);
int transport_connect(const char* addr_str, uint16_t port);
int transport_disconnect(void);
int transport_send_chat(const char* text);
int transport_send_connect_request(const char* addr_str, uint16_t port, const char* username, const char* display_name);
int transport_accept_connection(const char* addr_str, uint16_t port);
int transport_decline_connection(const char* addr_str, uint16_t port);
void transport_get_connection_info(conn_info_t* info);
int transport_poll_event(transport_event_t* ev);
int transport_port_hop(uint16_t new_port);
int transport_set_fec_enabled(int enabled);
int transport_discovery_scan(void);
int transport_get_peer_list(peer_entry_t* entries, int max_entries);

typedef struct {
    char version[64];
    int  layers_total;
    int  layers_passed;
    const char* layer_status[16];
    int  rules_total;
    int  rules_passed;
    const char* rule_status[20];
} transport_status_t;

void transport_get_status(transport_status_t* status);

int transport_audio_call_start(void);
int transport_audio_call_end(void);
int transport_video_call_start(void);
int transport_video_call_end(void);
int transport_send_file(const char* filepath);
int transport_send_typing(void);
int transport_send_delivery_ack(uint32_t msg_seq);
