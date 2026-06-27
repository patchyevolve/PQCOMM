#pragma once
#include <stdint.h>
#include "transport_api.h"
#include "session.h"
#include "udp.h"
#include "ring.h"
#include "scheduler.h"
#include "rx_demux.h"
#include "rx_thread.h"
#include "tx_thread.h"
#include "route_table.h"
#include "adaptive_bitrate.h"
#include "heartbeat.h"
#include "reconnect.h"
#include "audio_worker.h"
#include "video_worker.h"
#include "file_transfer.h"

#define ENGINE_MAX_SOCKETS 4
#define ENGINE_MAX_PATHS 2

typedef struct transport_engine_s {
    int initialized;
    transport_config_t config;
    int running;

    uint16_t sockets_bound[ENGINE_MAX_SOCKETS];
    udp_socket_t sockets[ENGINE_MAX_SOCKETS];
    int socket_count;

    spsc_ring_t rx_rings[ENGINE_MAX_SOCKETS];
    rx_queues_t rx_queues[ENGINE_MAX_SOCKETS];
    rx_thread_t rx_threads[ENGINE_MAX_SOCKETS];

    tx_queues_t tx_queues[ENGINE_MAX_SOCKETS];
    tx_thread_t tx_threads[ENGINE_MAX_SOCKETS];

    session_t* session;
    uint32_t seq_counter;
    uint64_t start_time_ms;
    int session_is_locked;

    struct sockaddr_in6 peer_addr;
    int peer_configured;
    int role_initiator;
    char connect_addr_str[64];
    uint16_t connect_port;

    abr_ctx_t abr;
    route_table_t route_table;

    spsc_ring_t event_ring;

    uint64_t loop_ticks;

    /* audio/video/file */
    audio_worker_t audio;
    video_worker_t video;
    file_transfer_ctx_t file_ctx;
    int audio_call_active;
    int video_call_active;
    int cur_file_send_idx;
    int cur_file_recv_idx;
    int file_tick;
} transport_engine_t;

int transport_engine_init(transport_engine_t* eng, const transport_config_t* config);
void transport_engine_shutdown(transport_engine_t* eng);
int transport_engine_connect(transport_engine_t* eng, const char* addr_str, uint16_t port);
int transport_engine_disconnect(transport_engine_t* eng);
int transport_engine_send_chat(transport_engine_t* eng, const char* text);
int transport_engine_send_connect_request(transport_engine_t* eng, const char* addr_str, uint16_t port, const char* username, const char* display_name);
int transport_engine_accept_connection(transport_engine_t* eng, const char* addr_str, uint16_t port);
int transport_engine_decline_connection(transport_engine_t* eng, const char* addr_str, uint16_t port);
int transport_engine_poll(transport_engine_t* eng, transport_event_t* ev);
void transport_engine_get_info(transport_engine_t* eng, conn_info_t* info);
int transport_engine_run_demo(void);

int transport_engine_audio_call_start(transport_engine_t* eng);
int transport_engine_audio_call_end(transport_engine_t* eng);
int transport_engine_video_call_start(transport_engine_t* eng);
int transport_engine_video_call_end(transport_engine_t* eng);
int transport_engine_send_file(transport_engine_t* eng, const char* filepath);
int transport_engine_send_typing(transport_engine_t* eng);
int transport_engine_send_delivery_ack(transport_engine_t* eng, uint32_t msg_seq);
