#pragma once
#include "session.h"
#include "packet.h"
#include "scheduler.h"
#include <netinet/in.h>

#define CONN_REQUEST_USERNAME_MAX 32
#define CONN_REQUEST_DISPLAY_MAX  64
#define CONN_REQUEST_MAX_PENDING  8

typedef struct {
    uint8_t addr[16];
    uint16_t port;
    char username[CONN_REQUEST_USERNAME_MAX];
    char display_name[CONN_REQUEST_DISPLAY_MAX];
    uint64_t timestamp_ms;
    int active;
} pending_request_t;

typedef struct {
    pending_request_t requests[CONN_REQUEST_MAX_PENDING];
    int count;
} conn_request_table_t;

extern conn_request_table_t g_conn_requests;

int conn_request_build(session_t* sess, tx_queues_t* txq, uint32_t* seq,
                        const char* username, const char* display_name);
int conn_request_handle(packet_buf_t* p, session_t* sess, tx_queues_t* txq,
                        uint32_t* seq, int is_responder);
int conn_request_send_accept(session_t* sess, tx_queues_t* txq, uint32_t* seq,
                              const struct sockaddr_in6* peer_addr);
int conn_request_send_decline(session_t* sess, tx_queues_t* txq, uint32_t* seq,
                               const struct sockaddr_in6* peer_addr,
                               const char* reason);
pending_request_t* conn_request_find(const struct sockaddr_in6* addr);
