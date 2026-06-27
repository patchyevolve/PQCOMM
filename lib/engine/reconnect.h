#pragma once
#include <stdint.h>
#include "session.h"
#include "scheduler.h"
#include <netinet/in.h>

int reconnect_send_request(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter);
int reconnect_send_ack(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter, struct sockaddr_in6* dest);
int reconnect_handle(packet_buf_t* p, session_t* sess, tx_queues_t* txq,
                     uint32_t* seq_counter, uint64_t now_ms);
int reconnect_tick(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter, uint64_t now_ms);
