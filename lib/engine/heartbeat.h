#pragma once
#include <stdint.h>
#include "session.h"
#include "scheduler.h"

int heartbeat_send(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter, uint64_t now_ms);
int heartbeat_handle(packet_buf_t* p, session_t* sess, tx_queues_t* txq, uint32_t* seq_counter, uint64_t now_ms);
int heartbeat_tick(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter, uint64_t now_ms);
