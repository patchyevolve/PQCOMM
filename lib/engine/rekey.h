#pragma once
#include "session.h"
#include "packet.h"
#include "scheduler.h"

int rekey_initiate(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter);
int rekey_handle(packet_buf_t* p, session_t* sess, tx_queues_t* txq, uint32_t* seq_counter);
