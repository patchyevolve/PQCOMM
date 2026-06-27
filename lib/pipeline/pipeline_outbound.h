#pragma once
#include "packet.h"
#include "session.h"

int pipeline_outbound_process(packet_buf_t* p, session_t* sess,
                              uint32_t seq, uint8_t channel,
                              const uint8_t* payload, uint32_t payload_len);
