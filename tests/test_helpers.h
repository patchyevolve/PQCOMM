#pragma once
#include "packet.h"

packet_buf_t* build_test_packet(uint32_t magic, uint8_t version, uint8_t flags,
                                 uint64_t session_id, uint8_t channel, uint32_t seq,
                                 const uint8_t* payload, uint32_t payload_len);
void free_test_packet(packet_buf_t* p);
