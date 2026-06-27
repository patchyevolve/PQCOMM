#pragma once

#include "session.h"
#include "packet.h"
#include "packet_view.h"

#define HS_OK           0
#define HS_ERROR       -1
#define HS_NEED_MORE    1
#define HS_COMPLETE     2

// Initialize handshake as initiator (we start the connection)
int handshake_init_initiator(session_t* sess, uint8_t kem_type);
 
// Initialize handshake as responder (we received HELLO)
int handshake_init_responder(session_t* sess, uint8_t kem_type);
 
// Process incoming handshake message
// Returns: HS_OK, HS_ERROR, HS_NEED_MORE, HS_COMPLETE
int handshake_process_message(session_t* sess, 
                               packet_buf_t* packet,
                               packet_view_t* view,
                               packet_buf_t** response_out);

// Build HELLO message (initiator sends first)
packet_buf_t* handshake_build_hello(session_t* sess, uint32_t* seq_counter);

// Build ACCEPT message (responder assigns session ID)
int handshake_build_accept(session_t* sess, packet_buf_t* out, uint32_t* seq_counter);

// Run initiator handshake flow
packet_buf_t* handshake_run_as_initiator(session_t* sess, packet_buf_t* in, uint32_t* seq_counter);

// Run responder handshake flow  
packet_buf_t* handshake_run_as_responder(session_t* sess, packet_buf_t* in, uint32_t* seq_counter);
 
// Build PQ_KEM_INIT message (initiator sends PQ public key)
int handshake_build_kem_init(session_t* sess, packet_buf_t* out,
                             uint32_t* seq_counter);
 
// Build PQ_KEM_RESPONSE message (responder sends ciphertext)
int handshake_build_kem_response(session_t* sess, packet_buf_t* out,
                                 uint32_t* seq_counter);
 
// Build IDENTITY_PROOF message (both directions)
int handshake_build_identity(session_t* sess, packet_buf_t* out,
                               uint32_t* seq_counter);
 
// Build SESSION_LOCKED confirmation
int handshake_build_locked(session_t* sess, packet_buf_t* out,
                           uint32_t* seq_counter);
 
// Build HANDSHAKE_ERROR message
int handshake_build_error(session_t* sess, packet_buf_t* out,
                          uint8_t error_code, uint32_t* seq_counter);
 
// Check if handshake has timed out
int handshake_check_timeout(session_t* sess, uint32_t current_time_ms);
 
// Get human-readable state name
const char* handshake_state_name(session_state_t state);
 
// Get human-readable error name
const char* handshake_error_name(uint8_t error_code);