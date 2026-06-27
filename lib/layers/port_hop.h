#pragma once
#include "session.h"
#include "packet.h"
#include "pool.h"
#include "scheduler.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

int port_hop_send_request(session_t* sess, tx_queues_t* txq,
                          struct sockaddr_in6* peer_addr,
                          uint16_t new_port, uint32_t* seq_counter);

int port_hop_send_ack(session_t* sess, tx_queues_t* txq,
                      struct sockaddr_in6* peer_addr,
                      uint32_t* seq_counter);

int port_hop_handle(packet_buf_t* p, session_t* sess);
