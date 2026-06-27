#pragma once
#include "route_table.h"
#include "session.h"
#include "packet.h"
#include "packet_view.h"
#include "scheduler.h"
#include <netinet/in.h>

#define CTRL_ROUTE_DATA 14
#define RELAY_NODE_INITIATOR 1
#define RELAY_NODE_RESPONDER 2

int relay_forward_route(packet_buf_t* p, packet_view_t* view,
                        session_t* local_sess,
                        route_table_t* rt, uint32_t* seq_counter,
                        tx_queues_t* txq, struct sockaddr_in6* peer_addr);

int relay_build_test_packet(session_t* sess, uint32_t* seq_counter,
                            uint64_t dest_node_id,
                            const char* message,
                            packet_buf_t** out);
