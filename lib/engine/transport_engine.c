#include "transport_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include "udp.h"
#include "ring.h"
#include "packet.h"
#include "packet_parse.h"
#include "pool.h"
#include "session.h"
#include "rx_worker.h"
#include "channel.h"
#include "handshake.h"
#include "kem.h"
#include "resilience_ctx.h"

#include "rx_thread.h"
#include "tx_thread.h"
#include "pipeline_inbound.h"
#include "pipeline_selftest.h"
#include "session_enc.h"
#include "port_hop.h"
#include "heartbeat.h"
#include "reconnect.h"
#include "route_table.h"
#include "relay.h"
#include "adaptive_bitrate.h"
#include "kernel_filter.h"
#include "anti_analysis.h"
#include "offensive.h"

static volatile int g_running = 1;

typedef struct {
    tx_queues_t* txq;
    rx_queues_t* rxq;
    session_t* sess;
    uint32_t* seq_counter;
} control_ctx_t;

static uint32_t g_seq_counter_initiator = 1;
static uint32_t g_seq_counter_responder = 1;

static session_t* g_sess_initiator = NULL;
static session_t* g_sess_responder = NULL;

static struct sockaddr_in6 g_initiator_peer_addr;
static struct sockaddr_in6 g_initiator_peer_addr1;
static struct sockaddr_in6 g_responder_peer_addr;
static struct sockaddr_in6 g_responder_peer_addr1;

static control_ctx_t ctx_initiator;
static control_ctx_t ctx_responder;

static tx_queues_t g_queues_initiator1;
static tx_queues_t g_queues_responder1;

static int g_initiator_locked = 0;
static int g_responder_locked = 0;
static route_table_t g_route_table;
static int g_initiator_route_sent = 0;
static abr_ctx_t g_abr_initiator;
static abr_ctx_t g_abr_responder;

static void sighandler(int sig)
{
    (void)sig;
    g_running = 0;
}

static packet_buf_t* build_chat_packet(session_t* sess, uint32_t* seq_counter,
                                        const char* msg)
{
    packet_buf_t* p = pool_get();
    if (!p) return NULL;

    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1, flags = 0, channel = CH_CHAT;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = (uint32_t)strlen(msg) + 1;

    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &sess->session_id, sizeof(sess->session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    memcpy(d + 24, msg, payload_len);

    p->len = 24 + payload_len;
    return p;
}

static int encrypt_tx_packet(packet_buf_t* p, session_t* sess)
{
    packet_view_t view = { 0 };
    if (packet_parse(p, &view) != 0) return -1;
    if (view.channel_id == CH_CONTROL) return 0;
    return session_enc_apply(p, &view, sess);
}

static void fec_tx_after_encrypt(packet_buf_t* p, session_t* sess, tx_queues_t* txq,
                                  struct sockaddr_in6* peer_addr)
{
    if (!sess->resilience.fec_enabled) return;
    uint32_t seq;
    uint64_t sid;
    uint8_t ch;
    memcpy(&seq, p->data + 15, 4);
    memcpy(&sid, p->data + 6, 8);
    memcpy(&ch, p->data + 14, 1);
    uint32_t payload_len = p->len > 24 ? p->len - 24 : 0;

    uint8_t parity_buf[FEC_MAX_PAYLOAD + 8];
    uint32_t parity_len = 0;
    int group_complete = 0;
    fec_tx_accumulate(&sess->resilience, p->data + 24, payload_len,
                      seq, sid, ch, parity_buf, &parity_len, &group_complete);

    if (group_complete && parity_len > 0) {
        packet_buf_t* par = pool_get();
        if (!par) return;
        uint8_t* d = par->data;
        uint32_t magic = 0xAABBCCDD;
        uint8_t ver = 1, fl = 0x02;
        memset(d, 0, 24);
        memcpy(d + 0, &magic, 4);
        memcpy(d + 4, &ver, 1);
        memcpy(d + 5, &fl, 1);
        memcpy(d + 6, &sid, 8);
        memcpy(d + 14, &ch, 1);
        memcpy(d + 15, &seq, 4);
        memcpy(d + 19, &parity_len, 4);
        memcpy(d + 24, parity_buf, parity_len);
        par->len = 24 + parity_len;
        memcpy(par->addr, peer_addr, sizeof(*peer_addr));
        par->addr_len = sizeof(*peer_addr);
        ring_push(&txq->control, par);
        printf("[FEC] group complete, sent parity seq=%u len=%u\n", seq, parity_len);
    }
}

void control_handler_initiator(packet_buf_t* p, void* ctx_ptr)
{
    control_ctx_t* ctx = (control_ctx_t*)ctx_ptr;
    session_t* sess = ctx->sess;

    packet_view_t view = { 0 };
    if (packet_parse(p, &view) != 0) {
        pool_return(p);
        return;
    }

    if (view.channel_id != 1) {
        if (sess->state == 6)
            printf("[INIT CHAT][P%u] %s\n", view.path_idx, (const char*)view.payload);
        pool_return(p);
        return;
    }

    if (sess->state == 6) {
        uint64_t now_ms = (uint64_t)time(NULL) * 1000;

        uint8_t opcode = p->data[24];
        if (sess->ignore_heartbeats_until_ms > now_ms &&
            (opcode == CTRL_HEARTBEAT || opcode == CTRL_HEARTBEAT_ACK)) {
            pool_return(p);
            return;
        }

        if (heartbeat_handle(p, sess, ctx->txq, ctx->seq_counter, now_ms) > 0) {
            pool_return(p);
            return;
        }
        if (reconnect_handle(p, sess, ctx->txq, ctx->seq_counter, now_ms) > 0) {
            if (sess->ignore_heartbeats_until_ms > 0) {
                sess->ignore_heartbeats_until_ms = 0;
                printf("[RECONNECT] simulation complete, path restored\n");
            }
            pool_return(p);
            return;
        }

        int hop_ret = port_hop_handle(p, sess);
        if (hop_ret == 1) {
            port_hop_send_ack(sess, ctx->txq, (struct sockaddr_in6*)p->addr, ctx->seq_counter);
        }
        if (hop_ret > 0) {
            /* after port hop ACK received, simulate transport loss to trigger reconnect */
            if (hop_ret == 2) {
                uint64_t now_ms = (uint64_t)time(NULL) * 1000;
                sess->ignore_heartbeats_until_ms = now_ms + 15000;
                /* restore addrs to working path 0 so heartbeats/reconnect hit live sockets */
                memcpy(sess->addr, &g_initiator_peer_addr, sizeof(g_initiator_peer_addr));
                sess->addr_len = sizeof(g_initiator_peer_addr);
                if (g_sess_responder) {
                    memcpy(g_sess_responder->addr, &g_responder_peer_addr,
                           sizeof(g_responder_peer_addr));
                    g_sess_responder->addr_len = sizeof(g_responder_peer_addr);
                }
                printf("[RECONNECT] simulating transport loss on initiator\n");
            }
            pool_return(p);
            return;
        }
    }

    packet_buf_t* response = handshake_run_as_initiator(sess, p, ctx->seq_counter);

    if (response) {
        memcpy(response->addr, &g_initiator_peer_addr, sizeof(g_initiator_peer_addr));
        response->addr_len = sizeof(g_initiator_peer_addr);
        ring_push(&ctx->txq->control, response);
    }

    pool_return(p);

    if (sess->state == 6 && !g_initiator_locked) {
        g_initiator_locked = 1;
        printf("[INITIATOR] session locked, sending test chats\n");

        tx_queues_t* txqs[2] = { ctx->txq, &g_queues_initiator1 };
        struct sockaddr_in6* addrs[2] = { &g_initiator_peer_addr, &g_initiator_peer_addr1 };

        for (int i = 0; i < 5; i++) {
            uint32_t path = resilience_select_path(&sess->resilience);
            if (path >= 2) path = 0;
            resilience_record_tx(&sess->resilience, path);
            char msg[64];
            snprintf(msg, sizeof(msg), "hello from initiator! #%d", i + 1);
            packet_buf_t* chat = build_chat_packet(sess, ctx->seq_counter, msg);
            if (chat) {
                encrypt_tx_packet(chat, sess);
                fec_tx_after_encrypt(chat, sess, txqs[path], addrs[path]);
                memcpy(chat->addr, addrs[path], sizeof(*addrs[path]));
                chat->addr_len = sizeof(*addrs[path]);
                if (i == 1) {
                    printf("[FEC LOSS DROP] seq=%u path=%u\n",
                           *(uint32_t*)(chat->data + 15), path);
                    pool_return(chat);
                } else {
                    ring_push(&txqs[path]->control, chat);
                }
            }
        }

        if (!g_initiator_route_sent) {
            g_initiator_route_sent = 1;
            packet_buf_t* route_pkt = NULL;
            if (relay_build_test_packet(sess, ctx->seq_counter, RELAY_NODE_RESPONDER,
                                        "hello via relay!", &route_pkt) == 0) {
                memcpy(route_pkt->addr, &g_initiator_peer_addr, sizeof(g_initiator_peer_addr));
                route_pkt->addr_len = sizeof(g_initiator_peer_addr);
                ring_push(&ctx->txq->chat, route_pkt);
                printf("[RELAY] sent route test to responder\n");
            }
        }

        uint16_t new_port = sess->local_port + 4;
        port_hop_send_request(sess, ctx->txq, &g_initiator_peer_addr, new_port, ctx->seq_counter);
    }
}

void control_handler_responder(packet_buf_t* p, void* ctx_ptr)
{
    control_ctx_t* ctx = (control_ctx_t*)ctx_ptr;
    session_t* sess = ctx->sess;

    packet_view_t view = { 0 };
    if (packet_parse(p, &view) != 0) {
        pool_return(p);
        return;
    }

    if (view.channel_id != 1) {
        if (view.channel_id == CH_ROUTE && sess->state == 6) {
            int ret = relay_forward_route(p, &view, sess, &g_route_table,
                                          ctx->seq_counter,
                                          ctx->txq, &g_responder_peer_addr);
            if (ret == 0)
                printf("[RESP] unknown route packet\n");
            pool_return(p);
            return;
        }
        if (sess->state == 6 && view.channel_id == CH_CHAT)
            printf("[RESP CHAT][P%u] %s\n", view.path_idx, (const char*)view.payload);
        pool_return(p);
        return;
    }

    if (sess->state == 6) {
        uint64_t now_ms = (uint64_t)time(NULL) * 1000;

        if (heartbeat_handle(p, sess, ctx->txq, ctx->seq_counter, now_ms) > 0) {
            pool_return(p);
            return;
        }
        if (reconnect_handle(p, sess, ctx->txq, ctx->seq_counter, now_ms) > 0) {
            pool_return(p);
            return;
        }

        int hop_ret = port_hop_handle(p, sess);
        if (hop_ret == 1) {
            port_hop_send_ack(sess, ctx->txq, (struct sockaddr_in6*)p->addr, ctx->seq_counter);
        }
        if (hop_ret > 0) {
            pool_return(p);
            return;
        }
    }

    packet_buf_t* response = handshake_run_as_responder(sess, p, ctx->seq_counter);

    if (response) {
        memcpy(response->addr, &g_responder_peer_addr, sizeof(g_responder_peer_addr));
        response->addr_len = sizeof(g_responder_peer_addr);
        ring_push(&ctx->txq->control, response);
    }

    pool_return(p);

    if (sess->state == 6 && !g_responder_locked) {
        g_responder_locked = 1;
        route_table_init(&g_route_table);
        route_table_add(&g_route_table, RELAY_NODE_RESPONDER, sess->session_id,
                       &g_responder_peer_addr, sizeof(g_responder_peer_addr));
        printf("[RELAY] route table: node %lu -> self\n", (unsigned long)RELAY_NODE_RESPONDER);
        printf("[RESPONDER] session locked, sending test chats\n");

        tx_queues_t* txqs[2] = { ctx->txq, &g_queues_responder1 };
        struct sockaddr_in6* addrs[2] = { &g_responder_peer_addr, &g_responder_peer_addr1 };

        for (int i = 0; i < 5; i++) {
            uint32_t path = resilience_select_path(&sess->resilience);
            if (path >= 2) path = 0;
            resilience_record_tx(&sess->resilience, path);
            char msg[64];
            snprintf(msg, sizeof(msg), "hey from responder! #%d", i + 1);
            packet_buf_t* chat = build_chat_packet(sess, ctx->seq_counter, msg);
            if (chat) {
                encrypt_tx_packet(chat, sess);
                fec_tx_after_encrypt(chat, sess, txqs[path], addrs[path]);
                memcpy(chat->addr, addrs[path], sizeof(*addrs[path]));
                chat->addr_len = sizeof(*addrs[path]);
                if (i == 1) {
                    printf("[FEC LOSS DROP] seq=%u path=%u\n",
                           *(uint32_t*)(chat->data + 15), path);
                    pool_return(chat);
                } else {
                    ring_push(&txqs[path]->control, chat);
                }
            }
        }
    }
}

static void print_stats(void)
{
    printf("[STATS] init=%s resp=%s pool=%u "
           "attempts=%u ok=%u fail=%u"
           " kf_drop=%u aa_drop=%u off=%u",
           handshake_state_name(g_sess_initiator ? g_sess_initiator->state : 0),
           handshake_state_name(g_sess_responder ? g_sess_responder->state : 0),
           pool_free_count(),
           g_handshake_stats.attempts_total,
           g_handshake_stats.successes,
           g_handshake_stats.failures_state,
           g_kernel_filter.drops_port + g_kernel_filter.drops_size + g_kernel_filter.drops_blocked,
           g_anti_analysis.drops_medium + g_anti_analysis.drops_high,
           g_offensive.total_decoys);

    if (g_sess_initiator && g_sess_initiator->state == 6)
        printf(" enc=on");

    if (g_sess_responder && g_sess_responder->resilience.multipath_enabled) {
        printf(" paths:");
        for (uint32_t i = 0; i < g_sess_responder->resilience.path_count; i++) {
            path_metrics_t* p = &g_sess_responder->resilience.paths[i];
            printf(" %u(s=%u r=%u l=%.2f)", i, p->packets_sent, p->packets_recv, p->loss_rate);
        }
    }
    printf("\n");
}

int transport_engine_run_demo(void)
{
    spsc_ring_t rx_ring_a, rx_ring_b;
    tx_queues_t queues_initiator, queues_responder;
    rx_queues_t rxq_a, rxq_b;

    ring_init(&rx_ring_a);
    ring_init(&rx_ring_b);
    rx_queues_init(&rxq_a);
    rx_queues_init(&rxq_b);
    tx_queues_init(&queues_initiator);
    tx_queues_init(&queues_responder);

    uint32_t loop_ticks = 0;

    pool_init();
    route_table_init(&g_route_table);
    abr_init(&g_abr_initiator);
    abr_init(&g_abr_responder);
    kernel_filter_init();
    anti_analysis_init();
    offensive_init();

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    memset(&g_initiator_peer_addr, 0, sizeof(g_initiator_peer_addr));
    g_initiator_peer_addr.sin6_family = AF_INET6;
    g_initiator_peer_addr.sin6_port = htons(9002);
    inet_pton(AF_INET6, "::1", &g_initiator_peer_addr.sin6_addr);

    memset(&g_responder_peer_addr, 0, sizeof(g_responder_peer_addr));
    g_responder_peer_addr.sin6_family = AF_INET6;
    g_responder_peer_addr.sin6_port = htons(9001);
    inet_pton(AF_INET6, "::1", &g_responder_peer_addr.sin6_addr);

    memset(&g_initiator_peer_addr1, 0, sizeof(g_initiator_peer_addr1));
    g_initiator_peer_addr1.sin6_family = AF_INET6;
    g_initiator_peer_addr1.sin6_port = htons(9004);
    inet_pton(AF_INET6, "::1", &g_initiator_peer_addr1.sin6_addr);

    memset(&g_responder_peer_addr1, 0, sizeof(g_responder_peer_addr1));
    g_responder_peer_addr1.sin6_family = AF_INET6;
    g_responder_peer_addr1.sin6_port = htons(9003);
    inet_pton(AF_INET6, "::1", &g_responder_peer_addr1.sin6_addr);

    g_sess_initiator = session_alloc_for_peer(&g_initiator_peer_addr,
                        sizeof(g_initiator_peer_addr), SESSION_DIR_OUTBOUND);
    if (!g_sess_initiator) return 1;
    g_sess_initiator->local_port = 9001;
    session_register_path(g_sess_initiator, 1, &g_initiator_peer_addr1, sizeof(g_initiator_peer_addr1));
    g_sess_initiator->resilience.path_count = 2;
    g_sess_initiator->resilience.multipath_enabled = 1;
    g_sess_initiator->resilience.paths[0].peer_port = htons(9002);
    g_sess_initiator->resilience.paths[1].peer_port = htons(9004);
    handshake_init_initiator(g_sess_initiator, 1);

    g_sess_responder = session_alloc_for_peer(&g_responder_peer_addr,
                        sizeof(g_responder_peer_addr), SESSION_DIR_INBOUND);
    if (!g_sess_responder) return 1;
    g_sess_responder->local_port = 9002;
    session_register_path(g_sess_responder, 1, &g_responder_peer_addr1, sizeof(g_responder_peer_addr1));
    g_sess_responder->resilience.path_count = 2;
    g_sess_responder->resilience.multipath_enabled = 1;
    g_sess_responder->resilience.paths[0].peer_port = htons(9001);
    g_sess_responder->resilience.paths[1].peer_port = htons(9003);
    handshake_init_responder(g_sess_responder, 1);

    ctx_initiator.txq = &queues_initiator;
    ctx_initiator.rxq = &rxq_a;
    ctx_initiator.sess = g_sess_initiator;
    ctx_initiator.seq_counter = &g_seq_counter_initiator;

    ctx_responder.txq = &queues_responder;
    ctx_responder.rxq = &rxq_b;
    ctx_responder.sess = g_sess_responder;
    ctx_responder.seq_counter = &g_seq_counter_responder;

    packet_buf_t* hello = handshake_build_hello(g_sess_initiator, &g_seq_counter_initiator);
    if (!hello) { printf("failed to build hello\n"); return 1; }
    memcpy(hello->addr, &g_initiator_peer_addr, sizeof(g_initiator_peer_addr));
    hello->addr_len = sizeof(g_initiator_peer_addr);
    ring_push(&queues_initiator.control, hello);
    printf("[MAIN] initiator sent hello\n");

    spsc_ring_t rx_ring_a1, rx_ring_b1;
    rx_queues_t rxq_a1, rxq_b1;

    ring_init(&rx_ring_a1);
    ring_init(&rx_ring_b1);
    rx_queues_init(&rxq_a1);
    rx_queues_init(&rxq_b1);
    tx_queues_init(&g_queues_initiator1);
    tx_queues_init(&g_queues_responder1);

    udp_socket_t a, b, a1, b1;
    if (udp_socket_create(&a, 9001) != 0) { printf("socket 9001 failed\n"); return 1; }
    if (udp_socket_create(&b, 9002) != 0) { printf("socket 9002 failed\n"); return 1; }
    if (udp_socket_create(&a1, 9003) != 0) { printf("socket 9003 failed\n"); return 1; }
    if (udp_socket_create(&b1, 9004) != 0) { printf("socket 9004 failed\n"); return 1; }

    rx_thread_t rx_thread_a, rx_thread_b, rx_thread_a1, rx_thread_b1;
    tx_thread_t tx_thread, tx_thread_b, tx_thread_a1, tx_thread_b1;

    if (rx_thread_start(&rx_thread_a, &a, &rx_ring_a, "init-p0") != 0) return 1;
    if (rx_thread_start(&rx_thread_b, &b, &rx_ring_b, "resp-p0") != 0) return 1;
    if (rx_thread_start(&rx_thread_a1, &a1, &rx_ring_a1, "init-p1") != 0) return 1;
    if (rx_thread_start(&rx_thread_b1, &b1, &rx_ring_b1, "resp-p1") != 0) return 1;
    if (tx_thread_start(&tx_thread, &a, &queues_initiator) != 0) return 1;
    if (tx_thread_start(&tx_thread_b, &b, &queues_responder) != 0) return 1;
    if (tx_thread_start(&tx_thread_a1, &a1, &g_queues_initiator1) != 0) return 1;
    if (tx_thread_start(&tx_thread_b1, &b1, &g_queues_responder1) != 0) return 1;

    printf("\n=== pqCOMMbulds transport ===\n");
    printf("multipath aead encrypted chat demo\n");
    printf("path0: :9001 <-> :9002\n");
    printf("path1: :9003 <-> :9004\n");
    printf("ctrl+c to stop\n\n");

    while (g_running) {
        pipeline_ctx_t ctx_a = { .sess = g_sess_initiator, .rxq = &rxq_a, .recovered = NULL };
        packet_buf_t* rp_a = (packet_buf_t*)ring_pop(&rx_ring_a);
        if (rp_a) {
            ctx_a.recovered = NULL;
            pipeline_result_t result = pipeline_inbound_process(rp_a, &ctx_a);
            if (result == 0)
                control_handler_initiator(rp_a, &ctx_initiator);
            else {
                if (rp_a->data[24] != 1 && rp_a->data[24] != 2)
                    printf("[INIT] drop reason=%d\n", result);
                pool_return(rp_a);
            }
        }
        if (ctx_a.recovered) {
            control_handler_initiator(ctx_a.recovered, &ctx_initiator);
            ctx_a.recovered = NULL;
        }

        pipeline_ctx_t ctx_b = { .sess = g_sess_responder, .rxq = &rxq_b, .recovered = NULL };
        packet_buf_t* rp_b = (packet_buf_t*)ring_pop(&rx_ring_b);
        if (rp_b) {
            ctx_b.recovered = NULL;
            pipeline_result_t result = pipeline_inbound_process(rp_b, &ctx_b);
            if (result == 0)
                control_handler_responder(rp_b, &ctx_responder);
            else {
                if (rp_b->data[24] != 1)
                    printf("[RESP] drop reason=%d\n", result);
                pool_return(rp_b);
            }
        }
        if (ctx_b.recovered) {
            control_handler_responder(ctx_b.recovered, &ctx_responder);
            ctx_b.recovered = NULL;
        }

        pipeline_ctx_t ctx_a1 = { .sess = g_sess_initiator, .rxq = &rxq_a1, .recovered = NULL };
        packet_buf_t* rp_a1 = (packet_buf_t*)ring_pop(&rx_ring_a1);
        if (rp_a1) {
            ctx_a1.recovered = NULL;
            pipeline_result_t result = pipeline_inbound_process(rp_a1, &ctx_a1);
            if (result == 0)
                control_handler_initiator(rp_a1, &ctx_initiator);
            else {
                if (rp_a1->data[24] != 1 && rp_a1->data[24] != 2)
                    printf("[INIT-p1] drop reason=%d\n", result);
                pool_return(rp_a1);
            }
        }
        if (ctx_a1.recovered) {
            control_handler_initiator(ctx_a1.recovered, &ctx_initiator);
            ctx_a1.recovered = NULL;
        }

        pipeline_ctx_t ctx_b1 = { .sess = g_sess_responder, .rxq = &rxq_b1, .recovered = NULL };
        packet_buf_t* rp_b1 = (packet_buf_t*)ring_pop(&rx_ring_b1);
        if (rp_b1) {
            ctx_b1.recovered = NULL;
            pipeline_result_t result = pipeline_inbound_process(rp_b1, &ctx_b1);
            if (result == 0)
                control_handler_responder(rp_b1, &ctx_responder);
            else {
                if (rp_b1->data[24] != 1)
                    printf("[RESP-p1] drop reason=%d\n", result);
                pool_return(rp_b1);
            }
        }
        if (ctx_b1.recovered) {
            control_handler_responder(ctx_b1.recovered, &ctx_responder);
            ctx_b1.recovered = NULL;
        }

        loop_ticks++;
        if (loop_ticks >= 100) {
            print_stats();
            loop_ticks = 0;
        }

        /* ABR update (every ~3s via the internal timer check) */
        if (loop_ticks % 30 == 0) {
            uint64_t now_ms = (uint64_t)time(NULL) * 1000;
            if (g_sess_initiator)
                abr_update(&g_abr_initiator, &g_sess_initiator->resilience, now_ms);
            if (g_sess_responder)
                abr_update(&g_abr_responder, &g_sess_responder->resilience, now_ms);
        }

        /* heartbeat + reconnect ticks (every ~100ms) */
        if (loop_ticks % 10 == 0) {
            uint64_t now_ms = (uint64_t)time(NULL) * 1000;
            heartbeat_tick(g_sess_initiator, ctx_initiator.txq, ctx_initiator.seq_counter, now_ms);
            heartbeat_tick(g_sess_responder, ctx_responder.txq, ctx_responder.seq_counter, now_ms);
            reconnect_tick(g_sess_initiator, ctx_initiator.txq, ctx_initiator.seq_counter, now_ms);
            reconnect_tick(g_sess_responder, ctx_responder.txq, ctx_responder.seq_counter, now_ms);
        }

#ifdef _WIN32
        Sleep(1);
#else
        usleep(1000);
#endif
    }

    printf("\nshutdown\n");
    rx_thread_stop(&rx_thread_a);
    rx_thread_stop(&rx_thread_b);
    rx_thread_stop(&rx_thread_a1);
    rx_thread_stop(&rx_thread_b1);
    tx_thread_stop(&tx_thread);
    tx_thread_stop(&tx_thread_b);
    tx_thread_stop(&tx_thread_a1);
    tx_thread_stop(&tx_thread_b1);
    udp_socket_close(&a);
    udp_socket_close(&b);
    udp_socket_close(&a1);
    udp_socket_close(&b1);

    return 0;
}
