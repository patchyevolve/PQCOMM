#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#include "rx_thread.h"
#include "tx_thread.h"
#include "pipeline_inbound.h"
#include "pipeline_selftest.h"





typedef struct {
    tx_queues_t* txq;
    rx_queues_t* rxq;
    session_t* sess;
    uint32_t* seq_counter;
} control_ctx_t;

typedef struct {
    uint64_t rx_total;
    uint64_t drop_parse;
    uint64_t drop_offensive;
    uint64_t drop_anti;
    uint64_t drop_static;
    uint64_t drop_kernel;
    uint64_t drop_session;
    uint64_t drop_resilience;
    uint64_t drop_session_enc;
    uint64_t drop_channel_enc;
    uint64_t drop_seq;
    uint64_t drop_channel;
    uint64_t drop_demux;
} rx_stats_t;



static uint32_t g_seq_counter = 1; // Global sequence counter for handshake
static uint32_t g_seq_counter_initiator = 1;
static uint32_t g_seq_counter_responder = 1;

static session_t* g_sess_initiator = NULL;
static session_t* g_sess_responder = NULL;

static struct sockaddr_in6 g_initiator_peer_addr;
static struct sockaddr_in6 g_responder_peer_addr;


void control_handler_initiator(packet_buf_t* p, void* ctx_ptr) {
    control_ctx_t* ctx = (control_ctx_t*)ctx_ptr;
    session_t* sess = ctx->sess;

    packet_view_t view = { 0 };
    if (packet_parse(p, &view) != 0) {
        pool_return(p);
        return;
    }

    packet_buf_t* response = handshake_run_as_initiator(sess, p, ctx->seq_counter);

    if (response) {
        memcpy(response->addr, &g_initiator_peer_addr, sizeof(g_initiator_peer_addr));
        response->addr_len = sizeof(g_initiator_peer_addr);
        ring_push(&ctx->txq->control, response);
    }

    pool_return(p);

    if (sess->state == SESSION_LOCKED) {
        printf("[INITIATOR] Session LOCKED!\n");
    }
}

void control_handler_responder(packet_buf_t* p, void* ctx_ptr) {
    control_ctx_t* ctx = (control_ctx_t*)ctx_ptr;
    session_t* sess = ctx->sess;

    printf("[RESP] handler called, sess=%p, role=%d, state=%d\n",
        (void*)sess, sess ? sess->role : -1, sess ? sess->state : -1);

    packet_view_t view = { 0 };
    if (packet_parse(p, &view) != 0) {
        printf("[RESP] parse failed\n");
        pool_return(p);
        return;
    }

    printf("[RESP] parse OK, opcode=%d\n", view.payload[0]);

    packet_buf_t* response = handshake_run_as_responder(sess, p, ctx->seq_counter);

    printf("[RESP] handshake_run returned %p\n", (void*)response);

    if (response) {
        memcpy(response->addr, &g_responder_peer_addr, sizeof(g_responder_peer_addr));
        response->addr_len = sizeof(g_responder_peer_addr);
        ring_push(&ctx->txq->control, response);
    }

    pool_return(p);

    if (sess->state == SESSION_LOCKED) {
        printf("[RESPONDER] Session LOCKED!\n");
    }
}

void audio_handler(packet_buf_t* p, void* ctx) {
    printf("[AUDIO]\n");
}

void chat_handler(packet_buf_t* p, void* ctx) {
    printf("[CHAT] %.*s\n", (int)(p->len - 24), (char*)(p->data + 24));
}

void file_handler(packet_buf_t* p, void* ctx) {
    printf("[FILE]\n");
}

int main() {
    spsc_ring_t rx_ring_a;
    spsc_ring_t rx_ring_b;
    tx_queues_t queues_initiator;
	tx_queues_t queues_responder;
    rx_queues_t rxq_a;
    rx_queues_t rxq_b;

    ring_init(&rx_ring_a);
    ring_init(&rx_ring_b);
    rx_queues_init(&rxq_a);
    rx_queues_init(&rxq_b);
    tx_queues_init(&queues_initiator);
    tx_queues_init(&queues_responder);

    control_ctx_t ctrl_ctx;
    rx_stats_t stats = { 0 };
    uint32_t loop_ticks = 0;

#if PHASE1_SELFTEST
    int seq_probe_queued = 0;
#endif

    pool_init();

    rx_worker_t w_control, w_audio, w_chat, w_file;
    rx_worker_t w_control_initiator;

#if PHASE2_SECURITY_ENABLED

    // Setup peer addresses
    memset(&g_initiator_peer_addr, 0, sizeof(g_initiator_peer_addr));
    g_initiator_peer_addr.sin6_family = AF_INET6;
    g_initiator_peer_addr.sin6_port = htons(9002);
    inet_pton(AF_INET6, "::1", &g_initiator_peer_addr.sin6_addr);

    memset(&g_responder_peer_addr, 0, sizeof(g_responder_peer_addr));
    g_responder_peer_addr.sin6_family = AF_INET6;
    g_responder_peer_addr.sin6_port = htons(9001);
    inet_pton(AF_INET6, "::1", &g_responder_peer_addr.sin6_addr);

    // Create initiator session
    g_sess_initiator = session_alloc_for_peer(&g_initiator_peer_addr, sizeof(g_initiator_peer_addr), SESSION_DIR_OUTBOUND);
    if (!g_sess_initiator) return 1;
    handshake_init_initiator(g_sess_initiator, PHASE2_KEM_ALGORITHM);

    // Create responder session
    g_sess_responder = session_alloc_for_peer(&g_responder_peer_addr, sizeof(g_responder_peer_addr), SESSION_DIR_INBOUND);
    if (!g_sess_responder) return 1;
    handshake_init_responder(g_sess_responder, PHASE2_KEM_ALGORITHM);

    // Setup initiator context
    control_ctx_t ctx_initiator = {
        .txq = &queues_initiator,
        .rxq = &rxq_a,
        .sess = g_sess_initiator,
        .seq_counter = &g_seq_counter_initiator
    };

    // Setup responder context  
    control_ctx_t ctx_responder = {
        .txq = &queues_responder,
        .rxq = &rxq_b,
        .sess = g_sess_responder,
        .seq_counter = &g_seq_counter_responder
    };

    // Start workers for both sides
//  rx_worker_start(&w_control, &rxq_b.control, &queues_responder.control, &ctx_responder);
//  rx_worker_start(&w_control_initiator, &rxq_a.control, &queues_initiator.control, &ctx_initiator);

    // Send initial HELLO from initiator
    packet_buf_t* hello = handshake_build_hello(g_sess_initiator, &g_seq_counter_initiator);
    if (!hello) {
        printf("[MAIN] Failed to build HELLO\n");
        return 1;
    }
    memcpy(hello->addr, &g_initiator_peer_addr, sizeof(g_initiator_peer_addr));
    hello->addr_len = sizeof(g_initiator_peer_addr);
    ring_push(&queues_initiator.control, hello);
    printf("[MAIN] Sent initial HELLO from INITIATOR\n");


#endif

    ctrl_ctx.txq = &queues_responder;
    ctrl_ctx.rxq = &rxq_b;
    ctrl_ctx.sess = g_sess_responder;
    ctrl_ctx.seq_counter = &g_seq_counter_responder;

#if !PHASE2_SECURITY_ENABLED
    rx_worker_start(&w_control, &rxq_b.control, control_handler_responder, &ctrl_ctx);
#endif
    //rx_worker_start(&w_audio, &rxq_b.audio, audio_handler, &ctrl_ctx);
    //rx_worker_start(&w_chat, &rxq_b.chat, chat_handler, &ctrl_ctx);
    //rx_worker_start(&w_file, &rxq_b.file, file_handler, &ctrl_ctx);



    udp_socket_t a, b;

    if (udp_socket_create(&a, 9001) != 0) {
        printf("create A failed\n");
        return 1;
    }

    if (udp_socket_create(&b, 9002) != 0) {
        printf("create B failed\n");
        return 1;
    }

    rx_thread_t rx_thread_a, rx_thread_b;
    tx_thread_t tx_thread, tx_thread_b;

    if (rx_thread_start(&rx_thread_a, &a, &rx_ring_a, "initiator") != 0) {
        printf("rx thread start failed\n");
        return 1;
    }
    if (rx_thread_start(&rx_thread_b, &b, &rx_ring_b, "responder") != 0) {
        printf("rx thread start failed\n");
        return 1;
    }
    if (tx_thread_start(&tx_thread, &a, &queues_initiator) != 0) {
        printf("tx thread start failed\n");
        return 1;
    }

    if (tx_thread_start(&tx_thread_b, &b, &queues_responder) != 0) {
        printf("tx thread b start failed\n");
        return 1;
    }

#if PHASE1_SELFTEST
    // PHASE1 selftest disabled - needs update for dual ring
    // pipeline_enqueue_phase1_selftests(&rx_ring_a);
#endif

#if PHASE2_SECURITY_ENABLED
    {
        printf("[MAIN] Phase 2 security enabled, using PQ handshake\n");
    }
#endif

    for (;;) {
        // Process INITIATOR side (socket A)
        packet_buf_t* rp_a = (packet_buf_t*)ring_pop(&rx_ring_a);
        if (rp_a) {
            pipeline_ctx_t ctx_a = {
                .sess = g_sess_initiator,
                .rxq = &rxq_a
            };
            pipeline_result_t result = pipeline_inbound_process(rp_a, &ctx_a);

            if (result == PIPELINE_OK) {
                control_handler_initiator(rp_a, &ctx_initiator);
            }
            else {
                printf("[INIT] DROP: %d\n", result);
                pool_return(rp_a);
            }
        }

        // Process RESPONDER side (socket B)
        packet_buf_t* rp_b = (packet_buf_t*)ring_pop(&rx_ring_b);
        if (rp_b) {
            pipeline_ctx_t ctx_b = {
                .sess = g_sess_responder,
                .rxq = &rxq_b
            };
            pipeline_result_t result = pipeline_inbound_process(rp_b, &ctx_b);

            if (result == PIPELINE_OK) {
                control_handler_responder(rp_b, &ctx_responder);
            }
            else {
                printf("[RESP] DROP: %d\n", result);
                pool_return(rp_b);
            }
        }

        loop_ticks++;
        if (loop_ticks >= 100) {
            printf("[STATS] INIT=%s RESP=%s\n",
                handshake_state_name(g_sess_initiator ? g_sess_initiator->state : SESSION_IDLE),
                handshake_state_name(g_sess_responder ? g_sess_responder->state : SESSION_IDLE));
            loop_ticks = 0;
        }

#ifdef _WIN32
        Sleep(1);
#else
        usleep(1000);
#endif
    }

    //rx_worker_stop(&w_control);
    //rx_worker_stop(&w_audio);
    //rx_worker_stop(&w_chat);
    //rx_worker_stop(&w_file);

    rx_thread_stop(&rx_thread_a);
    rx_thread_stop(&rx_thread_b);
    tx_thread_stop(&tx_thread);
    tx_thread_stop(&tx_thread_b);

    udp_socket_close(&a);
    udp_socket_close(&b);

    return 0;
}