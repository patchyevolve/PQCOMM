#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

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
#include "session_enc.h"

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
static struct sockaddr_in6 g_responder_peer_addr;

static control_ctx_t ctx_initiator;
static control_ctx_t ctx_responder;

static int g_initiator_locked = 0;
static int g_responder_locked = 0;

static void sighandler(int sig)
{
    (void)sig;
    g_running = 0;
}

/* build a chat packet with a text message */
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

/* encrypt a data packet before sending (session-level aead) */
static int encrypt_tx_packet(packet_buf_t* p, session_t* sess)
{
    packet_view_t view = { 0 };
    if (packet_parse(p, &view) != 0) return -1;
    if (view.channel_id == CH_CONTROL) return 0;
    return session_enc_apply(p, &view, sess);
}

void control_handler_initiator(packet_buf_t* p, void* ctx_ptr)
{
    control_ctx_t* ctx = (control_ctx_t*)ctx_ptr;
    session_t* sess = ctx->sess;

    packet_view_t view = { 0 };
    if (packet_parse(p, &view) == 0 && view.channel_id != CH_CONTROL) {
        if (sess->state == SESSION_LOCKED)
            printf("[INIT CHAT] %s\n", (const char*)view.payload);
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

    if (sess->state == SESSION_LOCKED && !g_initiator_locked) {
        g_initiator_locked = 1;
        printf("[INITIATOR] session locked, sending test chat\n");

        packet_buf_t* chat = build_chat_packet(sess, ctx->seq_counter,
                                                "hello from initiator!");
        if (chat) {
            encrypt_tx_packet(chat, sess);
            memcpy(chat->addr, &g_initiator_peer_addr, sizeof(g_initiator_peer_addr));
            chat->addr_len = sizeof(g_initiator_peer_addr);
            ring_push(&ctx->txq->control, chat);
        }
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

    /* if its an encrypted data packet, just print it */
    if (sess->state == SESSION_LOCKED && view.channel_id == CH_CHAT) {
        printf("[RESP CHAT] %s\n", (const char*)view.payload);
        pool_return(p);
        return;
    }

    packet_buf_t* response = handshake_run_as_responder(sess, p, ctx->seq_counter);

    if (response) {
        memcpy(response->addr, &g_responder_peer_addr, sizeof(g_responder_peer_addr));
        response->addr_len = sizeof(g_responder_peer_addr);
        ring_push(&ctx->txq->control, response);
    }

    pool_return(p);

    if (sess->state == SESSION_LOCKED && !g_responder_locked) {
        g_responder_locked = 1;
        printf("[RESPONDER] session locked, sending test chat\n");

        packet_buf_t* chat = build_chat_packet(sess, ctx->seq_counter,
                                                "hey from responder!");
        if (chat) {
            encrypt_tx_packet(chat, sess);
            memcpy(chat->addr, &g_responder_peer_addr, sizeof(g_responder_peer_addr));
            chat->addr_len = sizeof(g_responder_peer_addr);
            ring_push(&ctx->txq->control, chat);
        }
    }
}

static void print_stats(void)
{
    printf("[STATS] init=%s resp=%s pool=%u "
           "attempts=%u ok=%u fail=%u",
           handshake_state_name(g_sess_initiator ? g_sess_initiator->state : SESSION_IDLE),
           handshake_state_name(g_sess_responder ? g_sess_responder->state : SESSION_IDLE),
           pool_free_count(),
           g_handshake_stats.attempts_total,
           g_handshake_stats.successes,
           g_handshake_stats.failures_state);

    if (g_sess_initiator && g_sess_initiator->state == SESSION_LOCKED)
        printf(" enc=on");
    printf("\n");
}

int main()
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

    g_sess_initiator = session_alloc_for_peer(&g_initiator_peer_addr,
                        sizeof(g_initiator_peer_addr), SESSION_DIR_OUTBOUND);
    if (!g_sess_initiator) return 1;
    handshake_init_initiator(g_sess_initiator, PHASE2_KEM_ALGORITHM);

    g_sess_responder = session_alloc_for_peer(&g_responder_peer_addr,
                        sizeof(g_responder_peer_addr), SESSION_DIR_INBOUND);
    if (!g_sess_responder) return 1;
    handshake_init_responder(g_sess_responder, PHASE2_KEM_ALGORITHM);

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

    udp_socket_t a, b;
    if (udp_socket_create(&a, 9001) != 0) { printf("socket a failed\n"); return 1; }
    if (udp_socket_create(&b, 9002) != 0) { printf("socket b failed\n"); return 1; }

    rx_thread_t rx_thread_a, rx_thread_b;
    tx_thread_t tx_thread, tx_thread_b;

    if (rx_thread_start(&rx_thread_a, &a, &rx_ring_a, "initiator") != 0) return 1;
    if (rx_thread_start(&rx_thread_b, &b, &rx_ring_b, "responder") != 0) return 1;
    if (tx_thread_start(&tx_thread, &a, &queues_initiator) != 0) return 1;
    if (tx_thread_start(&tx_thread_b, &b, &queues_responder) != 0) return 1;

    printf("\n=== pqCOMMbulds transport ===\n");
    printf("handshake + aead encrypted chat demo\n");
    printf("initiator :9001 <-> responder :9002\n");
    printf("ctrl+c to stop\n\n");

    while (g_running) {
        packet_buf_t* rp_a = (packet_buf_t*)ring_pop(&rx_ring_a);
        if (rp_a) {
            pipeline_ctx_t ctx_a = { .sess = g_sess_initiator, .rxq = &rxq_a };
            pipeline_result_t result = pipeline_inbound_process(rp_a, &ctx_a);
            if (result == PIPELINE_OK)
                control_handler_initiator(rp_a, &ctx_initiator);
            else {
                if (rp_a->data[24] != CTRL_HELLO && rp_a->data[24] != CTRL_ACCEPT)
                    printf("[INIT] drop reason=%d\n", result);
                pool_return(rp_a);
            }
        }

        packet_buf_t* rp_b = (packet_buf_t*)ring_pop(&rx_ring_b);
        if (rp_b) {
            pipeline_ctx_t ctx_b = { .sess = g_sess_responder, .rxq = &rxq_b };
            pipeline_result_t result = pipeline_inbound_process(rp_b, &ctx_b);
            if (result == PIPELINE_OK)
                control_handler_responder(rp_b, &ctx_responder);
            else {
                if (rp_b->data[24] != CTRL_HELLO)
                    printf("[RESP] drop reason=%d\n", result);
                pool_return(rp_b);
            }
        }

        loop_ticks++;
        if (loop_ticks >= 100) {
            print_stats();
            loop_ticks = 0;
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
    tx_thread_stop(&tx_thread);
    tx_thread_stop(&tx_thread_b);
    udp_socket_close(&a);
    udp_socket_close(&b);

    return 0;
}
