#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "udp.h"
#include "ring.h"
#include "packet.h"
#include "pool.h"
#include "session.h"
#include "rx_worker.h"
#include "channel.h"

#include "rx_thread.h"
#include "tx_thread.h"
#include "pipeline_inbound.h"
#include "pipeline_selftest.h"

typedef struct
{
    tx_queues_t* txq;
    session_t* sess;

} control_ctx_t;

#define CTRL_HELLO   1
#define CTRL_ACCEPT  2

typedef struct
{
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

void control_handler(packet_buf_t* p, void* ctx_ptr)
{
    control_ctx_t* ctx = (control_ctx_t*)ctx_ptr;

    tx_queues_t* queues = ctx->txq;
    session_t* sess = ctx->sess;

    uint8_t* payload = p->data + 24;

    uint8_t opcode;
    memcpy(&opcode, payload, 1);

    if (opcode == CTRL_HELLO)
    {
        if (sess->state == SESSION_LOCKED)
            return;

        if (sess->state != SESSION_IDLE &&
            sess->state != SESSION_HANDSHAKE)
            return;

        printf("[CONTROL] HELLO received\n");

        packet_buf_t* resp = pool_get();
        if (!resp) return;

        uint8_t* d = resp->data;

        uint64_t session_id = ((uint64_t)rand() << 32) | rand();
        uint32_t length = 1 + 8;
        uint8_t channel = CH_CONTROL;
        uint32_t prev_seq;
        memcpy(&prev_seq, p->data + 15, 4);
        uint32_t seq = prev_seq + 1;

        // copy header
        memcpy(d, p->data, 24);

        memcpy(d + 6,  &session_id, 8);
        memcpy(d + 14, &channel, 1);
        memcpy(d + 15, &seq, 4);
        memcpy(d + 19, &length, 4);

        uint8_t op = CTRL_ACCEPT;
        memcpy(d + 24, &op, 1);
        memcpy(d + 25, &session_id, 8);

        resp->len = 24 + length;

        memcpy(resp->addr, p->addr, p->addr_len);
        resp->addr_len = p->addr_len;

        // learn peer on first contact
        if (sess->addr_len == 0)
        {
            memcpy(sess->addr, p->addr, p->addr_len);
            sess->addr_len = p->addr_len;
        }

        ring_push(&queues->control, resp);
    }
    else if (opcode == CTRL_ACCEPT)
    {
        if (sess->state != SESSION_HANDSHAKE &&
            sess->state != SESSION_IDLE)
            return;

        printf("[CONTROL] ACCEPT received\n");

        uint64_t sid;
        memcpy(&sid, payload + 1, 8);

        if (sess->addr_len == 0)
        {
            memcpy(sess->addr, p->addr, p->addr_len);
            sess->addr_len = p->addr_len;
        }

        sess->session_id = sid;
        sess->state = SESSION_VERIFY;
        sess->last_seq = 0;
        sess->recv_bitmap = 0;
        sess->state = SESSION_LOCKED;

        printf("Session established: %llu\n",
               (unsigned long long)sid);
    }
}

void audio_handler(packet_buf_t* p, void* ctx)
{
    printf("[AUDIO]\n");
}

void chat_handler(packet_buf_t* p, void* ctx)
{
    printf("[CHAT] %.*s\n",
        (int)(p->len - 24),
        (char*)(p->data + 24));
}

void file_handler(packet_buf_t* p,  void* ctx)
{
    printf("[FILE]\n");
}

int main()
{
	//initialize
    spsc_ring_t rx_ring;
    tx_queues_t queues;
    rx_queues_t rxq;

    ring_init(&rx_ring);
    rx_queues_init(&rxq);
    tx_queues_init(&queues);

    session_t sess = { 0 };
    sess.state = SESSION_IDLE;
    sess.session_id = 0;
	sess.last_seq = 0;
	sess.recv_bitmap = 0;

    control_ctx_t ctrl_ctx;
    
    rx_stats_t stats = {0};
    uint32_t loop_ticks = 0;

    #if PHASE1_SELFTEST
        int seq_probe_queued = 0;
    #endif

    ctrl_ctx.txq = &queues;
    ctrl_ctx.sess = &sess;

    rx_worker_t w_control, w_audio, w_chat, w_file;

    pool_init();

    rx_worker_start(&w_control, &rxq.control,   control_handler,&ctrl_ctx);
    rx_worker_start(&w_audio,   &rxq.audio,     audio_handler,  &ctrl_ctx);
    rx_worker_start(&w_chat,    &rxq.chat,      chat_handler,   &ctrl_ctx);
    rx_worker_start(&w_file,    &rxq.file,      file_handler,   &ctrl_ctx);


    udp_socket_t a;
    udp_socket_t b;

    if (udp_socket_create(&a, 9001) != 0)
    {
        printf("create A failed\n");
        return 1;
    }

    if (udp_socket_create(&b, 9002) != 0)
    {
        printf("create B failed\n");
        return 1;
    }

    

    //thread start
    rx_thread_t rx_thread_a;
    rx_thread_t rx_thread_b;
	tx_thread_t tx_thread;

    if (rx_thread_start(&rx_thread_a, &a, &rx_ring) != 0)
    {
        printf("rx thread start failed\n");
        return 1;
    }
    if (rx_thread_start(&rx_thread_b, &b, &rx_ring) != 0)
    {
        printf("rx thread start failed\n");
        return 1;
    }

    if (tx_thread_start(&tx_thread, &a, &queues) != 0)
    {
		printf("tx thread start failed\n");
        return 1;
    }

	//produce TX packet
    packet_buf_t* p = pool_get();

    if (!p) {
        printf("pool empty\n");
        return 1;
    }

    uint8_t* d = p->data;

    //header
    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1;
    uint8_t flags = 0;
    uint64_t session = 0;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = 1;

    // payload (HELLO)
    uint8_t opcode = CTRL_HELLO;
    uint64_t nonce = 12345;

    uint32_t length = 1 + 8;

    memcpy(d + 0,  &magic, 4);
    memcpy(d + 4,  &version, 1);
    memcpy(d + 5,  &flags, 1);
    memcpy(d + 6,  &session, 8);
    memcpy(d + 14, &channel, 1);
    memcpy(d + 15, &seq, 4);
    memcpy(d + 19, &length, 4);

    // payload write
    memcpy(d + 24, &opcode, 1);
    memcpy(d + 25, &nonce, 8);

    p->len = 24 + length;

    // destination (for sending)
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(9002);
    inet_pton(AF_INET6, "::1", &addr.sin6_addr);

    memcpy(p->addr, &addr, sizeof(addr));
    p->addr_len = sizeof(addr);

    // learn peer dynamically from first packet
    sess.addr_len = 0;

    switch (channel)
    {
        case CH_CONTROL:
            sess.state = SESSION_HANDSHAKE;
            ring_push(&queues.control, p);
            break;

        case CH_AUDIO:
            ring_push(&queues.audio, p);
            break;

        case CH_CHAT:
            ring_push(&queues.chat, p);
            break;

        case CH_FILE:
            ring_push(&queues.file, p);
            break;

        case CH_ROUTE:
            ring_push(&queues.fake, p);
            break;

        default:
            pool_return(p);  // invalid channel
            break;
    }

    #if PHASE1_SELFTEST
        printf("[SELFTEST] enqueue parse/static/session probes\n");
        pipeline_enqueue_phase1_selftests(&rx_ring);
    #endif

	//consume RX packet
    for (;;)
    {
        packet_view_t view = {0};

#if PHASE1_SELFTEST
        if (!seq_probe_queued && sess.state == SESSION_LOCKED && sess.addr_len != 0)
        {
            printf("[SELFTEST] enqueue duplicate seq probe\n");
            pipeline_enqueue_seq_duplicate_probe(&rx_ring, &sess);
            seq_probe_queued = 1;
        }
#endif
        packet_buf_t* rp = (packet_buf_t*)ring_pop(&rx_ring);

        if (rp)
        {
            stats.rx_total++;
            pipeline_result_t result =
                pipeline_inbound_process(rp, &view, &sess, &rxq);

            if (result == PIPELINE_OK)
            {
                // ownership moved to worker queue by pipeline
            }
            else
            {
                switch (result)
                {
                    case PIPELINE_DROP_PARSE:
                        stats.drop_parse++;
                        break;
                    case PIPELINE_DROP_OFFENSIVE:
                        stats.drop_offensive++;
                        break;
                    case PIPELINE_DROP_ANTI:
                        stats.drop_anti++;
                        break;
                    case PIPELINE_DROP_STATIC:
                        stats.drop_static++;
                        break;
                    case PIPELINE_DROP_KERNEL:
                        stats.drop_kernel++;
                        break;
                    case PIPELINE_DROP_SESSION:
                        stats.drop_session++;
                        break;
                    case PIPELINE_DROP_RESILIENCE:
                        stats.drop_resilience++;
                        break;
                    case PIPELINE_DROP_SESSION_ENC:
                        stats.drop_session_enc++;
                        break;
                    case PIPELINE_DROP_CHANNEL_ENC:
                        stats.drop_channel_enc++;
                        break;
                    case PIPELINE_DROP_SEQ:
                        stats.drop_seq++;
                        break;
                    case PIPELINE_DROP_CHANNEL:
                        stats.drop_channel++;
                        break;
                    case PIPELINE_DROP_DEMUX:
                        stats.drop_demux++;
                        break;
                    default:
                        break;
                }
                pool_return(rp);
            }

        }

        loop_ticks++;
        if (loop_ticks >= 100)
        {
            printf("[STATS] rx=%llu parse=%llu off=%llu anti=%llu static=%llu kernel=%llu session=%llu resil=%llu senc=%llu cenc=%llu seq=%llu chan=%llu demux=%llu\n",
                   (unsigned long long)stats.rx_total,
                   (unsigned long long)stats.drop_parse,
                   (unsigned long long)stats.drop_offensive,
                   (unsigned long long)stats.drop_anti,
                   (unsigned long long)stats.drop_static,
                   (unsigned long long)stats.drop_kernel,
                   (unsigned long long)stats.drop_session,
                   (unsigned long long)stats.drop_resilience,
                   (unsigned long long)stats.drop_session_enc,
                   (unsigned long long)stats.drop_channel_enc,
                   (unsigned long long)stats.drop_seq,
                   (unsigned long long)stats.drop_channel,
                   (unsigned long long)stats.drop_demux);
            loop_ticks = 0;
        }

        Sleep(1);

    }

    rx_worker_stop(&w_control);
    rx_worker_stop(&w_audio);
    rx_worker_stop(&w_chat);
    rx_worker_stop(&w_file);

    rx_thread_stop(&rx_thread_a);
    rx_thread_stop(&rx_thread_b);
	tx_thread_stop(&tx_thread);

    udp_socket_close(&a);
    udp_socket_close(&b);

    return 0;
}