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
#include "connection_manager.h"
#include "lan_discovery.h"
#include "rekey.h"
#include "crypto_worker.h"
#include "monitor.h"
#include "secure_store.h"
#include "kem.h"
#include "conn_request.h"

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
    }
}

static int process_ring_for_engine(
    spsc_ring_t* rx_ring,
    pipeline_ctx_t* ctx,
    void (*control_handler)(packet_buf_t*, void*),
    void* control_ctx,
    const char* drop_prefix)
{
    packet_buf_t* p = (packet_buf_t*)ring_pop(rx_ring);
    if (!p) return 0;

    ctx->recovered = NULL;
    pipeline_result_t result = pipeline_inbound_process(p, ctx);
    if (result == 0) {
        control_handler(p, control_ctx);
    } else {
        if (drop_prefix) {
            uint8_t op = p->data[24];
            if (op != 1 && op != 2)
                printf("%s drop reason=%d\n", drop_prefix, result);
        }
        pool_return(p);
    }
    if (ctx->recovered) {
        control_handler(ctx->recovered, control_ctx);
        ctx->recovered = NULL;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Engine API                                                         */
/* ------------------------------------------------------------------ */

int transport_engine_init(transport_engine_t* eng, const transport_config_t* config)
{
    if (!eng || !config) return -1;
    memset(eng, 0, sizeof(*eng));
    eng->config = *config;
    eng->running = 1;
    eng->loop_ticks = 0;

    secure_store_init();
    pool_init();
    route_table_init(&eng->route_table);
    abr_init(&eng->abr);
    kernel_filter_init();
    anti_analysis_init();
    offensive_init();
    crypto_worker_start();
    monitor_start();
    audio_worker_start(&eng->audio, NULL);
    video_worker_start(&eng->video, NULL, 0, 0);
    file_transfer_init(&eng->file_ctx);
    eng->audio_call_active = 0;
    eng->video_call_active = 0;
    eng->cur_file_send_idx = -1;
    eng->cur_file_recv_idx = -1;

    ring_init(&eng->event_ring);

    int n_sockets = config->multipath_enabled && config->path_count > 1 ? 2 : 1;
    eng->socket_count = n_sockets;

    uint16_t ports[2] = { config->local_port, config->local_port_alt };
    for (int i = 0; i < n_sockets; i++) {
        if (udp_socket_create(&eng->sockets[i], ports[i]) != 0) {
            printf("[ENGINE] socket %d on port %u failed\n", i, ports[i]);
            transport_engine_shutdown(eng);
            return -1;
        }
        eng->sockets_bound[i] = ports[i];
        ring_init(&eng->rx_rings[i]);
        rx_queues_init(&eng->rx_queues[i]);
        tx_queues_init(&eng->tx_queues[i]);

        char name[32];
        snprintf(name, sizeof(name), "eng-p%d", i);
        if (rx_thread_start(&eng->rx_threads[i], &eng->sockets[i], &eng->rx_rings[i], name) != 0) {
            transport_engine_shutdown(eng);
            return -1;
        }
        if (tx_thread_start(&eng->tx_threads[i], &eng->sockets[i], &eng->tx_queues[i]) != 0) {
            transport_engine_shutdown(eng);
            return -1;
        }
    }

    if (config->discovery_enabled) {
        if (lan_discovery_init(config->discovery_port) == 0) {
            lan_discovery_start();
        }
    }

    eng->initialized = 1;
    eng->start_time_ms = (uint64_t)time(NULL) * 1000;
    return 0;
}

void transport_engine_shutdown(transport_engine_t* eng)
{
    if (!eng || !eng->initialized) return;
    eng->running = 0;

    for (int i = 0; i < eng->socket_count; i++) {
        rx_thread_stop(&eng->rx_threads[i]);
        tx_thread_stop(&eng->tx_threads[i]);
        udp_socket_close(&eng->sockets[i]);
    }

    if (eng->session) {
        session_t* s = eng->session;
        eng->session = NULL;
        (void)s;
    }

    audio_worker_stop(&eng->audio);
    video_worker_stop(&eng->video);
    file_transfer_cleanup(&eng->file_ctx);
    crypto_worker_stop();
    monitor_stop();
    lan_discovery_shutdown();

    eng->initialized = 0;
}

static int resolve_peer(struct sockaddr_in6* out, const char* addr_str, uint16_t port)
{
    memset(out, 0, sizeof(*out));
    out->sin6_family = AF_INET6;
    out->sin6_port = htons(port);

    if (inet_pton(AF_INET6, addr_str, &out->sin6_addr) == 1)
        return 0;

    struct sockaddr_in v4;
    memset(&v4, 0, sizeof(v4));
    v4.sin_family = AF_INET;
    v4.sin_port = htons(port);
    if (inet_pton(AF_INET, addr_str, &v4.sin_addr) == 1) {
        memset(&out->sin6_addr, 0, 16);
        out->sin6_addr.s6_addr[10] = 0xFF;
        out->sin6_addr.s6_addr[11] = 0xFF;
        memcpy(out->sin6_addr.s6_addr + 12, &v4.sin_addr, 4);
        return 0;
    }
    return -1;
}

int transport_engine_connect(transport_engine_t* eng, const char* addr_str, uint16_t port)
{
    if (!eng || !addr_str || !eng->initialized) return -1;
    if (eng->session) return -1;

    if (resolve_peer(&eng->peer_addr, addr_str, port) != 0)
        return -1;
    eng->peer_configured = 1;
    eng->role_initiator = 1;

    int path_idx = 0;
    eng->session = session_alloc_for_peer(&eng->peer_addr, sizeof(eng->peer_addr),
                                          SESSION_DIR_OUTBOUND);
    if (!eng->session) return -1;
    eng->session->local_port = eng->config.local_port;

    if (eng->config.multipath_enabled && eng->socket_count > 1) {
        struct sockaddr_in6 alt_addr = eng->peer_addr;
        alt_addr.sin6_port = htons(port + 2);
        session_register_path(eng->session, 1, &alt_addr, sizeof(alt_addr));
        eng->session->resilience.path_count = 2;
        eng->session->resilience.multipath_enabled = 1;
        eng->session->resilience.paths[0].peer_port = eng->peer_addr.sin6_port;
        eng->session->resilience.paths[1].peer_port = alt_addr.sin6_port;
    } else {
        eng->session->resilience.path_count = 1;
    }

    handshake_init_initiator(eng->session, 1);

    packet_buf_t* hello = handshake_build_hello(eng->session, &eng->seq_counter);
    if (!hello) {
        session_reset(eng->session);
        eng->session = NULL;
        return -1;
    }

    memcpy(hello->addr, &eng->peer_addr, sizeof(eng->peer_addr));
    hello->addr_len = sizeof(eng->peer_addr);
    ring_push(&eng->tx_queues[path_idx].control, hello);

    eng->session_is_locked = 0;

    snprintf(eng->connect_addr_str, sizeof(eng->connect_addr_str), "%s", addr_str);
    eng->connect_port = port;
    connection_manager_connect(addr_str, port);
    return 0;
}

int transport_engine_disconnect(transport_engine_t* eng)
{
    if (!eng || !eng->session) return -1;
    session_t* s = eng->session;
    session_reset(s);
    eng->session = NULL;
    eng->session_is_locked = 0;
    eng->peer_configured = 0;
    eng->seq_counter = 0;
    connection_manager_disconnect();
    return 0;
}

int transport_engine_start_listener(transport_engine_t* eng)
{
    if (!eng || !eng->initialized) return -1;
    eng->role_initiator = 0;
    return 0;
}

static void engine_control_handler(transport_engine_t* eng, packet_buf_t* p)
{
    session_t* sess = eng->session;
    if (!sess) { pool_return(p); return; }

    packet_view_t view = { 0 };
    if (packet_parse(p, &view) != 0) { pool_return(p); return; }

    if (view.channel_id != CH_CONTROL) {
        if (sess->state == SESSION_LOCKED && view.channel_id == CH_CHAT) {
            transport_event_t ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = EVENT_CHAT_RECEIVED;
            ev.timestamp_ms = (uint64_t)time(NULL) * 1000;
            ev.data.chat.sender_port = eng->config.local_port;
            size_t msglen = view.length < sizeof(ev.data.chat.text) - 1 ? view.length : sizeof(ev.data.chat.text) - 1;
            memcpy(ev.data.chat.text, view.payload, msglen);
            ev.data.chat.text[msglen] = '\0';
            ring_push(&eng->event_ring, malloc(sizeof(transport_event_t)));
            if (eng->event_ring.slots[(eng->event_ring.write_idx - 1) & (RING_SIZE - 1)]) {
                memcpy(eng->event_ring.slots[(eng->event_ring.write_idx - 1) & (RING_SIZE - 1)], &ev, sizeof(ev));
            }
            /* auto-send delivery ack */
            transport_engine_send_delivery_ack(eng, view.seq);
        }
        pool_return(p);
        return;
    }

    if (sess->state == SESSION_LOCKED) {
        uint64_t now_ms = (uint64_t)time(NULL) * 1000;
        uint8_t opcode = p->data[24];

        if (eng->session_is_locked &&
            eng->config.local_port == 9001 &&
            eng->config.local_port_alt == 9003) {
            /* ignore heartbeats for reconnect simulation if ignore flag set */
            uint64_t ign = 0;
            if (now_ms < ign) {
                if (opcode == CTRL_HEARTBEAT || opcode == CTRL_HEARTBEAT_ACK) {
                    pool_return(p);
                    return;
                }
            }
        }

        if (heartbeat_handle(p, sess, &eng->tx_queues[0], &eng->seq_counter, now_ms) > 0) {
            pool_return(p); return;
        }
        if (reconnect_handle(p, sess, &eng->tx_queues[0], &eng->seq_counter, now_ms) > 0) {
            pool_return(p); return;
        }
        int hop_ret = port_hop_handle(p, sess);
        if (hop_ret == 1)
            port_hop_send_ack(sess, &eng->tx_queues[0], (struct sockaddr_in6*)p->addr, &eng->seq_counter);
        if (hop_ret > 0) { pool_return(p); return; }

        if (rekey_handle(p, sess, &eng->tx_queues[0], &eng->seq_counter) > 0) {
            pool_return(p); return;
        }

        /* typing indicator */
        if (opcode == CTRL_TYPING) {
            transport_event_t ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = EVENT_TYPING;
            ev.timestamp_ms = now_ms;
            transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
            if (evp) { memcpy(evp, &ev, sizeof(ev)); ring_push(&eng->event_ring, evp); }
            pool_return(p); return;
        }

        /* delivery ack */
        if (opcode == CTRL_DELIVERY_ACK && p->len >= 24 + 1 + 4) {
            uint32_t ack_seq;
            memcpy(&ack_seq, p->data + 25, 4);
            transport_event_t ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = EVENT_DELIVERY_ACK;
            ev.timestamp_ms = now_ms;
            ev.data.delivery_ack.message_seq = ack_seq;
            transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
            if (evp) { memcpy(evp, &ev, sizeof(ev)); ring_push(&eng->event_ring, evp); }
            pool_return(p); return;
        }

        /* read ack */
        if (opcode == CTRL_READ_ACK && p->len >= 24 + 1 + 4) {
            uint32_t ack_seq;
            memcpy(&ack_seq, p->data + 25, 4);
            transport_event_t ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = EVENT_READ_ACK;
            ev.timestamp_ms = now_ms;
            ev.data.read_ack.message_seq = ack_seq;
            transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
            if (evp) { memcpy(evp, &ev, sizeof(ev)); ring_push(&eng->event_ring, evp); }
            pool_return(p); return;
        }
    }

    packet_buf_t* response = handshake_run_as_initiator(sess, p, &eng->seq_counter);
    if (response) {
        memcpy(response->addr, &eng->peer_addr, sizeof(eng->peer_addr));
        response->addr_len = sizeof(eng->peer_addr);
        ring_push(&eng->tx_queues[0].control, response);
    }

    pool_return(p);

    if (sess->state == SESSION_LOCKED && !eng->session_is_locked) {
        eng->session_is_locked = 1;
        connection_manager_update_state(eng->connect_addr_str, eng->connect_port, PEER_LOCKED);
        transport_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.type = EVENT_CONNECTION_STATE_CHANGED;
        ev.timestamp_ms = (uint64_t)time(NULL) * 1000;
        ev.data.conn_state.old_state = CONN_HANDSHAKE;
        ev.data.conn_state.new_state = CONN_LOCKED;
        transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
        if (evp) {
            memcpy(evp, &ev, sizeof(ev));
            ring_push(&eng->event_ring, evp);
        }
    }
}

static void engine_responder_handler(transport_engine_t* eng, packet_buf_t* p)
{
    session_t* sess = eng->session;
    if (!sess) { pool_return(p); return; }

    packet_view_t view = { 0 };
    if (packet_parse(p, &view) != 0) { pool_return(p); return; }

    if (view.channel_id != CH_CONTROL) {
        if (view.channel_id == CH_ROUTE && sess->state == SESSION_LOCKED) {
            relay_forward_route(p, &view, sess, &eng->route_table,
                                &eng->seq_counter,
                                &eng->tx_queues[0], &eng->peer_addr);
        }
        if (sess->state == SESSION_LOCKED && view.channel_id == CH_CHAT) {
            transport_event_t ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = EVENT_CHAT_RECEIVED;
            ev.timestamp_ms = (uint64_t)time(NULL) * 1000;
            ev.data.chat.sender_port = eng->config.local_port;
            size_t msglen = view.length < sizeof(ev.data.chat.text) - 1 ? view.length : sizeof(ev.data.chat.text) - 1;
            memcpy(ev.data.chat.text, view.payload, msglen);
            ev.data.chat.text[msglen] = '\0';
            transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
            if (evp) {
                memcpy(evp, &ev, sizeof(ev));
                ring_push(&eng->event_ring, evp);
            }
            /* auto-send delivery ack */
            transport_engine_send_delivery_ack(eng, view.seq);
        }
        pool_return(p);
        return;
    }

    if (sess->state == SESSION_LOCKED) {
        uint64_t now_ms = (uint64_t)time(NULL) * 1000;
        uint8_t opcode = p->data[24];

        if (heartbeat_handle(p, sess, &eng->tx_queues[0], &eng->seq_counter, now_ms) > 0) {
            pool_return(p); return;
        }
        if (reconnect_handle(p, sess, &eng->tx_queues[0], &eng->seq_counter, now_ms) > 0) {
            pool_return(p); return;
        }
        int hop_ret = port_hop_handle(p, sess);
        if (hop_ret == 1)
            port_hop_send_ack(sess, &eng->tx_queues[0], (struct sockaddr_in6*)p->addr, &eng->seq_counter);
        if (hop_ret > 0) { pool_return(p); return; }

        if (rekey_handle(p, sess, &eng->tx_queues[0], &eng->seq_counter) > 0) {
            pool_return(p); return;
        }

        /* typing indicator */
        if (opcode == CTRL_TYPING) {
            transport_event_t ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = EVENT_TYPING;
            ev.timestamp_ms = now_ms;
            transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
            if (evp) { memcpy(evp, &ev, sizeof(ev)); ring_push(&eng->event_ring, evp); }
            pool_return(p); return;
        }

        /* delivery ack */
        if (opcode == CTRL_DELIVERY_ACK && p->len >= 24 + 1 + 4) {
            uint32_t ack_seq;
            memcpy(&ack_seq, p->data + 25, 4);
            transport_event_t ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = EVENT_DELIVERY_ACK;
            ev.timestamp_ms = now_ms;
            ev.data.delivery_ack.message_seq = ack_seq;
            transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
            if (evp) { memcpy(evp, &ev, sizeof(ev)); ring_push(&eng->event_ring, evp); }
            pool_return(p); return;
        }

        /* read ack */
        if (opcode == CTRL_READ_ACK && p->len >= 24 + 1 + 4) {
            uint32_t ack_seq;
            memcpy(&ack_seq, p->data + 25, 4);
            transport_event_t ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = EVENT_READ_ACK;
            ev.timestamp_ms = now_ms;
            ev.data.read_ack.message_seq = ack_seq;
            transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
            if (evp) { memcpy(evp, &ev, sizeof(ev)); ring_push(&eng->event_ring, evp); }
            pool_return(p); return;
        }
    }

    packet_buf_t* response = handshake_run_as_responder(sess, p, &eng->seq_counter);
    if (response) {
        memcpy(response->addr, &eng->peer_addr, sizeof(eng->peer_addr));
        response->addr_len = sizeof(eng->peer_addr);
        ring_push(&eng->tx_queues[0].control, response);
    }

    pool_return(p);

    if (sess->state == SESSION_LOCKED && !eng->session_is_locked) {
        eng->session_is_locked = 1;
        connection_manager_update_state(eng->connect_addr_str, eng->connect_port, PEER_LOCKED);
        route_table_add(&eng->route_table, RELAY_NODE_RESPONDER,
                        sess->session_id, &eng->peer_addr, sizeof(eng->peer_addr));
        transport_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.type = EVENT_CONNECTION_STATE_CHANGED;
        ev.timestamp_ms = (uint64_t)time(NULL) * 1000;
        ev.data.conn_state.old_state = CONN_HANDSHAKE;
        ev.data.conn_state.new_state = CONN_LOCKED;
        transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
        if (evp) {
            memcpy(evp, &ev, sizeof(ev));
            ring_push(&eng->event_ring, evp);
        }
    }
}

int transport_engine_send_chat(transport_engine_t* eng, const char* text)
{
    if (!eng || !eng->session || !eng->session_is_locked) return -1;

    session_t* sess = eng->session;
    int path_idx = 0;

    if (eng->config.multipath_enabled) {
        path_idx = resilience_select_path(&sess->resilience);
        if (path_idx >= eng->socket_count) path_idx = 0;
    }
    resilience_record_tx(&sess->resilience, path_idx);

    packet_buf_t* chat = build_chat_packet(sess, &eng->seq_counter, text);
    if (!chat) return -1;

    if (encrypt_tx_packet(chat, sess) != 0) {
        pool_return(chat);
        return -1;
    }

    struct sockaddr_in6* addrs[ENGINE_MAX_SOCKETS];
    for (int i = 0; i < eng->socket_count && i < ENGINE_MAX_SOCKETS; i++)
        addrs[i] = (struct sockaddr_in6*)&eng->peer_addr;
    if (eng->socket_count > 1 && path_idx == 1) {
        static struct sockaddr_in6 alt_addr;
        if (alt_addr.sin6_port == 0) {
            memcpy(&alt_addr, &eng->peer_addr, sizeof(alt_addr));
            alt_addr.sin6_port = htons(ntohs(eng->peer_addr.sin6_port) + 2);
        }
        addrs[1] = &alt_addr;
    }

    fec_tx_after_encrypt(chat, sess, &eng->tx_queues[path_idx], addrs[path_idx]);

    memcpy(chat->addr, addrs[path_idx], sizeof(*addrs[path_idx]));
    chat->addr_len = sizeof(*addrs[path_idx]);

    tx_queues_t* txq = &eng->tx_queues[path_idx];
    ring_push(&txq->chat, chat);
    return 0;
}

int transport_engine_poll(transport_engine_t* eng, transport_event_t* ev)
{
    if (!eng || !ev) return 0;

    monitor_mark_alive("rx-worker");

    /* check event ring first */
    transport_event_t* evp = (transport_event_t*)ring_pop(&eng->event_ring);
    if (evp) {
        memcpy(ev, evp, sizeof(*evp));
        free(evp);
        return 1;
    }

    /* check crypto results (decrypted packets) */
    packet_buf_t* decrypted = NULL;
    if (crypto_worker_pop_result(&decrypted) > 0 && decrypted) {
        if (eng->role_initiator)
            engine_control_handler(eng, decrypted);
        else
            engine_responder_handler(eng, decrypted);
    }

    /* process one RX ring per call for fairness */
    for (int i = 0; i < eng->socket_count; i++) {
        pipeline_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.sess = eng->session;
        ctx.rxq = &eng->rx_queues[i];

        packet_buf_t* p = (packet_buf_t*)ring_pop(&eng->rx_rings[i]);
        if (!p) continue;

        ctx.recovered = NULL;
        pipeline_result_t result = pipeline_inbound_pre_crypto(p, &ctx);
        if (result == 0) {
            if (ctx.view.encrypted) {
                crypto_job_t* job = (crypto_job_t*)malloc(sizeof(crypto_job_t));
                if (job) {
                    job->type = CRYPTO_JOB_DECRYPT;
                    job->p = p;
                    job->sess = eng->session;
                    if (crypto_worker_push(job) != 0) {
                        free(job);
                        pool_return(p);
                    }
                } else {
                    pool_return(p);
                }
            } else {
                if (eng->role_initiator)
                    engine_control_handler(eng, p);
                else
                    engine_responder_handler(eng, p);
            }
        } else if (result == PIPELINE_DROP_SESSION) {
            uint8_t ch = p->data[14];
            uint8_t op = p->data[24];
            if (ch == CH_CONTROL) {
                if (op == CTRL_CONNECT_REQUEST && !eng->role_initiator) {
                    int handled = conn_request_handle(p, NULL, NULL, NULL, 1);
                    if (handled > 0) {
                        transport_event_t ev;
                        memset(&ev, 0, sizeof(ev));
                        ev.type = EVENT_CONNECT_REQUEST;
                        ev.timestamp_ms = (uint64_t)time(NULL) * 1000;

                        pending_request_t* req = conn_request_find((struct sockaddr_in6*)p->addr);
                        if (req) {
                            inet_ntop(AF_INET6, ((struct sockaddr_in6*)p->addr)->sin6_addr.s6_addr,
                                      ev.data.conn_req.addr, sizeof(ev.data.conn_req.addr));
                            ev.data.conn_req.port = ntohs(((struct sockaddr_in6*)p->addr)->sin6_port);
                            snprintf(ev.data.conn_req.username, sizeof(ev.data.conn_req.username), "%s", req->username);
                            snprintf(ev.data.conn_req.display_name, sizeof(ev.data.conn_req.display_name), "%s", req->display_name);
                        }
                        transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
                        if (evp) {
                            memcpy(evp, &ev, sizeof(ev));
                            ring_push(&eng->event_ring, evp);
                        }
                    }
                } else if (op == CTRL_CONNECT_ACCEPT && eng->role_initiator) {
                    transport_event_t ev;
                    memset(&ev, 0, sizeof(ev));
                    ev.type = EVENT_CONNECT_ACCEPTED;
                    ev.timestamp_ms = (uint64_t)time(NULL) * 1000;
                    transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
                    if (evp) { memcpy(evp, &ev, sizeof(ev)); ring_push(&eng->event_ring, evp); }
                } else if (op == CTRL_CONNECT_DECLINE && eng->role_initiator) {
                    transport_event_t ev;
                    memset(&ev, 0, sizeof(ev));
                    ev.type = EVENT_CONNECT_DECLINED;
                    ev.timestamp_ms = (uint64_t)time(NULL) * 1000;
                    transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
                    if (evp) { memcpy(evp, &ev, sizeof(ev)); ring_push(&eng->event_ring, evp); }
                }
            }
            pool_return(p);
        } else {
            pool_return(p);
        }
        return 1;
    }

    /* periodic ticks */
    eng->loop_ticks++;
    if (eng->loop_ticks >= 100)
        eng->loop_ticks = 0;

    if (eng->loop_ticks % 30 == 0 && eng->session) {
        uint64_t now_ms = (uint64_t)time(NULL) * 1000;
        abr_update(&eng->abr, &eng->session->resilience, now_ms);
    }

    if (eng->loop_ticks % 10 == 0 && eng->session) {
        uint64_t now_ms = (uint64_t)time(NULL) * 1000;
        heartbeat_tick(eng->session, &eng->tx_queues[0], &eng->seq_counter, now_ms);
        reconnect_tick(eng->session, &eng->tx_queues[0], &eng->seq_counter, now_ms);
    }

    if (eng->loop_ticks % 20 == 0) {
        uint64_t now_ms = (uint64_t)time(NULL) * 1000;
        offensive_tick(now_ms);
    }

    if (eng->loop_ticks % 5 == 0 && eng->session && eng->session_is_locked) {
        packet_buf_t* decoy = offensive_build_decoy(&eng->peer_addr);
        if (decoy) {
            g_offensive.total_decoys++;
            ring_push(&eng->tx_queues[0].control, decoy);
        }
    }

    /* audio/video worker ticks */
    if (eng->session && eng->session_is_locked) {
        if (eng->audio_call_active)
            audio_worker_tick(&eng->audio, eng->session, &eng->tx_queues[0],
                              &eng->rx_queues[0], &eng->seq_counter, &eng->peer_addr);
        if (eng->video_call_active)
            video_worker_tick(&eng->video, eng->session, &eng->tx_queues[0],
                              &eng->rx_queues[0], &eng->seq_counter, &eng->peer_addr);
    }

    /* file transfer TX */
    if (eng->session_is_locked && eng->cur_file_send_idx >= 0 && eng->loop_ticks % 3 == 0) {
        uint8_t chunk[FILE_CHUNK_SIZE + 4]; /* 4 bytes for seq */
        uint32_t chunk_len = 0;
        int done = file_send_chunk(&eng->file_ctx, eng->cur_file_send_idx, chunk + 4, &chunk_len);
        if (done >= 0 && chunk_len > 0) {
            uint32_t seq = eng->seq_counter++;
            memcpy(chunk, &seq, 4);
            uint32_t total = 4 + chunk_len;

            packet_buf_t* p = pool_get();
            if (p) {
                uint8_t* d = p->data;
                uint32_t magic = 0xAABBCCDD;
                uint8_t ver = 1, fl = 0, ch = CH_FILE;
                memcpy(d + 0, &magic, 4);
                memcpy(d + 4, &ver, 1);
                memcpy(d + 5, &fl, 1);
                memcpy(d + 6, &eng->session->session_id, 8);
                memcpy(d + 14, &ch, 1);
                memcpy(d + 15, &seq, 4);
                memcpy(d + 19, &total, 4);
                memcpy(d + 24, chunk, total);
                p->len = 24 + total;

                packet_view_t view = { 0 };
                if (packet_parse(p, &view) == 0)
                    session_enc_apply(p, &view, eng->session);
                memcpy(p->addr, &eng->peer_addr, sizeof(eng->peer_addr));
                p->addr_len = sizeof(eng->peer_addr);
                ring_push(&eng->tx_queues[0].file, p);
            }
        }
        if (done == 1) {
            eng->cur_file_send_idx = -1;
            transport_event_t ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = EVENT_FILE_TRANSFER_COMPLETE;
            ev.timestamp_ms = (uint64_t)time(NULL) * 1000;
            transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
            if (evp) { memcpy(evp, &ev, sizeof(ev)); ring_push(&eng->event_ring, evp); }
        }
    }

    /* file transfer RX */
    if (eng->session_is_locked) {
        packet_buf_t* p = (packet_buf_t*)ring_pop(&eng->rx_queues[0].file);
        if (p) {
            packet_view_t view = { 0 };
            if (packet_parse(p, &view) == 0 && view.channel_id == CH_FILE && view.length >= 4) {
                uint32_t chunk_seq;
                memcpy(&chunk_seq, view.payload, 4);
                if (eng->cur_file_recv_idx >= 0) {
                    int done = file_recv_chunk(&eng->file_ctx, eng->cur_file_recv_idx,
                                               view.payload + 4, view.length - 4, chunk_seq);
                    if (done == 1) {
                        char* home = getenv("HOME");
                        char save_dir[256];
                        if (home) snprintf(save_dir, sizeof(save_dir), "%s/Downloads", home);
                        else snprintf(save_dir, sizeof(save_dir), "/tmp");
                        file_recv_finish(&eng->file_ctx, eng->cur_file_recv_idx, save_dir);
                        eng->cur_file_recv_idx = -1;
                        transport_event_t ev;
                        memset(&ev, 0, sizeof(ev));
                        ev.type = EVENT_FILE_TRANSFER_COMPLETE;
                        ev.timestamp_ms = (uint64_t)time(NULL) * 1000;
                        transport_event_t* evp = (transport_event_t*)malloc(sizeof(transport_event_t));
                        if (evp) { memcpy(evp, &ev, sizeof(ev)); ring_push(&eng->event_ring, evp); }
                    }
                }
            }
            pool_return(p);
        }
    }

    return 0;
}

int transport_engine_send_connect_request(transport_engine_t* eng, const char* addr_str,
                                           uint16_t port, const char* username,
                                           const char* display_name)
{
    if (!eng || !addr_str || !username || !eng->initialized) return -1;

    struct sockaddr_in6 peer_addr;
    if (resolve_peer(&peer_addr, addr_str, port) != 0) return -1;

    eng->peer_addr = peer_addr;
    eng->peer_configured = 1;
    eng->role_initiator = 1;
    snprintf(eng->connect_addr_str, sizeof(eng->connect_addr_str), "%s", addr_str);
    eng->connect_port = port;

    session_t* sess = session_alloc_for_peer(&peer_addr, sizeof(peer_addr), SESSION_DIR_OUTBOUND);
    if (!sess) return -1;
    sess->local_port = eng->config.local_port;
    eng->session = sess;
    eng->session_is_locked = 0;

    conn_request_build(sess, &eng->tx_queues[0], &eng->seq_counter, username, display_name);
    return 0;
}

int transport_engine_accept_connection(transport_engine_t* eng, const char* addr_str, uint16_t port)
{
    if (!eng || !addr_str || !eng->initialized) return -1;

    struct sockaddr_in6 peer_addr;
    if (resolve_peer(&peer_addr, addr_str, port) != 0) return -1;

    session_t* sess = session_alloc_for_peer(&peer_addr, sizeof(peer_addr), SESSION_DIR_INBOUND);
    if (!sess) return -1;
    sess->local_port = eng->config.local_port;

    if (eng->config.multipath_enabled && eng->socket_count > 1) {
        struct sockaddr_in6 alt_addr = peer_addr;
        alt_addr.sin6_port = htons(port + 2);
        session_register_path(sess, 1, &alt_addr, sizeof(alt_addr));
        sess->resilience.path_count = 2;
        sess->resilience.multipath_enabled = 1;
        sess->resilience.paths[0].peer_port = peer_addr.sin6_port;
        sess->resilience.paths[1].peer_port = alt_addr.sin6_port;
    } else {
        sess->resilience.path_count = 1;
    }

    if (eng->session) session_reset(eng->session);
    eng->session = sess;
    eng->peer_addr = peer_addr;
    eng->peer_configured = 1;
    eng->role_initiator = 0;
    eng->session_is_locked = 0;
    snprintf(eng->connect_addr_str, sizeof(eng->connect_addr_str), "%s", addr_str);
    eng->connect_port = port;

    conn_request_send_accept(sess, &eng->tx_queues[0], &eng->seq_counter, &peer_addr);
    connection_manager_connect(addr_str, port);
    return 0;
}

int transport_engine_decline_connection(transport_engine_t* eng, const char* addr_str, uint16_t port)
{
    if (!eng || !addr_str || !eng->initialized) return -1;

    struct sockaddr_in6 peer_addr;
    if (resolve_peer(&peer_addr, addr_str, port) != 0) return -1;

    session_t* sess = session_alloc_for_peer(&peer_addr, sizeof(peer_addr), SESSION_DIR_INBOUND);
    if (!sess) return -1;
    sess->local_port = eng->config.local_port;

    conn_request_send_decline(sess, &eng->tx_queues[0], &eng->seq_counter, &peer_addr, "Declined");
    session_reset(sess);
    return 0;
}

void transport_engine_get_info(transport_engine_t* eng, conn_info_t* info)
{
    memset(info, 0, sizeof(*info));
    if (!eng || !eng->session) {
        info->state = CONN_IDLE;
        return;
    }
    session_t* sess = eng->session;
    info->state = sess->state == SESSION_LOCKED ? CONN_LOCKED : CONN_HANDSHAKE;
    info->session_id = sess->session_id;
    info->peer_port = eng->config.local_port;
    info->uptime_ms = eng->start_time_ms > 0 ?
        (uint32_t)((uint64_t)time(NULL) * 1000 - eng->start_time_ms) : 0;
    info->fec_enabled = sess->resilience.fec_enabled;
    info->path_count = sess->resilience.path_count;
    for (uint32_t i = 0; i < info->path_count && i < RESILIENCE_MAX_PATHS; i++) {
        info->paths[i].loss_rate = sess->resilience.paths[i].loss_rate;
        info->paths[i].rtt_ns = sess->resilience.paths[i].rtt_ns;
        info->paths[i].packets_sent = sess->resilience.paths[i].packets_sent;
        info->paths[i].packets_recv = sess->resilience.paths[i].packets_recv;
    }
}

int transport_engine_audio_call_start(transport_engine_t* eng)
{
    if (!eng || !eng->session_is_locked) return -1;
    eng->audio_call_active = 1;
    audio_worker_set_active(&eng->audio, 1);
    return 0;
}

int transport_engine_audio_call_end(transport_engine_t* eng)
{
    if (!eng) return -1;
    eng->audio_call_active = 0;
    audio_worker_set_active(&eng->audio, 0);
    return 0;
}

int transport_engine_video_call_start(transport_engine_t* eng)
{
    if (!eng || !eng->session_is_locked) return -1;
    eng->video_call_active = 1;
    video_worker_set_active(&eng->video, 1);
    return 0;
}

int transport_engine_video_call_end(transport_engine_t* eng)
{
    if (!eng) return -1;
    eng->video_call_active = 0;
    video_worker_set_active(&eng->video, 0);
    return 0;
}

int transport_engine_send_file(transport_engine_t* eng, const char* filepath)
{
    if (!eng || !filepath || !eng->session_is_locked) return -1;
    int idx = file_send_start(&eng->file_ctx, filepath);
    if (idx < 0) return -1;

    /* send file meta packet */
    file_send_t* s = &eng->file_ctx.sends[idx];
    uint8_t meta[256];
    uint32_t meta_len = 0;
    uint32_t fname_len = (uint32_t)strlen(s->meta.filename);
    meta[meta_len++] = CTRL_FILE_META;
    meta[meta_len++] = (uint8_t)(fname_len > 63 ? 63 : fname_len);
    uint32_t fnc = fname_len > 63 ? 63 : fname_len;
    memcpy(meta + meta_len, s->meta.filename, fnc);
    meta_len += fnc;
    memcpy(meta + meta_len, &s->meta.total_size, 4);
    meta_len += 4;
    memcpy(meta + meta_len, &s->meta.total_chunks, 4);
    meta_len += 4;
    memcpy(meta + meta_len, &s->meta.checksum, 4);
    meta_len += 4;

    packet_buf_t* p = pool_get();
    if (!p) return -1;
    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t ver = 1, fl = 0, ch = CH_CONTROL;
    uint32_t seq = eng->seq_counter++;
    memcpy(d + 0, &magic, 4);
    memcpy(d + 4, &ver, 1);
    memcpy(d + 5, &fl, 1);
    memcpy(d + 6, &eng->session->session_id, 8);
    memcpy(d + 14, &ch, 1);
    memcpy(d + 15, &seq, 4);
    memcpy(d + 19, &meta_len, 4);
    memcpy(d + 24, meta, meta_len);
    p->len = 24 + meta_len;
    memcpy(p->addr, &eng->peer_addr, sizeof(eng->peer_addr));
    p->addr_len = sizeof(eng->peer_addr);
    ring_push(&eng->tx_queues[0].control, p);

    eng->cur_file_send_idx = idx;
    return 0;
}

int transport_engine_send_typing(transport_engine_t* eng)
{
    if (!eng || !eng->session || !eng->session_is_locked) return -1;
    session_t* sess = eng->session;

    packet_buf_t* p = pool_get();
    if (!p) return -1;
    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t ver = 1, fl = 0, ch = CH_CONTROL;
    uint32_t seq = eng->seq_counter++;
    uint32_t payload_len = 1;
    memset(d, 0, 24);
    memcpy(d + 0, &magic, 4);
    memcpy(d + 4, &ver, 1);
    memcpy(d + 5, &fl, 1);
    memcpy(d + 6, &sess->session_id, 8);
    memcpy(d + 14, &ch, 1);
    memcpy(d + 15, &seq, 4);
    memcpy(d + 19, &payload_len, 4);
    d[24] = CTRL_TYPING;
    p->len = 24 + payload_len;
    memcpy(p->addr, &eng->peer_addr, sizeof(eng->peer_addr));
    p->addr_len = sizeof(eng->peer_addr);
    ring_push(&eng->tx_queues[0].control, p);
    return 0;
}

int transport_engine_send_delivery_ack(transport_engine_t* eng, uint32_t msg_seq)
{
    if (!eng || !eng->session || !eng->session_is_locked) return -1;
    session_t* sess = eng->session;

    packet_buf_t* p = pool_get();
    if (!p) return -1;
    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t ver = 1, fl = 0, ch = CH_CONTROL;
    uint32_t seq = eng->seq_counter++;
    uint32_t payload_len = 1 + 4;
    memset(d, 0, 24);
    memcpy(d + 0, &magic, 4);
    memcpy(d + 4, &ver, 1);
    memcpy(d + 5, &fl, 1);
    memcpy(d + 6, &sess->session_id, 8);
    memcpy(d + 14, &ch, 1);
    memcpy(d + 15, &seq, 4);
    memcpy(d + 19, &payload_len, 4);
    d[24] = CTRL_DELIVERY_ACK;
    memcpy(d + 25, &msg_seq, 4);
    p->len = 24 + payload_len;
    memcpy(p->addr, &eng->peer_addr, sizeof(eng->peer_addr));
    p->addr_len = sizeof(eng->peer_addr);
    ring_push(&eng->tx_queues[0].control, p);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Demo (kept for backward compatibility)                             */
/* ------------------------------------------------------------------ */

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

        if (rekey_handle(p, sess, ctx->txq, ctx->seq_counter) > 0) {
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

        if (rekey_handle(p, sess, ctx->txq, ctx->seq_counter) > 0) {
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

    secure_store_init();
    pool_init();
    route_table_init(&g_route_table);
    abr_init(&g_abr_initiator);
    abr_init(&g_abr_responder);
    kernel_filter_init();
    anti_analysis_init();
    offensive_init();
    monitor_start();

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
