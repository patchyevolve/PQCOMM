#include "handshake.h"
#include "session_enc.h"
#include "session.h"
#include "pool.h"
#include "packet_parse.h"
#include "kem.h"
#include "secure_store.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * Load and stress tests.
 * Tests throughput, multi-session concurrency, long-running scenarios.
 */

/* High-throughput chat message exchange test */
static int test_load_bulk_chat_messages_internal(void)
{
    session_t alice, bob;
    session_init(&alice);
    session_init(&bob);
    pool_init();

    uint8_t alice_key[32];
    memset(alice_key, 0xAA, 32);
    secure_store_set_key(alice_key, 32);

    uint8_t bob_key[32];
    memset(bob_key, 0xBB, 32);

    uint32_t seq_a = 1, seq_b = 1;

    /* Full handshake */
    if (handshake_init_initiator(&alice, KEM_TYPE_MLKEM_768) != 0) return -1;
    session_init(&bob);
    secure_store_set_key(bob_key, 32);
    if (handshake_init_responder(&bob, KEM_TYPE_MLKEM_768) != 0) return -2;

    packet_buf_t* p = handshake_build_hello(&alice, &seq_a);
    if (!p) return -3;
    p = handshake_run_as_responder(&bob, p, &seq_b);
    if (!p) return -4;
    p = handshake_run_as_initiator(&alice, p, &seq_a);
    if (!p) return -5;
    p = handshake_run_as_responder(&bob, p, &seq_b);
    if (!p) return -6;
    p = handshake_run_as_initiator(&alice, p, &seq_a);
    if (!p) return -7;
    p = handshake_run_as_responder(&bob, p, &seq_b);
    if (!p) return -8;
    p = handshake_run_as_initiator(&alice, p, &seq_a);
    if (p != NULL) return -9;

    /* Send 1000 encrypted chat messages Alice → Bob */
    const int N = 1000;
    for (int i = 0; i < N; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Message %d from Alice", i);
        uint32_t msg_len = (uint32_t)strlen(msg) + 1;

        packet_buf_t* chat_pkt = pool_get();
        if (!chat_pkt) return -10;

        uint8_t* d = chat_pkt->data;
        uint32_t magic = 0xAABBCCDD;
        uint8_t ver = 1, ch = 3;
        uint64_t sid = alice.session_id;
        uint32_t seq = (uint32_t)(i + 1);

        memcpy(d + 0, &magic, 4);
        d[4] = ver;
        d[5] = 0;
        memcpy(d + 6, &sid, 8);
        memcpy(d + 14, &ch, 1);
        memcpy(d + 15, &seq, 4);
        memcpy(d + 19, &msg_len, 4);
        memcpy(d + 24, msg, msg_len);
        chat_pkt->len = 24 + msg_len;

        packet_view_t av2;
        if (packet_parse(chat_pkt, &av2) != 0) return -11;
        if (session_enc_apply(chat_pkt, &av2, &alice) != 0) return -12;

        packet_view_t bv2;
        if (packet_parse(chat_pkt, &bv2) != 0) return -13;
        if (session_enc_check(&bv2, &bob) != 0) return -14;

        char decrypted[64];
        uint32_t dlen = bv2.length;
        if (dlen >= sizeof(decrypted)) dlen = sizeof(decrypted) - 1;
        memcpy(decrypted, bv2.payload, dlen);
        decrypted[dlen] = '\0';

        if (strcmp(decrypted, msg) != 0) return -15;

        pool_return(chat_pkt);
    }

    /* Verify session keys intact after bulk exchange */
    if (memcmp(alice.keys.session_key, bob.keys.session_key, 32) != 0) return -14;

    return 0;
}

/* Multi-session concurrency test — simulate 8 independent handshakes */
static int test_load_multi_session_concurrent_internal(void)
{
    pool_init();

    for (int i = 0; i < 8; i++) {
        session_t init, resp;
        session_init(&init);
        session_init(&resp);

        uint32_t seq_a = 1, seq_b = 1;

        uint8_t key_a[32], key_b[32];
        memset(key_a, (uint8_t)(0xA0 + i), 32);
        memset(key_b, (uint8_t)(0xB0 + i), 32);

        secure_store_set_key(key_a, 32);
        if (handshake_init_initiator(&init, KEM_TYPE_MLKEM_768) != 0) return -1;

        secure_store_set_key(key_b, 32);
        if (handshake_init_responder(&resp, KEM_TYPE_MLKEM_768) != 0) return -2;

        packet_buf_t* p = handshake_build_hello(&init, &seq_a);
        if (!p) return -3;
        p = handshake_run_as_responder(&resp, p, &seq_b);
        if (!p) return -4;
        p = handshake_run_as_initiator(&init, p, &seq_a);
        if (!p) return -5;
        p = handshake_run_as_responder(&resp, p, &seq_b);
        if (!p) return -6;
        p = handshake_run_as_initiator(&init, p, &seq_a);
        if (!p) return -7;
        p = handshake_run_as_responder(&resp, p, &seq_b);
        if (!p) return -8;
        p = handshake_run_as_initiator(&init, p, &seq_a);
        if (p != NULL) return -9;

        if (init.state != SESSION_LOCKED) return -10;
        if (resp.state != SESSION_LOCKED) return -11;
    }

    return 0;
}

/* Long-running handshake with random round-trip delays */
static int test_load_random_delay_handshake_internal(void)
{
    srand((unsigned int)time(NULL));

    session_t alice, bob;
    session_init(&alice);
    session_init(&bob);
    pool_init();

    uint8_t alice_key[32];
    memset(alice_key, 0xAA, 32);
    secure_store_set_key(alice_key, 32);

    uint8_t bob_key[32];
    memset(bob_key, 0xBB, 32);

    uint32_t seq_a = 1, seq_b = 1;

    if (handshake_init_initiator(&alice, KEM_TYPE_MLKEM_768) != 0) return -1;
    session_init(&bob);
    secure_store_set_key(bob_key, 32);
    if (handshake_init_responder(&bob, KEM_TYPE_MLKEM_768) != 0) return -2;

    /* Run handshake with random delays between messages */
    packet_buf_t* p = handshake_build_hello(&alice, &seq_a);
    if (!p) return -3;
    /* Simulate network delay */
    for (volatile int d = 0; d < rand() % 10000; d++);
    p = handshake_run_as_responder(&bob, p, &seq_b);
    if (!p) return -4;

    for (volatile int d = 0; d < rand() % 10000; d++);
    p = handshake_run_as_initiator(&alice, p, &seq_a);
    if (!p) return -5;

    for (volatile int d = 0; d < rand() % 10000; d++);
    p = handshake_run_as_responder(&bob, p, &seq_b);
    if (!p) return -6;

    for (volatile int d = 0; d < rand() % 10000; d++);
    p = handshake_run_as_initiator(&alice, p, &seq_a);
    if (!p) return -7;

    for (volatile int d = 0; d < rand() % 10000; d++);
    p = handshake_run_as_responder(&bob, p, &seq_b);
    if (!p) return -8;

    for (volatile int d = 0; d < rand() % 10000; d++);
    p = handshake_run_as_initiator(&alice, p, &seq_a);
    if (p != NULL) return -9;

    if (alice.state != SESSION_LOCKED) return -10;
    if (bob.state != SESSION_LOCKED) return -11;

    return 0;
}

/* Repeated handshake cycle: connect ↔ disconnect ↔ reconnect */
static int test_load_reconnect_cycle_internal(void)
{
    for (int cycle = 0; cycle < 10; cycle++) {
        session_t alice, bob;
        session_init(&alice);
        session_init(&bob);
        pool_init();

        uint8_t alice_key[32];
        memset(alice_key, 0xAA, 32);
        secure_store_set_key(alice_key, 32);

        uint8_t bob_key[32];
        memset(bob_key, 0xBB, 32);

        uint32_t seq_a = 1, seq_b = 1;

        if (handshake_init_initiator(&alice, KEM_TYPE_MLKEM_768) != 0) return -1;
        session_init(&bob);
        secure_store_set_key(bob_key, 32);
        if (handshake_init_responder(&bob, KEM_TYPE_MLKEM_768) != 0) return -2;

        packet_buf_t* p = handshake_build_hello(&alice, &seq_a);
        if (!p) return -3;
        p = handshake_run_as_responder(&bob, p, &seq_b);
        if (!p) return -4;
        p = handshake_run_as_initiator(&alice, p, &seq_a);
        if (!p) return -5;
        p = handshake_run_as_responder(&bob, p, &seq_b);
        if (!p) return -6;
        p = handshake_run_as_initiator(&alice, p, &seq_a);
        if (!p) return -7;
        p = handshake_run_as_responder(&bob, p, &seq_b);
        if (!p) return -8;
        p = handshake_run_as_initiator(&alice, p, &seq_a);
        if (p != NULL) return -9;

        /* Verify locked */
        if (alice.state != SESSION_LOCKED) return -10;
        if (bob.state != SESSION_LOCKED) return -11;

        /* Disconnect and reconnect */
        session_init(&alice);
        session_init(&bob);
    }

    return 0;
}

int test_load_bulk_chat_messages(void) { return test_load_bulk_chat_messages_internal(); }
int test_load_multi_session_concurrent(void) { return test_load_multi_session_concurrent_internal(); }
int test_load_random_delay_handshake(void) { return test_load_random_delay_handshake_internal(); }
int test_load_reconnect_cycle(void) { return test_load_reconnect_cycle_internal(); }
