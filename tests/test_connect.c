#include "handshake.h"
#include "kem.h"
#include "session.h"
#include "pool.h"
#include "rekey.h"
#include "scheduler.h"
#include <string.h>
#include <stdio.h>

int test_connect_basic(void)
{
    session_t sess;
    session_init(&sess);
    sess.local_port = 9001;

    pool_init();

    if (handshake_init_initiator(&sess, KEM_TYPE_MLKEM_768) != 0) {
        printf("[FAIL] handshake_init_initiator\n");
        return -1;
    }

    uint32_t seq = 1;
    packet_buf_t* hello = handshake_build_hello(&sess, &seq);
    if (!hello) {
        printf("[FAIL] handshake_build_hello\n");
        return -1;
    }
    if (sess.state != SESSION_HANDSHAKE_START) {
        printf("[FAIL] expected HANDSHAKE_START, got %d\n", sess.state);
        return -1;
    }

    printf("[PASS] test_connect_basic\n");
    return 0;
}

int test_session_lifecycle(void)
{
    session_t s;
    session_init(&s);
    if (s.state != SESSION_IDLE) {
        printf("[FAIL] expected IDLE\n");
        return -1;
    }

    session_reset(&s);
    if (s.state != SESSION_IDLE) {
        printf("[FAIL] reset expected IDLE\n");
        return -1;
    }

    session_zero_secrets(&s);

    session_t s2;
    session_init(&s2);
    s2.keys.key_epoch = 42;
    session_zero_secrets(&s2);
    if (s2.keys.key_epoch != 0) {
        printf("[FAIL] zero_secrets should clear key_epoch\n");
        return -1;
    }

    printf("[PASS] test_session_lifecycle\n");
    return 0;
}

int test_rekey_protocol(void)
{
    session_t init, resp;
    session_init(&init);
    session_init(&resp);

    init.state = SESSION_LOCKED;
    init.handshake_complete = 1;
    init.keys.key_epoch = 0;
    resp.state = SESSION_LOCKED;
    resp.handshake_complete = 1;
    resp.keys.key_epoch = 0;

    uint32_t seq_i = 1, seq_r = 1;

    pool_init();
    tx_queues_t txq;
    tx_queues_init(&txq);

    if (rekey_initiate(&init, &txq, &seq_i) != 0) {
        printf("[FAIL] rekey_initiate\n");
        return -1;
    }

    printf("[PASS] test_rekey_protocol\n");
    return 0;
}

int test_pool_basic(void)
{
    pool_init();
    packet_buf_t* p = pool_get();
    if (!p) {
        printf("[FAIL] pool_get returned NULL\n");
        return -1;
    }
    pool_return(p);

    uint32_t free_count = pool_free_count();
    if (free_count != PACKET_POOL_SIZE) {
        printf("[FAIL] expected %u free, got %u\n", PACKET_POOL_SIZE, free_count);
        return -1;
    }

    printf("[PASS] test_pool_basic\n");
    return 0;
}
