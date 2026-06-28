#include "handshake.h"
#include "session_enc.h"
#include "session.h"
#include "pool.h"
#include "packet_parse.h"
#include "kem.h"
#include "secure_store.h"
#include "aead.h"
#include "hkdf.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * Performance benchmarks.
 * Each test measures throughput/latency and returns pass/fail;
 * results are printed to stdout for analysis.
 */

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* Benchmark: full handshake latency */
static int bench_handshake_latency(void)
{
    const int N = 100;
    double total_ms = 0;

    for (int i = 0; i < N; i++) {
        session_t alice, bob;
        session_init(&alice);
        session_init(&bob);
        pool_init();

        uint8_t key[32];
        memset(key, (uint8_t)(0xA0 + i), 32);
        secure_store_set_key(key, 32);

        uint32_t seq_a = 1, seq_b = 1;

        if (handshake_init_initiator(&alice, KEM_TYPE_MLKEM_768) != 0) return -1;
        secure_store_set_key(key, 32);
        if (handshake_init_responder(&bob, KEM_TYPE_MLKEM_768) != 0) return -2;

        double t0 = now_ms();

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

        double t1 = now_ms();
        total_ms += (t1 - t0);

        if (alice.state != SESSION_LOCKED) return -10;
        if (bob.state != SESSION_LOCKED) return -11;
    }

    double avg_ms = total_ms / N;
    printf("[BENCH] handshake latency: %.2f ms avg over %d runs\n", avg_ms, N);

    /* Must be under 5 seconds (should be ~100-500ms with ML-KEM) */
    if (avg_ms > 5000) return -12;

    return 0;
}

/* Benchmark: encrypted chat throughput */
static int bench_chat_throughput(void)
{
    session_t alice, bob;
    session_init(&alice);
    session_init(&bob);
    pool_init();

    uint8_t key[32];
    memset(key, 0xAA, 32);
    secure_store_set_key(key, 32);

    uint32_t seq_a = 1, seq_b = 1;

    if (handshake_init_initiator(&alice, KEM_TYPE_MLKEM_768) != 0) return -1;
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

    const int N = 5000;
    const char* msg = "Performance test message for throughput measurement!";
    uint32_t msg_len = (uint32_t)strlen(msg) + 1;

    double t0 = now_ms();

    for (int i = 0; i < N; i++) {
        packet_buf_t* pkt = pool_get();
        if (!pkt) return -10;

        uint8_t* d = pkt->data;
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
        pkt->len = 24 + msg_len;

        packet_view_t v;
        if (packet_parse(pkt, &v) != 0) return -11;
        if (session_enc_apply(pkt, &v, &alice) != 0) return -12;

        packet_view_t v2;
        if (packet_parse(pkt, &v2) != 0) return -13;
        if (session_enc_check(&v2, &bob) != 0) return -14;

        pool_return(pkt);
    }

    double t1 = now_ms();
    double total_ms = t1 - t0;
    double msgs_per_sec = (double)N / (total_ms / 1000.0);

    printf("[BENCH] chat throughput: %.0f msgs/sec over %d messages\n",
           msgs_per_sec, N);

    if (msgs_per_sec < 100) return -15;

    return 0;
}

/* Benchmark: AEAD encrypt throughput */
static int bench_aead_encrypt(void)
{
    const int N = 10000;
    uint8_t key[32], nonce[12], aad[24], plain[1024], cipher[1024], tag[16];
    memset(key, 0xCC, 32);
    memset(nonce, 0xDD, 12);
    memset(aad, 0xEE, 24);
    memset(plain, 0xFF, 1024);

    double t0 = now_ms();

    for (int i = 0; i < N; i++) {
        nonce[0] = (uint8_t)(i & 0xFF);
        if (aead_encrypt(key, nonce, aad, 24, plain, 1024, cipher, tag) != 0)
            return -1;
    }

    double t1 = now_ms();
    double total_ms = t1 - t0;
    double mb_per_sec = ((double)N * 1024) / (total_ms / 1000.0) / (1024.0 * 1024.0);

    printf("[BENCH] AEAD encrypt: %.2f MB/s (%d x 1KB in %.0f ms)\n",
           mb_per_sec, N, total_ms);

    if (mb_per_sec < 10) return -2;

    return 0;
}

/* Benchmark: AEAD decrypt throughput */
static int bench_aead_decrypt(void)
{
    const int N = 10000;
    uint8_t key[32], nonce[12], aad[24], plain[1024], cipher[1024], tag[16], dec[1024];
    memset(key, 0xCC, 32);
    memset(aad, 0xEE, 24);
    memset(plain, 0xFF, 1024);

    /* Pre-encrypt */
    memset(nonce, 0xDD, 12);
    aead_encrypt(key, nonce, aad, 24, plain, 1024, cipher, tag);

    double t0 = now_ms();

    for (int i = 0; i < N; i++) {
        if (aead_decrypt(key, nonce, aad, 24, cipher, 1024, tag, dec) != 0)
            return -1;
    }

    double t1 = now_ms();
    double total_ms = t1 - t0;
    double mb_per_sec = ((double)N * 1024) / (total_ms / 1000.0) / (1024.0 * 1024.0);

    printf("[BENCH] AEAD decrypt: %.2f MB/s (%d x 1KB in %.0f ms)\n",
           mb_per_sec, N, total_ms);

    if (mb_per_sec < 10) return -2;

    return 0;
}

/* Benchmark: HKDF derivation throughput */
static int bench_hkdf_derive(void)
{
    const int N = 5000;
    uint8_t ikm[32], salt[32];
    uint8_t session_key[32], channel_keys[6][32];
    memset(ikm, 0x11, 32);
    memset(salt, 0x22, 32);

    double t0 = now_ms();

    for (int i = 0; i < N; i++) {
        ikm[0] = (uint8_t)(i & 0xFF);
        if (derive_session_keys(ikm, 32, salt, 32,
                                session_key, 32, channel_keys) != 0)
            return -1;
    }

    double t1 = now_ms();
    double total_ms = t1 - t0;
    double ops_per_sec = (double)N / (total_ms / 1000.0);

    printf("[BENCH] HKDF derive: %.0f ops/sec (%d in %.0f ms)\n",
           ops_per_sec, N, total_ms);

    if (ops_per_sec < 100) return -2;

    return 0;
}

/* Benchmark: KEM keypair generation */
static int bench_kem_keypair(void)
{
    const int N = 50;
    uint8_t pk[1184], sk[2400];
    uint32_t pk_size = 1184, sk_size = 2400;

    kem_context_t ctx;
    if (kem_init(&ctx, KEM_TYPE_MLKEM_768) != 0) return -1;

    double t0 = now_ms();

    for (int i = 0; i < N; i++) {
        if (kem_keypair(&ctx, pk, &pk_size, sk, &sk_size) != 0) return -2;
    }

    double t1 = now_ms();
    double total_ms = t1 - t0;
    double ops_per_sec = (double)N / (total_ms / 1000.0);
    double avg_ms = total_ms / N;

    printf("[BENCH] KEM keypair: %.1f ops/sec (%.2f ms avg over %d runs)\n",
           ops_per_sec, avg_ms, N);

    kem_cleanup(&ctx);

    if (avg_ms > 5000) return -3;

    return 0;
}

/* Benchmark: KEM encapsulate */
static int bench_kem_encaps(void)
{
    const int N = 50;
    uint8_t pk[1184], sk[2400], ct[1088], ss[32];
    uint32_t pk_size = 1184, sk_size = 2400, ct_size = 1088, ss_size = 32;

    kem_context_t ctx;
    if (kem_init(&ctx, KEM_TYPE_MLKEM_768) != 0) return -1;
    if (kem_keypair(&ctx, pk, &pk_size, sk, &sk_size) != 0) return -2;

    double t0 = now_ms();

    for (int i = 0; i < N; i++) {
        if (kem_encapsulate(pk, pk_size, ct, ct_size, ss, ss_size) != 0)
            return -3;
    }

    double t1 = now_ms();
    double total_ms = t1 - t0;
    double avg_ms = total_ms / N;

    printf("[BENCH] KEM encapsulate: %.2f ms avg over %d runs\n", avg_ms, N);

    kem_cleanup(&ctx);

    if (avg_ms > 2000) return -4;

    return 0;
}

int test_bench_handshake_latency(void) { return bench_handshake_latency(); }
int test_bench_chat_throughput(void) { return bench_chat_throughput(); }
int test_bench_aead_encrypt(void) { return bench_aead_encrypt(); }
int test_bench_aead_decrypt(void) { return bench_aead_decrypt(); }
int test_bench_hkdf_derive(void) { return bench_hkdf_derive(); }
int test_bench_kem_keypair(void) { return bench_kem_keypair(); }
int test_bench_kem_encaps(void) { return bench_kem_encaps(); }
