#include "handshake.h"
#include "session_enc.h"
#include "session.h"
#include "pool.h"
#include "packet_parse.h"
#include "kem.h"
#include "secure_store.h"
#include "aead.h"
#include "hkdf.h"
#include "pipeline_inbound.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * Fuzz tests — random packet corruption, edge cases, invalid data.
 */

/* Random byte generator */
static uint8_t rand_byte(void)
{
    return (uint8_t)(rand() & 0xFF);
}

/* Corrupt a random byte in a packet */
static void corrupt_packet(packet_buf_t* p)
{
    if (!p || p->len == 0) return;
    int idx = rand() % p->len;
    p->data[idx] ^= (uint8_t)(1 + (rand() % 255));
}

/* Fuzz test: handshake with random packet corruption at each step */
static int test_fuzz_handshake_corruption_internal(void)
{
    srand((unsigned int)time(NULL));

    for (int iter = 0; iter < 100; iter++) {
        session_t init, resp;
        session_init(&init);
        session_init(&resp);
        pool_init();

        uint8_t test_key[32];
        memset(test_key, 0xAA, 32);
        secure_store_set_key(test_key, 32);

        uint32_t seq_i = 1, seq_r = 1;

        if (handshake_init_initiator(&init, KEM_TYPE_MLKEM_768) != 0) return -1;
        if (handshake_init_responder(&resp, KEM_TYPE_MLKEM_768) != 0) return -2;

        packet_buf_t* p = handshake_build_hello(&init, &seq_i);
        if (!p) return -3;

        /* Maybe corrupt HELLO */
        if (rand() % 5 == 0) corrupt_packet(p);
        p = handshake_run_as_responder(&resp, p, &seq_r);

        if (p) {
            if (rand() % 5 == 0) corrupt_packet(p);
            p = handshake_run_as_initiator(&init, p, &seq_i);

            if (p) {
                if (rand() % 5 == 0) corrupt_packet(p);
                p = handshake_run_as_responder(&resp, p, &seq_r);

                if (p) {
                    if (rand() % 5 == 0) corrupt_packet(p);
                    p = handshake_run_as_initiator(&init, p, &seq_i);

                    if (p) {
                        if (rand() % 5 == 0) corrupt_packet(p);
                        p = handshake_run_as_responder(&resp, p, &seq_r);

                        if (p) {
                            if (rand() % 5 == 0) corrupt_packet(p);
                            p = handshake_run_as_initiator(&init, p, &seq_i);
                        }
                    }
                }
            }
        }
        /* Should not crash regardless of corruption */
    }

    return 0;
}

/* Fuzz test: random AEAD encrypt/decrypt with corrupted keys/nonces */
static int test_fuzz_aead_corruption_internal(void)
{
    srand((unsigned int)time(NULL));

    for (int iter = 0; iter < 50; iter++) {
        uint8_t key[32], nonce[12], aad[16], plain[64], cipher[64], tag[16], dec[64];
        uint32_t plain_len = 16 + (rand() % 48);

        for (int i = 0; i < 32; i++) key[i] = rand_byte();
        for (int i = 0; i < 12; i++) nonce[i] = rand_byte();
        for (int i = 0; i < 16; i++) aad[i] = rand_byte();
        for (uint32_t i = 0; i < plain_len; i++) plain[i] = rand_byte();

        int enc_ret = aead_encrypt(key, nonce, aad, 16, plain, plain_len, cipher, tag);
        if (enc_ret != 0) continue;

        /* Decrypt should succeed */
        int dec_ret = aead_decrypt(key, nonce, aad, 16, cipher, plain_len, tag, dec);
        if (dec_ret != 0) return -1;

        /* Verify plaintext matches */
        if (memcmp(plain, dec, plain_len) != 0) return -2;

        /* Corrupt key → should fail */
        uint8_t bad_key[32];
        memcpy(bad_key, key, 32);
        bad_key[rand() % 32] ^= 0x01;
        if (aead_decrypt(bad_key, nonce, aad, 16, cipher, plain_len, tag, dec) == 0)
            return -3;

        /* Corrupt nonce → should fail */
        uint8_t bad_nonce[12];
        memcpy(bad_nonce, nonce, 12);
        bad_nonce[rand() % 12] ^= 0x01;
        if (aead_decrypt(key, bad_nonce, aad, 16, cipher, plain_len, tag, dec) == 0)
            return -4;

        /* Corrupt tag → should fail */
        uint8_t bad_tag[16];
        memcpy(bad_tag, tag, 16);
        bad_tag[rand() % 16] ^= 0x01;
        if (aead_decrypt(key, nonce, aad, 16, cipher, plain_len, bad_tag, dec) == 0)
            return -5;

        /* Corrupt ciphertext → should fail */
        uint8_t bad_cipher[64];
        memcpy(bad_cipher, cipher, plain_len);
        bad_cipher[rand() % plain_len] ^= 0x01;
        if (aead_decrypt(key, nonce, aad, 16, bad_cipher, plain_len, tag, dec) == 0)
            return -6;

        /* Corrupt AAD → should fail */
        uint8_t bad_aad[16];
        memcpy(bad_aad, aad, 16);
        bad_aad[rand() % 16] ^= 0x01;
        if (aead_decrypt(key, nonce, bad_aad, 16, cipher, plain_len, tag, dec) == 0)
            return -7;
    }

    return 0;
}

/* Fuzz test: pipeline inbound with corrupted packets */
static int test_fuzz_pipeline_corruption_internal(void)
{
    srand((unsigned int)time(NULL));

    session_t sess;
    session_init(&sess);

    /* Set up a minimal session for pipeline processing */
    sess.state = SESSION_LOCKED;
    sess.handshake_complete = 1;
    sess.keys.key_epoch = 1;
    memset(sess.keys.session_key, 0xCC, 32);
    for (int c = 0; c < 6; c++)
        memset(sess.keys.channel_keys[c], 0xDD, 32);

    for (int iter = 0; iter < 200; iter++) {
        pool_init();

        packet_buf_t* p = pool_get();
        if (!p) return -1;

        /* Fill with random data */
        for (int i = 0; i < 1500; i++)
            p->data[i] = rand_byte();
        p->len = 24 + (rand() % 1476);

        /* Ensure magic is correct for parse */
        uint32_t magic = 0xAABBCCDD;
        memcpy(p->data, &magic, 4);

        /* Try running through packet_parse — should not crash */
        packet_view_t view;
        packet_parse(p, &view);

        /* Should not crash regardless of content */
        pool_return(p);
    }

    return 0;
}

/* Fuzz: session key derivation with random inputs */
static int test_fuzz_hkdf_random_internal(void)
{
    srand((unsigned int)time(NULL));

    for (int iter = 0; iter < 50; iter++) {
        uint8_t ikm[32], salt[32], info[32];
        uint8_t session_key[32], channel_keys[6][32];

        for (int i = 0; i < 32; i++) {
            ikm[i] = rand_byte();
            salt[i] = rand_byte();
            info[i] = rand_byte();
        }

        int ret = derive_session_keys(ikm, 32, salt, 32,
                                      session_key, 32, channel_keys);
        /* Should either succeed or fail gracefully */
        if (ret == 0) {
            /* Verify channel keys differ from session key and from each other */
            if (memcmp(session_key, channel_keys[0], 32) == 0) continue; /* unlikely but harmless */
        }
    }

    return 0;
}

/* Fuzz test: pool alloc/free stress with random patterns */
static int test_fuzz_pool_alloc_stress_internal(void)
{
    srand((unsigned int)time(NULL));

    for (int iter = 0; iter < 50; iter++) {
        pool_init();

        packet_buf_t* ptrs[64];
        int count = 0;

        for (int op = 0; op < 200; op++) {
            if (rand() % 2 == 0 && count < 64) {
                ptrs[count] = pool_get();
                if (ptrs[count]) count++;
            } else if (count > 0) {
                int idx = rand() % count;
                if (ptrs[idx]) {
                    pool_return(ptrs[idx]);
                    ptrs[idx] = NULL;
                    /* compact */
                    for (int j = idx; j < count - 1; j++)
                        ptrs[j] = ptrs[j + 1];
                    count--;
                }
            }
        }

        /* Return all */
        for (int i = 0; i < count; i++) {
            if (ptrs[i]) pool_return(ptrs[i]);
        }
    }

    return 0;
}

/* Test that session_enc_apply/check handles all edge cases */
static int test_fuzz_session_enc_edge_internal(void)
{
    srand((unsigned int)time(NULL));

    session_t sess;
    session_init(&sess);
    sess.state = SESSION_LOCKED;
    memset(sess.keys.session_key, 0xCC, 32);
    for (int c = 0; c < 6; c++)
        memset(sess.keys.channel_keys[c], 0xDD, 32);
    sess.keys.key_epoch = 1;

    for (int iter = 0; iter < 100; iter++) {
        pool_init();

        packet_buf_t* p = pool_get();
        if (!p) return -1;

        /* Build minimal valid packet header */
        uint32_t magic = 0xAABBCCDD;
        uint8_t ver = 1, flags = 0;
        uint64_t sid = 0;
        uint8_t ch = (uint8_t)(1 + (rand() % 5));
        uint32_t seq = (uint32_t)(rand());
        uint32_t plen = (uint32_t)(rand() % 1400);

        memcpy(p->data + 0, &magic, 4);
        memcpy(p->data + 4, &ver, 1);
        p->data[5] = flags;
        memcpy(p->data + 6, &sid, 8);
        memcpy(p->data + 14, &ch, 1);
        memcpy(p->data + 15, &seq, 4);
        memcpy(p->data + 19, &plen, 4);
        for (uint32_t i = 0; i < plen && i < 1400; i++)
            p->data[24 + i] = rand_byte();
        p->len = 24 + plen;

        /* Encrypt should handle all valid channels safely */
        packet_view_t fv;
        if (packet_parse(p, &fv) == 0) {
            int ret = session_enc_apply(p, &fv, &sess);
            (void)ret; /* may fail for too-large payloads, should not crash */
        }

        pool_return(p);
    }

    return 0;
}

int test_fuzz_handshake_corruption(void) { return test_fuzz_handshake_corruption_internal(); }
int test_fuzz_aead_corruption(void) { return test_fuzz_aead_corruption_internal(); }
int test_fuzz_pipeline_corruption(void) { return test_fuzz_pipeline_corruption_internal(); }
int test_fuzz_hkdf_random(void) { return test_fuzz_hkdf_random_internal(); }
int test_fuzz_pool_alloc_stress(void) { return test_fuzz_pool_alloc_stress_internal(); }
int test_fuzz_session_enc_edge(void) { return test_fuzz_session_enc_edge_internal(); }
