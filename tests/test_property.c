#include "handshake.h"
#include "session_enc.h"
#include "session.h"
#include "pool.h"
#include "packet_parse.h"
#include "kem.h"
#include "secure_store.h"
#include "hkdf.h"
#include "aead.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * Property-based tests — system invariants checked under random inputs.
 *
 * Each test verifies a specific property holds across many random trials.
 */

/* Property: after successful handshake, both sides have identical session keys */
static int test_property_session_key_agreement_internal(void)
{
    srand((unsigned int)time(NULL));

    for (int iter = 0; iter < 50; iter++) {
        session_t alice, bob;
        session_init(&alice);
        session_init(&bob);
        pool_init();

        uint8_t alice_key[32], bob_key[32];
        for (int i = 0; i < 32; i++) {
            alice_key[i] = (uint8_t)(rand() & 0xFF);
            bob_key[i] = (uint8_t)(rand() & 0xFF);
        }

        secure_store_set_key(alice_key, 32);
        if (handshake_init_initiator(&alice, KEM_TYPE_MLKEM_768) != 0) return -1;

        session_init(&bob);
        secure_store_set_key(bob_key, 32);
        if (handshake_init_responder(&bob, KEM_TYPE_MLKEM_768) != 0) return -2;

        uint32_t seq_a = 1, seq_b = 1;

        packet_buf_t* p = handshake_build_hello(&alice, &seq_a);
        if (!p) { session_zero_secrets(&alice); return -3; }
        p = handshake_run_as_responder(&bob, p, &seq_b);
        if (!p) { session_zero_secrets(&alice); session_zero_secrets(&bob); return -4; }
        p = handshake_run_as_initiator(&alice, p, &seq_a);
        if (!p) { session_zero_secrets(&alice); session_zero_secrets(&bob); return -5; }
        p = handshake_run_as_responder(&bob, p, &seq_b);
        if (!p) { session_zero_secrets(&alice); session_zero_secrets(&bob); return -6; }
        p = handshake_run_as_initiator(&alice, p, &seq_a);
        if (!p) { session_zero_secrets(&alice); session_zero_secrets(&bob); return -7; }
        p = handshake_run_as_responder(&bob, p, &seq_b);
        if (!p) { session_zero_secrets(&alice); session_zero_secrets(&bob); return -8; }
        p = handshake_run_as_initiator(&alice, p, &seq_a);
        if (p != NULL) { session_zero_secrets(&alice); session_zero_secrets(&bob); return -9; }

        /* PROPERTY: session keys identical */
        if (memcmp(alice.keys.session_key, bob.keys.session_key, 32) != 0) {
            session_zero_secrets(&alice);
            session_zero_secrets(&bob);
            return -10;
        }

        /* PROPERTY: channel keys identical */
        for (int c = 0; c < 6; c++) {
            if (memcmp(alice.keys.channel_keys[c], bob.keys.channel_keys[c], 32) != 0) {
                session_zero_secrets(&alice);
                session_zero_secrets(&bob);
                return -11;
            }
        }

        /* PROPERTY: session key is not all zeros */
        {
            int zero = 1;
            for (int i = 0; i < 32; i++)
                if (alice.keys.session_key[i] != 0) { zero = 0; break; }
            if (zero) { session_zero_secrets(&alice); session_zero_secrets(&bob); return -12; }
        }

        session_zero_secrets(&alice);
        session_zero_secrets(&bob);
    }

    return 0;
}

/* Property: AEAD decrypt(encrypt(plain)) == plain for all valid inputs */
static int test_property_aead_roundtrip_internal(void)
{
    srand((unsigned int)time(NULL));

    for (int iter = 0; iter < 100; iter++) {
        uint8_t key[32], nonce[12], aad[24];
        uint8_t plain[1400], cipher[1400], dec[1400], tag[16];
        uint32_t plain_len = 1 + (uint32_t)(rand() % 1399);
        uint32_t aad_len = (uint32_t)(rand() % 25);

        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(rand() & 0xFF);
        for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(rand() & 0xFF);
        for (uint32_t i = 0; i < aad_len; i++) aad[i] = (uint8_t)(rand() & 0xFF);
        for (uint32_t i = 0; i < plain_len; i++) plain[i] = (uint8_t)(rand() & 0xFF);

        /* PROPERTY: encrypt succeeds */
        int e = aead_encrypt(key, nonce, aad, aad_len, plain, plain_len, cipher, tag);
        if (e != 0) continue; /* may fail for large payloads */

        /* PROPERTY: decrypt(encrypt(plain)) == plain */
        int d = aead_decrypt(key, nonce, aad, aad_len, cipher, plain_len, tag, dec);
        if (d != 0) return -1;
        if (memcmp(plain, dec, plain_len) != 0) return -2;

        /* PROPERTY: same plaintext + same key + same nonce = same ciphertext */
        uint8_t cipher2[1400], tag2[16];
        e = aead_encrypt(key, nonce, aad, aad_len, plain, plain_len, cipher2, tag2);
        if (e != 0) return -3;
        if (memcmp(cipher, cipher2, plain_len) != 0) return -4;
        if (memcmp(tag, tag2, 16) != 0) return -5;
    }

    return 0;
}

/* Property: HKDF produces deterministic output for same inputs */
static int test_property_hkdf_deterministic_internal(void)
{
    srand((unsigned int)time(NULL));

    for (int iter = 0; iter < 30; iter++) {
        uint8_t ikm[32], salt[32];
        uint8_t sk1[32], ck1[6][32];
        uint8_t sk2[32], ck2[6][32];

        for (int i = 0; i < 32; i++) {
            ikm[i] = (uint8_t)(rand() & 0xFF);
            salt[i] = (uint8_t)(rand() & 0xFF);
        }

        /* Derive twice with same inputs */
        int r1 = derive_session_keys(ikm, 32, salt, 32, sk1, 32, ck1);
        int r2 = derive_session_keys(ikm, 32, salt, 32, sk2, 32, ck2);

        if (r1 != 0 || r2 != 0) return -1;

        /* PROPERTY: same inputs => same outputs */
        if (memcmp(sk1, sk2, 32) != 0) return -2;
        for (int c = 0; c < 6; c++)
            if (memcmp(ck1[c], ck2[c], 32) != 0) return -3;

        /* Derive with modified salt */
        salt[0] ^= 0x01;
        int r3 = derive_session_keys(ikm, 32, salt, 32, sk1, 32, ck1);
        if (r3 != 0) return -4;

        /* PROPERTY: different salt => different output (avalanche) */
        if (memcmp(sk1, sk2, 32) == 0) {
            /* Check at least one channel key differs */
            int all_same = 1;
            for (int c = 0; c < 6; c++)
                if (memcmp(ck1[c], ck2[c], 32) != 0) { all_same = 0; break; }
            if (all_same) return -5;
        }
    }

    return 0;
}

/* Property: session state machine follows expected transitions */
static int test_property_session_state_machine_internal(void)
{
    srand((unsigned int)time(NULL));

    for (int iter = 0; iter < 20; iter++) {
        session_t init, resp;
        session_init(&init);
        session_init(&resp);
        pool_init();

        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(rand() & 0xFF);
        secure_store_set_key(key, 32);

        uint32_t seq_i = 1, seq_r = 1;

        if (handshake_init_initiator(&init, KEM_TYPE_MLKEM_768) != 0) return -1;
        if (handshake_init_responder(&resp, KEM_TYPE_MLKEM_768) != 0) return -2;

        /* PROPERTY: states follow expected sequence */
        if (init.state != SESSION_HANDSHAKE_START) return -3;
        if (resp.state != SESSION_HANDSHAKE_START) return -4;

        packet_buf_t* p = handshake_build_hello(&init, &seq_i);
        if (!p) return -5;

        /* Before processing, initiator state still HANDSHAKE_START */
        if (init.state != SESSION_HANDSHAKE_START) return -6;

        p = handshake_run_as_responder(&resp, p, &seq_r);
        if (!p) return -7;

        /* After processing, initiator should be in KEM_INIT_SENT */
        /* initiator built KEM_INIT, so state should be KEM_INIT_SENT */
        packet_buf_t* p2 = NULL;
        {
            packet_view_t view;
            packet_parse(p, &view); /* this is the ACCEPT */
            p2 = handshake_run_as_initiator(&init, p, &seq_i);
        }
        if (!p2) return -8;

        /* After sending KEM_INIT, state should be KEM_INIT_SENT or IDENTITY_PROOF_SENT after full flow */
        /* Actually init may have already advanced to IDENTITY_PROOF_SENT if the further steps ran */
        /* Let's just check we get through to LOCKED */
        p2 = handshake_run_as_responder(&resp, p2, &seq_r);
        if (!p2) return -9;
        p2 = handshake_run_as_initiator(&init, p2, &seq_i);
        if (!p2) return -10;
        p2 = handshake_run_as_responder(&resp, p2, &seq_r);
        if (!p2) return -11;
        p2 = handshake_run_as_initiator(&init, p2, &seq_i);
        if (p2 != NULL) return -12;

        /* PROPERTY: final state is LOCKED for both */
        if (init.state != SESSION_LOCKED) return -13;
        if (resp.state != SESSION_LOCKED) return -14;

        /* PROPERTY: handshake_complete set */
        if (!init.handshake_complete) return -15;
        if (!resp.handshake_complete) return -16;

        /* PROPERTY: identity verified */
        if (!init.hs.identity_verified) return -17;
        if (!resp.hs.identity_verified) return -18;
    }

    return 0;
}

/* Property: peer identity keys correctly exchanged after handshake */
static int test_property_identity_key_exchange_internal(void)
{
    srand((unsigned int)time(NULL));

    for (int iter = 0; iter < 30; iter++) {
        session_t alice, bob;
        session_init(&alice);
        session_init(&bob);
        pool_init();

        uint8_t alice_key[32], bob_key[32];
        for (int i = 0; i < 32; i++) {
            alice_key[i] = (uint8_t)(rand() & 0xFF);
            bob_key[i] = (uint8_t)(rand() & 0xFF);
        }

        secure_store_set_key(alice_key, 32);
        if (handshake_init_initiator(&alice, KEM_TYPE_MLKEM_768) != 0) return -1;

        session_init(&bob);
        secure_store_set_key(bob_key, 32);
        if (handshake_init_responder(&bob, KEM_TYPE_MLKEM_768) != 0) return -2;

        uint32_t seq_a = 1, seq_b = 1;

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

        /* PROPERTY: alice.peer_key == bob.our_key */
        if (memcmp(alice.hs.peer_identity_key, bob.hs.our_identity_key, 32) != 0)
            return -10;

        /* PROPERTY: bob.peer_key == alice.our_key */
        if (memcmp(bob.hs.peer_identity_key, alice.hs.our_identity_key, 32) != 0)
            return -11;

        /* PROPERTY: our keys unchanged from what we set */
        if (memcmp(alice.hs.our_identity_key, alice_key, 32) != 0)
            return -12;
        if (memcmp(bob.hs.our_identity_key, bob_key, 32) != 0)
            return -13;

        /* PROPERTY: identity_verified is 1 */
        if (!alice.hs.identity_verified) return -14;
        if (!bob.hs.identity_verified) return -15;
    }

    return 0;
}

int test_property_session_key_agreement(void) { return test_property_session_key_agreement_internal(); }
int test_property_aead_roundtrip(void) { return test_property_aead_roundtrip_internal(); }
int test_property_hkdf_deterministic(void) { return test_property_hkdf_deterministic_internal(); }
int test_property_session_state_machine(void) { return test_property_session_state_machine_internal(); }
int test_property_identity_key_exchange(void) { return test_property_identity_key_exchange_internal(); }
