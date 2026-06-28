#include "handshake.h"
#include "kem.h"
#include "session.h"
#include "pool.h"
#include "packet_parse.h"
#include "secure_store.h"
#include <string.h>
#include <stdio.h>

int test_identity_exchange_full(void)
{
    session_t init, resp;
    session_init(&init);
    session_init(&resp);
    pool_init();

    /* use a known identity key so we can verify exchange */
    uint8_t test_key[32];
    memset(test_key, 0xAA, 32);
    secure_store_set_key(test_key, 32);

    uint32_t seq_i = 1, seq_r = 1;

    /* 1. init both sides */
    if (handshake_init_initiator(&init, KEM_TYPE_MLKEM_768) != 0) return -1;
    if (handshake_init_responder(&resp, KEM_TYPE_MLKEM_768) != 0) return -2;

    /* verify our_identity_key was captured from secure_store */
    if (memcmp(init.hs.our_identity_key, test_key, 32) != 0) return -3;
    if (memcmp(resp.hs.our_identity_key, test_key, 32) != 0) return -4;

    /* 2. HELLO -> ACCEPT */
    packet_buf_t* p = handshake_build_hello(&init, &seq_i);
    if (!p) return -5;
    p = handshake_run_as_responder(&resp, p, &seq_r);
    if (!p) return -6;

    /* 3. ACCEPT -> KEM_INIT */
    p = handshake_run_as_initiator(&init, p, &seq_i);
    if (!p) return -7;

    /* 4. KEM_INIT -> KEM_RESPONSE */
    p = handshake_run_as_responder(&resp, p, &seq_r);
    if (!p) return -8;

    /* 5. KEM_RESPONSE -> IDENTITY_PROOF (AEAD-encrypted) */
    p = handshake_run_as_initiator(&init, p, &seq_i);
    if (!p) return -9;

    /* 6. IDENTITY_PROOF -> SESSION_LOCKED (responder verifies initiator + sends own proof) */
    p = handshake_run_as_responder(&resp, p, &seq_r);
    if (!p) return -11;

    /* responder should be LOCKED after build_locked */
    if (resp.state != SESSION_LOCKED) return -13;

    /* 7. SESSION_LOCKED (initiator verifies responder) */
    p = handshake_run_as_initiator(&init, p, &seq_i);
    if (p != NULL) return -14; /* NULL = handshake complete */

    /* 8. verify final states */
    if (init.state != SESSION_LOCKED) return -15;
    if (resp.state != SESSION_LOCKED) return -16;
    if (!init.handshake_complete) return -17;
    if (!resp.handshake_complete) return -18;
    if (!init.hs.identity_verified) return -19;
    if (!resp.hs.identity_verified) return -20;

    /* 9. verify peer key exchange */
    if (memcmp(init.hs.peer_identity_key, resp.hs.our_identity_key, 32) != 0)
        return -21;
    if (memcmp(resp.hs.peer_identity_key, init.hs.our_identity_key, 32) != 0)
        return -22;

    /* 10. verify session keys were derived (not all zeros) */
    {
        int zero = 1;
        for (int i = 0; i < 32; i++) {
            if (init.keys.session_key[i] != 0) { zero = 0; break; }
        }
        if (zero) return -23;
        zero = 1;
        for (int i = 0; i < 32; i++) {
            if (resp.keys.session_key[i] != 0) { zero = 0; break; }
        }
        if (zero) return -24;
    }

    /* 11. verify channel keys were derived */
    {
        int zero = 1;
        for (int c = 0; c < 6; c++) {
            zero = 1;
            for (int i = 0; i < 32; i++) {
                if (init.keys.channel_keys[c][i] != 0) { zero = 0; break; }
            }
            if (zero) return -25;
        }
    }

    return 0;
}

int test_identity_bad_signature_rejected(void)
{
    session_t init, resp;
    session_init(&init);
    session_init(&resp);
    pool_init();

    uint8_t test_key[32];
    memset(test_key, 0xBB, 32);
    secure_store_set_key(test_key, 32);

    uint32_t seq_i = 1, seq_r = 1;

    if (handshake_init_initiator(&init, KEM_TYPE_MLKEM_768) != 0) return -1;
    if (handshake_init_responder(&resp, KEM_TYPE_MLKEM_768) != 0) return -2;

    /* run through KEM_RESPONSE */
    packet_buf_t* p = handshake_build_hello(&init, &seq_i);
    if (!p) return -3;
    p = handshake_run_as_responder(&resp, p, &seq_r);
    if (!p) return -4;
    p = handshake_run_as_initiator(&init, p, &seq_i);
    if (!p) return -5;
    p = handshake_run_as_responder(&resp, p, &seq_r);
    if (!p) return -6;

    /* build IDENTITY_PROOF but corrupt the AEAD tag */
    packet_buf_t* id_proof = pool_get();
    if (!id_proof) return -7;
    if (handshake_build_identity(&init, id_proof, &seq_i) != 0) return -7;
    /* corrupt the tag (last byte of the AEAD-authenticated payload) */
    id_proof->data[24 + 1 + 12 + 64 + 15] ^= 0xFF; /* last byte of 16-byte tag */

    /* use process_message directly to capture error before session_reset */
    packet_view_t view;
    if (packet_parse(id_proof, &view) != 0) return -8;
    packet_buf_t* resp_out = NULL;
    int result = handshake_process_message(&resp, id_proof, &view, &resp_out);
    if (result != HS_ERROR) return -9;
    if (resp.hs.last_error != HS_ERR_BAD_IDENTITY) return -10;

    return 0;
}
