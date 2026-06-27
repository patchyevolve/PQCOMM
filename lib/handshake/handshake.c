#include "handshake.h"
#include "kem.h"
#include "hkdf.h"
#include "channel.h"
#include "pool.h"
#include "packet_parse.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>

/* long-term identity key for the demo (in production this comes from secure store) */
static const uint8_t g_identity_master_key[32] = {
    0x6b, 0xe5, 0x79, 0x3e, 0x7a, 0x1f, 0x2c, 0xd4,
    0x91, 0x82, 0x5a, 0x0d, 0x3b, 0xf8, 0x44, 0x97,
    0x1c, 0x63, 0xae, 0x90, 0xf5, 0x28, 0xbb, 0x50,
    0xcf, 0x21, 0x65, 0xde, 0x09, 0x74, 0x80, 0x3e
};

handshake_stats_t g_handshake_stats = { 0 };

static void update_transcript(session_t* sess, const uint8_t* data, uint32_t len)
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, sess->hs.transcript_hash, 32);
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, sess->hs.transcript_hash);
    mbedtls_sha256_free(&ctx);
    sess->hs.messages_exchanged++;
}

/* check that the incoming opcode makes sense for the current state */
static int verify_state_transition(session_t* sess, uint8_t received_opcode)
{
    session_state_t current = sess->state;
    session_state_t expected = SESSION_IDLE;

    if (sess->role == ROLE_INITIATOR) {
        switch (received_opcode) {
        case CTRL_HELLO:
            printf("[HANDSHAKE] initiator got a hello (loopback?)\n");
            sess->hs.last_error = HS_ERR_STATE_VIOLATION;
            return -1;
        case CTRL_ACCEPT:
            expected = SESSION_HANDSHAKE_START;
            break;
        case CTRL_PQ_KEM_RESPONSE:  expected = SESSION_PQ_KEM_INIT_SENT; break;
        case CTRL_IDENTITY_PROOF:   expected = SESSION_PQ_KEM_RESPONSE_SENT; break;
        case CTRL_SESSION_LOCKED:   expected = SESSION_IDENTITY_PROOF_SENT; break;
        default: return -1;
        }
    } else {
        switch (received_opcode) {
        case CTRL_HELLO:
            if (current != SESSION_IDLE && current != SESSION_HANDSHAKE_START)
                return -1;
            return 0;
        case CTRL_PQ_KEM_INIT:      expected = SESSION_HANDSHAKE_START; break;
        case CTRL_IDENTITY_PROOF:   expected = SESSION_PQ_KEM_RESPONSE_SENT; break;
        case CTRL_SESSION_LOCKED:   expected = SESSION_IDENTITY_PROOF_SENT; break;
        default: return -1;
        }
    }

    if (current != expected) {
        printf("[HANDSHAKE] state mismatch: was %s, expected %s for opcode %d\n",
            handshake_state_name(current),
            handshake_state_name(expected),
            received_opcode);
        sess->hs.last_error = HS_ERR_STATE_VIOLATION;
        return -1;
    }
    return 0;
}

int handshake_init_initiator(session_t* sess, uint8_t kem_type)
{
    if (!sess) return -1;
    session_reset(sess);
    sess->role = ROLE_INITIATOR;
    sess->state = SESSION_HANDSHAKE_START;
    sess->hs.kem_type = kem_type;
    sess->hs.timeout_ms = PHASE2_HANDSHAKE_TIMEOUT_MS;
    sess->hs.messages_exchanged = 0;

    kem_random_bytes((uint8_t*)&sess->session_id, sizeof(sess->session_id));

    /* compute our identity hash: SHA-256(g_identity_master_key) */
    {
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, g_identity_master_key, 32);
        mbedtls_sha256_finish(&ctx, sess->hs.our_identity_hash);
        mbedtls_sha256_free(&ctx);
    }

    /* transcript seeded from session id in ACCEPT payload */
    memset(sess->hs.transcript_hash, 0, 32);

    printf("[HANDSHAKE] initiator started, session %llu\n",
           (unsigned long long)sess->session_id);
    g_handshake_stats.attempts_total++;
    return 0;
}

int handshake_init_responder(session_t* sess, uint8_t kem_type)
{
    if (!sess) return -1;
    session_reset(sess);
    sess->role = ROLE_RESPONDER;
    sess->state = SESSION_HANDSHAKE_START;
    sess->hs.kem_type = kem_type;
    sess->hs.timeout_ms = PHASE2_HANDSHAKE_TIMEOUT_MS;
    sess->hs.messages_exchanged = 0;

    /* compute our identity hash: SHA-256(g_identity_master_key) */
    {
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, g_identity_master_key, 32);
        mbedtls_sha256_finish(&ctx, sess->hs.our_identity_hash);
        mbedtls_sha256_free(&ctx);
    }

    memset(sess->hs.transcript_hash, 0, 32);
    return 0;
}

packet_buf_t* handshake_build_hello(session_t* sess, uint32_t* seq_counter)
{
    packet_buf_t* p = pool_get();
    if (!p) return NULL;

    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1, flags = 0, channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1;
    uint8_t opcode = CTRL_HELLO;
    uint64_t session_id = 0;

    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &session_id, sizeof(session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    memcpy(d + 24, &opcode, sizeof(opcode));

    p->len = 24 + payload_len;
    update_transcript(sess, d + 24, payload_len);
    return p;
}

int handshake_build_accept(session_t* sess, packet_buf_t* out, uint32_t* seq_counter)
{
    if (!sess || !out || !seq_counter) return -1;

    uint64_t session_id;
    kem_random_bytes((uint8_t*)&session_id, sizeof(session_id));
    sess->session_id = session_id;

    uint8_t* d = out->data;
    uint32_t payload_len = 1 + 8;

    memcpy(d + 0, (uint32_t[]){ 0xAABBCCDD }, sizeof(uint32_t));
    d[4] = 1;
    d[5] = 0;
    memcpy(d + 6, &session_id, sizeof(session_id));
    d[14] = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    d[24] = CTRL_ACCEPT;
    memcpy(d + 25, &session_id, sizeof(session_id));

    out->len = 24 + payload_len;
    update_transcript(sess, d + 24, payload_len);
    return 0;
}

int handshake_build_kem_init(session_t* sess, packet_buf_t* out,
                             uint32_t* seq_counter)
{
    if (!sess || !out || !seq_counter) return -1;

    uint32_t pk_size = 0, sk_size = 0, ct_size = 0, ss_size = 0;
    kem_get_sizes(sess->hs.kem_type, &pk_size, &sk_size, &ct_size, &ss_size);
    if (pk_size == 0 || sk_size == 0) {
        printf("[HANDSHAKE] bad kem sizes: pk=%u sk=%u\n", pk_size, sk_size);
        return -1;
    }

    kem_context_t kem_ctx;
    if (kem_init(&kem_ctx, sess->hs.kem_type) != 0)
        return -1;
    if (kem_keypair(&kem_ctx,
                    sess->hs.kem_public_key, &pk_size,
                    sess->hs.kem_secret_key, &sk_size) != 0)
    {
        kem_cleanup(&kem_ctx);
        return -1;
    }
    kem_cleanup(&kem_ctx);

    uint8_t* d = out->data;
    uint32_t magic = 0xAABBCCDD, version = 1, flags = 0;
    uint64_t session_id = sess->session_id;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1 + pk_size;
    uint8_t opcode = CTRL_PQ_KEM_INIT;

    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &session_id, sizeof(session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    memcpy(d + 24, &opcode, sizeof(opcode));
    memcpy(d + 25, sess->hs.kem_public_key, pk_size);

    out->len = 24 + payload_len;
    update_transcript(sess, d + 24, payload_len);
    sess->state = SESSION_PQ_KEM_INIT_SENT;
    return 0;
}

int handshake_build_kem_response(session_t* sess, packet_buf_t* out,
                                 uint32_t* seq_counter)
{
    if (!sess || !out || !seq_counter) return -1;

    uint32_t ct_size = 0, ss_size = 0;
    kem_get_sizes(sess->hs.kem_type, NULL, NULL, &ct_size, &ss_size);
    if (ct_size == 0 || ss_size == 0) return -1;

    int ret = -1;
    uint8_t* ciphertext = malloc(ct_size);
    uint8_t* shared_secret = malloc(ss_size);
    if (!ciphertext || !shared_secret) goto cleanup;

    {
        uint32_t pk_size = 0;
        kem_get_sizes(sess->hs.kem_type, &pk_size, NULL, NULL, NULL);
        if (kem_encapsulate(sess->hs.peer_public_key, pk_size,
                            ciphertext, ct_size,
                            shared_secret, ss_size) != 0)
            goto cleanup;
    }

    if (derive_session_keys(shared_secret, ss_size,
                            sess->hs.transcript_hash, 32,
                            sess->keys.session_key, 32,
                            sess->keys.channel_keys) != 0)
        goto cleanup;
    memcpy(sess->hs.kem_shared_secret, shared_secret, ss_size);

    {
        uint8_t* d = out->data;
        uint32_t magic = 0xAABBCCDD, version = 1, flags = 0;
        uint64_t session_id = sess->session_id;
        uint8_t channel = CH_CONTROL;
        uint32_t seq = (*seq_counter)++;
        uint32_t payload_len = 1 + ct_size;
        uint8_t opcode = CTRL_PQ_KEM_RESPONSE;

        memcpy(d + 0, &magic, sizeof(magic));
        memcpy(d + 4, &version, sizeof(version));
        memcpy(d + 5, &flags, sizeof(flags));
        memcpy(d + 6, &session_id, sizeof(session_id));
        memcpy(d + 14, &channel, sizeof(channel));
        memcpy(d + 15, &seq, sizeof(seq));
        memcpy(d + 19, &payload_len, sizeof(payload_len));
        memcpy(d + 24, &opcode, sizeof(opcode));
        memcpy(d + 25, ciphertext, ct_size);

        out->len = 24 + payload_len;
        update_transcript(sess, d + 24, payload_len);
        sess->state = SESSION_PQ_KEM_RESPONSE_SENT;
    }

    ret = 0;

cleanup:
    if (shared_secret) {
        crypto_secure_wipe(shared_secret, ss_size);
        free(shared_secret);
    }
    free(ciphertext);
    return ret;
}

int handshake_build_identity(session_t* sess, packet_buf_t* out,
                             uint32_t* seq_counter)
{
    if (!sess || !out || !seq_counter) return -1;

    uint8_t* d = out->data;
    uint32_t magic = 0xAABBCCDD, version = 1, flags = 0;
    uint64_t session_id = sess->session_id;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1 + 64 + 32;
    uint8_t opcode = CTRL_IDENTITY_PROOF;

    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &session_id, sizeof(session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    memcpy(d + 24, &opcode, sizeof(opcode));

    /* signature = HMAC-SHA256(identity_master_key, transcript_hash) */
    {
        const mbedtls_md_info_t* md =
            mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        uint8_t sig[32];
        mbedtls_md_hmac(md, g_identity_master_key, 32,
                        sess->hs.transcript_hash, 32, sig);
        memcpy(d + 25, sig, 32);
        memset(d + 25 + 32, 0, 32);
    }
    memcpy(d + 25 + 64, sess->hs.our_identity_hash, 32);

    out->len = 24 + payload_len;
    update_transcript(sess, d + 24, payload_len);
    sess->state = SESSION_IDENTITY_PROOF_SENT;
    return 0;
}

int handshake_build_locked(session_t* sess, packet_buf_t* out,
                           uint32_t* seq_counter)
{
    if (!sess || !out || !seq_counter) return -1;

    uint8_t* d = out->data;
    uint32_t magic = 0xAABBCCDD, version = 1, flags = 0;
    uint64_t session_id = sess->session_id;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1;
    uint8_t opcode = CTRL_SESSION_LOCKED;

    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &session_id, sizeof(session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    memcpy(d + 24, &opcode, sizeof(opcode));

    out->len = 24 + payload_len;

    /* update transcript before deriving keys so both sides match */
    update_transcript(sess, d + 24, payload_len);

    uint32_t ss_size = 32;
    if (derive_session_keys(sess->hs.kem_shared_secret, ss_size,
                            sess->hs.transcript_hash, 32,
                            sess->keys.session_key, 32,
                            sess->keys.channel_keys) != 0)
        return -1;

    /* wipe sensitive material now that keys are derived */
    uint32_t sk_size = 0;
    kem_get_sizes(sess->hs.kem_type, NULL, &sk_size, NULL, NULL);
    crypto_secure_wipe(sess->hs.kem_secret_key, sk_size);
    crypto_secure_wipe(sess->hs.kem_shared_secret, ss_size);

    sess->state = SESSION_LOCKED;
    sess->handshake_complete = 1;
    return 0;
}

int handshake_build_error(session_t* sess, packet_buf_t* out,
                          uint8_t error_code, uint32_t* seq_counter)
{
    if (!sess || !out || !seq_counter) return -1;

    uint8_t* d = out->data;
    uint32_t magic = 0xAABBCCDD, version = 1, flags = 0;
    uint64_t session_id = sess->session_id;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 2;
    uint8_t opcode = CTRL_HANDSHAKE_ERROR;

    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &session_id, sizeof(session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    memcpy(d + 24, &opcode, sizeof(opcode));
    d[25] = error_code;

    out->len = 24 + payload_len;
    return 0;
}

/* high-level runner: feeds a received packet through the state machine,
 * builds whatever response is needed for the next step */
packet_buf_t* handshake_run_as_initiator(session_t* sess, packet_buf_t* in,
                                         uint32_t* seq_counter)
{
    if (!sess || !in) return NULL;

    packet_view_t view = { 0 };
    if (packet_parse(in, &view) != 0) return NULL;

    packet_buf_t* response = NULL;
    int result = handshake_process_message(sess, in, &view, &response);

    if (result == HS_ERROR) {
        printf("[HANDSHAKE] initiator error: %s\n",
               handshake_error_name(sess->hs.last_error));
        session_reset(sess);
        return NULL;
    }

    if (result == HS_NEED_MORE && !response) {
        uint8_t opcode = view.payload[0];
        switch (opcode) {
        case CTRL_ACCEPT:
            response = pool_get();
            if (!response) return NULL;
            if (handshake_build_kem_init(sess, response, seq_counter) != 0) {
                pool_return(response);
                return NULL;
            }
            break;
        case CTRL_PQ_KEM_RESPONSE:
            response = pool_get();
            if (!response) return NULL;
            if (handshake_build_identity(sess, response, seq_counter) != 0) {
                pool_return(response);
                return NULL;
            }
            break;
        case CTRL_SESSION_LOCKED:
            printf("[HANDSHAKE] initiator done!\n");
            return NULL;
        default:
            break;
        }
    }
    return response;
}

packet_buf_t* handshake_run_as_responder(session_t* sess, packet_buf_t* in,
                                         uint32_t* seq_counter)
{
    if (!sess || !in) return NULL;

    packet_view_t view = { 0 };
    if (packet_parse(in, &view) != 0) return NULL;

    packet_buf_t* response = NULL;
    int result = handshake_process_message(sess, in, &view, &response);

    if (result == HS_ERROR) {
        printf("[HANDSHAKE] responder error: %s\n",
               handshake_error_name(sess->hs.last_error));
        session_reset(sess);
        return NULL;
    }

    if (result == HS_NEED_MORE && !response) {
        uint8_t opcode = view.payload[0];
        switch (opcode) {
        case CTRL_HELLO:
            response = pool_get();
            if (!response) return NULL;
            if (handshake_build_accept(sess, response, seq_counter) != 0) {
                pool_return(response);
                return NULL;
            }
            break;
        case CTRL_PQ_KEM_INIT:
            response = pool_get();
            if (!response) return NULL;
            if (handshake_build_kem_response(sess, response, seq_counter) != 0) {
                pool_return(response);
                return NULL;
            }
            break;
        case CTRL_IDENTITY_PROOF:
            response = pool_get();
            if (!response) return NULL;
            if (handshake_build_locked(sess, response, seq_counter) != 0) {
                pool_return(response);
                return NULL;
            }
            break;
        default:
            break;
        }
    }
    return response;
}

int handshake_process_message(session_t* sess, packet_buf_t* packet,
                              packet_view_t* view, packet_buf_t** response_out)
{
    (void)packet;
    (void)response_out;

    if (!sess || !view || !view->payload || view->length < 1) {
        if (sess) sess->hs.last_error = HS_ERR_STATE_VIOLATION;
        return HS_ERROR;
    }

    uint8_t opcode = view->payload[0];

    /* reject pq ops on an already-locked session */
    if (sess->state == SESSION_LOCKED) {
        if (opcode == CTRL_PQ_KEM_INIT || opcode == CTRL_PQ_KEM_RESPONSE) {
            printf("[HANDSHAKE] rejected pq opcode %d on locked session\n", opcode);
            sess->hs.last_error = HS_ERR_STATE_VIOLATION;
            g_handshake_stats.failures_state++;
            return HS_ERROR;
        }
    }

    if (verify_state_transition(sess, opcode) != 0) {
        sess->hs.last_error = HS_ERR_STATE_VIOLATION;
        g_handshake_stats.failures_state++;
        return HS_ERROR;
    }

    /* capture transcript before the update for identity proof verification */
    uint8_t pre_update_transcript[32];
    memcpy(pre_update_transcript, sess->hs.transcript_hash, 32);

    update_transcript(sess, view->payload, view->length);

    switch (opcode) {
    case CTRL_HELLO:
        if (sess->role == ROLE_RESPONDER)
            return HS_NEED_MORE;
        sess->hs.last_error = HS_ERR_STATE_VIOLATION;
        return HS_ERROR;

    case CTRL_ACCEPT:
        if (view->length >= 9)
            memcpy(&sess->session_id, view->payload + 1, 8);
        return HS_NEED_MORE;

    case CTRL_PQ_KEM_INIT:
        /* minimum size: opcode(1) + 768-bit pk(1184) */
        if (view->length < 1 + 1184) return HS_ERROR;
        memcpy(sess->hs.peer_public_key, view->payload + 1,
               (sess->hs.kem_type == KEM_TYPE_MLKEM_768) ? 1184 : 1568);
        return HS_NEED_MORE;

    case CTRL_PQ_KEM_RESPONSE:
        if (view->length < 1 + 1088) return HS_ERROR;
        if (kem_decapsulate(sess->hs.kem_secret_key,
                            (sess->hs.kem_type == KEM_TYPE_MLKEM_768) ? 2400 : 3168,
                            view->payload + 1,
                            (sess->hs.kem_type == KEM_TYPE_MLKEM_768) ? 1088 : 1568,
                            sess->hs.kem_shared_secret, 32) != 0)
            return HS_ERROR;
        return HS_NEED_MORE;

    case CTRL_IDENTITY_PROOF:
        /* opcode(1) + sig(64) + hash(32) = 97 minimum */
        if (view->length < 97) return HS_ERROR;
        {
            /* verify HMAC-SHA256(identity_master_key, transcript_hash) */
            const mbedtls_md_info_t* md =
                mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            uint8_t expected_sig[32];
            mbedtls_md_hmac(md, g_identity_master_key, 32,
                            pre_update_transcript, 32, expected_sig);
            if (memcmp(view->payload + 1, expected_sig, 32) != 0) {
                printf("[HANDSHAKE] identity verification FAILED\n");
                sess->hs.last_error = HS_ERR_BAD_IDENTITY;
                g_handshake_stats.failures_identity++;
                return HS_ERROR;
            }
        }
        memcpy(sess->hs.peer_identity_hash, view->payload + 65, 32);
        sess->hs.identity_verified = 1;
        printf("[HANDSHAKE] identity verified OK\n");
        return HS_NEED_MORE;

    case CTRL_SESSION_LOCKED:
        /* derive session keys on lock (initiator path: responder already derived in build_locked) */
        {
            uint32_t ss_size = 32;
            if (derive_session_keys(sess->hs.kem_shared_secret, ss_size,
                                    sess->hs.transcript_hash, 32,
                                    sess->keys.session_key, 32,
                                    sess->keys.channel_keys) != 0)
                return HS_ERROR;

            uint32_t sk_size = 0;
            kem_get_sizes(sess->hs.kem_type, NULL, &sk_size, NULL, NULL);
            crypto_secure_wipe(sess->hs.kem_secret_key, sk_size);
            crypto_secure_wipe(sess->hs.kem_shared_secret, ss_size);
        }
        sess->state = SESSION_LOCKED;
        sess->handshake_complete = 1;
        g_handshake_stats.successes++;
        return HS_COMPLETE;

    default:
        return HS_ERROR;
    }
}

int handshake_check_timeout(session_t* sess, uint32_t current_time_ms)
{
    if (!sess || sess->hs.handshake_start_ms == 0) return 0;
    if (current_time_ms - sess->hs.handshake_start_ms > sess->hs.timeout_ms)
        return -1;
    return 0;
}

const char* handshake_state_name(session_state_t state)
{
    switch (state) {
    case SESSION_IDLE: return "IDLE";
    case SESSION_HANDSHAKE_START: return "START";
    case SESSION_PQ_KEM_INIT_SENT: return "KEM_INIT_SENT";
    case SESSION_PQ_KEM_RESPONSE_SENT: return "KEM_RESP_SENT";
    case SESSION_IDENTITY_PROOF_SENT: return "ID_PROOF_SENT";
    case SESSION_LOCKED: return "LOCKED";
    default: return "UNKNOWN";
    }
}

const char* handshake_error_name(uint8_t error_code)
{
    switch (error_code) {
    case HS_ERR_NONE: return "NONE";
    case HS_ERR_UNSUPPORTED_KEM: return "UNSUPPORTED_KEM";
    case HS_ERR_BAD_IDENTITY: return "BAD_IDENTITY";
    case HS_ERR_TIMEOUT: return "TIMEOUT";
    case HS_ERR_REPLAY: return "REPLAY";
    case HS_ERR_STATE_VIOLATION: return "STATE_VIOLATION";
    default: return "UNKNOWN";
    }
}
