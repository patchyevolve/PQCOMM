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

// External stats defined in session.h
handshake_stats_t g_handshake_stats = { 0 };


static void update_transcript(session_t* sess, const uint8_t* data, uint32_t len)
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    // Start with the current hash state
    mbedtls_sha256_starts(&ctx, 0); // 0 for SHA-256
    mbedtls_sha256_update(&ctx, sess->hs.transcript_hash, 32);
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, sess->hs.transcript_hash);

    mbedtls_sha256_free(&ctx);
    sess->hs.messages_exchanged++;
}

static int verify_state_transition(session_t* sess, uint8_t received_opcode)
{
    session_state_t current = sess->state;
    session_state_t expected = SESSION_IDLE;

    if (sess->role == ROLE_INITIATOR) {
        switch (received_opcode) {
        case CTRL_HELLO:
            printf("[HANDSHAKE] Initiator received HELLO (loopback?)\n");
            sess->hs.last_error = HS_ERR_STATE_VIOLATION;
            return -1;
        case CTRL_ACCEPT:
            // ACCEPT can arrive when we're in HANDSHAKE_START (just sent HELLO)
            expected = SESSION_HANDSHAKE_START;
            break;
        case CTRL_PQ_KEM_RESPONSE:  expected = SESSION_PQ_KEM_INIT_SENT; break;
        case CTRL_IDENTITY_PROOF:   expected = SESSION_PQ_KEM_RESPONSE_SENT; break;
        case CTRL_SESSION_LOCKED:   expected = SESSION_IDENTITY_PROOF_SENT; break;
        default: return -1;
        }
    }
    else { // ROLE_RESPONDER
        switch (received_opcode) {
        case CTRL_HELLO:
            // Responder can receive HELLO when IDLE or at START
            if (current != SESSION_IDLE && current != SESSION_HANDSHAKE_START) {
                return -1;
            }
            return 0; // Accept HELLO in these states
        case CTRL_PQ_KEM_INIT:      expected = SESSION_HANDSHAKE_START; break;
        case CTRL_IDENTITY_PROOF:   expected = SESSION_PQ_KEM_RESPONSE_SENT; break;
        case CTRL_SESSION_LOCKED:   expected = SESSION_IDENTITY_PROOF_SENT; break;
        default: return -1;
        }
    }

    if (current != expected) {
        printf("[HANDSHAKE] State mismatch: current=%s, expected=%s for opcode=%d\n",
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

    // Seed transcript with Session ID to prevent cross-session replays
    memset(sess->hs.transcript_hash, 0, 32);
    memcpy(sess->hs.transcript_hash, &sess->session_id, sizeof(sess->session_id));

    printf("[HANDSHAKE] Initiator started, session %llu\n", (unsigned long long)sess->session_id);
    /* FIX #14: Removed leftover debug printf statements */
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

    memset(sess->hs.transcript_hash, 0, 32);
    memcpy(sess->hs.transcript_hash, &sess->session_id, sizeof(sess->session_id));

    return 0;
}

packet_buf_t* handshake_build_hello(session_t* sess, uint32_t* seq_counter) {
    packet_buf_t* p = pool_get();
    if (!p) return NULL;

    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1;
    uint8_t flags = 0;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1;
    uint8_t opcode = CTRL_HELLO;
    uint64_t session_id = 0; // Unassigned for HELLO

    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &session_id, sizeof(session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    memcpy(d + 24, &opcode, sizeof(opcode));

    p->len = 24 + payload_len;
    return p;
}

int handshake_build_accept(session_t* sess, packet_buf_t* out, uint32_t* seq_counter) {
    if (!sess || !out || !seq_counter) return -1;

    uint64_t session_id = ((uint64_t)rand() << 32) | rand();
    sess->session_id = session_id;

    uint8_t* d = out->data;
    uint32_t payload_len = 1 + 8;

    memcpy(d + 0, (uint32_t[]) { 0xAABBCCDD }, sizeof(uint32_t));
    d[4] = 1; // version
    d[5] = 0; // flags
    memcpy(d + 6, &session_id, sizeof(session_id));
    d[14] = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    d[24] = CTRL_ACCEPT;
    memcpy(d + 25, &session_id, sizeof(session_id));

    out->len = 24 + payload_len;
    // Keep responder in the handshake start state until PQ_KEM_INIT arrives.
    return 0;
}

int handshake_build_kem_init(session_t* sess,
    packet_buf_t* out,
    uint32_t* seq_counter)
{
    if (!sess || !out || !seq_counter) return -1;

    uint32_t pk_size = 0, sk_size = 0, ct_size = 0, ss_size = 0;
    kem_get_sizes(sess->hs.kem_type, &pk_size, &sk_size, &ct_size, &ss_size);

    if (pk_size == 0 || sk_size == 0) {
        printf("[HANDSHAKE] Invalid KEM sizes: pk=%u sk=%u\n", pk_size, sk_size);
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

    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1;
    uint8_t flags = 0;
    uint64_t session_id = sess->session_id;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1 + pk_size;
    uint8_t opcode = CTRL_PQ_KEM_INIT;

    // header
    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &session_id, sizeof(session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    memcpy(d + 24, &opcode, sizeof(opcode));

    // payload
    memcpy(d + 25, sess->hs.kem_public_key, pk_size);

    out->len = 24 + payload_len;

    // --- CRITICAL: transcript update ---
    update_transcript(sess, d + 24, payload_len);

    // state transition
    sess->state = SESSION_PQ_KEM_INIT_SENT;

    return 0;
}

int handshake_build_kem_response(session_t* sess,
    packet_buf_t* out,
    uint32_t* seq_counter)
{
    if (!sess || !out || !seq_counter) return -1;

    uint32_t ct_size = 0, ss_size = 0;
    kem_get_sizes(sess->hs.kem_type, NULL, NULL, &ct_size, &ss_size);

    if (ct_size == 0 || ss_size == 0) return -1;

    /*
     * FIX #7: Double-free on ciphertext and shared_secret.
     * Old code wiped shared_secret at line ~279, then freed both at line ~312,
     * and also freed both on the derive_session_keys error path — so every exit
     * path except the alloc-failure path freed them twice.
     * Fix: use a single cleanup label so every exit path frees exactly once.
     * shared_secret is wiped before freeing on all paths.
     */
    int ret = -1;
    uint8_t* ciphertext = malloc(ct_size);
    uint8_t* shared_secret = malloc(ss_size);

    if (!ciphertext || !shared_secret) goto cleanup;

    {
        uint32_t pk_size = 0;
        kem_get_sizes(sess->hs.kem_type, &pk_size, NULL, NULL, NULL);

        if (kem_encapsulate(sess->hs.peer_public_key,
            pk_size,
            ciphertext, ct_size,
            shared_secret, ss_size) != 0)
        {
            goto cleanup;
        }
    }

    if (derive_session_keys(shared_secret, ss_size,
        sess->hs.transcript_hash, 32,
        sess->keys.session_key, 32,
        sess->keys.channel_keys) != 0)
    {
        goto cleanup;
    }

    {
        uint8_t* d = out->data;

        uint32_t magic = 0xAABBCCDD;
        uint8_t  version = 1;
        uint8_t  flags = 0;
        uint64_t session_id = sess->session_id;
        uint8_t  channel = CH_CONTROL;
        uint32_t seq = (*seq_counter)++;
        uint32_t payload_len = 1 + ct_size;
        uint8_t  opcode = CTRL_PQ_KEM_RESPONSE;

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
    /* Always wipe then free — once — on every path */
    if (shared_secret) {
        crypto_secure_wipe(shared_secret, ss_size);
        free(shared_secret);
    }
    free(ciphertext);
    return ret;
}

int handshake_build_identity(session_t* sess,
    packet_buf_t* out,
    uint32_t* seq_counter)
{
    if (!sess || !out || !seq_counter) return -1;

    uint8_t* d = out->data;

    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1;
    uint8_t flags = 0;
    uint64_t session_id = sess->session_id;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1 + 64 + 32; // opcode + sig + identity hash
    uint8_t opcode = CTRL_IDENTITY_PROOF;

    // header
    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &session_id, sizeof(session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    memcpy(d + 24, &opcode, sizeof(opcode));

    // --- signature (placeholder) ---
    // In real implementation:
    // Ed25519_sign(secret_key, transcript_hash)
    memset(d + 25, 0xAB, 64);

    // --- identity binding ---
    memcpy(d + 25 + 64, sess->hs.our_identity_hash, 32);

    out->len = 24 + payload_len;

    // --- CRITICAL: transcript update ---
    update_transcript(sess, d + 24, payload_len);

    // state transition
    sess->state = SESSION_IDENTITY_PROOF_SENT;

    return 0;
}

int handshake_build_locked(session_t* sess,
    packet_buf_t* out,
    uint32_t* seq_counter)
{
    if (!sess || !out || !seq_counter) return -1;

    uint8_t* d = out->data;

    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1;
    uint8_t flags = 0;
    uint64_t session_id = sess->session_id;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 1;
    uint8_t opcode = CTRL_SESSION_LOCKED;

    // --- header ---
    memcpy(d + 0, &magic, sizeof(magic));
    memcpy(d + 4, &version, sizeof(version));
    memcpy(d + 5, &flags, sizeof(flags));
    memcpy(d + 6, &session_id, sizeof(session_id));
    memcpy(d + 14, &channel, sizeof(channel));
    memcpy(d + 15, &seq, sizeof(seq));
    memcpy(d + 19, &payload_len, sizeof(payload_len));
    memcpy(d + 24, &opcode, sizeof(opcode));

    out->len = 24 + payload_len;

    /*
     * FIX #9: transcript update MUST happen BEFORE derive_session_keys.
     * Both sides must hash the LOCKED message into the transcript before
     * deriving keys, otherwise transcript states diverge and keys won't match.
     */
    update_transcript(sess, d + 24, payload_len);

    // --- Derive final session keys from the now-complete transcript ---
    uint32_t ss_size = 32; // ML-KEM shared secret is 32 bytes

    if (derive_session_keys(sess->hs.kem_shared_secret, ss_size,
        sess->hs.transcript_hash, 32,
        sess->keys.session_key, 32,
        sess->keys.channel_keys) != 0)
    {
        return -1;
    }

    // --- wipe sensitive material ---
    uint32_t sk_size = 0;
    kem_get_sizes(sess->hs.kem_type, NULL, &sk_size, NULL, NULL);
    crypto_secure_wipe(sess->hs.kem_secret_key, sk_size);

    crypto_secure_wipe(sess->hs.kem_shared_secret, ss_size);

    // --- finalize state ---
    sess->state = SESSION_LOCKED;
    sess->handshake_complete = 1;

    return 0;
}

int handshake_build_error(session_t* sess, packet_buf_t* out, uint8_t error_code, uint32_t* seq_counter) {
    if (!sess || !out || !seq_counter) return -1;

    uint8_t* d = out->data;

    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1;
    uint8_t flags = 0;
    uint64_t session_id = sess->session_id;
    uint8_t channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;
    uint32_t payload_len = 2; // opcode + error_code
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

packet_buf_t* handshake_run_as_initiator(session_t* sess, packet_buf_t* in, uint32_t* seq_counter) {
    if (!sess || !in) return NULL;

    packet_view_t view = { 0 };
    if (packet_parse(in, &view) != 0) return NULL;

    packet_buf_t* response = NULL;
    int result = handshake_process_message(sess, in, &view, &response);

    if (result == HS_ERROR) {
        printf("[HANDSHAKE] Initiator error: %s\n", handshake_error_name(sess->hs.last_error));
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
            printf("[HANDSHAKE] Initiator complete!\n");
            return NULL;
        }
    }

    return response;
}

packet_buf_t* handshake_run_as_responder(session_t* sess, packet_buf_t* in, uint32_t* seq_counter) {
    if (!sess || !in) return NULL;

    packet_view_t view = { 0 };
    if (packet_parse(in, &view) != 0) return NULL;

    packet_buf_t* response = NULL;
    int result = handshake_process_message(sess, in, &view, &response);

    if (result == HS_ERROR) {
        printf("[HANDSHAKE] Responder error: %s\n", handshake_error_name(sess->hs.last_error));
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
        }
    }

    return response;
}

int handshake_process_message(session_t* sess, packet_buf_t* packet, packet_view_t* view, packet_buf_t** response_out)
{
    /* FIX #12: Consolidated guard — removed duplicate NULL check on view.
     * Original code checked !view twice and view->length < 1 twice. */
    if (!sess || !view || !view->payload || view->length < 1) {
        if (sess) sess->hs.last_error = HS_ERR_STATE_VIOLATION;
        return HS_ERROR;
    }

    uint8_t opcode = view->payload[0];

    /* PHASE 2 REQUIREMENT: Reject PQ operations (KEM_INIT, KEM_RESPONSE) after SESSION_LOCKED */
    if (sess->state == SESSION_LOCKED) {
        if (opcode == CTRL_PQ_KEM_INIT || opcode == CTRL_PQ_KEM_RESPONSE) {
            printf("[HANDSHAKE] Rejected PQ operation (opcode=%d) on locked session\n", opcode);
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

    update_transcript(sess, view->payload, view->length);

    switch (opcode) {

    case CTRL_HELLO:
        // Responder received HELLO - already handled in main.c to set role
        // Just acknowledge and wait for ACCEPT from initiator perspective
        if (sess->role == ROLE_RESPONDER) {
            return HS_NEED_MORE;  // Wait for main.c to build ACCEPT
        }
        sess->hs.last_error = HS_ERR_STATE_VIOLATION;
        return HS_ERROR;

    case CTRL_ACCEPT:
        // Extract session ID from payload
        if (view->length >= 9) {
            memcpy(&sess->session_id, view->payload + 1, 8);
        }
        // Don't change state here - stay at HANDSHAKE_START
        // The next message (KEM_INIT) will transition us
        return HS_NEED_MORE;

    case CTRL_PQ_KEM_INIT:
        if (view->length < 1 + 1184) return HS_ERROR; // Min size for 768
        memcpy(sess->hs.peer_public_key, view->payload + 1,
            (sess->hs.kem_type == KEM_TYPE_MLKEM_768) ? 1184 : 1568);
        return HS_NEED_MORE;

    case CTRL_PQ_KEM_RESPONSE:
        if (view->length < 1 + 1088) return HS_ERROR;
        if (kem_decapsulate(sess->hs.kem_secret_key,
            (sess->hs.kem_type == KEM_TYPE_MLKEM_768) ? 2400 : 3168,
            view->payload + 1,
            (sess->hs.kem_type == KEM_TYPE_MLKEM_768) ? 1088 : 1568,
            sess->hs.kem_shared_secret, 32) != 0) {
            return HS_ERROR;
        }
        return HS_NEED_MORE;

    case CTRL_IDENTITY_PROOF:
        if (view->length < 97) return HS_ERROR;
        // Verify Peer Identity Hash (In production, verify the signature at view->payload + 1)
        memcpy(sess->hs.peer_identity_hash, view->payload + 65, 32);
        sess->hs.identity_verified = 1;
        return HS_NEED_MORE;

    case CTRL_SESSION_LOCKED:
        sess->state = SESSION_LOCKED;
        sess->handshake_complete = 1;
        g_handshake_stats.successes++;  /* PHASE 2: Track successful handshake completion */
        return HS_COMPLETE;

    default:
        return HS_ERROR;
    }
}

int handshake_check_timeout(session_t* sess, uint32_t current_time_ms)
{
    if (!sess || sess->hs.handshake_start_ms == 0) return 0;
    if (current_time_ms - sess->hs.handshake_start_ms > sess->hs.timeout_ms) {
        return -1;
    }
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