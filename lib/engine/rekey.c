#include "rekey.h"
#include "kem.h"
#include "hkdf.h"
#include "pool.h"
#include "channel.h"
#include <string.h>
#include <netinet/in.h>

#define REKEY_NONCE_SIZE 8

int rekey_initiate(session_t* sess, tx_queues_t* txq, uint32_t* seq_counter)
{
    if (!sess || !txq || !seq_counter) return -1;
    if (sess->state != SESSION_LOCKED) return -1;

    kem_context_t kem_ctx;
    uint32_t pk_size = KEM_MLKEM_768_PK_SIZE;
    uint32_t sk_size = KEM_MLKEM_768_SK_SIZE;
    uint8_t pk[KEM_MLKEM_768_PK_SIZE];
    uint8_t sk[KEM_MLKEM_768_SK_SIZE];

    if (kem_init(&kem_ctx, KEM_TYPE_MLKEM_768) != 0) return -1;
    if (kem_keypair(&kem_ctx, pk, &pk_size, sk, &sk_size) != 0) {
        kem_cleanup(&kem_ctx);
        return -1;
    }
    kem_cleanup(&kem_ctx);

    packet_buf_t* p = pool_get();
    if (!p) return -1;

    uint8_t* d = p->data;
    uint32_t magic = 0xAABBCCDD;
    uint8_t version = 1, flags = 0, channel = CH_CONTROL;
    uint32_t seq = (*seq_counter)++;

    memcpy(d + 0, &magic, 4);
    memcpy(d + 4, &version, 1);
    memcpy(d + 5, &flags, 1);
    memcpy(d + 6, &sess->session_id, 8);
    memcpy(d + 14, &channel, 1);
    memcpy(d + 15, &seq, 4);

    uint32_t payload_len = 1 + 8 + pk_size;
    memcpy(d + 19, &payload_len, 4);
    d[24] = CTRL_REKEY_INIT;
    memcpy(d + 25, &sess->keys.key_epoch, 8);
    memcpy(d + 33, pk, pk_size);
    p->len = 24 + payload_len;

    memcpy(p->addr, sess->addr, sess->addr_len);
    p->addr_len = sess->addr_len;

    memcpy(sess->hs.kem_secret_key, sk, sk_size);

    ring_push(&txq->control, p);
    return 0;
}

static int derive_rekey_keys(session_t* sess, const uint8_t* shared_secret, uint32_t ss_len)
{
    uint8_t context[40];
    uint64_t epoch = sess->keys.key_epoch + 1;
    memcpy(context, &sess->session_id, 8);
    memcpy(context + 8, &epoch, 8);
    memset(context + 16, 0x00, 24);

    uint8_t session_key[32];
    uint8_t channel_keys[5][32];
    if (derive_session_keys(shared_secret, ss_len, context, sizeof(context),
                            session_key, 32, channel_keys) != 0)
        return -1;

    crypto_secure_wipe(&sess->keys, sizeof(sess->keys));

    memcpy(sess->keys.session_key, session_key, 32);
    for (int i = 0; i < 5; i++)
        memcpy(sess->keys.channel_keys[i], channel_keys[i], 32);
    sess->keys.key_epoch = epoch;

    crypto_secure_wipe(session_key, sizeof(session_key));
    crypto_secure_wipe(channel_keys, sizeof(channel_keys));
    return 0;
}

int rekey_handle(packet_buf_t* p, session_t* sess, tx_queues_t* txq, uint32_t* seq_counter)
{
    if (!p || !sess || !txq) return -1;
    if (sess->state != SESSION_LOCKED) return -1;

    uint8_t opcode = p->data[24];

    if (opcode == CTRL_REKEY_INIT) {
        uint64_t epoch;
        memcpy(&epoch, p->data + 25, 8);
        if (epoch != sess->keys.key_epoch) return 0;

        uint8_t* peer_pk = p->data + 33;
        uint32_t pk_size = KEM_MLKEM_768_PK_SIZE;
        uint32_t ct_size = KEM_MLKEM_768_CT_SIZE;
        uint32_t ss_size = KEM_MLKEM_768_SS_SIZE;

        uint8_t ct[KEM_MLKEM_768_CT_SIZE];
        uint8_t ss[KEM_MLKEM_768_SS_SIZE];
        if (kem_encapsulate(peer_pk, pk_size, ct, ct_size, ss, ss_size) != 0)
            return -1;

        if (derive_rekey_keys(sess, ss, ss_size) != 0)
            return -1;

        uint32_t seq = (*seq_counter)++;
        packet_buf_t* resp = pool_get();
        if (!resp) return -1;

        uint8_t* d = resp->data;
        uint32_t magic = 0xAABBCCDD;
        uint8_t ver = 1, fl = 0, ch = CH_CONTROL;
        memcpy(d + 0, &magic, 4);
        memcpy(d + 4, &ver, 1);
        memcpy(d + 5, &fl, 1);
        memcpy(d + 6, &sess->session_id, 8);
        memcpy(d + 14, &ch, 1);
        memcpy(d + 15, &seq, 4);

        uint32_t payload_len = 1 + 8 + ct_size;
        memcpy(d + 19, &payload_len, 4);
        d[24] = CTRL_REKEY_CONFIRM;
        memcpy(d + 25, &sess->keys.key_epoch, 8);
        memcpy(d + 33, ct, ct_size);
        resp->len = 24 + payload_len;

        memcpy(resp->addr, p->addr, sizeof(struct sockaddr_in6));
        resp->addr_len = sizeof(struct sockaddr_in6);
        ring_push(&txq->control, resp);
        return 1;
    }

    if (opcode == CTRL_REKEY_CONFIRM) {
        uint64_t epoch;
        memcpy(&epoch, p->data + 25, 8);
        if (epoch != sess->keys.key_epoch + 1) return 0;

        uint8_t* ct = p->data + 33;
        uint8_t ss[KEM_MLKEM_768_SS_SIZE];
        uint32_t sk_size = KEM_MLKEM_768_SK_SIZE;
        uint32_t ct_size = KEM_MLKEM_768_CT_SIZE;
        uint32_t ss_size = KEM_MLKEM_768_SS_SIZE;
        if (kem_decapsulate(sess->hs.kem_secret_key, sk_size, ct, ct_size, ss, ss_size) != 0)
            return -1;

        if (derive_rekey_keys(sess, ss, ss_size) != 0)
            return -1;

        crypto_secure_wipe(sess->hs.kem_secret_key, KEM_MLKEM_768_SK_SIZE);
        return 2;
    }

    return 0;
}
