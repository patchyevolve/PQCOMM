#include "session_enc.h"
#include "aead.h"
#include "channel.h"
#include <string.h>
#include <stdio.h>

static int build_aad(packet_view_t* view, uint8_t aad[HEADER_SIZE])
{
    uint8_t* d = view->buf->data;
    memcpy(aad, d, HEADER_SIZE);
    aad[5] &= ~PACKET_FLAG_ENCRYPTED;
    return HEADER_SIZE;
}

int session_enc_check(packet_view_t* p, session_t* sess)
{
    if (!p || !sess) return -1;
    if (sess->state != SESSION_LOCKED) return 0;
    if (p->channel_id == CH_CONTROL) return 0;

    uint8_t aad[HEADER_SIZE];
    build_aad(p, aad);

    uint8_t* cipher = p->payload;
    uint32_t cipher_len = p->length;

    /* decrypt in-place */
    int ret = aead_decrypt(sess->keys.session_key, p->nonce,
                           aad, HEADER_SIZE,
                           cipher, cipher_len,
                           p->tag,
                           cipher);
    if (ret != 0) {
        printf("[ENC] session decryption failed: ch=%u seq=%u len=%u\n",
               p->channel_id, p->seq, cipher_len);
        sess->hs.last_error = HS_ERR_BAD_IDENTITY;
        return -1;
    }

    p->encrypted = 0;
    return 0;
}

int session_enc_apply(packet_buf_t* p, packet_view_t* view, session_t* sess)
{
    if (!p || !view || !sess) return -1;
    if (sess->state != SESSION_LOCKED) return 0;
    if (view->channel_id == CH_CONTROL) return 0;

    uint8_t* plain = view->payload;
    uint32_t plain_len = view->length;

    uint8_t* cipher = p->data + HEADER_SIZE + AEAD_NONCE_SIZE;

    uint32_t enc_len = AEAD_NONCE_SIZE + plain_len + AEAD_TAG_SIZE;
    memcpy(p->data + 19, &enc_len, 4);

    uint8_t aad[HEADER_SIZE];
    memcpy(aad, p->data, HEADER_SIZE);
    aad[5] &= ~PACKET_FLAG_ENCRYPTED;

    uint8_t nonce[AEAD_NONCE_SIZE];
    memset(nonce, 0, AEAD_NONCE_SIZE);
    memcpy(nonce, &sess->session_id, 8);
    nonce[8] = view->channel_id;
    nonce[10] = (uint8_t)(view->seq >> 8);
    nonce[11] = (uint8_t)(view->seq);

    uint8_t tag[AEAD_TAG_SIZE];
    if (aead_encrypt(sess->keys.session_key, nonce,
                     aad, HEADER_SIZE,
                     plain, plain_len,
                     cipher, tag) != 0)
        return -1;

    p->data[5] |= PACKET_FLAG_ENCRYPTED;
    memcpy(p->data + HEADER_SIZE, nonce, AEAD_NONCE_SIZE);
    memcpy(p->data + HEADER_SIZE + AEAD_NONCE_SIZE + plain_len, tag, AEAD_TAG_SIZE);
    p->len = HEADER_SIZE + enc_len;

    return 0;
}
