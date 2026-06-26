#include "aead.h"
#include "config.h"
#include <string.h>
#include <mbedtls/cipher.h>

int aead_encrypt(const uint8_t key[32], const uint8_t nonce[AEAD_NONCE_SIZE],
                 const uint8_t* aad, uint32_t aad_len,
                 const uint8_t* plain, uint32_t plain_len,
                 uint8_t* cipher, uint8_t tag[AEAD_TAG_SIZE])
{
    const mbedtls_cipher_info_t* info = mbedtls_cipher_info_from_type(
        MBEDTLS_CIPHER_CHACHA20_POLY1305);
    if (!info) return -1;

    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    int ret = -1;

    do {
        if (mbedtls_cipher_setup(&ctx, info) != 0) break;
        if (mbedtls_cipher_setkey(&ctx, key, 256, MBEDTLS_ENCRYPT) != 0) break;

        size_t out_len = plain_len + AEAD_TAG_SIZE;
        uint8_t out_buf[MAX_PACKET_SIZE];
        if (out_len > sizeof(out_buf)) break;

        size_t olen = 0;
        ret = mbedtls_cipher_auth_encrypt_ext(&ctx,
                                               nonce, AEAD_NONCE_SIZE,
                                               aad, aad_len,
                                               plain, plain_len,
                                               out_buf, out_len, &olen,
                                               AEAD_TAG_SIZE);
        if (ret == 0 && olen == out_len) {
            memcpy(cipher, out_buf, plain_len);
            memcpy(tag, out_buf + plain_len, AEAD_TAG_SIZE);
        }
    } while (0);

    mbedtls_cipher_free(&ctx);
    return ret;
}

int aead_decrypt(const uint8_t key[32], const uint8_t nonce[AEAD_NONCE_SIZE],
                 const uint8_t* aad, uint32_t aad_len,
                 const uint8_t* cipher, uint32_t cipher_len,
                 const uint8_t tag[AEAD_TAG_SIZE],
                 uint8_t* plain)
{
    const mbedtls_cipher_info_t* info = mbedtls_cipher_info_from_type(
        MBEDTLS_CIPHER_CHACHA20_POLY1305);
    if (!info) return -1;

    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    int ret = -1;

    do {
        if (mbedtls_cipher_setup(&ctx, info) != 0) break;
        if (mbedtls_cipher_setkey(&ctx, key, 256, MBEDTLS_DECRYPT) != 0) break;

        size_t in_len = cipher_len + AEAD_TAG_SIZE;
        uint8_t in_buf[MAX_PACKET_SIZE];
        if (in_len > sizeof(in_buf)) break;
        memcpy(in_buf, cipher, cipher_len);
        memcpy(in_buf + cipher_len, tag, AEAD_TAG_SIZE);

        size_t olen = 0;
        ret = mbedtls_cipher_auth_decrypt_ext(&ctx,
                                               nonce, AEAD_NONCE_SIZE,
                                               aad, aad_len,
                                               in_buf, in_len,
                                               plain, cipher_len, &olen,
                                               AEAD_TAG_SIZE);
    } while (0);

    mbedtls_cipher_free(&ctx);
    return ret;
}
