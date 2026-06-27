#pragma once
#include <stdint.h>
#include "config.h"

/* aead encrypt/decrypt using chacha20-poly1305 via mbedtls
 * returns 0 on success, -1 on failure
 * aad is the data to authenticate (header bytes, not encrypted)
 * nonce is AEAD_NONCE_SIZE bytes
 * key is 32 bytes
 * tag is written/read at tag_out/tag_in (AEAD_TAG_SIZE bytes) */
int aead_encrypt(const uint8_t key[32], const uint8_t nonce[AEAD_NONCE_SIZE],
                 const uint8_t* aad, uint32_t aad_len,
                 const uint8_t* plain, uint32_t plain_len,
                 uint8_t* cipher, uint8_t tag[AEAD_TAG_SIZE]);

int aead_decrypt(const uint8_t key[32], const uint8_t nonce[AEAD_NONCE_SIZE],
                 const uint8_t* aad, uint32_t aad_len,
                 const uint8_t* cipher, uint32_t cipher_len,
                 const uint8_t tag[AEAD_TAG_SIZE],
                 uint8_t* plain);
