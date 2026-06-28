#pragma once

#include <stdint.h>

#define HKDF_HASH_SIZE  32
#define HKDF_MAX_OKM_LEN 8160  // 255 * 32

// HKDF-Extract
int hkdf_extract(const uint8_t* salt, uint32_t salt_len,
                 const uint8_t* ikm, uint32_t ikm_len,
                 uint8_t* prk_output);

// HKDF-Expand
int hkdf_expand(const uint8_t* prk, uint32_t prk_len,
                const uint8_t* info, uint32_t info_len,
                uint8_t* okm, uint32_t okm_len);

// Full HKDF
int hkdf(const uint8_t* salt, uint32_t salt_len,
         const uint8_t* ikm, uint32_t ikm_len,
         const uint8_t* info, uint32_t info_len,
         uint8_t* okm, uint32_t okm_len);

// Derive session keys
int derive_session_keys(const uint8_t* kem_secret, uint32_t secret_len,
                        const uint8_t* transcript_hash, uint32_t hash_len,
                        uint8_t* session_key, uint32_t sk_len,
                        uint8_t channel_keys[6][32]);