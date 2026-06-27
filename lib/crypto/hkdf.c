#include "hkdf.h"
#include <string.h>
#include <stddef.h>
#include <mbedtls/md.h>

static int crypto_hmac_sha256(const uint8_t *key, uint32_t key_len,
                              const uint8_t *data, uint32_t data_len,
                              uint8_t out[HKDF_HASH_SIZE])
{
    const mbedtls_md_info_t *info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return -1;
    return (mbedtls_md_hmac(info, key, key_len, data, data_len, out) == 0) ? 0 : -1;
}

/* streaming hmac so we dont need to concat into a temp buffer */
static int crypto_hmac_sha256_stream(const uint8_t *key, uint32_t key_len,
                                     const uint8_t *a, uint32_t a_len,
                                     const uint8_t *b, uint32_t b_len,
                                     const uint8_t *c, uint32_t c_len,
                                     uint8_t out[HKDF_HASH_SIZE])
{
    const mbedtls_md_info_t *info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return -1;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, info, 1) != 0) return -1;

    if (mbedtls_md_hmac_starts(&ctx, key, key_len) != 0) goto fail;
    if (a && a_len && mbedtls_md_hmac_update(&ctx, a, a_len) != 0) goto fail;
    if (b && b_len && mbedtls_md_hmac_update(&ctx, b, b_len) != 0) goto fail;
    if (c && c_len && mbedtls_md_hmac_update(&ctx, c, c_len) != 0) goto fail;
    if (mbedtls_md_hmac_finish(&ctx, out) != 0) goto fail;

    mbedtls_md_free(&ctx);
    return 0;
fail:
    mbedtls_md_free(&ctx);
    return -1;
}

static void secure_wipe(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

/* hkdf-extract: prk = hmac(salt, ikm) */
int hkdf_extract(const uint8_t *salt, uint32_t salt_len,
                 const uint8_t *ikm, uint32_t ikm_len,
                 uint8_t *prk_output)
{
    if (!ikm || !prk_output) return -1;

    static const uint8_t zero_salt[HKDF_HASH_SIZE] = {0};
    if (!salt || salt_len == 0) {
        salt = zero_salt;
        salt_len = HKDF_HASH_SIZE;
    }
    return crypto_hmac_sha256(salt, salt_len, ikm, ikm_len, prk_output);
}

/* hkdf-expand, streaming so no big T buffer needed */
int hkdf_expand(const uint8_t *prk, uint32_t prk_len,
                const uint8_t *info, uint32_t info_len,
                uint8_t *okm, uint32_t okm_len)
{
    if (!prk || !okm) return -1;
    if (prk_len < HKDF_HASH_SIZE) return -1;
    if (okm_len == 0 || okm_len > HKDF_MAX_OKM_LEN) return -1;
    if (info_len > 0 && !info) return -1;

    uint8_t T[HKDF_HASH_SIZE];
    uint32_t offset = 0;
    uint8_t counter = 1;
    uint32_t T_len = 0;

    memset(okm, 0, okm_len);

    while (offset < okm_len) {
        if (counter == 0) {
            secure_wipe(T, sizeof T);
            return -1;
        }
        if (crypto_hmac_sha256_stream(
                prk, prk_len,
                (T_len ? T : NULL), T_len,
                info, info_len,
                &counter, 1, T) != 0)
        {
            secure_wipe(T, sizeof T);
            memset(okm, 0, okm_len);
            return -1;
        }
        uint32_t copy = okm_len - offset;
        if (copy > HKDF_HASH_SIZE) copy = HKDF_HASH_SIZE;
        memcpy(okm + offset, T, copy);
        offset += copy;
        T_len = HKDF_HASH_SIZE;
        counter++;
    }
    secure_wipe(T, sizeof T);
    return 0;
}

int hkdf(const uint8_t *salt, uint32_t salt_len,
         const uint8_t *ikm, uint32_t ikm_len,
         const uint8_t *info, uint32_t info_len,
         uint8_t *okm, uint32_t okm_len)
{
    uint8_t prk[HKDF_HASH_SIZE];
    if (hkdf_extract(salt, salt_len, ikm, ikm_len, prk) != 0)
        return -1;
    int ret = hkdf_expand(prk, HKDF_HASH_SIZE, info, info_len, okm, okm_len);
    secure_wipe(prk, sizeof prk);
    return ret;
}

static const uint8_t LABEL_SESSION[]  = "SCv1 session key";
static const uint8_t LABEL_CHANNEL0[] = "SCv1 channel key 0";
static const uint8_t LABEL_CHANNEL1[] = "SCv1 channel key 1";
static const uint8_t LABEL_CHANNEL2[] = "SCv1 channel key 2";
static const uint8_t LABEL_CHANNEL3[] = "SCv1 channel key 3";
static const uint8_t LABEL_CHANNEL4[] = "SCv1 channel key 4";
static const uint8_t LABEL_CHANNEL5[] = "SCv1 channel key 5";

/* derives one session key + 5 channel keys from kem shared secret + transcript */
int derive_session_keys(const uint8_t *kem_secret, uint32_t secret_len,
                        const uint8_t *transcript_hash, uint32_t hash_len,
                        uint8_t *session_key, uint32_t sk_len,
                         uint8_t channel_keys[6][32])
{
    if (!kem_secret || !transcript_hash || !session_key || !channel_keys)
        return -1;
    if (secret_len == 0 || hash_len == 0 || sk_len == 0)
        return -1;

    uint8_t prk[HKDF_HASH_SIZE];

    if (hkdf_extract(transcript_hash, hash_len,
                     kem_secret, secret_len, prk) != 0)
        return -1;

    if (hkdf_expand(prk, HKDF_HASH_SIZE,
                    LABEL_SESSION, sizeof(LABEL_SESSION) - 1,
                    session_key, sk_len) != 0)
        goto fail;

    static const struct {
        const uint8_t *label;
        uint32_t len;
    } labels[6] = {
        { LABEL_CHANNEL0, sizeof(LABEL_CHANNEL0) - 1 },
        { LABEL_CHANNEL1, sizeof(LABEL_CHANNEL1) - 1 },
        { LABEL_CHANNEL2, sizeof(LABEL_CHANNEL2) - 1 },
        { LABEL_CHANNEL3, sizeof(LABEL_CHANNEL3) - 1 },
        { LABEL_CHANNEL4, sizeof(LABEL_CHANNEL4) - 1 },
        { LABEL_CHANNEL5, sizeof(LABEL_CHANNEL5) - 1 },
    };

    for (int i = 0; i < 6; i++) {
        if (hkdf_expand(prk, HKDF_HASH_SIZE,
                        labels[i].label, labels[i].len,
                        channel_keys[i], 32) != 0)
            goto fail;
    }

    secure_wipe(prk, sizeof prk);
    return 0;

fail:
    secure_wipe(prk, sizeof prk);
    secure_wipe(session_key, sk_len);
    secure_wipe(channel_keys, 6 * 32);
    return -1;
}
