#include "secure_store.h"
#include "kem.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __linux__
#include <sys/mman.h>
#include <unistd.h>
#endif

static uint8_t g_identity_key[IDENTITY_KEY_SIZE];
static int g_key_initialized = 0;

static const uint8_t g_fallback_key[IDENTITY_KEY_SIZE] = {
    0x6b, 0xe5, 0x79, 0x3e, 0x7a, 0x1f, 0x2c, 0xd4,
    0x91, 0x82, 0x5a, 0x0d, 0x3b, 0xf8, 0x44, 0x97,
    0x1c, 0x63, 0xae, 0x90, 0xf5, 0x28, 0xbb, 0x50,
    0xcf, 0x21, 0x65, 0xde, 0x09, 0x74, 0x80, 0x3e
};

static int hex_to_bytes(const char* hex, uint8_t* out, uint32_t out_len)
{
    uint32_t hex_len = (uint32_t)strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (uint32_t i = 0; i < out_len; i++) {
        char byte_str[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        char* end = NULL;
        long val = strtol(byte_str, &end, 16);
        if (*end != '\0') return -1;
        out[i] = (uint8_t)val;
    }
    return 0;
}

int secure_store_init(void)
{
    if (g_key_initialized) return 0;

    const char* env_key = getenv("IDENTITY_KEY");
    if (env_key && strlen(env_key) == IDENTITY_KEY_SIZE * 2) {
        if (hex_to_bytes(env_key, g_identity_key, IDENTITY_KEY_SIZE) != 0) {
            printf("[SECURE_STORE] invalid IDENTITY_KEY hex string\n");
            memcpy(g_identity_key, g_fallback_key, IDENTITY_KEY_SIZE);
        }
    } else {
        memcpy(g_identity_key, g_fallback_key, IDENTITY_KEY_SIZE);
    }

#ifdef __linux__
    if (mlock(g_identity_key, IDENTITY_KEY_SIZE) != 0) {
        perror("[SECURE_STORE] mlock failed");
    }
    if (madvise(g_identity_key, IDENTITY_KEY_SIZE, MADV_DONTDUMP) != 0) {
        perror("[SECURE_STORE] madvise DONTDUMP failed");
    }
#endif

    g_key_initialized = 1;
    return 0;
}

int secure_store_set_key(const uint8_t* key, uint32_t key_len)
{
    if (!key || key_len != IDENTITY_KEY_SIZE) return -1;
    if (!g_key_initialized) secure_store_init();
    memcpy(g_identity_key, key, IDENTITY_KEY_SIZE);
    return 0;
}

const uint8_t* secure_store_get_identity_key(void)
{
    if (!g_key_initialized) secure_store_init();
    return g_identity_key;
}

void secure_store_shutdown(void)
{
    if (!g_key_initialized) return;
#ifdef __linux__
    munlock(g_identity_key, IDENTITY_KEY_SIZE);
#endif
    crypto_secure_wipe(g_identity_key, IDENTITY_KEY_SIZE);
    g_key_initialized = 0;
}
