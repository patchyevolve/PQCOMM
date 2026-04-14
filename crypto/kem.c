#include "kem.h"
#include <string.h>
#include <stddef.h>

#ifdef _WIN32
  #include <windows.h>
  #include <wincrypt.h>
#else
  #include <sys/random.h>
#endif

//Plug in your ML-KEM primitive here (e.g. liboqs, pqclean, aws-lc)
#include <oqs/kem_ml_kem.h>   // OQS_KEM_ml_kem_768_keypair / _encaps / _decaps



// Internal RNG (not exposed in kem.h)
static int crypto_random_bytes(uint8_t *buf, uint32_t len)
{
#ifdef _WIN32
    HCRYPTPROV hprov = 0;
    if (!CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
        return -1;
    BOOL ok = CryptGenRandom(hprov, (DWORD)len, buf);
    CryptReleaseContext(hprov, 0);
    return ok ? 0 : -1;
#else
    ssize_t ret = getrandom(buf, (size_t)len, 0);
    return (ret == (ssize_t)len) ? 0 : -1;
#endif
}


//Public utilities 

// Declared in kem.h as kem_random_bytes 
void kem_random_bytes(uint8_t *buf, uint32_t len)
{
    // Best-effort; callers that need error handling should use the internal
    // crypto_random_bytes() directly and check the return value.
    crypto_random_bytes(buf, len);
}

// the compiler from optimising the loop away in the wipe function below.
int crypto_secure_memcmp(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= pa[i] ^ pb[i];
    return diff; /* 0 == equal */
}

// header declares crypto_secure_wipe
void crypto_secure_wipe(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < len; i++)
        p[i] = 0;
}


// Size table 
void kem_get_sizes(uint8_t kem_type,
                   uint32_t *pk_size, uint32_t *sk_size,
                   uint32_t *ct_size, uint32_t *ss_size)
{
    uint32_t pk = 0, sk = 0, ct = 0, ss = 0;

    switch (kem_type) {
        case KEM_TYPE_MLKEM_768:
            pk = KEM_MLKEM_768_PK_SIZE;
            sk = KEM_MLKEM_768_SK_SIZE;
            ct = KEM_MLKEM_768_CT_SIZE;
            ss = KEM_MLKEM_768_SS_SIZE;
            break;
        case KEM_TYPE_MLKEM_1024:
            pk = KEM_MLKEM_1024_PK_SIZE;
            sk = KEM_MLKEM_1024_SK_SIZE;
            ct = KEM_MLKEM_1024_CT_SIZE;
            ss = KEM_MLKEM_1024_SS_SIZE;
            break;
        default:
            break; /* all zeros */
    }

    if (pk_size) *pk_size = pk;
    if (sk_size) *sk_size = sk;
    if (ct_size) *ct_size = ct;
    if (ss_size) *ss_size = ss;
}


//Lifecycle 

int kem_init(kem_context_t *ctx, uint8_t kem_type)
{
    if (!ctx) return -1;

    if (kem_type != KEM_TYPE_MLKEM_768 && kem_type != KEM_TYPE_MLKEM_1024)
        return -1;

    memset(ctx, 0, sizeof(kem_context_t));
    ctx->type = kem_type;
    return 0;
}

void kem_cleanup(kem_context_t *ctx)
{
    if (!ctx) return;
    crypto_secure_wipe(ctx, sizeof(kem_context_t));
}


// Core KEM operations 

int kem_keypair(kem_context_t *ctx,
                uint8_t *public_key,  uint32_t *pk_size,
                uint8_t *secret_key,  uint32_t *sk_size)
{
    if (!ctx || !public_key || !secret_key || !pk_size || !sk_size)
        return -1;

    uint32_t expected_pk, expected_sk;
    kem_get_sizes(ctx->type, &expected_pk, &expected_sk, NULL, NULL);

    if (*pk_size < expected_pk || *sk_size < expected_sk)
        return -1;

    int ret = -1;
    switch (ctx->type) {
        case KEM_TYPE_MLKEM_768:
            ret = OQS_KEM_ml_kem_768_keypair(public_key, secret_key);
            break;
        case KEM_TYPE_MLKEM_1024:
            ret = OQS_KEM_ml_kem_1024_keypair(public_key, secret_key);
            break;
        default:
            return -1;
    }

    if (ret != 0) {
        crypto_secure_wipe(secret_key, *sk_size);
        return -1;
    }

    *pk_size = expected_pk;
    *sk_size = expected_sk;
    return 0;
}

int kem_encapsulate(const uint8_t *public_key,  uint32_t pk_size,
                    uint8_t       *ciphertext,   uint32_t ct_size,
                    uint8_t       *shared_secret, uint32_t ss_size)
{
    if (!public_key || !ciphertext || !shared_secret) return -1;

    /* Determine algo type from the public-key size */
    uint8_t kem_type;
    if      (pk_size == KEM_MLKEM_768_PK_SIZE)  kem_type = KEM_TYPE_MLKEM_768;
    else if (pk_size == KEM_MLKEM_1024_PK_SIZE) kem_type = KEM_TYPE_MLKEM_1024;
    else return -1;

    uint32_t expected_ct, expected_ss;
    kem_get_sizes(kem_type, NULL, NULL, &expected_ct, &expected_ss);

    if (ct_size < expected_ct || ss_size < expected_ss) return -1;

    int ret = -1;
    switch (kem_type) {
        case KEM_TYPE_MLKEM_768:
            ret = OQS_KEM_ml_kem_768_encaps(ciphertext, shared_secret, public_key);
            break;
        case KEM_TYPE_MLKEM_1024:
            ret = OQS_KEM_ml_kem_1024_encaps(ciphertext, shared_secret, public_key);
            break;
    }

    if (ret != 0) {
        crypto_secure_wipe(shared_secret, ss_size);
        return -1;
    }
    return 0;
}

int kem_decapsulate(const uint8_t *secret_key,   uint32_t sk_size,
                    const uint8_t *ciphertext,    uint32_t ct_size,
                    uint8_t       *shared_secret, uint32_t ss_size)
{
    if (!secret_key || !ciphertext || !shared_secret) return -1;

    /* Determine algo type from the secret-key size */
    uint8_t kem_type;
    if      (sk_size == KEM_MLKEM_768_SK_SIZE)  kem_type = KEM_TYPE_MLKEM_768;
    else if (sk_size == KEM_MLKEM_1024_SK_SIZE) kem_type = KEM_TYPE_MLKEM_1024;
    else return -1;

    uint32_t expected_ct, expected_ss;
    kem_get_sizes(kem_type, NULL, NULL, &expected_ct, &expected_ss);

    if (ct_size < expected_ct || ss_size < expected_ss) return -1;

    int ret = -1;
    switch (kem_type) {
        case KEM_TYPE_MLKEM_768:
            ret = OQS_KEM_ml_kem_768_decaps(shared_secret, ciphertext, secret_key);
            break;
        case KEM_TYPE_MLKEM_1024:
            ret = OQS_KEM_ml_kem_1024_decaps(shared_secret, ciphertext, secret_key);
            break;
    }

    if (ret != 0) {
        crypto_secure_wipe(shared_secret, ss_size);
        return -1;
    }
    return 0;
}