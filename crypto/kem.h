#pragma once
#include <stdint.h>
#include <stddef.h>

#define KEM_TYPE_NONE       0
#define KEM_TYPE_MLKEM_768  1
#define KEM_TYPE_MLKEM_1024 2

#define KEM_MLKEM_768_PK_SIZE   1184
#define KEM_MLKEM_768_SK_SIZE   2400
#define KEM_MLKEM_768_CT_SIZE   1088
#define KEM_MLKEM_768_SS_SIZE   32

#define KEM_MLKEM_1024_PK_SIZE  1568
#define KEM_MLKEM_1024_SK_SIZE  3168
#define KEM_MLKEM_1024_CT_SIZE  1568
#define KEM_MLKEM_1024_SS_SIZE  32

typedef struct {
    uint8_t type;
} kem_context_t;

int kem_init(kem_context_t *ctx, uint8_t type);
int kem_keypair(kem_context_t *ctx,
                uint8_t* public_key, uint32_t* pk_size,
                uint8_t* secret_key, uint32_t* sk_size);
int kem_encapsulate(const uint8_t* public_key, uint32_t pk_size,
                    uint8_t *ciphertext, uint32_t ct_size,
                    uint8_t *shared_secret, uint32_t ss_size);
int kem_decapsulate(const uint8_t* secret_key, uint32_t sk_size,
                    const uint8_t *ciphertext, uint32_t ct_size,
                    uint8_t *shared_secret, uint32_t ss_size);
void kem_get_sizes(uint8_t kem_type, uint32_t* pk_size, uint32_t* sk_size,
                   uint32_t* ct_size, uint32_t* ss_size);
void kem_cleanup(kem_context_t *ctx);
void kem_random_bytes(uint8_t *buf, uint32_t len);
int crypto_secure_memcmp(const void *a, const void *b, size_t len);
void crypto_secure_wipe(void *ptr, size_t len);

