#pragma once
#include <stdint.h>

#define IDENTITY_KEY_SIZE 32

int secure_store_init(void);
int secure_store_set_key(const uint8_t* key, uint32_t key_len);
const uint8_t* secure_store_get_identity_key(void);
void secure_store_shutdown(void);
