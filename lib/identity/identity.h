#pragma once
#include <stdint.h>

#define IDENTITY_USERNAME_MAX  32
#define IDENTITY_DISPLAY_MAX   64
#define IDENTITY_KEY_HEX_MAX  65

typedef struct {
    char username[IDENTITY_USERNAME_MAX];
    char display_name[IDENTITY_DISPLAY_MAX];
    uint8_t identity_key[32];
    int initialized;
} identity_t;

int identity_init(identity_t* id, const char* config_dir);
int identity_create(identity_t* id, const char* config_dir,
                    const char* username, const char* display_name);
int identity_load(identity_t* id, const char* config_dir);
const uint8_t* identity_get_key(identity_t* id);
int identity_get_key_hex(identity_t* id, char* buf, uint32_t buf_size);
int identity_get_fingerprint(identity_t* id, char* buf, uint32_t buf_size);
int identity_import_key(identity_t* id, const char* config_dir, const char* hex_key);
void identity_print_fingerprint(identity_t* id);
