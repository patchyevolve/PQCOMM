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
int identity_export_key(identity_t* id, const char* export_path);
int identity_backup(identity_t* id, const char* backup_path, const char* passphrase);
int identity_restore(identity_t* id, const char* backup_path, const char* passphrase);
void identity_print_fingerprint(identity_t* id);

/* known_hosts API — TOFU peer key storage */
int known_hosts_add(const char* config_dir, const char* addr, uint16_t port,
                    const char* username, const uint8_t* peer_key);
int known_hosts_check(const char* config_dir, const char* addr, uint16_t port,
                      const uint8_t* peer_key);
void known_hosts_print(const char* config_dir);
