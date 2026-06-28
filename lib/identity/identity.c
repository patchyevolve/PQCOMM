#include "identity.h"
#include "kem.h"
#include "secure_store.h"
#include "platform.h"
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define IDENTITY_FILE "identity.dat"

static void bytes_to_hex(const uint8_t* bytes, uint32_t len, char* hex)
{
    for (uint32_t i = 0; i < len; i++)
        sprintf(hex + i * 2, "%02x", bytes[i]);
    hex[len * 2] = '\0';
}

static int hex_to_bytes(const char* hex, uint8_t* bytes, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        char byte_str[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        char* end = NULL;
        long val = strtol(byte_str, &end, 16);
        if (*end != '\0') return -1;
        bytes[i] = (uint8_t)val;
    }
    return 0;
}

static int save_identity(identity_t* id, const char* config_dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", config_dir, IDENTITY_FILE);

    FILE* f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f, "username=%s\n", id->username);
    fprintf(f, "display_name=%s\n", id->display_name);

    char hex[65];
    bytes_to_hex(id->identity_key, 32, hex);
    fprintf(f, "identity_key=%s\n", hex);

    fclose(f);
    platform_chmod(path, 0600);
    return 0;
}

static int load_identity(identity_t* id, const char* config_dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", config_dir, IDENTITY_FILE);

    FILE* f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char key[64], val[192];
        if (sscanf(line, "%63[^=]=%191s", key, val) != 2) continue;

        char* nl = strchr(val, '\n');
        if (nl) *nl = '\0';

        if (strcmp(key, "username") == 0)
            snprintf(id->username, sizeof(id->username), "%s", val);
        else if (strcmp(key, "display_name") == 0)
            snprintf(id->display_name, sizeof(id->display_name), "%s", val);
        else if (strcmp(key, "identity_key") == 0 && strlen(val) == 64)
            hex_to_bytes(val, id->identity_key, 32);
    }
    fclose(f);

    id->initialized = (id->username[0] != '\0');
    return id->initialized ? 0 : -1;
}

int identity_init(identity_t* id, const char* config_dir)
{
    if (!id || !config_dir) return -1;
    memset(id, 0, sizeof(*id));

    if (platform_stat_exists(config_dir) == 0)
        platform_mkdir(config_dir);

    int ret = load_identity(id, config_dir);
    if (ret == 0)
        secure_store_set_key(id->identity_key, 32);
    return ret;
}

int identity_create(identity_t* id, const char* config_dir,
                    const char* username, const char* display_name)
{
    if (!id || !config_dir || !username || !display_name) return -1;
    memset(id, 0, sizeof(*id));

    snprintf(id->username, sizeof(id->username), "%s", username);
    snprintf(id->display_name, sizeof(id->display_name), "%s", display_name);

    /* use IDENTITY_KEY env var if set (for cross-device key import) */
    const char* env_key = getenv("IDENTITY_KEY");
    if (env_key && strlen(env_key) == 64 &&
        hex_to_bytes(env_key, id->identity_key, 32) == 0)
    {
        /* imported key from env var */
    } else {
        kem_random_bytes(id->identity_key, 32);
    }

    secure_store_set_key(id->identity_key, 32);
    if (save_identity(id, config_dir) != 0) return -1;
    id->initialized = 1;
    return 0;
}

int identity_load(identity_t* id, const char* config_dir)
{
    return identity_init(id, config_dir);
}

const uint8_t* identity_get_key(identity_t* id)
{
    if (!id || !id->initialized) return NULL;
    return id->identity_key;
}

int identity_get_key_hex(identity_t* id, char* buf, uint32_t buf_size)
{
    if (!id || !id->initialized || !buf || buf_size < 65) return -1;
    bytes_to_hex(id->identity_key, 32, buf);
    return 0;
}

int identity_get_fingerprint(identity_t* id, char* buf, uint32_t buf_size)
{
    if (!id || !id->initialized || !buf || buf_size < 128) return -1;
    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, id->identity_key, 32);
    mbedtls_sha256_update(&ctx, (uint8_t*)id->username, strlen(id->username));
    mbedtls_sha256_finish(&ctx, hash);

    char hex[65];
    bytes_to_hex(hash, 32, hex);
    int pos = 0;
    for (int i = 0; i < 32; i++) {
        if (buf_size - (uint32_t)pos < 4) break;
        pos += snprintf(buf + pos, (uint32_t)(buf_size - (uint32_t)pos),
                        "%02x%s", hash[i], i < 31 ? ":" : "");
    }
    return 0;
}

int identity_import_key(identity_t* id, const char* config_dir, const char* hex_key)
{
    if (!id || !config_dir || !hex_key) return -1;
    if (strlen(hex_key) != 64) return -1;
    uint8_t key[32];
    if (hex_to_bytes(hex_key, key, 32) != 0) return -1;
    memcpy(id->identity_key, key, 32);
    secure_store_set_key(key, 32);
    return save_identity(id, config_dir);
}

void identity_print_fingerprint(identity_t* id)
{
    if (!id || !id->initialized) return;
    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, id->identity_key, 32);
    mbedtls_sha256_update(&ctx, (uint8_t*)id->username, strlen(id->username));
    mbedtls_sha256_finish(&ctx, hash);

    char hex[65];
    bytes_to_hex(hash, 32, hex);
    printf("Fingerprint: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
        if (i < 31) printf(":");
    }
    printf("\n");
}

int identity_export_key(identity_t* id, const char* export_path)
{
    if (!id || !id->initialized || !export_path) return -1;
    FILE* f = fopen(export_path, "w");
    if (!f) return -1;
    char hex[65];
    bytes_to_hex(id->identity_key, 32, hex);
    fprintf(f, "# PQCOMM identity key export\n");
    fprintf(f, "# username: %s\n", id->username);
    fprintf(f, "# display_name: %s\n", id->display_name);
    fprintf(f, "identity_key=%s\n", hex);
    fclose(f);
    platform_chmod(export_path, 0600);
    return 0;
}

int identity_backup(identity_t* id, const char* backup_path, const char* passphrase)
{
    (void)passphrase;
    if (!id || !id->initialized || !backup_path) return -1;
    /* Save encrypted backup: just copy identity.dat for now, wrapped with metadata */
    FILE* f = fopen(backup_path, "w");
    if (!f) return -1;
    char hex[65];
    bytes_to_hex(id->identity_key, 32, hex);
    fprintf(f, "# PQCOMM identity backup\n");
    fprintf(f, "# created: %ld\n", (long)time(NULL));
    fprintf(f, "username=%s\n", id->username);
    fprintf(f, "display_name=%s\n", id->display_name);
    fprintf(f, "identity_key=%s\n", hex);
    fclose(f);
    platform_chmod(backup_path, 0600);
    return 0;
}

int identity_restore(identity_t* id, const char* backup_path, const char* passphrase)
{
    (void)passphrase;
    if (!id || !backup_path) return -1;
    FILE* f = fopen(backup_path, "r");
    if (!f) return -1;
    memset(id, 0, sizeof(*id));
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue;
        char key[64], val[192];
        if (sscanf(line, "%63[^=]=%191s", key, val) != 2) continue;
        if (strcmp(key, "username") == 0)
            snprintf(id->username, sizeof(id->username), "%s", val);
        else if (strcmp(key, "display_name") == 0)
            snprintf(id->display_name, sizeof(id->display_name), "%s", val);
        else if (strcmp(key, "identity_key") == 0 && strlen(val) == 64)
            hex_to_bytes(val, id->identity_key, 32);
    }
    fclose(f);
    id->initialized = (id->username[0] != '\0' && id->identity_key[0] != 0);
    return id->initialized ? 0 : -1;
}

/* ================================================================
 * known_hosts — TOFU peer key storage (similar to SSH known_hosts)
 * ================================================================ */

#define KNOWN_HOSTS_FILE "known_hosts"

int known_hosts_add(const char* config_dir, const char* addr, uint16_t port,
                    const char* username, const uint8_t* peer_key)
{
    if (!config_dir || !addr || !peer_key) return -1;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", config_dir, KNOWN_HOSTS_FILE);
    FILE* f = fopen(path, "a");
    if (!f) return -1;
    char hex[65];
    bytes_to_hex(peer_key, 32, hex);
    fprintf(f, "%s:%d %s %s\n", addr, port, username ? username : "unknown", hex);
    fclose(f);
    return 0;
}

int known_hosts_check(const char* config_dir, const char* addr, uint16_t port,
                      const uint8_t* peer_key)
{
    if (!config_dir || !addr || !peer_key) return -1;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", config_dir, KNOWN_HOSTS_FILE);
    FILE* f = fopen(path, "r");
    if (!f) return -1; /* no known_hosts file yet, first contact */
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue;
        char entry_addr[64], entry_user[32], entry_hex[65];
        int entry_port;
        if (sscanf(line, "%63[^:]:%d %31s %64s", entry_addr, &entry_port,
                   entry_user, entry_hex) != 4) continue;
        if (strcmp(entry_addr, addr) == 0 && entry_port == port) {
            uint8_t entry_key[32];
            if (hex_to_bytes(entry_hex, entry_key, 32) == 0) {
                int match = (memcmp(entry_key, peer_key, 32) == 0) ? 1 : -2;
                fclose(f);
                return match; /* 1 = match, -2 = mismatch (MITM warning) */
            }
        }
    }
    fclose(f);
    return 0; /* not found, first contact */
}

void known_hosts_print(const char* config_dir)
{
    if (!config_dir) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", config_dir, KNOWN_HOSTS_FILE);
    FILE* f = fopen(path, "r");
    if (!f) { printf("(no known_hosts entries)\n"); return; }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] != '#') printf("%s", line);
    }
    fclose(f);
}
