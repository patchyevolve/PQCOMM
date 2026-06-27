#include "identity.h"
#include "kem.h"
#include "secure_store.h"
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

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
    chmod(path, 0600);
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

    struct stat st;
    if (stat(config_dir, &st) != 0)
        mkdir(config_dir, 0700);

    return load_identity(id, config_dir);
}

int identity_create(identity_t* id, const char* config_dir,
                    const char* username, const char* display_name)
{
    if (!id || !config_dir || !username || !display_name) return -1;
    memset(id, 0, sizeof(*id));

    snprintf(id->username, sizeof(id->username), "%s", username);
    snprintf(id->display_name, sizeof(id->display_name), "%s", display_name);

    kem_random_bytes(id->identity_key, 32);

    secure_store_init();
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
