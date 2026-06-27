#include "toml_config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CONFIG_LINE_MAX 256

static void trim(char* s)
{
    char* end;
    while (*s == ' ' || *s == '\t') s++;
    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
        end--;
    *(end + 1) = '\0';
}

static int parse_line(const char* line, const char* section,
                       config_t* cfg)
{
    char key[64], val[192];
    if (sscanf(line, "%63[^=] = %191[^#]", key, val) != 2)
        return 0;
    trim(key);
    trim(val);

    if (strcmp(section, "transport") == 0) {
        if (strcmp(key, "local_port") == 0) cfg->local_port = (uint16_t)atoi(val);
        else if (strcmp(key, "local_port_alt") == 0) cfg->local_port_alt = (uint16_t)atoi(val);
        else if (strcmp(key, "remote_port") == 0) cfg->remote_port = (uint16_t)atoi(val);
        else if (strcmp(key, "remote_addr") == 0)
            snprintf(cfg->remote_addr, sizeof(cfg->remote_addr), "%s", val);
    } else if (strcmp(section, "discovery") == 0) {
        if (strcmp(key, "port") == 0) cfg->discovery_port = (uint16_t)atoi(val);
        else if (strcmp(key, "enabled") == 0) cfg->discovery_enabled = atoi(val) != 0;
    } else if (strcmp(section, "multipath") == 0) {
        if (strcmp(key, "enabled") == 0) cfg->multipath_enabled = atoi(val) != 0;
        else if (strcmp(key, "path_count") == 0) cfg->path_count = atoi(val);
    } else if (strcmp(section, "identity") == 0) {
        if (strcmp(key, "key_hex") == 0)
            snprintf(cfg->identity_key_hex, sizeof(cfg->identity_key_hex), "%s", val);
    }
    return 0;
}

int config_load(config_t* cfg, const char* path)
{
    if (!cfg) return -1;
    config_load_default(cfg);

    FILE* f = fopen(path, "r");
    if (!f) return -1;

    char line[CONFIG_LINE_MAX];
    char section[64] = "";
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        if (line[0] == '[') {
            char* end = strchr(line + 1, ']');
            if (end) {
                *end = '\0';
                snprintf(section, sizeof(section), "%s", line + 1);
            }
            continue;
        }
        parse_line(line, section, cfg);
    }
    fclose(f);
    return 0;
}

int config_load_default(config_t* cfg)
{
    if (!cfg) return -1;
    memset(cfg, 0, sizeof(*cfg));
    cfg->local_port = 9001;
    cfg->local_port_alt = 9003;
    cfg->remote_port = 9002;
    snprintf(cfg->remote_addr, sizeof(cfg->remote_addr), "::1");
    cfg->discovery_port = 0;
    cfg->discovery_enabled = 0;
    cfg->multipath_enabled = 0;
    cfg->path_count = 1;
    cfg->identity_key_hex[0] = '\0';
    return 0;
}

void config_dump(const config_t* cfg)
{
    if (!cfg) return;
    printf("[config] local=%u alt=%u remote=%s:%u\n",
           cfg->local_port, cfg->local_port_alt,
           cfg->remote_addr, cfg->remote_port);
    printf("[config] discovery=%s port=%u\n",
           cfg->discovery_enabled ? "on" : "off", cfg->discovery_port);
    printf("[config] multipath=%s count=%d\n",
           cfg->multipath_enabled ? "on" : "off", cfg->path_count);
}
