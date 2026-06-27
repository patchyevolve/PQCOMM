#include "session.h"
#include "kem.h"
#include "resilience_ctx.h"
#include <string.h>
#include <stdlib.h>

#define MAX_SESSION_ENTRIES 32

static session_t g_session_pool[MAX_SESSION_ENTRIES];
static session_entry_t g_session_table[MAX_SESSION_ENTRIES];
static int g_session_count = 0;

void session_table_init(void)
{
    memset(g_session_table, 0, sizeof(g_session_table));
    g_session_count = 0;
}

session_t* session_find_by_id(uint64_t session_id)
{
    for (int i = 0; i < MAX_SESSION_ENTRIES; i++) {
        if (g_session_table[i].in_use &&
            g_session_table[i].sess->session_id == session_id)
            return g_session_table[i].sess;
    }
    return NULL;
}

session_t* session_find_by_addr(void* addr, int addr_len)
{
    for (int i = 0; i < MAX_SESSION_ENTRIES; i++) {
        if (g_session_table[i].in_use &&
            g_session_table[i].sess->addr_len == addr_len &&
            memcmp(g_session_table[i].sess->addr, addr, addr_len) == 0)
            return g_session_table[i].sess;
    }
    return NULL;
}

session_t* session_alloc_for_peer(void* addr, int addr_len, session_dir_t dir)
{
    if (g_session_count >= MAX_SESSION_ENTRIES) return NULL;

    int idx = g_session_count++;
    session_entry_t* entry = &g_session_table[idx];
    entry->sess = &g_session_pool[idx];

    if (!entry->sess) {
        g_session_count--;
        return NULL;
    }

    session_init(entry->sess);
    entry->dir = dir;
    entry->in_use = 1;

    memcpy(entry->sess->addr, addr, addr_len);
    entry->sess->addr_len = addr_len;

    return entry->sess;
}

void session_init(session_t* s)
{
    if (!s) return;
    memset(s, 0, sizeof(session_t));
    s->state = SESSION_IDLE;
    s->role = ROLE_UNASSIGNED;
    resilience_init(&s->resilience);
}

void session_reset(session_t* s)
{
    if (!s) return;

    uint64_t current_id = s->session_id;
    uint8_t current_addr[sizeof(s->addr)];
    uint32_t current_addr_len = s->addr_len;
    memcpy(current_addr, s->addr, sizeof(s->addr));

    uint8_t current_peer_addrs[RESILIENCE_MAX_PATHS][32];
    uint32_t current_peer_lens[RESILIENCE_MAX_PATHS];
    memcpy(current_peer_addrs, s->peer_addrs, sizeof(s->peer_addrs));
    memcpy(current_peer_lens, s->peer_addr_lens, sizeof(s->peer_addr_lens));

    uint16_t current_port = s->local_port;

    session_zero_secrets(s);
    memset(s, 0, sizeof(session_t));

    s->local_port = current_port;
    s->session_id = current_id;
    s->addr_len = current_addr_len;
    memcpy(s->addr, current_addr, sizeof(s->addr));
    memcpy(s->peer_addrs, current_peer_addrs, sizeof(s->peer_addrs));
    memcpy(s->peer_addr_lens, current_peer_lens, sizeof(s->peer_addr_lens));

    s->state = SESSION_IDLE;
    s->role = ROLE_UNASSIGNED;
    resilience_init(&s->resilience);
}

void session_zero_secrets(session_t* s)
{
    if (!s) return;
    crypto_secure_wipe(s->hs.kem_secret_key, sizeof(s->hs.kem_secret_key));
    crypto_secure_wipe(s->hs.kem_shared_secret, sizeof(s->hs.kem_shared_secret));
    crypto_secure_wipe(&s->keys, sizeof(session_keys_t));
}

int session_register_path(session_t* sess, uint32_t path_idx, void* addr, int addr_len)
{
    if (!sess || path_idx >= RESILIENCE_MAX_PATHS || !addr) return -1;
    if ((size_t)addr_len > sizeof(sess->peer_addrs[path_idx])) return -1;
    memcpy(sess->peer_addrs[path_idx], addr, addr_len);
    sess->peer_addr_lens[path_idx] = addr_len;
    return 0;
}

int session_is_ready_for_data(session_t* s)
{
    return (s && s->state == SESSION_LOCKED && s->handshake_complete);
}
