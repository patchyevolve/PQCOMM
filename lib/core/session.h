#pragma once
#include <stdint.h>
#include <string.h>
#include "packet.h"
#include "resilience_ctx.h"

#define REPLAY_WINDOW_SIZE 64

#define KEM_TYPE_NONE       0
#define KEM_TYPE_MLKEM_768  1
#define KEM_TYPE_MLKEM_1024 2

#define KEM_MLKEM_768_PK_SIZE   1184
#define KEM_MLKEM_768_SK_SIZE   2400
#define KEM_MLKEM_768_CT_SIZE   1088
#define KEM_MLKEM_768_SS_SIZE   32

#define CTRL_HELLO              1
#define CTRL_ACCEPT             2
#define CTRL_PQ_KEM_INIT        3
#define CTRL_PQ_KEM_RESPONSE    4
#define CTRL_IDENTITY_PROOF     5
#define CTRL_SESSION_LOCKED     6
#define CTRL_HANDSHAKE_ERROR    7
#define CTRL_PORT_HOP           8
#define CTRL_PORT_HOP_ACK       9
#define CTRL_HEARTBEAT          10
#define CTRL_HEARTBEAT_ACK      11
#define CTRL_RECONNECT          12
#define CTRL_RECONNECT_ACK      13
#define CTRL_ROUTE_DATA         14
#define CTRL_REKEY_INIT         15
#define CTRL_REKEY_CONFIRM      16
#define CTRL_CONNECT_REQUEST    17
#define CTRL_CONNECT_ACCEPT     18
#define CTRL_CONNECT_DECLINE    19
#define CTRL_AUDIO_CALL         20
#define CTRL_AUDIO_CALL_ACK     21
#define CTRL_AUDIO_CALL_END     22
#define CTRL_VIDEO_CALL         23
#define CTRL_VIDEO_CALL_ACK     24
#define CTRL_VIDEO_CALL_END     25
#define CTRL_FILE_META          26
#define CTRL_FILE_CHUNK         27
#define CTRL_FILE_ACK           28
#define CTRL_TYPING             29
#define CTRL_DELIVERY_ACK       30
#define CTRL_READ_ACK           31

/* Group/multi-peer chat opcodes */
#define CTRL_GROUP_CREATE       32
#define CTRL_GROUP_JOIN         33
#define CTRL_GROUP_LEAVE        34
#define CTRL_GROUP_MSG          35
#define CTRL_GROUP_LIST         36

#define HS_ERR_NONE             0
#define HS_ERR_UNSUPPORTED_KEM  1
#define HS_ERR_BAD_IDENTITY     2
#define HS_ERR_TIMEOUT          3
#define HS_ERR_REPLAY           4
#define HS_ERR_STATE_VIOLATION  5

typedef enum {
    SESSION_IDLE = 0,
    SESSION_HANDSHAKE_START,
    SESSION_PQ_KEM_INIT_SENT,
    SESSION_PQ_KEM_RESPONSE_SENT,
    SESSION_IDENTITY_PROOF_SENT,
    SESSION_VERIFY,
    SESSION_LOCKED
} session_state_t;

typedef enum {
    ROLE_UNASSIGNED = 0,
    ROLE_INITIATOR,
    ROLE_RESPONDER
} handshake_role_t;

typedef struct {
    uint8_t kem_type;
    uint8_t kem_public_key[KEM_MLKEM_768_PK_SIZE];
    uint8_t kem_secret_key[KEM_MLKEM_768_SK_SIZE];
    uint8_t peer_public_key[KEM_MLKEM_768_PK_SIZE];
    uint8_t kem_ciphertext[KEM_MLKEM_768_CT_SIZE];
    uint8_t kem_shared_secret[KEM_MLKEM_768_SS_SIZE];
    uint8_t our_identity_key[32];
    uint8_t peer_identity_key[32];
    uint8_t identity_verified;
    uint8_t transcript_hash[32];
    uint32_t messages_exchanged;
    uint32_t handshake_start_ms;
    uint32_t last_message_ms;
    uint32_t timeout_ms;
    uint8_t last_error;
} handshake_crypto_t;

typedef struct {
    uint8_t session_key[32];
    uint8_t channel_keys[6][32];
    uint64_t key_epoch;
} session_keys_t;

typedef struct {
    uint64_t session_id;
    uint8_t addr[32];
    uint32_t addr_len;
    uint32_t last_seq;
    uint64_t recv_bitmap;
    session_state_t state;
    handshake_role_t role;
    handshake_crypto_t hs;
    session_keys_t keys;
    volatile long keys_guard;  /* spinlock for rekey vs crypto worker */
    resilience_t resilience;
    uint8_t handshake_complete;
    packet_buf_t* fec_recovered;
    uint8_t peer_addrs[RESILIENCE_MAX_PATHS][32];
    uint32_t peer_addr_lens[RESILIENCE_MAX_PATHS];
    uint16_t local_port;
    uint16_t hop_target_port;
    uint64_t hop_start_ms;
    uint32_t reconnect_attempts;
    uint64_t last_heartbeat_rx_ms;
    uint8_t reconnect_pending;
    uint64_t reconnect_start_ms;
    uint64_t ignore_heartbeats_until_ms;
} session_t;

typedef struct {
    volatile uint32_t attempts_total;
    volatile uint32_t successes;
    volatile uint32_t failures_timeout;
    volatile uint32_t failures_identity;
    volatile uint32_t failures_replay;
    volatile uint32_t failures_state;
} handshake_stats_t;

extern handshake_stats_t g_handshake_stats;

void session_init(session_t* s);
void session_reset(session_t* s);
void session_zero_secrets(session_t* s);
int session_is_ready_for_data(session_t* s);

typedef enum {
    SESSION_DIR_OUTBOUND = 0,
    SESSION_DIR_INBOUND = 1
} session_dir_t;

typedef struct {
    session_t* sess;
    session_dir_t dir;
    uint8_t in_use;
} session_entry_t;

void session_table_init(void);
session_t* session_alloc_for_peer(void* addr, int addr_len, session_dir_t dir);
session_t* session_find_by_id(uint64_t session_id);
session_t* session_find_by_addr(void* addr, int addr_len);
int session_register(session_t* sess, void* addr, int addr_len, session_dir_t dir);
int session_register_path(session_t* sess, uint32_t path_idx, void* addr, int addr_len);

/* keys_guard spinlock: protects keys during rekey vs crypto worker access */
static inline void session_lock_keys(session_t* s) {
    if (!s) return;
    while (__sync_lock_test_and_set(&s->keys_guard, 1))
        __sync_synchronize();
}
static inline void session_unlock_keys(session_t* s) {
    if (!s) return;
    __sync_lock_release(&s->keys_guard);
}