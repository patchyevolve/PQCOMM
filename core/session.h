#pragma once

#include <stdint.h>
#include <string.h>
#include "packet.h"

#define REPLAY_WINDOW_SIZE 64

// KEM types
#define KEM_TYPE_NONE       0
#define KEM_TYPE_MLKEM_768  1
#define KEM_TYPE_MLKEM_1024 2

// KEM sizes
#define KEM_MLKEM_768_PK_SIZE   1184
#define KEM_MLKEM_768_SK_SIZE   2400
#define KEM_MLKEM_768_CT_SIZE   1088
#define KEM_MLKEM_768_SS_SIZE   32

// Control opcodes
#define CTRL_HELLO              1
#define CTRL_ACCEPT             2
#define CTRL_PQ_KEM_INIT        3
#define CTRL_PQ_KEM_RESPONSE    4
#define CTRL_IDENTITY_PROOF     5
#define CTRL_SESSION_LOCKED     6
#define CTRL_HANDSHAKE_ERROR    7

// Error codes
#define HS_ERR_NONE             0
#define HS_ERR_UNSUPPORTED_KEM  1
#define HS_ERR_BAD_IDENTITY     2
#define HS_ERR_TIMEOUT          3
#define HS_ERR_REPLAY           4
#define HS_ERR_STATE_VIOLATION  5

// Session states
typedef enum 
{
    SESSION_IDLE = 0,
    SESSION_HANDSHAKE_START,
    SESSION_PQ_KEM_INIT_SENT,
    SESSION_PQ_KEM_RESPONSE_SENT,
    SESSION_IDENTITY_PROOF_SENT,
    SESSION_VERIFY,
    SESSION_LOCKED
} session_state_t;

// Role in handshake
typedef enum
{
    ROLE_UNASSIGNED = 0,
    ROLE_INITIATOR,
    ROLE_RESPONDER
} handshake_role_t;

// Handshake crypto context
typedef struct
{
    uint8_t kem_type;
    uint8_t kem_public_key[KEM_MLKEM_768_PK_SIZE];
    uint8_t kem_secret_key[KEM_MLKEM_768_SK_SIZE];
    uint8_t peer_public_key[KEM_MLKEM_768_PK_SIZE];
    uint8_t kem_ciphertext[KEM_MLKEM_768_CT_SIZE];
    uint8_t kem_shared_secret[KEM_MLKEM_768_SS_SIZE];
    
    uint8_t our_identity_hash[32];
    uint8_t peer_identity_hash[32];
    uint8_t identity_verified;
    
    uint8_t transcript_hash[32];
    uint32_t messages_exchanged;
    
    uint32_t handshake_start_ms;
    uint32_t last_message_ms;
    uint32_t timeout_ms;
    uint8_t last_error;
} handshake_crypto_t;

// Derived session keys
typedef struct
{
    uint8_t session_key[32];
    uint8_t channel_keys[5][32];
    uint64_t key_epoch;
} session_keys_t;

// Main session structure
typedef struct
{
    uint64_t session_id;
    uint8_t addr[32];
    uint32_t addr_len;
    uint32_t last_seq;
    uint64_t recv_bitmap;
    session_state_t state;
    handshake_role_t role;
    
    // Phase 2 additions
    handshake_crypto_t hs;
    session_keys_t keys;
    uint8_t handshake_complete;
    
} session_t;

// Handshake stats
typedef struct
{
    uint32_t attempts_total;
    uint32_t successes;
    uint32_t failures_timeout;
    uint32_t failures_identity;
    uint32_t failures_replay;
    uint32_t failures_state;
} handshake_stats_t;

extern handshake_stats_t g_handshake_stats;

// Function prototypes
void session_init(session_t* s);
void session_reset(session_t* s);
void session_zero_secrets(session_t* s);
int session_is_ready_for_data(session_t* s);
const char* session_state_name(session_state_t state);

// Session direction for bidirectional routing
typedef enum {
    SESSION_DIR_OUTBOUND = 0,  // We initiated this session
    SESSION_DIR_INBOUND = 1     // Peer initiated this session
} session_dir_t;

// Extended session entry
typedef struct {
    session_t* sess;
    session_dir_t dir;
    uint8_t in_use;
} session_entry_t;

// Session table management
void session_table_init(void);
session_t* session_alloc_for_peer(void* addr, int addr_len, session_dir_t dir);
session_t* session_find_by_id(uint64_t session_id);
session_t* session_find_by_addr(void* addr, int addr_len);
int session_register(session_t* sess, void* addr, int addr_len, session_dir_t dir);