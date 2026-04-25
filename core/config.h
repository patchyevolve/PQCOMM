#pragma once

#define MAX_PACKET_SIZE     1500
#define PACKET_POOL_SIZE    4096
#define RING_SIZE           1024

//phase toggles
#define PHASE1_SELFTEST     0

// Phase 2 Configuration
#define PHASE2_SECURITY_ENABLED     1   // Set to 1 when ready
#define PHASE2_KEM_ALGORITHM        KEM_TYPE_MLKEM_768
#define PHASE2_HANDSHAKE_TIMEOUT_MS 30000
#define PHASE2_MAX_HANDSHAKE_ATTEMPTS 3

// Security constants
#define SESSION_KEY_SIZE        32
#define CHANNEL_KEY_SIZE        32
#define IDENTITY_KEY_SIZE       32
#define TRANSCRIPT_HASH_SIZE    32

// Handshake payload sizes
#define HS_PAYLOAD_HELLO_SIZE           32
#define HS_PAYLOAD_KEM_INIT_SIZE        (KEM_MLKEM_768_PK_SIZE + 16)
#define HS_PAYLOAD_KEM_RESPONSE_SIZE    (KEM_MLKEM_768_CT_SIZE + 16)
#define HS_PAYLOAD_IDENTITY_SIZE        96