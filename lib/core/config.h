#pragma once

#define MAX_PACKET_SIZE     1500
#define PACKET_POOL_SIZE    4096
#define RING_SIZE           1024

#define PHASE1_SELFTEST     0
#define PHASE2_SECURITY_ENABLED     1
#define PHASE2_KEM_ALGORITHM        1
#define PHASE2_HANDSHAKE_TIMEOUT_MS 30000

#define SESSION_KEY_SIZE        32
#define CHANNEL_KEY_SIZE        32
#define TRANSCRIPT_HASH_SIZE    32

#define AEAD_NONCE_SIZE         12
#define AEAD_TAG_SIZE           16
#define HEADER_SIZE             24

#define PACKET_FLAG_ENCRYPTED   0x01
#define PACKET_FLAG_FEC_PARITY  0x02

// limits for phase 4-5
#define OFFENSIVE_MAX_SOURCES   256
#define OFFENSIVE_WINDOW_MS     1000
#define OFFENSIVE_THRESHOLD     100

#define RESILIENCE_MAX_PATHS    4
#define RESILIENCE_FEC_GROUP    4