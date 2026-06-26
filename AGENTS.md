# AGENTS.md — SSM Secure Communication Transport

## Must Read Before Making Changes

- `SSM_Secure_Communication_Spec_v1.0.md` — Locked architecture spec (NO structural changes)
- `PHASE1_WIRE_CONTRACT.md` — Wire format, header layout, AEAD nonce/tag, rules
- `IMPLEMENTATION_PHASE_STATUS.md` — Current status, what's done, what's next
- `core/session.h` — Handshake opcodes, session state machine, key structs

## Phase 3 Status (current) ✅ COMPLETE

### What's Implemented
- ChaCha20-Poly1305 session AEAD encrypt/decrypt via mbedtls
- CSPRNG session IDs via `kem_random_bytes()` (getrandom syscall)
- HMAC-SHA256 identity signature verification
- Channel binding via channel key XOR-folded into AEAD AAD
- Deterministic nonce from session_id, channel_id, seq
- No malloc (RULE-8) and no logging (RULE-9) in encrypt/decrypt path
- Demo verified: `attempts=1 ok=1 fail=0 enc=on`, chat messages delivered

### Key Decisions
- Ed25519 via PSA unavailable in mbedtls 3.6.6. Using HMAC-SHA256 identity instead.
- Single-layer AEAD (session-level). Channel enc is HMAC key binding in AAD, not double-encryption.
- Nonce = session_id[0..7] + channel_id[8] + zeros[9] + seq[10..11] — deterministic, no per-packet RNG.
- AAD = 24-byte header with encryption flag cleared, XOR-folded with channel key.
- RESPONDER generates session_id in `handshake_build_accept`, initiator adopts it via ACCEPT payload.

### Files Touched
- `crypto/aead.c` / `crypto/aead.h` — ChaCha20-Poly1305 wrapper
- `layers/session_enc.c` / `layers/session_enc.h` — Session-level AEAD
- `layers/channel_enc.c` / `layers/channel_enc.h` — No-op stub
- `layers/packet_parse.c` — Strips AEAD nonce+tag when `PACKET_FLAG_ENCRYPTED` set
- `layers/static_shell.c` — Accepts `PACKET_FLAG_ENCRYPTED` (0x01)
- `core/packet_view.h` — nonce[12], tag[16], encrypted fields
- `handshake/handshake.c` — CSPRNG session_id, HMAC identity signature, Ed25519 key init
- `main.c` — Control handlers, non-control early drop, chat packet send
- `crypto/hkdf.c` / `crypto/hkdf.h` — HKDF key derivation, channel keys

## After Compilation — Checklist

Every time you compile and before committing, verify:

1. **Build passes** — `cmake --build build_linux/` succeeds with no warnings
2. **Demo runs** — `timeout 5 ./build_linux/transport` completes with:
   - `identity verified OK`
   - Both sides `LOCKED`
   - Chat messages delivered both ways
   - `ok=1` in stats
3. **No regressions** — Check that `fail=0`, `enc=on`
4. **Docs match** — Update `IMPLEMENTATION_PHASE_STATUS.md` and `PHASE1_WIRE_CONTRACT.md` if wire format or status changed

## Architecture Rules (never violate)

| ID | Rule |
|----|------|
| RULE-1 | Session gate before decrypt |
| RULE-2 | Outer layers must not decrypt |
| RULE-3 | PQ only during handshake |
| RULE-4 | Trusted packets bypass offense |
| RULE-5 | Scheduler before encrypt |
| RULE-8 | No malloc in fast path |
| RULE-9 | No logging in fast path |
| RULE-11 | Packet parsed only once |
| RULE-16 | Replay window always active |

## Key Crypto Parameters

- KEM: ML-KEM 768 (liboqs)
- Session AEAD: ChaCha20-Poly1305 (mbedtls)
- Identity: HMAC-SHA256 with 32-byte master key
- Key derivation: HKDF (SHA-256), extract then expand
- Session key: 32 bytes
- Channel keys: 5 × 32 bytes (CONTROL, AUDIO, CHAT, FILE, ROUTE)
- Nonce: 12 bytes
- AEAD tag: 16 bytes
- Transcript hash: SHA-256 (32 bytes)

## Handshake Opcodes

| Code | Name | Direction |
|------|------|-----------|
| 1 | CTRL_HELLO | I → R |
| 2 | CTRL_ACCEPT | R → I |
| 3 | CTRL_PQ_KEM_INIT | I → R (pubkey) |
| 4 | CTRL_PQ_KEM_RESPONSE | R → I (ciphertext) |
| 5 | CTRL_IDENTITY_PROOF | I → R (sig + hash) |
| 6 | CTRL_SESSION_LOCKED | R → I |
| 7 | CTRL_HANDSHAKE_ERROR | either → either |

## Session States

IDLE → HANDSHAKE_START → PQ_KEM_INIT_SENT → PQ_KEM_RESPONSE_SENT → IDENTITY_PROOF_SENT → LOCKED

## Channels

| ID | Name | Encrypted |
|----|------|-----------|
| 1 | CONTROL | No (pass-through) |
| 2 | AUDIO | Yes |
| 3 | CHAT | Yes |
| 4 | FILE | Yes |
| 5 | ROUTE | Yes |
