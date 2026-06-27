# Phase 1 Wire Contract (Transport)

Status: FROZEN (all phases)
Scope: Packet format and validation behavior used by current transport pipeline.
Security mode: AEAD session encryption (ChaCha20-Poly1305), HMAC identity verification, CSPRNG session IDs
Last updated: Phase 6 Group E — final freeze

## Header Layout (24 bytes)

Offsets (bytes):
- 0..3   : magic      (uint32)
- 4      : version    (uint8)
- 5      : flags      (uint8)
- 6..13  : session_id (uint64)
- 14     : channel_id (uint8)
- 15..18 : seq        (uint32)
- 19..22 : length     (uint32)
- 23     : reserved/padding (currently unused)

Payload starts at offset 24.

## Encrypted Packet Layout

When `PACKET_FLAG_ENCRYPTED` (0x01) is set in `flags`:

- Offset 24..35 : nonce      (12 bytes)
- Offset 36..   : ciphertext (length - AEAD_NONCE_SIZE - AEAD_TAG_SIZE)
- End - 16..    : tag        (16 bytes, ChaCha20-Poly1305)

The `length` field covers the encrypted payload: nonce + ciphertext + tag.
The `tag` follows immediately after the ciphertext at offset `24 + length - AEAD_TAG_SIZE`.

## Parse Invariants

- Packet size must be >= 24.
- Declared `length` must satisfy:
  - `length <= MAX_PACKET_SIZE - 24`
  - `buf->len == 24 + length`
- If `PACKET_FLAG_ENCRYPTED` set, `length >= AEAD_NONCE_SIZE + AEAD_TAG_SIZE` (28 bytes).
- Parser strips nonce and tag from payload pointers when encrypted flag is set.
- Parser performs a single header extraction pass (RULE-11).

## Static Shell Invariants

- `magic == 0xAABBCCDD`
- `version == 1`
- `flags == 0` or `flags == 0x01` (PACKET_FLAG_ENCRYPTED)
- `length > 0`
- `length <= 1400`
- `channel_id` in [1..5]
- `seq != 0`

## Session Gate Invariants

- Pre-lock: only CONTROL channel allowed.
- Locked: packet must match:
  - `session_id`
  - peer address family
  - peer port
  - peer IPv6 bytes
- CONTROL channel passes unconditionally (no session_enc applied).

## Replay/Sequence Invariants

- Replay check active in locked state.
- First accepted seq initializes replay window.
- Duplicate seq in window is dropped.
- Too-old seq outside window is dropped.

## Channel IDs

- 1: CONTROL
- 2: AUDIO
- 3: CHAT
- 4: FILE
- 5: ROUTE

## Scheduler Priority (TX)

- control > audio > chat > file > fake

## AEAD Session Encryption

- Algorithm: ChaCha20-Poly1305 (via mbedtls `mbedtls_cipher_auth_encrypt_ext`/`decrypt_ext`)
- Session key: 32 bytes, derived via HKDF from KEM shared secret + transcript hash
- Nonce: 12 bytes, deterministic:
  - bytes 0..7: session_id (little-endian)
  - byte 8: channel_id
  - byte 9: zero
  - bytes 10..11: sequence number (big-endian)
- Tag: 16 bytes, appended after ciphertext
- AAD: 24-byte header with `PACKET_FLAG_ENCRYPTED` flag cleared, XOR-folded with per-channel key for channel binding
- No malloc in encrypt/decrypt path (RULE-8)
- No logging in encrypt/decrypt path (RULE-9)

## Identity Verification

- Algorithm: HMAC-SHA256 with pre-shared 32-byte identity master key
- Identity hash: SHA-256 of identity master key (32 bytes)
- Identity signature: HMAC-SHA256(identity_master_key, transcript_hash) (32 bytes, zero-padded to 64)
- Failed verification increments `failures_identity` and returns `HS_ERR_BAD_IDENTITY`

## CSPRNG Usage

- Session IDs generated via `kem_random_bytes()` which calls `getrandom()` (Linux) or `CryptGenRandom` (Windows)
- No `rand()` calls remain in handshake path

## Observability

- No per-packet hot-path logs.
- Periodic stats line is allowed.
- Selftest code is compile-time gated (`PHASE1_SELFTEST`).

## Control Opcodes (Phase 4 additions)

The following CONTROL-channel opcodes are used post-handshake:

| Code | Constant | Direction | Payload |
|---|---|---|---|
| 1 | `CTRL_HELLO` | Initiator→Responder | opcode(1) |
| 2 | `CTRL_ACCEPT` | Responder→Initiator | opcode(1) + session_id(8) |
| 3 | `CTRL_PQ_KEM_INIT` | Initiator→Responder | opcode(1) + public_key(1184) |
| 4 | `CTRL_PQ_KEM_RESPONSE` | Responder→Initiator | opcode(1) + ciphertext(1088) |
| 5 | `CTRL_IDENTITY_PROOF` | Initiator→Responder | opcode(1) + signature(64) + identity_hash(32) |
| 6 | `CTRL_SESSION_LOCKED` | Responder→Initiator | opcode(1) |
| 7 | `CTRL_HANDSHAKE_ERROR` | Either | opcode(1) + error_code(1) |
| 8 | `CTRL_PORT_HOP` | Either | opcode(1) + new_port(2) + session_id(8) |
| 9 | `CTRL_PORT_HOP_ACK` | Either | opcode(1) + session_id(8) |
| 10 | `CTRL_HEARTBEAT` | Either | opcode(1) |
| 11 | `CTRL_HEARTBEAT_ACK` | Either | opcode(1) |
| 12 | `CTRL_RECONNECT` | Either | opcode(1) + session_id(8) |
| 13 | `CTRL_RECONNECT_ACK` | Either | opcode(1) + session_id(8) |
| 14 | `CTRL_ROUTE_DATA` | Either | opcode(1) + dest_node_id(8) + inner_channel(1) + inner_payload(N) |

## FEC Parity Packet Wire Format

FEC parity is sent on the CONTROL channel when a data-packet group completes:

```
Offset  Size  Field
0       4     group_start_seq    Sequence number of first packet in group (little-endian)
4       1     group_size         Number of packets in group (typically 4 or 8)
5       1     channel_id         Channel this group belongs to (e.g. 3 for CHAT)
6       N     xor_parity         XOR of all payloads in group (length = max payload in group)
```

Total parity packet payload: 6 + N bytes (N ≤ 1400).
The receiver calls `fec_rx_store_parity` to store this, then `fec_rx_rebuild` to recover missing packets.

## Addressed in Later Phases

| Feature | Phase | Doc Reference |
|---|---|---|
| Resilience (multipath/FEC/hop/relay/reconnect/abr) | Phase 4 | Spec §16 |
| Kernel filter (BPF/eBPF) | Phase 5 | Spec §6 |
| Anti-analysis layer | Phase 5 | Spec §9 |
| Offensive shell | Phase 5 | Spec §10 |
| CLI command surface | Phase 6 | Spec §20 |
| Key rotation protocol | Phase 6 | Spec §17 |
| Audio pipeline + crypto thread | Phase 6 | Spec §15 |
| Secure key storage (locked memory) | Phase 6 | Spec §17 |
| Full regression test suite | Phase 7 | Spec §21 |

## Phase Cross-Reference

| Phase | Delivered |
|---|---|
| Phase 1 | Core transport, packet parsing, static shell, session gate, replay, scheduler, pipeline |
| Phase 2 | PQ handshake (ML-KEM 768), state machine, transcript hash, HKDF derivation, handshake stats |
| Phase 3 | ChaCha20-Poly1305 AEAD, CSPRNG session IDs, HMAC identity verification, channel key AAD binding |
| Phase 4 | Resilience — FEC, multipath, reconnect, port hop, adaptive bitrate |
| Phase 5 | Outer defense — kernel BPF, anti-analysis, offensive shell |
| Phase 6 | CLI, key rotation, audio pipeline, secure storage, operational features |
| Phase 7 | Compliance closure — remove hot-path logs, fast-path audit, regression suite, freeze interfaces |
