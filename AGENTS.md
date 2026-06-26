# AGENTS.md — SSM Secure Communication Transport

## Must Read Before Changing Code

| Doc | Why |
|---|---|
| `SSM_Secure_Communication_Spec_v1.0.md` | Locked architecture — NO structural changes |
| `PHASE1_WIRE_CONTRACT.md` | Wire format, offsets, nonce/tag layout, rules |
| `IMPLEMENTATION_PHASE_STATUS.md` | What's done, what's next, detailed substeps |
| `core/session.h` | Opcodes, state enum, key structs, handshake struct |

---

## Current State — Phase 3 ✅ Complete

### Implemented
- ChaCha20-Poly1305 session AEAD via mbedtls (encrypt/decrypt, no malloc, no printf)
- CSPRNG session IDs via `kem_random_bytes()` (getrandom syscall)
- HMAC-SHA256 identity signature verification (hardcoded master key)
- Channel key binding via AAD XOR-fold (single-layer AEAD)
- Deterministic nonce: `session_id[0..7] + channel_id[8] + 0x00[9] + seq[10..11]`
- Demo verified: `attempts=1 ok=1 fail=0 enc=on`, both chat messages delivered

### Key Decisions
- **Ed25519**: PSA Ed25519 unavailable in mbedtls 3.6.6 → HMAC-SHA256 identity instead
- **Single-layer AEAD**: Session-level only. Channel binding via AAD, not double-encryption
- **Nonce**: Deterministic (no per-packet RNG), unique via `session_id + channel_id + seq`
- **AAD**: 24-byte header with `PACKET_FLAG_ENCRYPTED` cleared, XOR-folded with `channel_keys[channel_id]`
- **Session ID**: Responder generates in `handshake_build_accept`, initiator adopts from ACCEPT payload

---

## Phase Roadmap

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | Core transport, parsing, static shell, session gate, replay, scheduler, pipeline | ✅ Complete |
| **Phase 2** | PQ handshake (ML-KEM 768), state machine, HKDF derivation, handshake stats | ✅ Complete |
| **Phase 3** | AEAD encryption, CSPRNG, HMAC identity, channel binding | ✅ Complete |
| **Phase 4** | Resilience: FEC, multipath, reconnect, port hop, adaptive bitrate | 📋 Planned |
| **Phase 5** | Outer defense: kernel BPF, anti-analysis, offensive shell | 📋 Planned |
| **Phase 6** | CLI, key rotation, audio pipeline, secure storage, crypto thread | 📋 Planned |
| **Phase 7** | Compliance closure: hot-path audit, regression suite, freeze interfaces | 📋 Planned |

---

## After Compilation — Checklist

Every time before committing:

1. **Build**: `cmake --build build_linux/` — zero warnings
2. **Demo**: `timeout 5 ./build_linux/transport` — verify output contains:
   - `identity verified OK`
   - `init=LOCKED resp=LOCKED`
   - `ok=1` in stats line
   - Both chat messages printed (`hey from responder!`, `hello from initiator!`)
3. **Regressions**: `fail=0` and `enc=on` in stats
4. **Docs**: Update `IMPLEMENTATION_PHASE_STATUS.md` and `PHASE1_WIRE_CONTRACT.md` if wire format or status changes
5. **Rules**: No violation of RULE-8 (malloc) or RULE-9 (logging) in pipeline / fast-path code

---

## Architecture Rules (All 18)

| ID | Rule | Compliance |
|---|---|---|
| RULE-1 | Session gate before decrypt | ✅ `session_gate.c` before `session_enc.c` |
| RULE-2 | Outer layers must not decrypt | ✅ Static shell / gate never decrypt |
| RULE-3 | PQ only during handshake | ✅ Rejected with `failures_state++` post-lock |
| RULE-4 | Trusted packets bypass offense | ✅ Offense is stub (returns pass) |
| RULE-5 | Scheduler before encrypt | ✅ TX dequeues before `session_enc_apply` |
| RULE-6 | Audio never wait for file | 🔲 Audio not yet implemented |
| RULE-7 | Control never wait for audio | 🔲 Audio not yet implemented |
| RULE-8 | No malloc in fast path | ✅ Stack buffers only in `aead.c`, `session_enc.c` |
| RULE-9 | No logging in fast path | ✅ No printf in encrypt/decrypt |
| RULE-10 | No mutex in audio path | 🔲 Audio not yet implemented |
| RULE-11 | Packet parsed only once | ✅ Single `packet_parse` call per pipeline walk |
| RULE-12 | Session must be exclusive | ✅ Single session per socket pair |
| RULE-13 | Kernel filter must be first | 🔲 Kernel filter is stub |
| RULE-14 | Keys never leave secure store | ✅ Stack-only, no export |
| RULE-15 | Resilience must not change session_id | 🔲 Resilience not yet implemented |
| RULE-16 | Replay window always active | ✅ `seq_check.c` bitmap |
| RULE-17 | Channel must not access transport | ✅ Channel demux is pure routing |
| RULE-18 | CLI must not access UDP directly | 🔲 CLI not yet implemented |

---

## Key Crypto Parameters

| Parameter | Value | Source |
|---|---|---|
| KEM | ML-KEM 768 (NIST level 3) | `oqs_kem_*` (liboqs) |
| Session AEAD | ChaCha20-Poly1305 | `mbedtls_cipher_auth_encrypt_ext` |
| Identity | HMAC-SHA256, 32-byte key | `mbedtls_md_hmac` |
| Key derivation | HKDF-extract + expand (SHA-256) | `crypto/hkdf.c` |
| Session key | 32 bytes | HKDF-expand(PRK, "SCv1 session key") |
| Channel keys | 5 × 32 bytes | HKDF-expand(PRK, "SCv1 channel key N") |
| Nonce | 12 bytes | session_id + channel_id + seq |
| AEAD tag | 16 bytes | Poly1305 |
| Transcript hash | 32 bytes | SHA-256 |

---

## Handshake Opcodes

| Code | Constant | From | Payload |
|---|---|---|---|
| 1 | `CTRL_HELLO` | Initiator | opcode(1) |
| 2 | `CTRL_ACCEPT` | Responder | opcode(1) + session_id(8) |
| 3 | `CTRL_PQ_KEM_INIT` | Initiator | opcode(1) + public_key(1184) |
| 4 | `CTRL_PQ_KEM_RESPONSE` | Responder | opcode(1) + ciphertext(1088) |
| 5 | `CTRL_IDENTITY_PROOF` | Initiator | opcode(1) + signature(64) + identity_hash(32) |
| 6 | `CTRL_SESSION_LOCKED` | Responder | opcode(1) |
| 7 | `CTRL_HANDSHAKE_ERROR` | Either | opcode(1) + error_code(1) |

## Error Codes

| Code | Constant | Meaning |
|---|---|---|
| 0 | `HS_ERR_NONE` | No error |
| 1 | `HS_ERR_UNSUPPORTED_KEM` | KEM type not supported |
| 2 | `HS_ERR_BAD_IDENTITY` | Identity verification failed |
| 3 | `HS_ERR_TIMEOUT` | Handshake timed out |
| 4 | `HS_ERR_REPLAY` | Replay detected |
| 5 | `HS_ERR_STATE_VIOLATION` | Invalid state transition |

## Session States

```
IDLE → HANDSHAKE_START → PQ_KEM_INIT_SENT → PQ_KEM_RESPONSE_SENT
    → IDENTITY_PROOF_SENT → LOCKED
```

## Channels

| ID | Name | Encrypted | Key Label |
|---|---|---|---|
| 1 | CONTROL | No (bypass) | N/A |
| 2 | AUDIO | Yes | "SCv1 channel key 1" |
| 3 | CHAT | Yes | "SCv1 channel key 2" |
| 4 | FILE | Yes | "SCv1 channel key 3" |
| 5 | ROUTE | Yes | "SCv1 channel key 4" |

---

## File Map

| File | Responsibility |
|---|---|
| `core/session.h` | Session struct, opcodes, state enum, key structs |
| `core/packet_view.h` | `packet_view_t`, `packet_buf_t`, nonce/tag fields |
| `core/pool.c` | Pre-allocated packet buffer pool (4096 buffers) |
| `core/udp_posix.c` | UDP socket create/send/recv (Linux) |
| `core/rx_thread.c` | RX thread: read UDP → push to ring |
| `core/tx_thread.c` | TX thread: pull from queues → send UDP |
| `core/session.c` | Session table, alloc/find/reset |
| `core/scheduler.c` | Priority queue (ring buffers per priority) |
| `crypto/kem.c` | ML-KEM 768 wrappers, CSPRNG `kem_random_bytes` |
| `crypto/hkdf.c` | HKDF-extract/expand, `derive_session_keys` |
| `crypto/aead.c` | ChaCha20-Poly1305 (no malloc, no printf) |
| `handshake/handshake.c` | All 6 handshake builders + process_message + state machine |
| `layers/packet_parse.c` | Single-pass parser, nonce/tag extraction |
| `layers/static_shell.c` | Magic, version, flags, length, channel, seq validation |
| `layers/session_gate.c` | Session ID + peer address binding |
| `layers/seq_check.c` | 64-bit bitmap replay window |
| `layers/session_enc.c` | AEAD encrypt/decrypt with channel key AAD binding |
| `layers/channel_enc.c` | Per-channel verification stub |
| `layers/rx_demux.c` | Channel dispatch to handler |
| `pipeline/pipeline_inbound.c` | Inbound layer chain (all 10 layers) |
| `main.c` | Event loop, control handlers, chat demo |
