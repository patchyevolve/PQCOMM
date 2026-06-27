# AGENTS.md — SSM Secure Communication Transport

## Must Read Before Changing Code

| Doc | Why |
|---|---|
| `SSM_Secure_Communication_Spec_v1.0.md` | Locked architecture — NO structural changes |
| `PHASE1_WIRE_CONTRACT.md` | Wire format, offsets, nonce/tag layout, rules |
| `ARCHITECTURE.md` | Full system design — target architecture for refactored project |
| `IMPLEMENTATION_PHASE_STATUS.md` | What's done, what's next, detailed substeps |
| `lib/core/session.h` | Opcodes, state enum, key structs, handshake struct |
| `lib/api/transport_api.h` | Public C API (consumed by TUI + test_runner) |

---

## Current State — Phase 3 ✅ Complete, Phase 4 ⏳ In Progress, Phase 4.5 ✅ Complete

### Implemented (Phase 1-3)
- ChaCha20-Poly1305 session AEAD via mbedtls (encrypt/decrypt, no malloc, no printf)
- CSPRNG session IDs via `kem_random_bytes()` (getrandom syscall)
- HMAC-SHA256 identity signature verification (hardcoded master key)
- Channel key binding via AAD XOR-fold (single-layer AEAD)
- Deterministic nonce: `session_id[0..7] + channel_id[8] + 0x00[9] + seq[10..11]`
- Full PQ handshake (ML-KEM 768) with 6-message state machine
- All 10 pipeline layers (static shell, session gate, resilience, session enc, etc.)

### Implemented (Phase 4 substeps 1-4)
- Resilience context: path metrics, loss window, path states
- FEC: XOR parity TX/RX, group-based recovery (group size 4)
- Multipath: 2 UDP socket pairs, per-path seq tracking, path selection
- Port hop: CTRL_PORT_HOP (8) / CTRL_PORT_HOP_ACK (9) opcodes, request/ack protocol
- Relay: route table with add/find/remove, CTRL_ROUTE_DATA (14) opcode, CH_ROUTE channel forwarding

### Key Decisions
- **Ed25519**: PSA Ed25519 unavailable in mbedtls 3.6.6 → HMAC-SHA256 identity instead
- **Single-layer AEAD**: Session-level only. Channel binding via AAD, not double-encryption
- **Nonce**: Deterministic (no per-packet RNG), unique via `session_id + channel_id + seq`
- **AAD**: 24-byte header with `PACKET_FLAG_ENCRYPTED` cleared, XOR-folded with `channel_keys[channel_id]`
- **Session ID**: Responder generates in `handshake_build_accept`, initiator adopts from ACCEPT payload
- **Connection model**: Hybrid manual + LAN broadcast discovery. Discovery is not a trust mechanism.
- **TUI**: In-process with threads + lock-free queues (no IPC, no daemon)
- **Testing**: Separate `test_runner` executable linking libtransport.a
- **Library**: Single `libtransport.a` static library consumed by both `transport` (TUI) and `test_runner`

---

## Phase Roadmap

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | Core transport, parsing, static shell, session gate, replay, scheduler, pipeline | ✅ Complete |
| **Phase 2** | PQ handshake (ML-KEM 768), state machine, HKDF derivation, handshake stats | ✅ Complete |
| **Phase 3** | AEAD encryption, CSPRNG, HMAC identity, channel binding | ✅ Complete |
| **Phase 4** | Resilience: FEC, multipath, reconnect, port hop, adaptive bitrate | ✅ Complete (1-8 done) |
| **Phase 4.5** | Architecture restructure: libtransport_core.a + transport + test_runner | ✅ Complete |
| **Phase 5** | Outer defense: kernel BPF, anti-analysis, offensive shell | 📋 Planned |
| **Phase 6** | CLI, key rotation, audio pipeline, secure storage, crypto thread | 📋 Planned |
| **Phase 7** | Compliance closure: hot-path audit, regression suite, freeze interfaces | 📋 Planned |

---

## After Compilation — Checklist

Every time before committing:

1. **Build**: `cmake -S . -B build_linux -G Ninja && cmake --build build_linux` — zero warnings
2. **Demo**: `timeout 14 ./build_linux/transport` — verify output contains:
   - `identity verified OK`
   - `init=LOCKED resp=LOCKED`
   - `ok=1` in stats line
   - All 5 chat messages each side delivered
   - `[FEC] recovered seq=5` shown (both sides)
   - `[PORT_HOP]` request/ack exchange shown
   - `[RECONNECT] ack received, session re-established` shown
    - `[RELAY] forwarded seq=...` and `[INIT CHAT] hello via relay!` shown
    - `[ABR] loss=0.0% fec=on group=4 -> off group=0` shown (both sides)
3. **Tests**: `./build_linux/test_runner` — returns 0 with "11/11 tests passed"
4. **Regressions**: `fail=0` and `enc=on` in stats
5. **Docs**: Update `IMPLEMENTATION_PHASE_STATUS.md`, `ARCHITECTURE.md`, and `PHASE1_WIRE_CONTRACT.md` if wire format or status changes
6. **Rules**: No violation of RULE-8 (malloc) or RULE-9 (logging) in pipeline / fast-path code

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
| RULE-15 | Resilience must not change session_id | ✅ FEC/multipath/port-hop preserve session_id |
| RULE-16 | Replay window always active | ✅ `seq_check.c` bitmap |
| RULE-17 | Channel must not access transport | ✅ Channel demux is pure routing |
| RULE-18 | CLI must not access UDP directly | 🔲 CLI/TUI not yet implemented (will use API) |

---

## Build

```bash
cmake -S . -B build_linux -G Ninja
cmake --build build_linux
# Outputs:
#   build_linux/libtransport_core.a  — static library
#   build_linux/transport            — TUI executable (links libtransport_core.a)
#   build_linux/test_runner          — test executable (links libtransport_core.a)

# Run demo
timeout 5 ./build_linux/transport

# Run tests
./build_linux/test_runner
```

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
| 8 | `CTRL_PORT_HOP` | Either | opcode(1) + new_port(2) + session_id(8) |
| 9 | `CTRL_PORT_HOP_ACK` | Either | opcode(1) + session_id(8) |

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
| **lib/api/transport_api.h** | Public C API for TUI + test_runner |
| **lib/core/session.h** | Session struct, opcodes, state enum, key structs |
| **lib/core/packet_view.h** | `packet_view_t`, `packet_buf_t`, nonce/tag fields |
| **lib/core/session.c** | Session table, alloc/find/reset |
| **lib/core/pool.c** | Pre-allocated packet buffer pool (4096 buffers) |
| **lib/core/udp_posix.c** | UDP socket create/send/recv (Linux) |
| **lib/core/rx_thread.c** | RX thread: read UDP → push to ring |
| **lib/core/tx_thread.c** | TX thread: pull from queues → send UDP |
| **lib/core/scheduler.c** | Priority queue (ring buffers per priority) |
| **lib/core/ring.c** | SPSC lock-free ring |
| **lib/core/resilience_ctx.c** | Path metrics, FEC TX/RX state |
| **lib/core/rx_worker.c** | RX dispatch worker |
| **lib/crypto/kem.c** | ML-KEM 768 wrappers, CSPRNG `kem_random_bytes` |
| **lib/crypto/hkdf.c** | HKDF-extract/expand, `derive_session_keys` |
| **lib/crypto/aead.c** | ChaCha20-Poly1305 (no malloc, no printf) |
| **lib/handshake/handshake.c** | All 6 handshake builders + process_message + state machine |
| **lib/pipeline/pipeline_inbound.c** | 10-layer inbound chain |
| **lib/pipeline/pipeline_outbound.c** | Outbound processing |
| **lib/layers/packet_parse.c** | Single-pass parser, nonce/tag extraction |
| **lib/layers/static_shell.c** | Magic, version, flags, length, channel, seq validation |
| **lib/layers/session_gate.c** | Session ID + peer address binding |
| **lib/layers/session_enc.c** | AEAD encrypt/decrypt with channel key AAD binding |
| **lib/layers/channel_enc.c** | Per-channel verification stub |
| **lib/layers/seq_check.c** | 64-bit bitmap replay window |
| **lib/layers/resilience.c** | FEC + multipath pipeline layer |
| **lib/layers/port_hop.c** | Port hop control protocol |
| **lib/layers/rx_demux.c** | Channel dispatch |
| **lib/connection/connection_manager.c** | Peer table, connect/disconnect state machine |
| **lib/discovery/lan_discovery.c** | UDP beacon broadcast + peer timeout |
| **lib/engine/transport_engine.c** | Thread orchestration, event dispatch, timer wheel |
| **app/main.c** | TUI frontend entry point |
| **app/tui_screen.c** | Terminal rendering (ANSI escape codes) |
| **app/tui_input.c** | Keyboard input processing |
| **app/tui_panels.c** | Connection / Chat / Status panel rendering |
| **tests/test_runner_main.c** | Test runner entry point |
| **tests/test_*.c** | Individual test scenarios |

> Phase 4.5 refactor complete. All source code now lives under `lib/`.
> The `app/main.c` entry point replaces the old root-level `main.c`.
> Old source directories (`core/`, `crypto/`, `handshake/`, `layers/`, `pipeline/`) have been removed.
