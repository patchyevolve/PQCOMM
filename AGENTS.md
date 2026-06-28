# AGENTS.md — pqCOMMbulds Secure Communication Transport

## Must Read Before Changing Code

| Doc | Why |
|---|---|
| `SSM_Secure_Communication_Spec_v1.0.md` | Locked architecture — NO structural changes |
| `PHASE1_WIRE_CONTRACT.md` | Wire format, offsets, nonce/tag layout, rules |
| `ARCHITECTURE.md` | Full system design — target architecture for refactored project |
| `IMPLEMENTATION_PHASE_STATUS.md` | What's done, what's next, detailed substeps |
| `SSM_USER_FLOW.md` | User-facing connection flow, screens, identity setup |
| `lib/core/session.h` | Opcodes, state enum, key structs, handshake struct |
| `lib/api/transport_api.h` | Public C API (consumed by TUI + test_runner) |

---

## Current State — ✅ All Phases 1-7 Complete

All 23 substeps across Phases 1-7 are implemented. No stubs remain. 25/25 tests pass.

### Implemented
- **Core**: UDP sockets, RX/TX threads, lock-free rings, packet pool, scheduler
- **Pipeline**: 10-layer inbound + outbound (parse, static shell, session gate, resilience, session enc, seq check, kernel filter, anti-analysis, offensive, demux)
- **Handshake**: 6-message PQ (ML-KEM 768) with state machine, HKDF derivation, HMAC identity
- **AEAD**: ChaCha20-Poly1305, deterministic nonce, channel binding via AAD XOR-fold
- **Resilience**: FEC (XOR group-4), multipath (2 paths), port hop, reconnect, ABR, relay
- **Defense**: Kernel filter (whitelist/blocklist/port/size), anti-analysis (per-source scoring), offensive (trusted bypass, rate limiting)
- **Identity**: Username/display name, key gen, file save/load
- **Connection**: Peer table, connect/disconnect state machine, conn request/accept/decline protocol
- **Discovery**: UDP beacon broadcast on separate port, username broadcast, peer timeout/stale marking
- **TUI**: Full standalone terminal app — login, peer list, chat, incoming request/call popups, statusbar
- **Audio**: Opus encode/decode with jitter buffer, arecord/aplay subprocess I/O
- **Video**: V4L2 capture + ffmpeg pipe, per-frame send/display
- **File transfer**: Chunked (1024B), metadata, checksum
- **Realtime**: Typing indicator, delivery receipts (sent/delivered/read), message timestamps, latency display, unread badges
- **Crypto thread**: Dedicated worker for async crypto operations
- **Monitor/watchdog**: Thread health, pool pressure, periodic checks
- **Secure storage**: mlock/MADV_DONTDUMP, environment variable key loading
- **Config**: TOML file parser with CLI overrides
- **Key rotation**: REKEY_INIT/CONFIRM protocol, no-session-interruption rekeying

### Key Decisions
- **Ed25519**: PSA Ed25519 unavailable in mbedtls 3.6.6 → HMAC-SHA256 identity instead
- **Single-layer AEAD**: Session-level only. Channel binding via AAD, not double-encryption
- **Nonce**: Deterministic (no per-packet RNG), unique via `session_id + channel_id + seq`
- **AAD**: 24-byte header with `PACKET_FLAG_ENCRYPTED` cleared, XOR-folded with `channel_keys[channel_id]`
- **Session ID**: Responder generates in `handshake_build_accept`, initiator adopts from ACCEPT payload
- **Connection model**: Hybrid manual + LAN broadcast discovery. Discovery is not a trust mechanism.
- **TUI**: In-process with threads + lock-free queues (no IPC, no daemon). Raw terminal mode (tcsetattr).
- **Testing**: Separate `test_runner` executable linking `libtransport_core.a` — 25 tests across 15 files.

---

## After Compilation — Checklist

Every time before committing:

1. **Build**: `cmake -S . -B build_linux -G Ninja && cmake --build build_linux` — zero warnings
2. **Demo**: `timeout 14 ./build_linux/transport` — verify output contains:
   - `identity verified OK`
   - `init=LOCKED resp=LOCKED`
   - `ok=1` in stats line
   - `[FEC] recovered seq=5` shown (both sides)
   - `[PORT_HOP]` request/ack exchange shown
   - `[RECONNECT] ack received, session re-established` shown
   - `[RELAY] forwarded seq=...` and `[INIT CHAT] hello via relay!` shown
   - `[ABR] loss=0.0% fec=on group=4 -> off group=0` shown (both sides)
3. **Tests**: `./build_linux/test_runner` — returns 0 with **"25/25 tests passed"**
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
| RULE-4 | Trusted packets bypass offense | ✅ Offensive layer checks magic/version/session_id/channel before scoring |
| RULE-5 | Scheduler before encrypt | ✅ TX dequeues before `session_enc_apply` |
| RULE-6 | Audio never wait for file | ✅ Audio uses dedicated thread + ring buffer |
| RULE-7 | Control never wait for audio | ✅ Control channel separate from audio |
| RULE-8 | No malloc in fast path | ✅ Stack buffers only in `aead.c`, `session_enc.c` |
| RULE-9 | No logging in fast path | ✅ No printf in encrypt/decrypt |
| RULE-10 | No mutex in audio path | ✅ Audio uses lock-free ring buffers |
| RULE-11 | Packet parsed only once | ✅ Single `packet_parse` call per pipeline walk |
| RULE-12 | Session must be exclusive | ✅ Single session per socket pair |
| RULE-13 | Kernel filter must be first | ✅ Kernel filter runs 4th (after static, offensive, anti-analysis), before session gate |
| RULE-14 | Keys never leave secure store | ✅ Stack-only, no export |
| RULE-15 | Resilience must not change session_id | ✅ FEC/multipath/port-hop preserve session_id |
| RULE-16 | Replay window always active | ✅ `seq_check.c` bitmap |
| RULE-17 | Channel must not access transport | ✅ Channel demux is pure routing |
| RULE-18 | CLI must not access UDP directly | ✅ TUI uses transport API, never touches sockets |

---

## Build

```bash
cmake -S . -B build_linux -G Ninja
cmake --build build_linux
# Outputs:
#   build_linux/libtransport_core.a  — static library
#   build_linux/transport            — TUI executable (links libtransport_core.a)
#   build_linux/test_runner          — test executable (links libtransport_core.a)

# Run TUI (standalone terminal app)
./build_linux/transport --tui

# Run demo (two in-process peers, automated)
timeout 14 ./build_linux/transport

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
| Channel keys | 6 × 32 bytes | HKDF-expand(PRK, "SCv1 channel key N") |
| Nonce | 12 bytes | session_id + channel_id + seq |
| AEAD tag | 16 bytes | Poly1305 |
| Transcript hash | 32 bytes | SHA-256 |

## Full Opcode Table (1-31)

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
| 10 | `CTRL_HEARTBEAT` | Either | opcode(1) |
| 11 | `CTRL_HEARTBEAT_ACK` | Either | opcode(1) |
| 12 | `CTRL_RECONNECT` | Either | opcode(1) + session_id(8) + seq(4) |
| 13 | `CTRL_RECONNECT_ACK` | Either | opcode(1) + session_id(8) |
| 14 | `CTRL_ROUTE_DATA` | Either | opcode(1) + dest_node_id(1) + inner_channel(1) + payload(N) |
| 15 | `CTRL_REKEY_INIT` | Initiator | opcode(1) + public_key(1184) + key_epoch(1) |
| 16 | `CTRL_REKEY_CONFIRM` | Responder | opcode(1) + ciphertext(1088) + key_epoch(1) |
| 17 | `CTRL_CONNECT_REQUEST` | Either | opcode(1) + username(32) + display_name(64) + kem_type(1) |
| 18 | `CTRL_CONNECT_ACCEPT` | Either | opcode(1) |
| 19 | `CTRL_CONNECT_DECLINE` | Either | opcode(1) + reason(64) |
| 20 | `CTRL_AUDIO_CALL` | Either | opcode(1) |
| 21 | `CTRL_AUDIO_CALL_ACK` | Either | opcode(1) |
| 22 | `CTRL_AUDIO_CALL_END` | Either | opcode(1) |
| 23 | `CTRL_VIDEO_CALL` | Either | opcode(1) |
| 24 | `CTRL_VIDEO_CALL_ACK` | Either | opcode(1) |
| 25 | `CTRL_VIDEO_CALL_END` | Either | opcode(1) |
| 26 | `CTRL_FILE_META` | Either | opcode(1) + filename(64) + total_size(4) + checksum(32) |
| 27 | `CTRL_FILE_CHUNK` | Either | opcode(1) + file_id(1) + chunk_idx(2) + data(1024) |
| 28 | `CTRL_FILE_ACK` | Either | opcode(1) + file_id(1) + chunk_idx(2) |
| 29 | `CTRL_TYPING` | Either | opcode(1) |
| 30 | `CTRL_DELIVERY_ACK` | Either | opcode(1) |
| 31 | `CTRL_READ_ACK` | Either | opcode(1) |

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
| 6 | VIDEO | Yes | "SCv1 channel key 5" |

## TUI Keybindings

| Key | Screen | Action |
|---|---|---|
| Type + Tab + Enter | LOGIN | Enter username/display name, submit |
| ↑↓ / j/k + →/Enter + Esc/← + q | PEER LIST | Navigate, select, back, quit |
| Type + Enter + Esc/← + Ctrl+A + Ctrl+V + Ctrl+F + q | CHAT | Send message, back, audio toggle, video toggle, file send, quit |
| Ctrl+C | Anywhere | Quit |
| Ctrl+Z | Anywhere | Suspend (fg to resume) |

---

## File Map

| File | Responsibility |
|---|---|
| **lib/api/transport_api.h** | Public C API for TUI + test_runner |
| **lib/core/session.h** | Session struct, opcodes 1-31, state enum, key structs |
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
| **lib/pipeline/pipeline_outbound.c** | Header build + encrypt pipeline |
| **lib/layers/packet_parse.c** | Single-pass parser, nonce/tag extraction |
| **lib/layers/static_shell.c** | Magic, version, flags, length, channel, seq validation |
| **lib/layers/session_gate.c** | Session ID + peer address binding |
| **lib/layers/session_enc.c** | AEAD encrypt/decrypt with channel key AAD binding |
| **lib/layers/seq_check.c** | 64-bit bitmap replay window |
| **lib/layers/resilience.c** | FEC + multipath pipeline layer |
| **lib/layers/port_hop.c** | Port hop control protocol |
| **lib/layers/rx_demux.c** | Channel dispatch |
| **lib/connection/connection_manager.c** | Peer table, connect/disconnect state machine |
| **lib/discovery/lan_discovery.c** | UDP beacon broadcast + peer timeout |
| **lib/engine/transport_engine.c** | Thread orchestration, event dispatch, timer wheel |
| **lib/engine/crypto_worker.c** | Dedicated crypto worker thread |
| **lib/engine/audio_worker.c** | Opus encode/decode, play/capture via arecord/aplay |
| **lib/engine/audio_pipeline.c** | Audio jitter buffer + pipeline glue |
| **lib/engine/video_worker.c** | V4L2 capture, ffmpeg pipe, frame dispatch |
| **lib/engine/file_transfer.c** | Chunked file send/receive with checksum |
| **lib/engine/monitor.c** | Watchdog thread, health checks, pool pressure |
| **lib/engine/rekey.c** | Key rotation protocol (CTRL_REKEY_INIT/CONFIRM) |
| **lib/engine/conn_request.c** | Connect request/accept/decline protocol |
| **lib/identity/identity.c** | Username, display name, key gen, file save/load |
| **lib/crypto/toml_config.c** | TOML config file parser |
| **lib/crypto/secure_store.c** | mlock/MADV_DONTDUMP, env var key loading |
| **app/main.c** | Entry point: `--tui` for TUI, default for demo |
| **app/tui.h** | TUI state struct, screen enum, action codes |
| **app/tui_screen.c** | Renderer, raw terminal mode, SIGWINCH/SIGCONT handling |
| **app/tui_input.c** | Keyboard input per screen, arrow keys, Ctrl+C/Z |
| **app/tui_panels.c** | Topbar, login, peer list, chat, popups, statusbar |
| **tests/test_runner_main.c** | Test runner entry point (25 tests) |
| **tests/test_*.c** | 15 individual test scenario files |
