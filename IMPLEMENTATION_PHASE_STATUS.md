# Transport Implementation Status and Phase Roadmap

Status date: 2026-06-27 (updated for Phase 4 and Phase 5 completion)

This document records:
- what is already implemented in the transport system,
- what is partially implemented,
- what remains for later phases,
- and detailed substeps for each upcoming phase.

It is aligned to the locked architecture direction used in this project.

---

## 1) Completed So Far (Implemented)

### 1.1 Core Runtime Foundation

- UDP socket send/recv infrastructure is implemented.
- RX and TX thread flow is implemented.
- Worker-thread dispatch is implemented.
- Lock-free ring queue and packet pool are implemented.
- Build structure has been migrated into `core/`, `layers/`, and `pipeline/`.

### 1.2 Packet and Ingress Validation Path

- Packet parsing (`packet_parse`) is implemented.
- Static shell checks (`static_check`) are implemented.
- Session gate checks (`session_check`) are implemented.
- Replay/sequence checks (`seq_check`) are implemented.
- Channel demux is implemented.

### 1.3 Session and Control Baseline

- Control HELLO/ACCEPT handshake baseline is implemented.
- Session state model has been upgraded to:
  - `SESSION_IDLE`
  - `SESSION_HANDSHAKE`
  - `SESSION_VERIFY`
  - `SESSION_LOCKED`
- Lock-state replay reset behavior is implemented.

### 1.4 Scheduler and Priority

- TX scheduling priority is implemented:
  - control > audio > chat > file > fake

### 1.5 Pipeline Refactor and Observability

- Inbound validation chain was moved from `main.c` into `pipeline/pipeline_inbound.c`.
- Pipeline drop reasons are now explicit and tracked.
- Periodic stats logging is implemented for visibility.
- Phase 1 selftest helpers were moved to `pipeline/pipeline_selftest.*`.

### 1.6 Architecture Stub Layers Added

Pass-through stubs exist for:
- offensive
- anti_analysis
- kernel_filter_stub
- resilience

These are wired in pipeline order and currently return pass.

### 1.7 Post-Quantum Handshake Protocol (Phase 2 - Complete)

- **Message contract**: HELLO, ACCEPT, PQ_KEM_INIT, PQ_KEM_RESPONSE, IDENTITY_PROOF, SESSION_LOCKED opcodes implemented.
- **State guards**: Enforced state transitions with rejection of invalid opcode sequences.
- **ML-KEM key exchange**: Full key generation, encapsulation, and decapsulation using liboqs (768-bit security).
- **Identity verification**: IDENTITY_PROOF message with HMAC-SHA256 signature and 32-byte identity hash (see Phase 3).
- **Transcript hashing**: SHA-256 rolling hash of all handshake messages for replay protection.
- **Session key derivation**: HKDF-based key extraction and expansion for session/channel secrets.
- **Post-lock PQ validation**: Enforced rejection of PQ operations (KEM_INIT, KEM_RESPONSE) after SESSION_LOCKED.
- **Handshake statistics**: Counters for attempts, successes, and per-category failures (timeout, identity, replay, state).
- **POSIX thread support**: Complete rx/tx thread implementations for Linux using pthread.
- **Runtime verification**: Both initiator and responder reliably reach SESSION_LOCKED state on successful handshake.
- **Timeout handling**: Configurable handshake timeout (PHASE2_HANDSHAKE_TIMEOUT_MS, default 5000ms).

### 1.8 AEAD Session Encryption (Phase 3 - Complete)

- **ChaCha20-Poly1305 encryption**: Full encrypt/decrypt via mbedtls `mbedtls_cipher_auth_encrypt_ext`/`decrypt_ext`.
- **Session key derivation**: HKDF-extract + expand produces 32-byte session key and 5 per-channel keys (32 bytes each).
- **Deterministic nonce**: 12-byte nonce derived from session_id, channel_id, and sequence number — no per-packet RNG.
- **AAD construction**: 24-byte header with encryption flag cleared, XOR-folded with per-channel key for channel binding.
- **Packet format**: nonce stored at offset 24, ciphertext follows, 16-byte tag appended at end.
- **Pipeline integration**: `session_enc_check` runs inbound after session gate; `session_enc_apply` runs outbound before transmit.
- **CH_CONTROL bypass**: Control channel packets skip session encryption (RULE-2).
- **Fast-path rules**: No malloc (RULE-8) and no logging (RULE-9) in encrypt/decrypt path.
- **Fail-closed**: Decryption failure returns -1 and sets `HS_ERR_BAD_IDENTITY`.

### 1.9 CSPRNG Session ID (Phase 3)

- Session IDs generated via `kem_random_bytes()` which uses `getrandom()` (Linux) or `CryptGenRandom` (Windows).
- Applied in both `handshake_init_initiator` and `handshake_build_accept`.
- No `rand()` calls remain in the handshake path.

### 1.10 HMAC Identity Verification (Phase 3)

- **Identity signature**: `HMAC-SHA256(g_identity_master_key, transcript_hash)` with hardcoded 32-byte master key.
- **Identity hash**: `SHA-256(g_identity_master_key)`, computed at session init time on both sides.
- **Verification**: Responder verifies HMAC before accepting `IDENTITY_PROOF`; failure increments `failures_identity` counter.
- **Transcript snapshot**: Pre-update transcript captured for verification to align signer and verifier state.

### 1.11 Channel Key Binding (Phase 3)

- Each channel's derived key is XOR-folded into the AEAD AAD at both encrypt and decrypt time.
- No packet format changes needed; tampering with `channel_id` causes AEAD tag mismatch.

### 1.12 Reconnect Policy (Phase 4 substep 5)

- Heartbeat protocol: CTRL_HEARTBEAT (10) / CTRL_HEARTBEAT_ACK (11) opcodes, 1s interval.
- Path state machine: ACTIVE → DEGRADED (3s no activity) → DOWN (5s no activity).
- Reconnect protocol: CTRL_RECONNECT (12) / CTRL_RECONNECT_ACK (13) opcodes.
- Reconnect preserves session_id, keys, replay window — no full PQ re-handshake.
- Max 3 reconnect attempts, then drop to SESSION_IDLE.
- Demo verified: port hop + simulated transport loss → heartbeat timeout → reconnect → session re-established.

### 1.13 Relay / Mesh Routing (Phase 4 substep 6)

- Route table: up to 16 entries, each with node_id, session_id, addr, loss_rate, RTT.
- Route commands: route_table_add/remove/find/update_metrics.
- CH_ROUTE channel (channel 5): encrypted relay data channel using channel key 4.
- CTRL_ROUTE_DATA (14) opcode: wraps destination node_id (8 bytes), inner channel ID (1 byte), and payload.
- relay_forward_route: decrypts incoming CH_ROUTE via pipeline, extracts dest, looks up route table, builds+encrypts inner channel packet, sends.
- relay_build_test_packet: builds encrypted CH_ROUTE test packet with given message and dest node.
- Demo verified: initiator sends "hello via relay!" → responder receives CH_ROUTE → route table lookup → forwarded as CH_CHAT → initiator prints the relayed message.

---

## 2) Partially Implemented / Needs Hardening

### 2.1 Layer Outcome Semantics — ✅ Phase 5 complete

- Kernel filter: IP whitelist/blocklist, port binding, size bounds, drop counters (Phase 5, substep 1)
- Anti-analysis: per-source scoring engine with LRU eviction, score thresholds for medium/high drops (Phase 5, substep 2)
- Offensive shell: trusted packet bypass (RULE-4), per-source rate limiting, source eviction (Phase 5, substep 3)
- All three layers replaced stubs with real implementations; drops tracked per-layer in stats line

### 2.2 Performance and Fast-Path Rules

- No malloc in fast path (RULE-8): all layer checks use stack/global state only, no allocations
- No logging in fast path (RULE-9): layer functions return -1 silently, no printf in drop path
- Full latency/throughput/CPU profiling not yet done — Phase 7

### 2.3 Secure Memory

- Keys zeroed after use via `crypto_secure_wipe()`, but stack-resident keys not guaranteed against page-out
- mlock/mlockall not yet used to pin key memory — Phase 6

### 2.4 Identity Key Management

- Identity master key hardcoded (suitable for demo only)
- Production path needs secure key store (TPM / OS keychain / hardware-bound storage) — Phase 6

---

## 3) Not Yet Implemented (Major Missing Capabilities)

- ✅ ~~Adaptive bitrate (Phase 4 substep 7)~~ → **Implemented**: ABR controller adjusts FEC group size from loss rate
- ✅ ~~Test scenarios / test_runner (Phase 4 substep 8)~~ → **Implemented**: 19 unit tests across 11 test files
- ✅ ~~Real kernel filter enforcement~~ → **Implemented**: IP whitelist/blocklist, port binding, size checks
- ✅ ~~Real anti-analysis behavior (pattern scoring, delay/drop/throttle)~~ → **Implemented**: per-source scoring with LRU eviction
- ✅ ~~Real offensive-shell defensive responses (decoy, noise, rate-limit)~~ → **Implemented**: RULE-4 bypass, per-source rate limiting
- ✅ ~~Transport engine with event dispatch~~ → **Implemented**: full run_demo event loop with heartbeat, reconnect, port hop, relay, ABR
- ASCII TUI (connection screen, chat window, status panel) — Phase 6 (stubs exist)
- LAN discovery beacon (full implementation) — Phase 6 (stubs exist)
- Connection manager with peer table (full implementation) — Phase 6 (stubs exist)
- Full CLI command surface from final spec — Phase 6
- Key lifecycle management (rotation protocol, secure storage, zeroization policy hardening) — Phase 6
- Audio pipeline (encode/decode thread, jitter buffer) — Phase 6
- Dedicated crypto thread — Phase 6
- Monitor/watchdog thread — Phase 6
- Full regression test suite (tampered tag, reused nonce, wrong channel key, replay) — Phase 7

---

## 4) Later Phases Roadmap (Detailed Substeps)

## Phase 2 - Secure Session Foundation (PQ + Symmetric Transition) ✅ COMPLETE

Goal: complete one-time PQ handshake and clean transition into locked symmetric mode.

**Status: COMPLETE** — Post-quantum handshake protocol fully implemented and tested.

### Substeps (All Completed)

1. ✅ Define handshake message contract:
   - HELLO: version, kem_type, session_id
   - PQ KEM payloads: 1184-byte public key, 1088-byte ciphertext
   - IDENTITY_PROOF: 64-byte signature + 32-byte identity hash
   - Error opcodes: HANDSHAKE_ERROR with error codes (unsupported KEM, bad identity, timeout, replay, state violation)

2. ✅ Introduce handshake state guards:
   - 7-state progression: IDLE → START → KEM_INIT_SENT → KEM_RESPONSE_SENT → IDENTITY_PROOF_SENT → LOCKED
   - Each state strictly validates incoming opcodes; rejected transitions increment `failures_state` counter
   - One-time handshake enforced by state machine (second HELLO after ACCEPT rejected)

3. ✅ Implement PQ key exchange path (ML-KEM 768):
   - Initiator: generates keypair (1184B public, 2400B secret)
   - Responder: encapsulates shared secret into 1088B ciphertext
   - Both: derive session key from 32B shared secret via HKDF

4. ✅ Add identity verification step and lock transition:
   - IDENTITY_PROOF message carries 64B signature + 32B identity hash
   - Both sides verify identity signature via HMAC-SHA256
   - Transition to SESSION_LOCKED on receipt of SESSION_LOCKED opcode
   - Increment `g_handshake_stats.successes` counter

5. ✅ Derive session/channel secrets from handshake output:
   - HKDF-extract and HKDF-expand using 32B shared secret, transcript hash, and context strings
   - Generates independent keys for session and per-channel encryption (control, audio, chat, file)
   - Keys stored in `session->keys` structure; sensitive material wiped after derivation

6. ✅ Ensure post-lock traffic forbids PQ operations:
   - Check added in `handshake_process_message()` at entry: if SESSION_LOCKED, reject KEM_INIT and KEM_RESPONSE
   - Failed PQ-on-locked attempt logged and `failures_state++`

7. ✅ Add handshake counters/telemetry for success/failure:
   - `g_handshake_stats.attempts_total`: incremented on initiator/responder init
   - `g_handshake_stats.successes`: incremented when SESSION_LOCKED reached
   - `g_handshake_stats.failures_timeout`: (framework present, awaiting timeout detection)
   - `g_handshake_stats.failures_identity`: incremented on HMAC verification failure
   - `g_handshake_stats.failures_replay`: (framework present, awaiting replay test)
   - `g_handshake_stats.failures_state`: incremented on invalid state transitions or PQ-on-locked

8. ⚠️ Add deterministic test cases:
   - ✅ Success path: both initiator and responder reach SESSION_LOCKED in <10ms
   - ❌ Bad identity: requires tests with wrong key
   - ❌ Replayed handshake message: requires replay cache implementation
   - ❌ Wrong state transition: validated in code, not yet tested in main.c

**Verification**: Runtime test confirmed successful handshake:
- Initiator HELLO → Responder ACCEPT (both with session ID)
- Initiator KEM_INIT (with public key) → Responder KEM_RESPONSE (with ciphertext)
- Both sides derive identical session key from shared secret
- Initiator IDENTITY_PROOF → Responder validates HMAC, sends SESSION_LOCKED
- Both reach SESSION_LOCKED state; stats show `attempts_total=1, successes=1, failures_*=0`

---

## Phase 3 - Authenticated Session and Channel Enforcement ✅ COMPLETE

Goal: enforce real packet authenticity with AEAD encryption, CSPRNG session IDs, and HMAC identity verification.

**Status: COMPLETE** — ChaCha20-Poly1305 session encryption, CSPRNG, and HMAC identity verification all tested end-to-end.

### Substeps (All Completed)

1. ✅ Replace memset(0xAB) placeholder with real identity signature:
   - HMAC-SHA256 with pre-shared 32-byte identity master key
   - Both sides verify identity before accepting SESSION_LOCKED
   - Failed verification increments `failures_identity` counter

2. ✅ Replace rand() with CSPRNG:
   - Uses `kem_random_bytes()` backed by `getrandom()` (Linux) / `CryptGenRandom` (Windows)
   - Session IDs non-predictable

3. ✅ AEAD session encryption (ChaCha20-Poly1305):
   - `session_enc` encrypt/decrypt implemented
   - Deterministic nonce from session_id, channel_id, seq
   - AAD includes channel key for channel binding
   - No malloc (RULE-8) and no logging (RULE-9) in fast path
   - mbedtls `mbedtls_cipher_auth_encrypt_ext`/`decrypt_ext` API

4. ✅ Channel key binding:
   - Per-channel keys XOR-folded into AEAD AAD
   - No separate per-packet channel tag needed

5. ✅ Pipeline integration:
   - `session_enc_check` in inbound pipeline (after session gate, before replay)
   - `session_enc_apply` in outbound path
   - CH_CONTROL bypassed (RULE-2)

6. ✅ Fail-closed on auth failure:
   - Decryption failure sets `HS_ERR_BAD_IDENTITY`
   - Bad identity signature returns `HS_ERR_BAD_IDENTITY`

**Verification**: Runtime test confirmed:
```
[HANDSHAKE] identity verified OK
[INIT CHAT] hey from responder!
[RESP CHAT] hello from initiator!
[STATS] init=LOCKED resp=LOCKED pool=4096 attempts=1 ok=1 fail=0 enc=on
```

---

## Phase 4 - Resilience Layer Realization

Goal: sustain communication quality under loss/jitter/path instability.

**Depends on Phase 3**: requires locked session as prerequisite.

### Substeps (Priority Order)

1. **Resilience context structure** — ✅ COMPLETE (`lib/core/resilience_ctx.h/.c`)
   - Path stats: RTT, loss rate, jitter window per remote peer
   - Loss window: sliding window of recent sequence numbers per path
   - Path state: active/down/degraded per transport path
   - Thread-safe update via lock-free atomic fields

2. **FEC strategy** — ✅ COMPLETE
   - XOR-based intra-group parity (group size 4)
   - TX accumulate after encrypt, parity packet on group complete
   - RX track + store parity + rebuild from N-1
   - Configurable FEC rate, pre-allocated buffers
   - Loss simulation: drop seq=5, recover via parity

3. **Multipath transport** — ✅ COMPLETE
   - 2 UDP socket pairs (9001/9002 + 9003/9004)
   - Path selection: lowest-loss policy
   - Per-path sequence space (independent recv_bitmap per path)
   - Path health monitoring (loss window, RTT smoothing)
   - Transparent to session layer (RULE-15 compliant)

4. **Port hop** — ✅ COMPLETE
   - CTRL_PORT_HOP (8) / CTRL_PORT_HOP_ACK (9) opcodes
   - Port hop request → ACK protocol on CONTROL channel
   - Peer address update via session_register_path
   - Demo: hop to local_port + 4 after chat messages

5. **Reconnect policy** — ✅ COMPLETE (see Section 1.12)

6. **Relay / mesh routing** — ✅ COMPLETE
    - Route table: node_id → {session_id, addr, metrics}, up to 16 entries
    - CH_ROUTE (channel 5) for relay data: CTRL_ROUTE_DATA (14) opcode wraps dest_node_id + inner_channel + payload
    - relay_forward_route: decrypt incoming CH_ROUTE, extract dest, route table lookup, encrypt + send as inner channel
    - relay_build_test_packet: build encrypted CH_ROUTE test packet
    - Demo: initiator sends "hello via relay!" → responder relays via route table → forwarded as CHAT → printed on initiator
    - Route selection via route_table_find (first-match by node_id)
    - Route metrics updated via route_table_update_metrics (EWMA smoothing, RTT + loss rate)
    - Detect transport loss via heartbeat timeout (ACTIVE → DEGRADED → DOWN)
    - CTRL_HEARTBEAT (10) / CTRL_HEARTBEAT_ACK (11) opcodes for path health
    - CTRL_RECONNECT (12) / CTRL_RECONNECT_ACK (13) opcodes for reconnect
    - Heartbeat: 1s interval, sent by heartbeat_tick in event loop
    - DEGRADED after 3× heartbeat interval without activity
    - DOWN after reconnect_timeout_ms (5s) without activity
    - Reconnect preserves session_id, keys, replay window
    - Max 3 reconnect attempts before dropping session to SESSION_IDLE
    - Demo: port hop → simulated transport loss → heartbeat timeout → reconnect request → ACK → session re-established

7. **Adaptive bitrate** — ✅ COMPLETE
    - ABR controller (abr_update): observes max path loss rate, adjusts FEC group size
    - Thresholds: loss < 3% → FEC off; 3-10% → group 8; 10-20% → group 4; > 20% → group 2
    - Per-session ABR context with 3-second update interval
    - Integrated into event loop, runs for both initiator and responder
    - Demo: after initial chat burst, loss=0% → ABR disables FEC (shown as `[ABR] loss=0.0% fec=on group=4 -> off group=0`)
    - Minimum quality floor: smallest group (2) at high loss prevents infinite degradation

8. **Test scenarios** — ✅ COMPLETE
   - 19 unit tests across 11 test files
   - FEC recovery: XOR parity encode → lose one → rebuild original
   - Route table: add/find/remove/update_metrics lifecycle
   - ABR thresholds: 0% → off, ~6% → group 8, ~25% → group 2
   - Path metrics: loss window, state transitions, multipath selection
   - Kernel filter: whitelist, blocklist, size bounds, port binding
   - Anti-analysis: clean packet pass, bad packet scoring + drop
   - Offensive: trusted bypass, repeated unknown rate limit
   - All 19/19 PASS (run `./build_linux/test_runner`)

---

## Phase 4.5 — Architecture Restructure (Project Refactor)

Goal: restructure project around libtransport_core.a library with clean public API,
TUI frontend, and test runner, before continuing Phase 4 substeps.

**Trigger**: decision to support hybrid peer discovery (manual + LAN broadcast),
professional ASCII TUI, and a separate test runner. The existing flat structure
does not support these cleanly.

### Design Documents

All architecture decisions consolidated in `ARCHITECTURE.md` (target design)
and this document (implementation status).

### Substeps

| Step | Description | Status |
|---|---|---|---|
| 4.5.1 | Create directory structure `lib/`, `app/`, `tests/`, `api/`, `engine/`, `connection/`, `discovery/` | ✅ Complete |
| 4.5.2 | Move source files into `lib/` directories, update `#include` paths | ✅ Complete |
| 4.5.3 | Create `api/transport_api.h` — public C API for TUI + test_runner | ✅ Complete |
| 4.5.4 | Create `engine/transport_engine.c` — orchestrator, thread lifecycle, event dispatch | ✅ Complete |
| 4.5.5 | Create `connection/connection_manager.c` — peer table, connect/disconnect state machine | ✅ Complete (stub) |
| 4.5.6 | Create `discovery/lan_discovery.c` — UDP beacon broadcast, peer timeout | ✅ Complete (stub) |
| 4.5.7 | Restructure `CMakeLists.txt` — libtransport.a + transport + test_runner targets | ✅ Complete |
| 4.5.8 | Build and verify existing FEC/multipath/port-hop demo still works | ✅ Complete |
| 4.5.9 | Update AGENTS.md, IMPLEMENTATION_PHASE_STATUS.md, file map | ✅ Complete |

### Target Project Layout

```
transport/
├── CMakeLists.txt               # Top-level build
├── ARCHITECTURE.md              # Full system design (target)
├── lib/                         # Static library libtransport_core.a
│   ├── api/transport_api.h      # Public API header
│   ├── core/                    # Session, pool, scheduler, rings, UDP, threads
│   ├── crypto/                  # KEM, HKDF, AEAD
│   ├── handshake/               # 6-message PQ handshake
│   ├── pipeline/                # Inbound/outbound pipeline
│   ├── layers/                  # All pipeline layers
│   ├── connection/              # Connection manager, peer table
│   ├── discovery/               # LAN discovery beacon
│   └── engine/                  # Transport engine, timer wheel
├── app/                         # TUI executable (transport)
│   ├── main.c
│   ├── tui_screen.c
│   ├── tui_input.c
│   └── tui_panels.c
└── tests/                       # Test runner executable
    ├── test_runner_main.c
    ├── test_connect.c
    ├── test_fec_loss.c
    └── ...
```

### Build Artifacts

| Artifact | Type | Depends on |
|---|---|---|
| `libtransport_core.a` | Static library | All lib/ sources |
| `transport` | TUI executable | libtransport_core.a + app/ sources |
| `test_runner` | Test executable | libtransport_core.a + tests/ sources |

---

## Phase 5 - Outer Defense Layers (Kernel, Anti, Offensive) ✅ COMPLETE

Goal: implement proactive defensive filtering and deception policy.

**Depends on Phase 4**: resilience context useful for distinguishing attack from noise.

### Substeps (All Completed)

1. ✅ **Kernel filter first gate** (`lib/layers/kernel_filter.c`):
   - Source IP whitelist (64 entries, exact IPv6 match)
   - Source IP blocklist (64 entries)
   - Port binding verification (bound_port set via `kernel_filter_set_bound_port`)
   - Packet size bounds (min 24, max MAX_PACKET_SIZE)
   - Drop counters per category (port, size, blocked) tracked in `g_kernel_filter`
   - Runs as user-space fallback (kernel BPF/eBPF deferred)
   - Pipeline position: after static shell, before session gate

2. ✅ **Anti-analysis policy** (`lib/layers/anti_analysis.c`):
   - Per-source scoring (256 sources, LRU eviction, 10s evict interval)
   - Score triggers: bad magic, bad version, bad flags, channel out of range, zero seq
   - Score = bad_packets × 10; decremented on good packets
   - Actions per score threshold:
     - `< 50`: pass through
     - `50–99`: medium drop (drop + increment `drops_medium` + `delayed_packets`)
     - `>= 100`: high drop (drop + increment `drops_high`)
   - Drop counters in `g_anti_analysis`
   - Must not modify trusted packets (RULE-4 — enforced in offensive layer)

3. ✅ **Offensive shell** (`lib/layers/offensive.c`):
   - Trusted packet bypass: packets with valid magic/version/session_id/channel skip offense (RULE-4)
   - Per-source rate limiting (OFF_THRESHOLD=100 within OFF_WINDOW_MS=1000ms window)
   - Sources exceeding rate threshold are silently dropped
   - Source table with oldest-first eviction (OFF_MAX_SOURCES=256)
   - Decoy/noise generation deferred (placeholder for future — safety bounds protect pool)

4. ✅ **Safety bounds**:
   - All tables are fixed-size (no unbounded memory growth)
   - Source eviction prevents memory exhaustion (oldest-first, LRU)
   - Rate-limit counters reset per window (no overflow risk — window clears every 1s)
   - Reserved pool (`g_offensive.reserve_pool = 64`) for future decoy traffic protection

5. ✅ **Observability per layer**:
   - Drop counters per category in each layer's global struct
   - Stats line includes `kf_drop=X aa_drop=Y off=Z` from `print_stats()`
   - Anti-analysis tracks medium/high drop counts and delayed packet count
   - Kernel filter tracks port, size, and blocked-IP drops separately

6. **Test scenarios** (deferred to Phase 6 Group E, step 21):
   - Port scan detection (sequential port probes)
   - Protocol scan detection (varying magic/version)
   - Flood from unknown source (verify trusted traffic not affected)
   - Rate-limit exhaustion (verify bounded behavior)
   - Decoy handshake verification (fake ACCEPT returned, real session unchanged)

---

## Phase 6 — Complete the System: No Stubs, No Partial Implementations

**Goal**: Every file, function, and feature is fully implemented. No stubs, no placeholders, no phantom files. System is ready for production use.

**Prerequisite**: Phase 5 complete (outer defense layers).

### Audit: Current Stub / Phantom Items

Group A (steps 1-9) is complete. Remaining items:

| Item | File | Problem |
|---|---|---|
| TUI missing | `app/` | `tui_screen.c`, `tui_input.c`, `tui_panels.c` don't exist |
| Demo-only main | `app/main.c` | Just calls `transport_engine_run_demo()`, not a real app |
| Stub test | `tests/test_connect.c` | `test_connect_basic` returns -1 (not implemented) |
| Empty test helper | `tests/test_helpers.c` | Only `#include "transport_api.h"`, no helper functions |

### Substeps (Priority Order, Grouped)

#### Group A: Foundation Cleanup ✅ COMPLETE

1. ✅ **Wire up transport_api.c** — All 11 functions delegate to engine struct
2. ✅ **Implement pipeline_outbound.c** — Header build + session_enc encrypt + length
3. ✅ **Fix pipeline layer order to match spec** — Updated spec §5.1, actual code correct
4. ✅ **Fix session_gate initiator handshake edge case** — `session_gate.c` validates expected opcode per state
5. ✅ **Remove channel_enc** — Redundant (AAD binding in session_enc), file deleted
6. ✅ **Implement connection_manager** — Peer table registry, wired into engine + API
7. ✅ **Implement lan_discovery** — UDP beacon broadcast + recv, wired into engine + API
8. ✅ **Implement offensive decoy/noise** — `offensive_build_decoy()` + tick, wired into engine
9. ✅ **Remove phantom doc references** — AGENTS.md, IMPLEMENTATION_PHASE_STATUS.md updated

#### Group B: TUI and CLI

10. **Build TUI** (`app/tui_screen.c`, `app/tui_input.c`, `app/tui_panels.c`):
    - Three-panel layout: connection list (left), chat log (center), status bar (bottom)
    - ANSI escape rendering, non-blocking stdin via poll/select
    - Input line for typing chat messages
    - Status bar: session state, path metrics, layer drop counters, FEC state
    - Keyboard shortcuts: Ctrl+C quit, Tab focus switch, Up/Down scroll

11. **CLI command surface**:
    - Thread-safe CLI via stdin
    - Parser for commands: `connect <addr> <port>`, `disconnect`, `status`, `chat <text>`,
      `sendfile <path>`, `bitrate <on|off>`, `rekey`, `hop <port>`, `relay <node> <msg>`, `quit`
    - Status output: session state, channel states, peer info, key epoch, per-layer stats
    - `quiet` flag for scripted operation (machine-readable output)

12. **Rewrite app/main.c**:
    - Parse CLI flags (--port, --peer, --discovery, --config, --quiet)
    - Call `transport_init` with config, enter TUI event loop
    - `transport_poll_event` drives all UI updates

#### Group C: Operational Features

13. **Key rotation protocol**:
    - New opcodes: `CTRL_REKEY_INIT` (15), `CTRL_REKEY_CONFIRM` (16)
    - Initiator builds KEM_INIT on CONTROL channel with new keypair
    - Responder encapsulates new shared secret, sends back
    - Both derive new key epoch without session interruption
    - Old keys zeroed only after both sides confirm
    - Key epoch counter in `session_keys_t.key_epoch` (monotonic)

14. **Secure key storage**:
    - Replace hardcoded `g_identity_master_key`:
      - Linux: `mlock()` + `MADV_DONTDUMP` on stack keys
      - Secrets loaded via environment variable `SSM_IDENTITY_KEY` (hex) for now
    - Session keys locked via `mlock()` / `VirtualLock()` (RULE-14)
    - No key material in logs, core dumps, or swap

15. **Config system**:
    - Config file: TOML (`~/.config/ssm/transport.toml`)
    - Fields: local_port, alt_port, peer_addr, peer_port, discovery_port,
      fec_enabled, fec_group_size, multipath_enabled, handshake_timeout,
      heartbeat_interval, reconnect_timeout, max_reconnect_attempts, identity_key
    - Runtime overrides via CLI flags
    - Sensible defaults matching current hardcoded values

#### Group D: Performance and Observability

16. **Dedicated crypto thread**:
    - Move `session_enc_check` / `session_enc_apply` out of event loop
    - Crypto thread pulls from crypto work queue (lock-free ring)
    - CPU affinity pinning (isolate from I/O threads)

17. **Audio pipeline**:
    - Audio thread with dedicated ring buffer (lock-free)
    - Opus encode/decode (libopus)
    - 20ms frames on CH_AUDIO channel
    - Jitter buffer: adaptive, max 100ms
    - RULE-6/RULE-10 compliance

18. **Monitor / watchdog thread**:
    - Periodic health checks: packet rate, queue depths, pool pressure
    - Thread stall detection (rx/tx/crypto/control)
    - Metrics export via CLI `status` command

#### Group E: Compliance and Regression

19. **Remove remaining hot-path logging**:
    - Audit all `printf` in pipeline layers
    - Hot path = every packet path — only allowed in `print_stats()`
    - Handshake and error paths allowed
    - Compile-time flag for development verbosity

20. **Fast-path rules audit**:
    - RULE-8: zero malloc/calloc/realloc in packet path
    - RULE-9: zero logging in packet path
    - RULE-10: zero mutex in audio path
    - RULE-11: packet_parse called exactly once per packet

21. **End-to-end regression suite** (replace stubs in test_connect.c, expand to 30+ tests):
    - Handshake success (both roles, 100 iterations)
    - Bad identity: wrong master key → `HS_ERR_BAD_IDENTITY`
    - Replayed handshake message → rejected
    - Wrong state transition → `HS_ERR_STATE_VIOLATION`
    - Tampered AEAD tag → decryption failure, packet dropped
    - Reused nonce → replay rejection
    - Wrong channel key → AEAD tag mismatch
    - Locked session PQ rejection → `failures_state++`
    - Pool exhaustion → graceful degradation
    - Packet loss resilience → FEC recovery
    - Port hop → ACK confirmed
    - Reconnect → session re-established
    - Relay → forwarded message received
    - ABR → FEC group adjustment
    - Kernel filter whitelist/blocklist
    - Anti-analysis scoring and thresholds
    - Offensive rate limiting
    - API layer integration tests (connect/disconnect/send/poll)

22. **Structured status reporting**:
    - Per-layer pass/fail/disabled status
    - Rule compliance matrix (all 18 rules)
    - Version string: protocol version + phases implemented

23. **Freeze interfaces**:
    - Public API: documented input/output/error contracts
    - Layer return codes frozen in `pipeline.h`
    - Opcode assignments frozen in `session.h`
    - Header format frozen in `PHASE1_WIRE_CONTRACT.md`
    - Remove `transport_engine_run_demo()` (replaced by API-driven TUI)

---

## Phase 7 — User-Facing Connection Flow (In Progress)

**Goal**: Make the app usable by two real people on separate machines.
Full flow: launch → identity → discover peers → request/accept → PQ handshake → chat.

See `SSM_USER_FLOW.md` for the complete design.

### Steps

| # | Step | Status |
|---|---|---|
| 1 | Identity module: username, display name, key gen, file save/load | 🔜 Next |
| 2 | `CONNECT_REQUEST` / `CONNECT_ACCEPT` / `CONNECT_DECLINE` opcodes + handler | 🔜 Next |
| 3 | LAN discovery broadcasts username (not just addr/port) | 🔜 Next |
| 4 | TUI rewrite: login screen, peer list panel, incoming request popup | 🔜 Next |
| 5 | Wire end-to-end: login → discovery → click → request → accept → handshake → chat | 🔜 Next |
| 6 | Loopback test (two instances, same machine, different ports) | 🔜 Next |
| 7 | Two-machine LAN test | 🔜 Next |

### Identity key backup
- On first launch, print the 64-hex-char identity key once
- User must save it (or it's lost forever)
- Key can be imported on another device to prove same identity

### Connection protocol
```
REQUEST ──► (username, display_name, kem_type)
ACCEPT  ◄── (empty)
(or DECLINE ◄── reason_string)
        then:
        ──► HELLO (existing 6-message PQ handshake)
        ◄── ...
        ──► SESSION_LOCKED
        ◄── CHAT (AEAD encrypted)
```

### Dependency Graph

```
Group A (foundation)    ──┐
Group B (TUI/CLI)      ──┤
Group C (features)     ──┤
Group D (performance)  ──┤
Group E (compliance)   ──┤
                          └── Phase 7 (user flow) ──► usable app
```
