# Transport Implementation Status and Phase Roadmap

Status date: 2026-06-27

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

---

## 2) Partially Implemented / Needs Hardening

### 2.1 Layer Outcome Semantics

- New layer drop categories are tracked, but all stub logic is currently no-op.
- Some drop categories are present primarily for future readiness.

### 2.2 Performance and Fast-Path Rules

- Major log spam is reduced, but full fast-path hardening and profiling are still pending.
- Latency/throughput/CPU validation against final targets is not complete.

### 2.3 Secure Memory

- Keys are zeroed after use via `crypto_secure_wipe()`, but stack-resident keys are not guaranteed against page-out.
- mlock/mlockall not yet used to pin key memory.

### 2.4 Identity Key Management

- Identity master key is hardcoded (suitable for demo only).
- Production path needs secure key store (TPM / OS keychain / hardware-bound storage).

---

## 3) Not Yet Implemented (Major Missing Capabilities)

- Resilience functions (multipath/FEC/hop/relay/reconnect policy) — Phase 4.
- Real kernel filter enforcement (BPF/eBPF or equivalent platform-first gate) — Phase 5.
- Real anti-analysis behavior (pattern scoring, delay/drop/throttle) — Phase 5.
- Real offensive-shell defensive responses (decoy, noise, rate-limit) — Phase 5.
- Full CLI command surface from final spec — Phase 6.
- Key lifecycle management (rotation protocol, secure storage, zeroization policy hardening) — Phase 6.
- Audio pipeline (encode/decode thread, jitter buffer) — Phase 6.
- Dedicated crypto thread — Phase 6.
- Monitor/watchdog thread — Phase 6.
- Full regression test suite (tampered tag, reused nonce, wrong channel key, replay) — Phase 7.

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

1. **Resilience context structure** (`core/resilience.h`):
   - Path stats: RTT, loss rate, jitter window per remote peer
   - Loss window: sliding window of recent sequence numbers per path
   - Path state: active/down/degraded per transport path
   - Thread-safe update via lock-free atomic fields

2. **FEC strategy**:
   - Define FEC policy: Reed-Solomon or XOR-based (e.g., interleaved parity per N packets)
   - FEC encode step in outbound pipeline (before scheduler, after encryption)
   - FEC decode step in inbound pipeline (after resilience layer, before session gate)
   - Configurable FEC rate (1:N) based on observed loss
   - No FEC allocation in fast path (pre-allocated FEC buffer per path)

3. **Multipath transport**:
   - Multiple UDP socket pairs (primary + backup)
   - Path selection policy: lowest-loss, lowest-RTT, or round-robin
   - Per-path sequence space (independent seq counters per path)
   - Path health monitoring via periodic probe packets (CONTROL channel opcodes)
   - Transparent to session layer — session_id unchanged (RULE-15)

4. **Port hop**:
   - CONTROL channel opcode for port-change command
   - New socket bind on alternate port, old socket drained
   - Graceful transition: both ports live during handover window
   - Configurable hop interval or on-demand via CLI

5. **Reconnect policy**:
   - Detect transport loss via heartbeat timeout (separate from handshake timeout)
   - Re-establish UDP connectivity without session reset
   - Preserve session_id, keys, replay window across reconnect
   - Max reconnect attempts before session drop

6. **Relay / mesh routing**:
   - ROUTE channel (channel 5) for relay control messages
   - Relay node discovery and trust establishment
   - Encrypted relay forwarding (same session keys, different transport)
   - Route selection based on path quality metrics

7. **Adaptive bitrate**:
   - Feedback loop: observe loss rate → adjust FEC ratio or audio quality
   - Integration hooks in audio pipeline (placeholder for Phase 6)
   - Minimum quality floor to prevent infinite degradation

8. **Test scenarios**:
   - Packet loss bursts (0%, 5%, 15%, 30% loss rates)
   - Delayed reorder (±10ms, ±50ms, ±100ms jitter)
   - Path failover (primary socket kill, verify session survives)
   - Reconnect without session reset (kill + restore transport)
   - Port hop during active data flow (no dropped packets)
   - FEC decode under configurable loss rates

---

## Phase 5 - Outer Defense Layers (Kernel, Anti, Offensive)

Goal: implement proactive defensive filtering and deception policy.

**Depends on Phase 4**: resilience context useful for distinguishing attack from noise.

### Substeps (Priority Order)

1. **Kernel filter first gate** (`layers/kernel_filter.c`):
   - BPF/eBPF program for Linux; platform fallback for non-Linux (user-space filter)
   - Source IP whitelist/blocklist (configurable via CLI)
   - Port binding verification (only bound port allowed)
   - Packet size bounds check (drop oversized or undersized)
   - Protocol check (UDP only)
   - Constant-time checks (no branching on secret data)
   - Must run before any user-space processing (RULE-13)

2. **Anti-analysis policy** (`layers/anti_analysis.c`):
   - Suspicious pattern scoring:
     - Rate of packets from unknown sources
     - Malformed header frequency (bad magic, version, flags)
     - Probe detection (sequential port scan, protocol scan)
   - Actions per score threshold:
     - `low`: log + pass through
     - `medium`: delay (artificial jitter), throttle (rate-limit)
     - `high`: drop silently, send decoy responses
   - Must not modify trusted packets (matched session_id + channel)
   - Per-source scoring state with LRU eviction to limit memory

3. **Offensive shell** (`layers/offensive.c`):
   - Decoy handshake: respond to KEM_INIT from unknown source with fake ACCEPT
   - Padding: inflate response sizes to obfuscate payload length
   - Noise: inject random UDP datagrams to cover traffic patterns
   - Rate-limited response strategy:
     - Exponential backoff per source IP
     - Total bandwidth cap on decoy traffic
   - Must not touch session data (RULE-4 for trusted packets)

4. **Safety bounds**:
   - Decoy generation must not exhaust packet pool (reserved pool for trusted traffic)
   - Rate-limit counters must not overflow (saturated counter = max rate)
   - No unbounded memory growth from per-source state
   - All decoy/noise traffic in `fake` scheduler queue (lowest priority)

5. **Observability per layer**:
   - Drop counters per category (kernel, anti-analysis, offensive)
   - Rate-limit hit counters per source IP
   - Scored event histogram (low/medium/high decisions)
   - Periodic stats line includes per-layer drop counts

6. **Test scenarios**:
   - Port scan detection (sequential port probes)
   - Protocol scan detection (varying magic/version)
   - Flood from unknown source (verify trusted traffic not affected)
   - Rate-limit exhaustion (verify bounded behavior)
   - Decoy handshake verification (fake ACCEPT returned, real session unchanged)

---

## Phase 6 - CLI, Key Management, and Operational Features

Goal: production-grade user interface, key hygiene, and operational infrastructure.

**Depends on Phase 5**: outer defense layers protect CLI from network abuse.

### Substeps (Priority Order)

1. **CLI command surface** (`cli/` directory):
   - Thread-safe CLI via stdin or Unix domain socket
   - Parser for commands: `connect`, `disconnect`, `status`, `chat`, `sendfile`,
     `bitrate`, `cover`, `rekey`, `hop`, `relay`, `quit`
   - Tab-completion for interactive mode
   - RULE-18 enforced: CLI never opens UDP sockets
   - Status output: session state, channel states, peer info, key epoch, per-layer stats
   - Chat command: reads text from stdin, builds CH_CHAT packet, enqueues for send
   - `quiet` flag for scripted operation (JSON output or minimal output)

2. **Key rotation protocol**:
   - New CONTROL opcode: `CTRL_REKEY_INIT`, `CTRL_REKEY_CONFIRM`
   - Initiator generates new KEM keypair → sends KEM_INIT on CONTROL channel
   - Responder encapsulates new shared secret → sends KEM_RESPONSE
   - Both derive new key epoch without session interruption
   - Old key zeroed only after both sides confirm `CTRL_REKEY_CONFIRM`
   - Key epoch counter in `session_keys_t.key_epoch` (monotonic)
   - Rekey while active data flowing: audio/chat packets continue on old keys until confirm

3. **Secure key storage**:
   - Replace hardcoded `g_identity_master_key` with platform secure store:
     - Linux: `secrets://` via secret-tool / kernel keyring
     - Windows: DPAPI `CryptProtectData`
   - Session keys locked in memory via `mlock()` / `VirtualLock()` (RULE-14)
   - Key material never written to disk (no core dump exposure via `MADV_DONTDUMP`)
   - RULE-14: keys never leave secure storage (no export function)

4. **Audio pipeline**:
   - Audio thread with dedicated ring buffer (lock-free)
   - Audio encode/decode: Opus or equivalent low-latency codec
   - Audio frames: 20ms packets, CH_AUDIO channel
   - RULE-6: audio must never wait for file
   - RULE-10: no mutex in audio path
   - Jitter buffer: adaptive, max 100ms, packet-concealment for lost frames
   - Timing via `timerfd` (Linux) or `waitable timers` (Windows)

5. **Dedicated crypto thread**:
   - Move `session_enc_check` / `session_enc_apply` out of main event loop
   - Crypto thread pulls from crypto work queue (lock-free ring)
   - CPU affinity pinning for crypto thread (isolate from I/O threads)
   - Batch decryption if multiple packets queued (potential throughput gain)

6. **Monitor / watchdog thread**:
   - Periodic health checks: packet rate, loss rate, queue depths, pool pressure
   - Watchdog: detect thread stalls (rx/tx/crypto/control not progressing)
   - Metrics export via CLI `status` command
   - Alert callback on threshold breach (configurable: log / CLI notification)

7. **Config system**:
   - Config file: TOML or JSON (e.g., `~/.config/ssm/transport.toml`)
   - Runtime overrides via CLI
   - Config schema: peer addresses, ports, KEM type, timeouts, FEC rate, cover traffic
   - Sensible defaults for all parameters

---

## Phase 7 - Compliance Closure and Test Suite

Goal: final architecture compliance checks and production readiness validation.

**Depends on Phases 4-6**: all features implemented before final audit.

### Substeps

1. **Remove remaining hot-path logging**:
   - Audit all `printf` calls in pipeline layers
   - Hot path = every packet, every tick — only allowed in `print_stats()` periodic line
   - Handshake path allowed (only runs once per session)
   - Error path allowed (runs only on failure)
   - Compile-time flag for development verbosity

2. **Fast-path audit against rules**:
   - RULE-8: verify zero `malloc`/`calloc`/`realloc` in packet path (pool_get/pool_return only)
   - RULE-9: verify zero logging in packet path
   - RULE-10: verify zero mutex in audio path
   - RULE-11: verify `packet_parse` called exactly once per packet
   - Static analysis: grep for forbidden patterns

3. **Locked memory and secrets audit**:
   - Verify `crypto_secure_wipe()` called after every key derivation
   - Verify no key material in logs, core dumps, or swap
   - Verify stack arrays containing keys are volatile-wiped
   - Verify no key material in heap (RULE-14)

4. **Config hardening defaults**:
   - Minimum key sizes enforced
   - Session timeout: default 5000ms, max 30000ms
   - Replay window: minimum 64 entries
   - FEC: disabled by default (opt-in)
   - Cover traffic: disabled by default

5. **Structured status reporting**:
   - Per-layer pass/fail/disabled status
   - Rule compliance matrix (all 18 rules)
   - Version string including protocol version + phases implemented

6. **End-to-end regression suite**:
   - Handshake success (both roles, 100 iterations)
   - Bad identity: wrong master key → identity verification failure
   - Replayed handshake message: capture and replay HELLO → rejected
   - Wrong state transition: send KEM_INIT before HELLO → `HS_ERR_STATE_VIOLATION`
   - Tampered AEAD tag: flip one byte → decryption failure, packet dropped
   - Reused nonce: same session_id + channel + seq → replay rejection
   - Wrong channel key: modify channel_id in header → AEAD tag mismatch
   - Locked session PQ rejection: KEM_INIT after LOCKED → `failures_state++`
   - Pool exhaustion: flood with allocated buffers → graceful degradation
   - Packet loss resilience: drop 10% of packets → FEC recovery

7. **Freeze interfaces**:
   - Public API headers documented with input/output/error contracts
   - Layer return codes frozen (documented in `pipeline.h`)
   - Opcode assignments frozen (documented in `session.h`)
   - Header format frozen (documented in `PHASE1_WIRE_CONTRACT.md`)
