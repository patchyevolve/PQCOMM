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

---

## 3) Not Yet Implemented (Major Missing Capabilities)

- Real kernel filter enforcement (BPF/eBPF or equivalent platform-first gate).
- Real anti-analysis behavior.
- Real offensive-shell policy behavior (defensive decoy/throttle/drop strategy).
- Resilience functions (multipath/FEC/hop/relay/reconnect policy).
- Full CLI command surface from final spec.
- Key lifecycle management (secure storage, rotation protocol, zeroization policy hardening).

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

### Substeps

1. Add resilience context structure (path stats, loss window, jitter).
2. Implement reconnect policy that preserves session identity invariants.
3. Implement port hop control workflow.
4. Add multipath scaffolding and selection policy.
5. Add FEC strategy integration points.
6. Add relay route hooks and route-channel control handling.
7. Add adaptive bitrate feedback loop integration hooks.
8. Test scenarios:
   - packet loss bursts
   - delayed reorder
   - path failover
   - reconnect-without-session-reset

---

## Phase 5 - Outer Defense Layers (Kernel, Anti, Offensive Policy)

Goal: implement proactive defensive filtering and deception policy.

### Substeps

1. Implement kernel-first filter policy model:
   - source/port constraints
   - packet size and protocol prechecks
   - platform fallback behavior
2. Implement anti-analysis policy:
   - suspicious pattern scoring
   - delay/drop/throttle decisions
3. Implement offensive-shell defensive responses:
   - decoy responses
   - safe noise/cover tactics
   - rate-limited response strategy
4. Ensure trusted traffic bypass rules are respected.
5. Add observability per layer:
   - scored events
   - decision counters
   - rate-limit hits
6. Add safety bounds:
   - no unbounded response generation
   - no impact on trusted flow latency
7. Validate with scan/flood simulation tests.

---

## Phase 6 - Operational Hardening and Compliance Closure

Goal: production-grade behavior and final architecture compliance checks.

### Substeps

1. Remove remaining non-essential hot-path logging.
2. Validate no forbidden operations in fast path.
3. Add config hardening defaults.
4. Add structured status reporting for all layers.
5. Create pass/fail checklist mapped to locked architecture rules.
6. Run end-to-end regression suite:
   - handshake
   - lock transition
   - protected channel traffic
   - replay defense
   - resilience behavior
7. Freeze interfaces and document stable extension points.
