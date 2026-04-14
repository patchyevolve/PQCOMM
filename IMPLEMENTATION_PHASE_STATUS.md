# Transport Implementation Status and Phase Roadmap

Status date: 2026-04-13

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
- session_enc
- channel_enc

These are wired in pipeline order and currently return pass.

---

## 2) Partially Implemented / Needs Hardening

### 2.1 Control and Session Logic

- Handshake exists but is still a transport-level placeholder (not PQ).
- Session establishment is functional but not cryptographically verified.

### 2.2 Layer Outcome Semantics

- New layer drop categories are tracked, but all stub logic is currently no-op.
- Some drop categories are present primarily for future readiness.

### 2.3 Performance and Fast-Path Rules

- Major log spam is reduced, but full fast-path hardening and profiling are still pending.
- Latency/throughput/CPU validation against final targets is not complete.

---

## 3) Not Yet Implemented (Major Missing Capabilities)

- Real kernel filter enforcement (BPF/eBPF or equivalent platform-first gate).
- Real anti-analysis behavior.
- Real offensive-shell policy behavior (defensive decoy/throttle/drop strategy).
- Post-quantum handshake and identity verification.
- Session/channel encryption and authenticated packet enforcement.
- Resilience functions (multipath/FEC/hop/relay/reconnect policy).
- Full CLI command surface from final spec.
- Key lifecycle management (secure storage, rotation protocol, zeroization policy hardening).

---

## 4) Later Phases Roadmap (Detailed Substeps)

## Phase 2 - Secure Session Foundation (PQ + Symmetric Transition)

Goal: complete one-time PQ handshake and clean transition into locked symmetric mode.

### Substeps

1. Define handshake message contract:
   - HELLO fields
   - PQ KEM payload fields
   - identity proof fields
   - handshake failure reasons
2. Introduce handshake state guards:
   - reject invalid transitions
   - enforce one-time handshake per session
3. Implement PQ key exchange path (session setup only).
4. Add identity verification step and lock transition criteria.
5. Derive session/channel secrets from handshake output.
6. Ensure post-lock traffic forbids PQ operations.
7. Add handshake counters/telemetry for success/failure.
8. Add deterministic test cases:
   - success path
   - bad identity
   - replayed handshake message
   - wrong state transition

---

## Phase 3 - Authenticated Session and Channel Enforcement

Goal: enforce real packet authenticity and confidentiality in the data path.

### Substeps

1. Define authenticated packet fields and ordering:
   - nonce handling policy
   - auth tag expectations
2. Implement `session_enc` validation/decrypt path.
3. Implement `channel_enc` validation/decrypt path.
4. Bind replay checks to authenticated packet semantics.
5. Ensure decrypt/auth checks happen at correct pipeline position.
6. Add fail-closed behavior on auth failure.
7. Add key-epoch/version handling for rotations.
8. Add tests for:
   - tampered tag
   - reused nonce
   - wrong channel key
   - out-of-order packet replay

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

---

## 5) Immediate Next Action Recommendation

If continuing now, the best next phase entry is:

- Phase 2, substep 1:
  - formalize handshake contract and transition rules,
  - then implement one-time PQ session setup path.

Reason: this unlocks real `session_enc`/`channel_enc` behavior and makes subsequent layers meaningful.

