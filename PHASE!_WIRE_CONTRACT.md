diff --git a/transport/PHASE1_WIRE_CONTRACT.md b/transport/PHASE1_WIRE_CONTRACT.md
new file mode 100644
--- /dev/null
+++ b/transport/PHASE1_WIRE_CONTRACT.md
@@
+# Phase 1 Wire Contract (Transport)
+
+Status: Frozen for Phase 1
+Scope: Packet format and validation behavior used by current transport pipeline.
+Security mode: Phase 1 transport-only (no PQ, no AEAD tag validation in active path)
+
+## Header Layout (24 bytes)
+
+Offsets (bytes):
+- 0..3   : magic      (uint32)
+- 4      : version    (uint8)
+- 5      : flags      (uint8)
+- 6..13  : session_id (uint64)
+- 14     : channel_id (uint8)
+- 15..18 : seq        (uint32)
+- 19..22 : length     (uint32)
+- 23     : reserved/padding (currently unused)
+
+Payload starts at offset 24.
+
+## Parse Invariants
+
+- Packet size must be >= 24.
+- Declared `length` must satisfy:
+  - `length <= MAX_PACKET_SIZE - 24`
+  - `buf->len == 24 + length`
+- Parser performs a single header extraction pass.
+
+## Static Shell Invariants
+
+- `magic == 0xAABBCCDD`
+- `version == 1`
+- `flags == 0`
+- `length > 0`
+- `length <= 1400`
+- `channel_id` in [1..5]
+- `seq != 0`
+
+## Session Gate Invariants
+
+- Pre-lock: only CONTROL channel allowed.
+- Locked: packet must match:
+  - `session_id`
+  - peer address family
+  - peer port
+  - peer IPv6 bytes
+
+## Replay/Sequence Invariants
+
+- Replay check active in locked state.
+- First accepted seq initializes replay window.
+- Duplicate seq in window is dropped.
+- Too-old seq outside window is dropped.
+
+## Channel IDs
+
+- 1: CONTROL
+- 2: AUDIO
+- 3: CHAT
+- 4: FILE
+- 5: ROUTE
+
+## Scheduler Priority (TX)
+
+- control > audio > chat > file > fake
+
+## Observability
+
+- No per-packet hot-path logs.
+- Periodic stats line is allowed.
+- Selftest code is compile-time gated (`PHASE1_SELFTEST`).
+
+## Out of Scope for Phase 1
+
+- PQ KEM handshake details
+- AEAD nonce/tag enforcement
+- Anti-analysis layer
+- Offensive shell
+- Kernel filter (BPF/eBPF)
+- Resilience features (multipath/FEC/hop/relay)
+
+## Phase 2 Enablement Gate
+
+Set `PHASE2_SECURITY=1` only after all are true:
+- Phase 1 selftests pass (parse/static/session/seq)
+- No hot-path regressions (stats stable under normal run)
+- Session state reaches `SESSION_LOCKED` reliably
+- Packet contract doc updated for nonce/tag fields
+- Security insertion point remains between session gate and replay check
+
