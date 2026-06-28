# Secure Full-Duplex Post-Quantum SSM Communication System
## Final Engineering Specification v1.0 — LOCKED

| Field | Value |
|---|---|
| **Status** | 🔒 LOCKED |
| **Document Type** | Full Engineering Specification |
| **Scope** | Real-time secure duplex communication system |
| **Transport** | UDP multi-path |
| **Modes** | Audio · Chat · File · Control |
| **Security** | Post-Quantum handshake + symmetric session AEAD |
| **Architecture** | Multi-layer locked tunnel with outer defense shells |
| **Phase** | Phase 3 complete — PQ handshake, AEAD encryption, identity verification |
| **KEM** | ML-KEM 768 (liboqs) |
| **Session cipher** | ChaCha20-Poly1305 (mbedtls) |
| **Identity** | HMAC-SHA256 with pre-shared master key |

> **This document defines the final architecture. After this document, structural changes are not allowed.**

---

## Table of Contents

- [0. Goals](#0-goals)
- [1. Design Philosophy](#1-design-philosophy)
- [2. Threat Model](#2-threat-model)
- [3. Global Rules](#3-global-rules)
- [4. System State Machine](#4-system-state-machine)
- [5. Layer Architecture](#5-layer-architecture)
- [6. Kernel Filter](#6-kernel-filter)
- [7. Static Shell](#7-static-shell)
- [8. Session Gate](#8-session-gate)
- [9. Anti-Analysis Layer](#9-anti-analysis-layer)
- [10. Offensive Shell](#10-offensive-shell)
- [11. Packet Model](#11-packet-model)
- [12. Session Protocol](#12-session-protocol)
- [13. Channel System](#13-channel-system)
- [14. Scheduler](#14-scheduler)
- [15. Thread Model](#15-thread-model)
- [16. Resilience System](#16-resilience-system)
- [17. Key Management](#17-key-management)
- [18. Performance Constraints](#18-performance-constraints)
- [19. Security Guarantees](#19-security-guarantees)
- [20. CLI + Chat](#20-cli--chat)
- [21. Implementation Constraints](#21-implementation-constraints)
- [22. Implementation Status](#22-implementation-status)

---

## 0. Goals

### System Must Provide

| Category | Capability |
|---|---|
| **Communication** | Real-time duplex communication |
| **Audio** | Low latency audio transmission |
| **Data** | Secure chat and file transfer |
| **Session** | Exclusive session tunnel |
| **Identity** | Strong identity verification via HMAC-SHA256 |
| **Cryptography** | Post-quantum safe handshake (ML-KEM 768) + AEAD session (ChaCha20-Poly1305) |
| **Performance** | Low CPU usage in trusted mode |
| **Defense** | Resistance to spoof, flood, replay |
| **Resilience** | Survive packet loss / delay |
| **Adaptability** | Adapt under jamming |
| **Kernel** | Kernel-level filtering support |
| **Hardware** | Hardware crypto acceleration support |
| **Keys** | Secure key storage + HKDF-based key derivation |
| **Transport** | Multi-path transport |
| **Mesh** | Relay / mesh support |
| **Control** | CLI control interface |

### Non-Goals

The following are explicitly **out of scope**:

- Anonymity network
- Internet routing replacement
- RF hardware layer protection
- Defeating physical jamming completely

---

## 1. Design Philosophy

The system follows the **Trusted Pipe Model**.

### Core Rules

| Rule | Description |
|---|---|
| Minimal path | Trusted packets must move through the minimal path |
| Hard gate | Unknown packets must never reach the session |
| Layer separation | Outer layers protect link; inner layers carry data |
| Transport independence | Transport may change; session must not |

### Core Principles

```
Gate before decrypt
Decrypt before channel
Scheduler before encrypt
Control before audio
Audio before file
Outer layers must not see plaintext
Session must be exclusive
Handshake must run once
Fast path must be constant time
```

---

## 2. Threat Model

### Attacker CAN

- Send UDP packets
- Spoof IP
- Replay packets
- Flood port
- Scan protocol
- Delay / drop / reorder packets
- Observe traffic
- Attempt identity spoof
- Attempt handshake hijack

### Attacker CANNOT

- Break AEAD crypto (ChaCha20-Poly1305)
- Break PQ KEM (ML-KEM 768)
- Read secure memory
- Bypass kernel filter locally

### No Guarantee Against

- Full bandwidth saturation
- RF jamming
- ISP blocking
- Local OS compromise
- Hardware key theft

---

## 3. Global Rules

| Rule ID | Rule |
|---|---|
| **RULE-1** | Session gate must run before decrypt |
| **RULE-2** | Outer layers must not decrypt payload |
| **RULE-3** | PQ only allowed during handshake |
| **RULE-4** | Trusted packets must bypass offense |
| **RULE-5** | Scheduler must run before encryption |
| **RULE-6** | Audio must never wait for file |
| **RULE-7** | Control must never wait for audio |
| **RULE-8** | No malloc in fast path |
| **RULE-9** | No logging in fast path |
| **RULE-10** | No mutex in audio path |
| **RULE-11** | Packet parsed only once |
| **RULE-12** | Session must be exclusive |
| **RULE-13** | Kernel filter must be first |
| **RULE-14** | Keys must never leave secure store |
| **RULE-15** | Resilience must not change session ID |
| **RULE-16** | Replay window must always be active |
| **RULE-17** | Channel must not access transport |
| **RULE-18** | CLI must not access UDP directly |

---

## 4. System State Machine

### States

| State | Meaning |
|---|---|
| `INIT` | System initializing |
| `IDLE` | Ready, awaiting connection |
| `HANDSHAKE` | PQ key exchange in progress |
| `VERIFY` | Identity verification in progress |
| `LOCKED` | Session exists |
| `TRUSTED` | Fast path enabled |
| `ATTACK` | Offense allowed |
| `JAM` | Resilience active |
| `RESYNC` | Re-synchronizing after jam |
| `RECONNECT` | Re-establishing session |
| `CLOSED` | Session terminated |

### Transitions

```
INIT        → IDLE
IDLE        → HANDSHAKE
HANDSHAKE   → VERIFY
VERIFY      → LOCKED
LOCKED      → TRUSTED
TRUSTED     → ATTACK
TRUSTED     → JAM
JAM         → RESYNC
RESYNC      → TRUSTED
TRUSTED     → RECONNECT
RECONNECT   → LOCKED
LOCKED      → CLOSED
```

### State Diagram

```
[INIT] → [IDLE] → [HANDSHAKE] → [VERIFY] → [LOCKED] ←──────────────┐
                                                ↓                    │
                                           [TRUSTED] ──→ [RECONNECT]─┘
                                           ↙      ↘
                                      [ATTACK]   [JAM]
                                                   ↓
                                               [RESYNC]
                                                   └──────→ [TRUSTED]

[LOCKED] → [CLOSED]
```

### Handshake Sub-States (Session-Level)

These are the internal session states used during the PQ handshake (mapped to system-level `HANDSHAKE` / `VERIFY`):

```
IDLE → HANDSHAKE_START → PQ_KEM_INIT_SENT → PQ_KEM_RESPONSE_SENT → IDENTITY_PROOF_SENT → VERIFY → LOCKED
```

---

## 5. Layer Architecture

### Layer Stack (Inbound — outermost to innermost)

```
┌─────────────────────────────┐
│  OFFENSIVE SHELL            │  ← Responds to floods/scans
├─────────────────────────────┤
│  ANTI-ANALYSIS LAYER        │  ← Hides metadata, detects probing
├─────────────────────────────┤
│  STATIC SHELL               │  ← Magic, version, header, flags
├─────────────────────────────┤
│  KERNEL FILTER              │  ← First drop gate (BPF/eBPF)
├─────────────────────────────┤
│  SESSION GATE               │  ← Session ID, IP, port check
├─────────────────────────────┤
│  RESILIENCE                 │  ← FEC, multipath, relay
├─────────────────────────────┤
│  CONTROL                    │  ← Session control processing
├─────────────────────────────┤
│  SESSION ENC                │  ← Session-level AEAD decrypt
├─────────────────────────────┤
│  CHANNEL ENC                │  ← Per-channel key binding
├─────────────────────────────┤
│  CHANNEL                    │  ← Channel demux/dispatch
├─────────────────────────────┤
│  DATA                       │  ← Application payload
└─────────────────────────────┘
```

### Pipeline Order (Inbound Implementation)

As implemented in `pipeline/pipeline_inbound.c` (Phase 5):

1. `offensive_check` — trusted packet bypass (RULE-4), per-source rate limiting
2. `anti_analysis_check` — per-source scoring: bad magic/version/flags/channel/seq → medium/high drop
3. `static_check` — validates magic, version, flags, length, channel_id, seq
4. `kernel_filter_check` — IP whitelist/blocklist, port binding, size bounds (24–1500)
5. `session_check` — validates session_id, peer IP/port against active session; multipath support
6. `resilience_check` — FEC RX tracking, parity storage, packet recovery (runs before decrypt so FEC operates on ciphertext)
7. `session_enc_check` — decrypts ChaCha20-Poly1305, verifies tag, channel key AAD binding
8. `seq_check` — replay window (runs after decrypt so recovered packets get proper seq)
9. `rx_demux_push` — routes to channel queue (CONTROL → control, CHAT → chat, ROUTE → route, etc.)

### Outbound Order

1. Application builds plaintext payload (or uses `pipeline_outbound_process`)
2. `pipeline_outbound_process` — sets header fields, calls `session_enc_apply`
3. FEC TX accumulate (if enabled) — XOR parity built across group, sent as separate flagged packet
4. Scheduler selects next packet from priority queues (control > audio > chat > file > fake)
5. UDP send via TX thread

---

## 6. Kernel Filter

**Purpose:** Drop packets before user space.

| Check | Field |
|---|---|
| Source IP | Whitelist / block list |
| Port | Bound port check |
| Packet size | Min/max bounds |
| Protocol | UDP only |

- Must be **constant time**
- Must **not decrypt**
- Implemented via BPF / eBPF or equivalent
- Implemented in `lib/layers/kernel_filter.c` (IP whitelist/blocklist, port binding, size checks)

---

## 7. Static Shell

**Purpose:** Fast structural validation, no crypto.

| Check | Description | Current impl |
|---|---|---|
| `magic` | Protocol magic bytes must equal `0xAABBCCDD` | `layers/static_shell.c` |
| `version` | Must equal `1` | `layers/static_shell.c` |
| `header size` | Must be exactly 24 bytes | Implicit in parser |
| `flags` | Must be `0x00` (plain) or `0x01` (encrypted) | `layers/static_shell.c` |
| `length` | Declared length must match packet size minus header | `layers/packet_parse.c` |
| `channel_id` | Must be in range 1–5 | `layers/static_shell.c` |
| `seq` | Must not be zero | `layers/static_shell.c` |

### Flag Bits

| Bit | Mask | Meaning |
|---|---|---|
| 0 | `0x01` | `PACKET_FLAG_ENCRYPTED` — payload is AEAD-encrypted, nonce+tag follow header |
| 1–7 | `0xFE` | Reserved, must be zero |

- **No crypto**
- **No allocation**

---

## 8. Session Gate

**Purpose:** Verify this packet belongs to the active session.

| Check | Field |
|---|---|
| `session_id` | Matches active session |
| `peer_ip` | Expected remote IP |
| `peer_port` | Expected remote port |
| `format` | Packet structure valid |

**Additional rules:**
- Pre-lock: only CONTROL channel packets are accepted
- Locked: CONTROL channel packets pass unconditionally (no session_enc applied, RULE-2)
- After lock: `session_id` must match; if mismatch, packet is dropped with no response
- Fail → **drop immediately** (no error response)
- Must be **O(1)** lookup

Current implementation: `layers/session_gate.c` — uses flat session table, O(1) lookup by session_id.

---

## 9. Anti-Analysis Layer

**Purpose:** Hide metadata and detect protocol probing.

### Allowed Actions

| Action | Description |
|---|---|
| `drop` | Silently discard suspicious traffic |
| `delay` | Introduce artificial latency |
| `fake` | Send decoy responses |
| `noise` | Inject cover traffic |
| `throttle` | Rate-limit suspicious sources |

> Must **not modify trusted packets**.

Current implementation: stub in `layers/anti_analysis.c` (returns pass).

---

## 10. Offensive Shell

**Purpose:** Respond to active flood and scan attacks.

### Allowed Actions

| Action | Description |
|---|---|
| `fake packets` | Return misleading responses |
| `padding` | Inflate response sizes |
| `decoy handshake` | Simulate fake negotiation |
| `noise` | Inject random UDP noise |
| `rate limit` | Cap inbound per-source rate |

> Must **not touch session data**.

Current implementation: stub in `layers/offensive.c` (returns pass).

---

## 11. Packet Model

### Header Layout (24 bytes)

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 4 | `magic` | Protocol magic: `0xAABBCCDD` (little-endian) |
| 4 | 1 | `version` | Protocol version: `0x01` |
| 5 | 1 | `flags` | Bitfield: `0x01` = encrypted, `0x00` = plain |
| 6 | 8 | `session_id` | 64-bit session identifier (CSPRNG-generated) |
| 14 | 1 | `channel_id` | Channel number: 1 (CONTROL) through 5 (ROUTE) |
| 15 | 4 | `seq` | Monotonically increasing sequence number per channel |
| 19 | 4 | `length` | Total payload length after header (see encrypted layout) |
| 23 | 1 | _reserved_ | Currently unused, must be zero |

### Plain Packet Layout

```
[24-byte header] [payload: length bytes]
```

- `flags == 0x00`
- `payload` starts at offset 24
- `length` is actual payload size

### Encrypted Packet Layout

```
[24-byte header] [12-byte nonce] [ciphertext: length - 28 bytes] [16-byte tag]
```

- `flags == 0x01` (PACKET_FLAG_ENCRYPTED)
- `nonce` at offset 24, 12 bytes
- `ciphertext` starts at offset 36
- `tag` at offset `24 + length - AEAD_TAG_SIZE`, 16 bytes
- The `length` field covers: nonce(12) + ciphertext + tag(16)
- Minimum encrypted payload length: 28 bytes (12 nonce + 0 data + 16 tag)

### AEAD Parameters

| Parameter | Value |
|---|---|
| Algorithm | ChaCha20-Poly1305 |
| Key size | 32 bytes (session key) |
| Nonce size | 12 bytes |
| Tag size | 16 bytes |
| AAD size | 24 bytes (header with mods) |

### Nonce Construction

The 12-byte nonce is deterministic — no per-packet random number generator:

| Byte(s) | Source |
|---|---|
| 0–7 | `session_id` (little-endian) |
| 8 | `channel_id` |
| 9 | Zero (`0x00`) |
| 10–11 | `seq` (big-endian) |

Nonce uniqueness is guaranteed by the session_id + channel_id + seq tuple.
The sequence number is strictly monotonic per channel, so nonce never repeats within a session.

### AAD Construction

The AAD is 24 bytes, constructed as follows:
1. Copy the raw 24-byte header
2. Clear bit 0 of the `flags` byte (byte 5): `aad[5] &= ~0x01`
3. XOR-fold the per-channel key into the AAD:
   ```
   for i in 0..23:
       aad[i] ^= channel_keys[channel_id][i & 31]
   ```

This binds each encrypted packet to its claimed channel. Tampering with `channel_id` causes AEAD tag verification failure.

### parse Invariants

- `buf->len >= 24` (minimum header size)
- `length <= MAX_PACKET_SIZE - 24` (MAX_PACKET_SIZE = 2048)
- `buf->len == 24 + length` (exact match)
- If `PACKET_FLAG_ENCRYPTED` set: `length >= 28` (nonce + minimum tag)
- Parser strips nonce and tag from payload pointers; `out->payload` points to ciphertext
- Parser sets `out->tag` to the 16-byte tag pointer; `out->nonce` to the 12-byte nonce
- Packet is parsed exactly once per pipeline walk (RULE-11)

---

## 12. Session Protocol

### Handshake Sequence (6 Messages)

```
Initiator                          Responder
    │                                  │
    │──── HELLO (CTRL=1) ────────────▶│  session_id=0, kem_type
    │                                  │
    │◀─── ACCEPT (CTRL=2) ────────────│  session_id (CSPRNG)
    │                                  │
    │──── PQ KEM INIT (CTRL=3) ──────▶│  1184B ML-KEM 768 public key
    │                                  │
    │◀─── PQ KEM RESPONSE (CTRL=4) ───│  1088B ciphertext
    │                                  │
    │  [both derive shared secret]     │  kem_decapsulate
    │                                  │
    │──── IDENTITY PROOF (CTRL=5) ───▶│  HMAC-SHA256 sig(64) + identity_hash(32)
    │                                  │
    │  [Signature Verify]              │  HMAC-SHA256 verification
    │                                  │
    │  [Key Derivation]                │  HKDF(shared_secret, transcript_hash)
    │                                  │
    │◀══ SESSION LOCKED (CTRL=6) ═════│  symmetric AEAD mode active
```

### Handshake Opcodes

| Code | Constant | Sender | Payload |
|---|---|---|---|
| 1 | `CTRL_HELLO` | Initiator | opcode(1) |
| 2 | `CTRL_ACCEPT` | Responder | opcode(1) + session_id(8) |
| 3 | `CTRL_PQ_KEM_INIT` | Initiator | opcode(1) + public_key(1184) |
| 4 | `CTRL_PQ_KEM_RESPONSE` | Responder | opcode(1) + ciphertext(1088) |
| 5 | `CTRL_IDENTITY_PROOF` | Initiator | opcode(1) + signature(64) + identity_hash(32) |
| 6 | `CTRL_SESSION_LOCKED` | Responder | opcode(1) |
| 7 | `CTRL_HANDSHAKE_ERROR` | Either | opcode(1) + error_code(1) |

### Handshake Sub-States (Internal state enum)

| State | Meaning |
|---|---|
| `SESSION_IDLE` | No handshake in progress |
| `SESSION_HANDSHAKE_START` | Handshake initialized, awaiting first response |
| `SESSION_PQ_KEM_INIT_SENT` | KEM public key sent, awaiting ciphertext |
| `SESSION_PQ_KEM_RESPONSE_SENT` | KEM ciphertext received, identity pending |
| `SESSION_IDENTITY_PROOF_SENT` | Identity sent, awaiting lock |
| `SESSION_LOCKED` | Session established, symmetric encryption active |

### State Transition Rules

Each state accepts only specific incoming opcodes; any other opcode triggers `HS_ERR_STATE_VIOLATION`:

| Current State | Accepted Opcodes |
|---|---|
| `SESSION_HANDSHAKE_START` | ACCEPT (initiator) / HELLO (responder) |
| `SESSION_PQ_KEM_INIT_SENT` | KEM_RESPONSE |
| `SESSION_PQ_KEM_RESPONSE_SENT` | IDENTITY_PROOF |
| `SESSION_IDENTITY_PROOF_SENT` | SESSION_LOCKED |
| `SESSION_LOCKED` | None (KEM_INIT and KEM_RESPONSE are rejected with `failures_state++`) |

### Transcript Hash

A SHA-256 rolling hash of all handshake messages is maintained in `handshake_crypto_t.transcript_hash[32]`.

- Initial value: all zeros
- Each handshake message payload is appended: `transcript = SHA-256(transcript || payload)`
- The transcript is used as the salt for HKDF-extract during key derivation
- The transcript snapshot before adding `IDENTITY_PROOF` is used for signature verification

### Identity Verification

| Parameter | Value |
|---|---|
| Algorithm | HMAC-SHA256 |
| Key | 32-byte pre-shared identity master key (hardcoded for demo, secure store in production) |
| Identity hash | `SHA-256(identity_master_key)` — 32 bytes |
| Signature | `HMAC-SHA256(identity_master_key, transcript_hash)` — first 32 bytes of 64-byte field (rest zeroed) |

Verification flow:
1. Responder receives IDENTITY_PROOF
2. Captures transcript hash before adding IDENTITY_PROOF payload
3. Computes `expected = HMAC-SHA256(g_identity_master_key, pre_update_transcript)`
4. Compares first 32 bytes of received signature with `expected`
5. On mismatch: sets `HS_ERR_BAD_IDENTITY`, increments `g_handshake_stats.failures_identity`

### Error Codes

| Code | Constant | Meaning |
|---|---|---|
| 0 | `HS_ERR_NONE` | No error |
| 1 | `HS_ERR_UNSUPPORTED_KEM` | KEM type not supported |
| 2 | `HS_ERR_BAD_IDENTITY` | Identity verification failed |
| 3 | `HS_ERR_TIMEOUT` | Handshake timed out |
| 4 | `HS_ERR_REPLAY` | Replay detected |
| 5 | `HS_ERR_STATE_VIOLATION` | Invalid state transition |

### Session ID Generation

- Generated via `kem_random_bytes()` which calls `getrandom()` (Linux) or `CryptGenRandom` (Windows)
- Both sides: responder generates in `handshake_build_accept`, initiator adopts via ACCEPT payload
- 64-bit random value, CSPRNG-backed (no `rand()` anywhere in the handshake path)
- Session ID seeds the transcript and is compared by session gate post-lock

### Post-Handshake Rules

- **Symmetric only** — PQ primitives not used after lock (RULE-3)
- **Key rotation** — allowed without session interruption (not yet implemented)
- **No re-handshake** — handshake runs exactly once per session
- **CONTROL bypass** — CONTROL channel packets skip session_enc, pass through session gate only

---

## 13. Channel System

### Channel Map

| Channel ID | Name | Purpose | Encrypted |
|---|---|---|---|
| `1` | `CONTROL` | Session control, rekey, hop commands | No (bypasses session_enc) |
| `2` | `AUDIO` | Real-time voice / audio stream | Yes |
| `3` | `CHAT` | Encrypted text messaging | Yes |
| `4` | `FILE` | Bulk file transfer | Yes |
| `5` | `ROUTE` | Relay and mesh routing | Yes |

### Per-Channel State

| Field | Description |
|---|---|
| `channel_seq` | Independent sequence counter per channel |
| `channel_key` | Per-channel derived key (32 bytes, from HKDF) |

### Channel Key Derivation

Each channel key is independently derived via HKDF-expand using the PRK (from HKDF-extract) and a unique label:

```
PRK = HKDF-extract(transcript_hash, kem_shared_secret)

session_key = HKDF-expand(PRK, "SCv1 session key")
channel_0   = HKDF-expand(PRK, "SCv1 channel key 0")   // CONTROL
channel_1   = HKDF-expand(PRK, "SCv1 channel key 1")   // AUDIO
channel_2   = HKDF-expand(PRK, "SCv1 channel key 2")   // CHAT
channel_3   = HKDF-expand(PRK, "SCv1 channel key 3")   // FILE
channel_4   = HKDF-expand(PRK, "SCv1 channel key 4")   // ROUTE
```

### Channel Binding

The per-channel key is XOR-folded into the AEAD AAD (see §11 AAD Construction).
This ensures that a packet claiming `channel_id=N` can only be decrypted with `channel_key[N]`.

### Channel Rules

- Channels are **independent** — one must never block another
- CONTROL has highest implicit priority (see Scheduler)
- AUDIO must never wait for FILE (RULE-6)
- CONTROL must never wait for AUDIO (RULE-7)

---

## 14. Scheduler

**Purpose:** Determine packet transmission order before encryption.

### Queues

| Queue | Priority | Notes |
|---|---|---|
| `control` | **1 (highest)** | Rekey, hop, session management |
| `audio` | **2** | Real-time voice frames |
| `chat` | **3** | Text messages |
| `file` | **4** | File chunks |
| `fake` | **5 (lowest)** | Cover traffic / noise |

### Rules

- Runs **before** encryption (RULE-5)
- Priority strictly enforced
- No starvation protection required for `fake` queue

Current implementation: `core/scheduler.c` with ring buffers per priority.

---

## 15. Thread Model

### Thread Roster

| Thread | Responsibility | Current impl |
|---|---|---|
| `rx` | Receive UDP packets from NIC | `core/rx_thread.c` — posix/win32 |
| `tx` | Transmit packets to NIC | `core/tx_thread.c` — posix/win32 |
| `crypto` | Encryption / decryption operations | Inline in session_enc (no dedicated thread) |
| `control` | Session control and state machine | `main.c` — synchronous in event loop |
| `resilience` | FEC, multipath, reconnect logic | Inline in engine event loop (no dedicated thread) |
| `monitor` | Health checks, metrics, watchdog | Inline in engine event loop |
| `audio` | Audio encode/decode pipeline | Not yet implemented |
| `cli` | CLI command interface | Not yet implemented |

### Thread Communication Rules

- All inter-thread communication via **lock-free queues** (spsc_ring)
- **No blocking** between threads
- No mutex in audio path (RULE-10)
- CLI must not access UDP directly (RULE-18)

---

## 16. Resilience System

### Capabilities

| Feature | Description | Status |
|---|---|---|
| `multipath` | Simultaneously use multiple network paths | ✅ Implemented |
| `relay` | Route through trusted relay nodes | ✅ Implemented |
| `FEC` | Forward Error Correction for packet loss | ✅ Implemented |
| `port hop` | Dynamically change UDP port | ✅ Implemented |
| `reconnect` | Re-establish transport without session loss | ✅ Implemented |
| `adaptive bitrate` | Adjust FEC group size based on loss rate | ✅ Implemented |

### Critical Rule

> Resilience operations **must not change session ID** (RULE-15). The session layer is transparent to transport changes.

Current implementation: stub in `layers/resilience.c` (returns pass).

---

## 17. Key Management

### Key Hierarchy

| Key | Scope | Size | Derivation |
|---|---|---|---|
| `master` | Long-term identity key | 32 bytes | Pre-shared (hardcoded for demo) |
| `session` | Per-session symmetric key | 32 bytes | HKDF-expand(PRK, "SCv1 session key") |
| `channel` | Per-channel derived keys (×5) | 32 bytes each | HKDF-expand(PRK, "SCv1 channel key N") |

### Key Derivation Details

The HKDF operation uses SHA-256:

```
PRK = HMAC-SHA256(salt=transcript_hash, ikm=kem_shared_secret)
       ↑ HKDF-Extract
       
Output key material = HKDF-Expand(PRK, label, L)
                     = T(1) || T(2) || ...
       where T(1) = HMAC-SHA256(PRK, label || 0x01)
             T(i) = HMAC-SHA256(PRK, T(i-1) || label || i)
```

### Storage Rules

| Rule | Requirement | Current compliance |
|---|---|---|
| Secure memory | Keys stored in locked, non-swappable memory | Stack-only (no heap allocation) |
| Zero after use | Keys zeroed immediately when no longer needed | `crypto_secure_wipe()` on KEM secret key and shared secret post-derivation |
| No swap | Memory pages containing keys must be pinned | Stack frames not guaranteed (future hardening) |
| No log | Key material must never appear in logs | No key material is logged |
| Never leave store | RULE-14: keys never leave secure storage | Compliant (keys in `session_t` struct, never exported) |

### Rotation

- Rotation allowed during active session
- Rotation must **not stop stream**
- Both peers must confirm new key before old key is zeroed
- Not yet implemented (requires rekey protocol on CONTROL channel)

---

## 18. Performance Constraints

| Metric | Requirement | Current status |
|---|---|---|
| Audio latency | **< 20 ms** end-to-end | Not yet measured |
| CPU usage (normal) | **< 15%** of single core | Not yet profiled |
| Packet rate | **≥ 1,000 packets/second** | Pipeline overhead measured (loop at ~1ms/tick) |
| Loss tolerance | **≥ 30%** packet loss with FEC active | FEC not yet implemented |
| Fast path allocation | **Zero** — no malloc in hot path | Compliant: `aead.c` uses stack buffers, `session_enc.c` uses stack AAD |

---

## 19. Security Guarantees

### Protected

| Property | Mechanism | Phase |
|---|---|---|
| `payload` | ChaCha20-Poly1305 AEAD with session key | Phase 3 ✅ |
| `identity` | ML-KEM 768 + HMAC-SHA256 signature verification | Phase 3 ✅ |
| `session` | Exclusive session gate + CSPRNG session ID | Phase 3 ✅ |
| `channel` | Per-channel independent keys + AAD channel binding | Phase 3 ✅ |
| `replay` | Replay window always active (RULE-16) | Phase 2 ✅ |
| `spoof` | Session gate + peer IP/port binding | Phase 2 ✅ |
| `MITM` | PQ handshake + identity signature verification | Phase 3 ✅ |
| `scan` | Anti-analysis layer + static shell | Stub only |

### Layer Security Model

```
Outer layers (offensive, anti-analysis, static):
  - structural validation only
  - no crypto, no keys, no plaintext

Session gate:
  - session_id + IP/port binding
  - drops unknown traffic before crypto

Session enc:
  - ChaCha20-Poly1305 with session key
  - AAD bound to channel key
  - fail-closed on tag mismatch

Channel enc:
  - per-channel HMAC key binding (via AAD)
  - no separate per-packet tag (single-layer AEAD)

Channel demux:
  - routes decrypted plaintext to application
```

### NOT Guaranteed

| Threat | Reason |
|---|---|
| RF jamming | Physical layer, out of scope |
| Full DoS | Bandwidth saturation possible |
| Local root attack | OS compromise assumed fatal |

---

## 20. CLI + Chat

### CLI Commands

| Command | Description | Status |
|---|---|---|
| `connect` | Initiate connection to peer | Built into main.c (automatic) |
| `disconnect` | Gracefully close session | Not yet implemented |
| `status` | Display session and channel status | Automatic stats in main.c |
| `chat` | Send encrypted chat message | Demo only (hardcoded in main.c) |
| `sendfile` | Initiate file transfer | Not yet implemented |
| `bitrate` | Set / query audio bitrate | Not yet implemented |
| `cover` | Toggle cover traffic generation | Not yet implemented |
| `rekey` | Trigger manual key rotation | Not yet implemented |
| `hop` | Trigger port hop | ✅ Implemented (demo auto-triggers after lock) |
| `relay` | Set relay node | ✅ Implemented (route table + forwarding in responder) |
| `quit` | Terminate application | SIGINT handler |

### Chat Rules

- Chat channel must be **encrypted** (ChaCha20-Poly1305 session key, channel binding)
- Chat must **not block audio** (RULE-6 enforced via scheduler)
- CLI must not access UDP directly (RULE-18)

### Current Demo Flow

As implemented in `lib/engine/transport_engine.c` (run_demo):
1. Both sides initialize on localhost (::1, ports 9001/9002, alt 9003/9004)
2. Initiator builds and sends HELLO
3. Responder accepts, generates session_id, sends ACCEPT
4. Initiator generates ML-KEM 768 keypair, sends KEM_INIT (public key)
5. Responder encapsulates shared secret, derives session keys, sends KEM_RESPONSE (ciphertext)
6. Initiator decapsulates shared secret, builds IDENTITY_PROOF (HMAC signature)
7. Responder verifies identity, derives session keys, sends SESSION_LOCKED
8. Both sides locked: chat messages exchanged with AEAD encryption, FEC loss simulation
9. Relay: initiator builds CH_ROUTE packet → responder forwards via route table → initiator prints relayed chat
10. Port hop: initiator sends CTRL_PORT_HOP → responder acks → both switch to port 9005
11. ABR: loss detected at 0% → FEC disabled
12. Reconnect: initiator stops heartbeats → path DOWN → reconnect request/ack → session restored

---

## 21. Implementation Constraints

### Fast Path Requirements

| Constraint | Rule | Compliance |
|---|---|---|
| Single parse | Packet parsed exactly once (RULE-11) | ✅ `packet_parse` called once per pipeline walk |
| Zero copy | No unnecessary data copies | ✅ In-place AEAD decrypt |
| Fixed buffers | Pre-allocated, no runtime malloc | ✅ Packet pool (4096 buffers) |
| Constant time | Crypto operations constant time | ✅ ChaCha20-Poly1305, SHA-256, HMAC are data-independent |
| No malloc | Zero dynamic allocation in fast path (RULE-8) | ✅ Stack buffers only in aead.c, session_enc.c |
| No logging | Zero log writes in fast path (RULE-9) | ✅ No printf in aead.c encrypt/decrypt; session_enc.c decrypt fail returns silently |

### Ordering Requirements

| Constraint | Rule | Compliance |
|---|---|---|
| Gate before decrypt | Session gate always runs first (RULE-1) | ✅ `session_gate.c` runs before `session_enc.c` in pipeline |
| Scheduler before encrypt | Scheduling before outbound encryption (RULE-5) | ✅ Scheduler runs tx dequeues before `session_enc_apply` |

### Source File Map

| File | Responsibility |
|---|---|
| `core/session.h` | Session struct, opcodes, state enum, keys |
| `core/packet_view.h` | `packet_view_t`, `packet_buf_t`, nonce/tag fields |
| `core/pool.c` | Pre-allocated packet buffer pool |
| `crypto/kem.c` | ML-KEM 768 wrappers, CSPRNG (`kem_random_bytes`) |
| `crypto/hkdf.c` | HKDF-extract/expand, `derive_session_keys` |
| `crypto/aead.c` | ChaCha20-Poly1305 encrypt/decrypt (no malloc, no printf) |
| `handshake/handshake.c` | Handshake builders, state machine, transcript, identity |
| `layers/packet_parse.c` | Single-pass packet parsing |
| `layers/static_shell.c` | Magic/version/flags/length/channel validation |
| `layers/session_gate.c` | Session ID + peer address binding |
| `layers/seq_check.c` | Replay window (64-bit bitmap) |
| `layers/session_enc.c` | Session-level AEAD encrypt/decrypt (AAD with channel binding) |
| `layers/rx_demux.c` | Channel dispatch |
| `pipeline/pipeline_inbound.c` | Inbound layer chain |

---

## 22. Implementation Status

| Layer | Phase | Status | File |
|---|---|---|---|---|
| Offensive Shell | Phase 5 | ✅ Complete | `lib/layers/offensive.c` |
| Anti-Analysis | Phase 5 | ✅ Complete | `lib/layers/anti_analysis.c` |
| Static Shell | Phase 1 | ✅ Complete | `lib/layers/static_shell.c` |
| Kernel Filter | Phase 5 | ✅ Complete | `lib/layers/kernel_filter.c` |
| Session Gate | Phase 1 | ✅ Complete | `lib/layers/session_gate.c` |
| Resilience (layer pipe) | Phase 4 | ✅ Complete | `lib/layers/resilience.c` (pipe passthrough) |
| Resilience (engine) | Phase 4 | ✅ Complete | `lib/core/resilience_ctx.c`, `lib/engine/heartbeat.c`, `lib/engine/reconnect.c`, `lib/engine/adaptive_bitrate.c` |
| Relay / Mesh | Phase 4 | ✅ Complete | `lib/relay/relay.c`, `lib/relay/route_table.c` |
| Control / Handshake | Phase 2 | ✅ Complete | `lib/handshake/handshake.c`, `lib/engine/transport_engine.c` |
| Session Enc (AEAD) | Phase 3 | ✅ Complete | `lib/layers/session_enc.c`, `lib/crypto/aead.c` |
| Channel Enc (Binding) | Phase 3 | ✅ Complete | AAD channel binding in `lib/layers/session_enc.c` |
| Channel Demux | Phase 1 | ✅ Complete | `lib/layers/rx_demux.c` |
| CSPRNG | Phase 3 | ✅ Complete | `lib/crypto/kem.c` (`kem_random_bytes`) |
| Identity (HMAC) | Phase 3 | ✅ Complete | `lib/handshake/handshake.c` |
| CLI | Phase 6 | Not started | — |
| Key Rotation | Phase 6 | Not started | — |

### Phase Summary

| Phase | Description | Status |
|---|---|---|
| Phase 1 | Core transport, pipeline, layer stack | ✅ Complete |
| Phase 2 | PQ handshake (ML-KEM 768), state machine, key derivation | ✅ Complete |
| Phase 3 | AEAD session encryption, CSPRNG, identity verification, channel binding | ✅ Complete |
| Phase 4 | Resilience (FEC, multipath, port hop, reconnect, relay, adaptive bitrate) | ✅ Complete |
| Phase 5 | Outer defense layers (kernel filter, anti-analysis, offensive) | 📋 Planned |
| Phase 6 | Operational hardening, CLI, key rotation | 📋 Planned |

### Verification Output (Current — Phase 4 Full Demo)

```
[HANDSHAKE] identity verified OK
[RELAY] route table: node 2 -> self
[INITIATOR] session locked, sending test chats
[FEC LOSS DROP] seq=5 path=0
[FEC] recovered seq=5 len=53 from parity
[PORT_HOP] request sent: hop to port 9005
[PORT_HOP] ack received: hop confirmed
[RELAY] forwarded seq=11 to node 2 ch=3 (17 bytes)
[INIT CHAT][P0] hello via relay!
[ABR] loss=0.0% fec=on group=4 -> off group=0
[RECONNECT] simulation complete, path restored
[STATS] init=LOCKED resp=LOCKED pool=4096 attempts=1 ok=1 fail=0 enc=on
```

---

> *Secure Full-Duplex Post-Quantum SSM Communication System — Final Engineering Specification v1.0*
> *Document status: LOCKED. No structural changes permitted after this version.*

### Referenced Documents

- `PHASE1_WIRE_CONTRACT.md` — Wire format, header layout, AEAD nonce/tag, validation rules
- `IMPLEMENTATION_PHASE_STATUS.md` — Detailed implementation status and phase roadmap
- `AGENTS.md` — Quick reference for developers working on this codebase
