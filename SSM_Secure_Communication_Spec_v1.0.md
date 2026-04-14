# Secure Full-Duplex Post-Quantum SSM Communication System
## Final Engineering Specification v1.0 — LOCKED

| Field | Value |
|---|---|
| **Status** | 🔒 LOCKED |
| **Document Type** | Full Engineering Specification |
| **Scope** | Real-time secure duplex communication system |
| **Transport** | UDP multi-path |
| **Modes** | Audio · Chat · File · Control |
| **Security** | Post-Quantum handshake + symmetric session |
| **Architecture** | Multi-layer locked tunnel with outer defense shells |

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
- [22. Final Status](#22-final-status)

---

## 0. Goals

### System Must Provide

| Category | Capability |
|---|---|
| **Communication** | Real-time duplex communication |
| **Audio** | Low latency audio transmission |
| **Data** | Secure chat and file transfer |
| **Session** | Exclusive session tunnel |
| **Identity** | Strong identity verification |
| **Cryptography** | Post-quantum safe handshake |
| **Performance** | Low CPU usage in trusted mode |
| **Defense** | Resistance to spoof, flood, replay |
| **Resilience** | Survive packet loss / delay |
| **Adaptability** | Adapt under jamming |
| **Kernel** | Kernel-level filtering support |
| **Hardware** | Hardware crypto acceleration support |
| **Keys** | Secure key storage + automatic key rotation |
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

- Break AEAD crypto
- Break PQ KEM
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

---

## 5. Layer Architecture

### Layer Stack (Inbound — outermost to innermost)

```
┌─────────────────────────────┐
│  OFFENSIVE SHELL            │  ← Responds to floods/scans
├─────────────────────────────┤
│  ANTI-ANALYSIS LAYER        │  ← Hides metadata, detects probing
├─────────────────────────────┤
│  STATIC SHELL               │  ← Magic, version, header checks
├─────────────────────────────┤
│  KERNEL FILTER              │  ← First drop gate (BPF/eBPF)
├─────────────────────────────┤
│  SESSION GATE               │  ← Session ID, IP, port check
├─────────────────────────────┤
│  RESILIENCE                 │  ← FEC, multipath, relay
├─────────────────────────────┤
│  CONTROL                    │  ← Session control processing
├─────────────────────────────┤
│  SESSION ENC                │  ← Session-level decryption
├─────────────────────────────┤
│  CHANNEL ENC                │  ← Per-channel decryption
├─────────────────────────────┤
│  CHANNEL                    │  ← Channel demux/dispatch
├─────────────────────────────┤
│  DATA                       │  ← Application payload
└─────────────────────────────┘
```

Each layer defines: **input**, **output**, **allowed actions**, **forbidden actions**.

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

---

## 7. Static Shell

**Purpose:** Fast structural validation, no crypto.

| Check | Description |
|---|---|
| `magic` | Protocol magic bytes |
| `version` | Supported version range |
| `header size` | Expected fixed size |
| `flags` | Valid flag combinations |
| `length` | Declared vs. actual size |
| `checksum` | Header integrity |

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

- Fail → **drop immediately** (no error response)
- Must be **O(1)** lookup

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

---

## 11. Packet Model

### Header Fields

| Field | Description |
|---|---|
| `magic` | Protocol identifier (fixed bytes) |
| `version` | Protocol version number |
| `flags` | Packet type / control flags |
| `session_id` | Unique session identifier |
| `channel_id` | Channel number (1–5) |
| `seq` | Monotonically increasing sequence number |
| `nonce` | Unique per-packet nonce for AEAD |
| `length` | Payload length in bytes |
| `tag` | AEAD authentication tag |

### Field Rules

| Rule | Constraint |
|---|---|
| `seq` | Must strictly increase; no gaps allowed |
| `nonce` | Must never repeat within session lifetime |
| `length` | Must exactly match actual payload size |
| `tag` | Must verify before decryption proceeds |

---

## 12. Session Protocol

### Handshake Sequence

```
Initiator                          Responder
    │                                  │
    │──── HELLO ──────────────────────▶│
    │                                  │
    │◀─── PQ KEM (encapsulation) ──────│
    │                                  │
    │  [both derive shared secret]     │
    │                                  │
    │──── Encrypted Identity ─────────▶│
    │                                  │
    │  [Signature Verify]              │
    │                                  │
    │  [Key Derivation]                │
    │                                  │
    │◀══ SESSION LOCKED ══════════════▶│
```

### Handshake Steps

1. `HELLO` — initiate connection, exchange parameters
2. `PQ KEM` — post-quantum key encapsulation
3. `Shared Secret` — derive shared secret from KEM result
4. `Encrypted Identity` — transmit identity under session key
5. `Signature Verify` — verify peer identity signature
6. `Key Derive` — derive session and channel keys
7. `Lock` — session transitions to LOCKED state

### Post-Handshake Rules

- **Symmetric only** — PQ primitives not used after lock (RULE-3)
- **Key rotation** — allowed without session interruption
- **No re-handshake** — handshake runs exactly once per session

---

## 13. Channel System

### Channel Map

| Channel ID | Name | Purpose |
|---|---|---|
| `1` | `CONTROL` | Session control, rekey, hop commands |
| `2` | `AUDIO` | Real-time voice / audio stream |
| `3` | `CHAT` | Encrypted text messaging |
| `4` | `FILE` | Bulk file transfer |
| `5` | `ROUTE` | Relay and mesh routing |

### Per-Channel State

| Field | Description |
|---|---|
| `channel_seq` | Independent sequence counter per channel |
| `channel_key` | Dedicated encryption key per channel |

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

---

## 15. Thread Model

### Thread Roster

| Thread | Responsibility |
|---|---|
| `rx` | Receive UDP packets from NIC |
| `tx` | Transmit packets to NIC |
| `crypto` | Encryption / decryption operations |
| `control` | Session control and state machine |
| `resilience` | FEC, multipath, reconnect logic |
| `monitor` | Health checks, metrics, watchdog |
| `audio` | Audio encode/decode pipeline |
| `cli` | CLI command interface |

### Thread Communication Rules

- All inter-thread communication via **lock-free queues**
- **No blocking** between threads
- No mutex in audio path (RULE-10)
- CLI must not access UDP directly (RULE-18)

---

## 16. Resilience System

### Capabilities

| Feature | Description |
|---|---|
| `multipath` | Simultaneously use multiple network paths |
| `relay` | Route through trusted relay nodes |
| `FEC` | Forward Error Correction for packet loss |
| `port hop` | Dynamically change UDP port |
| `reconnect` | Re-establish transport without session loss |
| `adaptive bitrate` | Adjust audio quality to network conditions |

### Critical Rule

> Resilience operations **must not change session ID** (RULE-15). The session layer is transparent to transport changes.

---

## 17. Key Management

### Key Hierarchy

| Key | Scope |
|---|---|
| `master` | Long-term identity key |
| `session` | Per-session symmetric key |
| `channel` | Per-channel derived key |

### Storage Rules

| Rule | Requirement |
|---|---|
| Secure memory | Keys stored in locked, non-swappable memory |
| Zero after use | Keys zeroed immediately when no longer needed |
| No swap | Memory pages containing keys must be pinned |
| No log | Key material must never appear in logs |
| Never leave store | RULE-14: keys never leave secure storage |

### Rotation

- Rotation allowed during active session
- Rotation must **not stop stream**
- Both peers must confirm new key before old key is zeroed

---

## 18. Performance Constraints

| Metric | Requirement |
|---|---|
| Audio latency | **< 20 ms** end-to-end |
| CPU usage (normal) | **< 15%** of single core |
| Packet rate | **≥ 1,000 packets/second** |
| Loss tolerance | **≥ 30%** packet loss with FEC active |
| Fast path allocation | **Zero** — no malloc in hot path |

---

## 19. Security Guarantees

### Protected

| Property | Mechanism |
|---|---|
| `payload` | AEAD encryption (session + channel keys) |
| `identity` | PQ KEM + signature verification |
| `session` | Exclusive session gate + session ID |
| `channel` | Per-channel independent keys |
| `replay` | Replay window always active (RULE-16) |
| `spoof` | Session gate + peer IP/port binding |
| `MITM` | PQ handshake + identity signature |
| `scan` | Anti-analysis layer + static shell |

### NOT Guaranteed

| Threat | Reason |
|---|---|
| RF jamming | Physical layer, out of scope |
| Full DoS | Bandwidth saturation possible |
| Local root attack | OS compromise assumed fatal |

---

## 20. CLI + Chat

### CLI Commands

| Command | Description |
|---|---|
| `connect` | Initiate connection to peer |
| `disconnect` | Gracefully close session |
| `status` | Display session and channel status |
| `chat` | Send encrypted chat message |
| `sendfile` | Initiate file transfer |
| `bitrate` | Set / query audio bitrate |
| `cover` | Toggle cover traffic generation |
| `rekey` | Trigger manual key rotation |
| `hop` | Trigger port hop |
| `relay` | Set relay node |
| `quit` | Terminate application |

### Chat Rules

- Chat channel must be **encrypted** (channel key)
- Chat must **not block audio** (RULE-6 enforced via scheduler)
- CLI must not access UDP directly (RULE-18)

---

## 21. Implementation Constraints

### Fast Path Requirements

| Constraint | Rule |
|---|---|
| Single parse | Packet parsed exactly once (RULE-11) |
| Zero copy | No unnecessary data copies |
| Fixed buffers | Pre-allocated, no runtime malloc |
| Constant time | Crypto operations constant time |
| No malloc | Zero dynamic allocation in fast path (RULE-8) |
| No logging | Zero log writes in fast path (RULE-9) |

### Ordering Requirements

| Constraint | Rule |
|---|---|
| Gate before decrypt | Session gate always runs first (RULE-1) |
| Scheduler before encrypt | Scheduling before outbound encryption (RULE-5) |

---

## 22. Final Status

| Field | Value |
|---|---|
| **Architecture** | ✅ LOCKED |
| **Specification** | ✅ FINAL |
| **Implementation Ready** | ✅ YES |

---

> *Secure Full-Duplex Post-Quantum SSM Communication System — Final Engineering Specification v1.0*
> *Document status: LOCKED. No structural changes permitted after this version.*
