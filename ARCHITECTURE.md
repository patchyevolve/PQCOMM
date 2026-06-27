# Transport Architecture — Full System Design

## Status: TARGET DESIGN (aspirational — not all items exist yet)

This document defines the target architecture. Files listed here may not yet exist.
See `IMPLEMENTATION_PHASE_STATUS.md` §Audit for current stub/phantom inventory.
All implementation work must conform to this design.

---

## 1. Project Structure

```
transport/
├── CMakeLists.txt
├── CMakePresets.json
├── lib/                          # Static library (libtransport.a)
│   ├── CMakeLists.txt
│   ├── api/                      # Public API header
│   │   └── transport_api.h
│   ├── core/                     # Core runtime
│   │   ├── session.h / .c         # Session struct, state, table
│   │   ├── packet_view.h           # Packet view + buf types
│   │   ├── pool.c                  # Lock-free buffer pool
│   │   ├── udp_posix.c             # UDP socket (Linux)
│   │   ├── udp_win.c               # UDP socket (Windows)
│   │   ├── rx_thread.c             # UDP receive thread
│   │   ├── tx_thread.c             # UDP send thread
│   │   ├── scheduler.c             # Priority TX queues
│   │   ├── ring.h                  # SPSC lock-free ring (ring.c not in CMakeLists)
│   │   └── resilience_ctx.c / .h   # Path metrics, FEC state
│   ├── crypto/
│   │   ├── kem.c                   # ML-KEM 768 wrappers
│   │   ├── hkdf.c                  # HKDF-extract/expand
│   │   ├── aead.c                  # ChaCha20-Poly1305
│   │   └── crypto_util.h           # secure_wipe, random
│   ├── handshake/
│   │   └── handshake.c             # Full 6-message handshake
│   ├── pipeline/
│   │   ├── pipeline_inbound.c      # 10-layer inbound chain
│   │   ├── pipeline_outbound.c     # ❌ Outbound processing (not yet implemented)
│   │   └── pipeline_selftest.c     # Phase 1 selftests
│   ├── layers/
│   │   ├── packet_parse.c          # Single-pass parser
│   │   ├── static_shell.c          # Magic/version/flags
│   │   ├── session_gate.c          # Session ID check
│   │   ├── session_enc.c           # AEAD encrypt/decrypt + channel key AAD binding
│   │   ├── seq_check.c             # Replay window
│   │   ├── rx_demux.c              # Channel dispatch
│   │   ├── resilience.c            # FEC + multipath layer
│   │   ├── port_hop.c              # Port hop control
│   │   ├── offensive.c             # Implemented (Phase 5) — decoy/noise is Phase 6
│   │   ├── anti_analysis.c         # Implemented (Phase 5)
│   │   └── kernel_filter.c         # Implemented (Phase 5, replaced kernel_filter_stub.c)
│   ├── connection/                 # Connection manager
│   │   ├── connection_manager.h / .c
│   │   └── peer_table.h / .c       # ❌ Does not exist
│   ├── discovery/                  # LAN discovery
│   │   ├── lan_discovery.h / .c
│   │   └── beacon.h / .c           # ❌ Does not exist
│   ├── relay/                      # Relay / mesh routing
│   │   ├── relay.h / .c            # CH_ROUTE forwarding
│   │   └── route_table.h / .c      # Route table (16 entries)
│   └── engine/                     # Transport engine orchestrator
│       ├── transport_engine.h / .c # Thread lifecycle, event dispatch
│       ├── heartbeat.h / .c        # Heartbeat send/handle/tick
│       ├── reconnect.h / .c        # Reconnect protocol
│       ├── adaptive_bitrate.h / .c # ABR: FEC group size from loss rate
│       └── timer_wheel.h / .c      # ❌ Does not exist (heartbeat uses direct tick)
├── app/                           # TUI executable (transport)
│   ├── CMakeLists.txt
│   ├── main.c                     # Demo entry point (calls transport_engine_run_demo)
│   ├── tui_screen.c               # ❌ Does not exist
│   ├── tui_input.c                # ❌ Does not exist
│   └── tui_panels.c              # ❌ Does not exist
├── tests/                         # Test runner executable
│   ├── CMakeLists.txt
│   ├── test_runner_main.c
│   ├── test_connect.c
│   ├── test_fec_loss.c            # FEC encode/recover unit tests
│   ├── test_reconnect.c
│   ├── test_port_hop.c
│   ├── test_multipath_failover.c
│   ├── test_route_table.c         # Route table add/find/remove
│   ├── test_abr.c                 # ABR threshold transitions
│   ├── test_path_metrics.c        # Loss window, state transitions, path select
│   └── test_helpers.c             # ❌ Empty stub
├── docs/                          # Documentation
│   ├── SSM_Secure_Communication_Spec_v1.0.md  # LOCKED
│   ├── PHASE1_WIRE_CONTRACT.md
│   ├── ARCHITECTURE.md            ← you are here
│   ├── IMPLEMENTATION_PHASE_STATUS.md
│   └── AGENTS.md
├── AGENTS.md
└── IMPLEMENTATION_PHASE_STATUS.md
```

### Build Outputs

| Artifact | Type | Contents |
|---|---|---|
| `libtransport.a` | Static library | All core, crypto, handshake, pipeline, layers, connection, discovery, engine |
| `transport` | Executable | TUI frontend, links `libtransport.a` |
| `test_runner` | Executable | Test scenarios, links `libtransport.a` |

---

## 2. Library API (`api/transport_api.h`)

The transport engine is entirely in-process. The API is C, thread-safe, and
designed to be consumed by both the TUI and test_runner.

### 2.1 Lifecycle

```c
// Initialize engine. Spawns worker threads (RX, TX, discovery, timer).
// Must be called once before any other API function.
int transport_init(const transport_config_t* config);

// Graceful shutdown. Stops all threads, cleans up.
void transport_shutdown(void);
```

### 2.2 Configuration

```c
typedef struct {
    // Local bind ports for each path
    uint16_t local_port;                  // Primary (path 0)
    uint16_t local_port_alt;              // Secondary (path 1)

    // Discovery
    uint16_t discovery_port;              // LAN broadcast port
    int      discovery_enabled;

    // FEC
    int      fec_enabled;
    uint8_t  fec_group_size;              // Default 4

    // Paths
    uint8_t  multipath_enabled;
    uint32_t path_count;

    // Timeouts (ms)
    uint32_t handshake_timeout_ms;
    uint32_t heartbeat_interval_ms;
    uint32_t reconnect_timeout_ms;
    uint32_t max_reconnect_attempts;
} transport_config_t;
```

### 2.3 Connection Management

```c
// Manual connect to a peer
int transport_connect(const char* addr_str, uint16_t port);

// Disconnect active session
int transport_disconnect(void);

// Connection status
typedef enum {
    CONN_IDLE,
    CONN_CONNECTING,
    CONN_HANDSHAKE,
    CONN_LOCKED,
    CONN_FAILED
} conn_state_t;

typedef struct {
    conn_state_t state;
    uint64_t     session_id;
    char         peer_addr[64];
    uint16_t     peer_port;
    uint32_t     uptime_ms;
    int          fec_enabled;
    uint32_t     fec_recovered_count;
    uint32_t     path_count;
    // Per-path stats
    struct {
        float loss_rate;
        uint64_t rtt_ns;
        uint32_t packets_sent;
        uint32_t packets_recv;
    } paths[RESILIENCE_MAX_PATHS];
} conn_info_t;

void transport_get_connection_info(conn_info_t* info);
```

### 2.4 Chat

```c
// Send a chat message (thread-safe, non-blocking)
int transport_send_chat(const char* text);
```

### 2.5 Events (TUI Event Loop)

The engine pushes events into a lock-free event queue.
The application polls events in its main loop.

```c
typedef enum {
    EVENT_NONE,
    EVENT_CONNECTION_STATE_CHANGED,   // State transition
    EVENT_CHAT_RECEIVED,              // Incoming chat message
    EVENT_PEER_DISCOVERED,            // LAN discovery found peer
    EVENT_STATS_UPDATE,               // Periodic stats
    EVENT_ERROR,                       // Non-fatal error
} transport_event_type_t;

typedef struct {
    transport_event_type_t type;
    uint64_t timestamp_ms;
    union {
        struct { conn_state_t old_state; conn_state_t new_state; } conn_state;
        struct { char text[1024]; uint16_t sender_port; } chat;
        struct { char addr[64]; uint16_t port; uint8_t identity_hash[32]; } peer;
        struct { char message[256]; } error;
        struct { conn_info_t info; } stats;
    } data;
} transport_event_t;

// Poll next event. Returns 0 if no event, 1 if event available.
int transport_poll_event(transport_event_t* ev);
```

### 2.6 Control Commands

```c
// Trigger port hop to new port
int transport_port_hop(uint16_t new_port);

// Enable/disable FEC at runtime
int transport_set_fec_enabled(int enabled);

// Trigger LAN discovery scan (immediate beacon burst)
int transport_discovery_scan(void);
```

### 2.7 Discovery Peer Table

```c
typedef struct {
    char     addr[64];
    uint16_t port;
    uint8_t  identity_hash[32];
    uint8_t  is_online;    // 0 = offline (missed beacons), 1 = online
    uint64_t last_seen_ms;
    uint8_t  is_connected; // Currently has active session
} peer_entry_t;

// Get list of discovered peers
int transport_get_peer_list(peer_entry_t* entries, int max_entries);
```

---

## 3. Threading Model

```
┌─────────────────────────────────────────────────────────────┐
│  MAIN THREAD (TUI / Test Runner)                           │
│  - Render UI / drive test scenarios                        │
│  - Poll events via transport_poll_event()                  │
│  - Submit commands via API functions                        │
│                                                             │
│  ┌─────────────────────┐   ┌─────────────────────────┐     │
│  │  Event Queue (SPSC)  │   │  Command API calls      │     │
│  │  (engine → main)     │   │  (main → engine)        │     │
│  └──────────┬──────────┘   └──────────┬──────────────┘     │
└─────────────┼──────────────────────────┼────────────────────┘
              │                          │
┌─────────────┼──────────────────────────┼────────────────────┐
│  ENGINE     ▼                          ▼                    │
│                                                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  TRANSPORT ENGINE (state machine)                      │ │
│  │  - Connection manager                                  │ │
│  │  - Event dispatch                                      │ │
│  │  - Timer wheel (heartbeats, reconnect, FEC)            │ │
│  └────┬──────────┬─────────────┬──────────────┬──────────┘ │
│       │          │             │              │            │
│  ┌────┴──┐  ┌───┴────┐  ┌────┴─────┐  ┌─────┴──────┐     │
│  │ RX    │  │ TX     │  │ Discovery│  │ Timer      │     │
│  │ thread│  │ thread │  │ thread   │  │ thread     │     │
│  │ (1-2) │  │ (1-2)  │  │ (1)      │  │ (1)        │     │
│  │ UDP   │  │ UDP    │  │ Beacon   │  │ Heartbeat  │     │
│  │ recv  │  │ send   │  │ send/recv│  │ Timeouts   │     │
│  │ pipe  │  │ sched  │  │ peer     │  │ FEC timers │     │
│  │ push  │  │ pull   │  │ timeout  │  │            │     │
│  └───────┘  └────────┘  └──────────┘  └────────────┘     │
└────────────────────────────────────────────────────────────┘
```

### 3.1 Inter-Thread Communication

| Channel | Producer | Consumer | Mechanism |
|---|---|---|---|
| `cmd_queue` | TUI/test | Engine | Lock-free SPSC ring (commands) |
| `event_queue` | Engine | TUI/test | Lock-free SPSC ring (events) |
| `rx_ring[X]` | RX thread | Engine | SPSC ring (raw packets) |
| `tx_ring[prio]` | Engine | TX thread | SPSC ring (outbound packets) |
| `discovery_ring` | Discovery thread | Engine | SPSC ring (peer found/lost) |
| `timer_ring` | Timer thread | Engine | SPSC ring (timeout firings) |

All rings are **lock-free single-producer single-consumer**.
No mutexes in any data path (RULE-10, RULE-8).

### 3.2 Thread Lifecycle

```
transport_init():
  1. Create RX thread(s) — 1 per path (bound to path's UDP socket)
  2. Create TX thread(s) — 1 per path (bound to path's UDP socket)
  3. Create discovery thread (if enabled)
  4. Create timer thread (periodic ticks)
  5. All threads start in paused state
  6. Engine state = INIT

transport_connect():
  1. Engine state = CONNECTING
  2. Unpause RX/TX threads
  3. Trigger handshake state machine
  4. Push HELLO packet into TX ring

transport_shutdown():
  1. Engine state = SHUTDOWN
  2. Signal all threads to stop
  3. Join threads (with timeout)
  4. Clean up resources
```

---

## 4. Connection Manager

### 4.1 Peer Table

The connection manager maintains a table of known peers.
Peers are added via:
- Manual `transport_connect()` call
- LAN discovery beacon received

```c
typedef struct {
    uint8_t     identity_hash[32];
    char        addr_str[64];
    uint16_t    port;
    uint8_t     is_online;
    uint64_t    last_seen_ms;
    conn_state_t conn_state;       // Per-peer connection state
    session_t*  session;           // Active session (NULL if none)
} peer_t;
```

### 4.2 Connection State Machine (Per Peer)

```
                    ┌─────────┐
                    │  IDLE   │
                    └────┬────┘
                         │ transport_connect() or user selects peer
                    ┌────▼────┐
                    │CONNECTING│ ← bind socket, resolve address
                    └────┬────┘
                         │ HELLO sent
                    ┌────▼────┐
                    │HANDSHAKE│ ← 6-message PQ handshake
                    └────┬────┘
                         │ SESSION_LOCKED
                    ┌────▼────┐
                    │ LOCKED  │ ← data transfer active
                    └────┬────┘
                    ┌────▼────┐
                    │DISCONN. │ ← user disconnect or transport loss
                    └────┬────┘
                         │
                    ┌────▼────┐
                    │  IDLE   │ (back to start)
                    └─────────┘
```

### 4.3 Reconnect (Phase 4, substep 5)

When LOCKED and heartbeat timeout fires:
1. Mark peer state = DEGRADED
2. Send heartbeat probe (CONTROL opcode)
3. If 3 consecutive heartbeats unanswered → CONNECTING
4. Re-establish UDP socket (same local port or rebind)
5. Re-send last-known-good session packet
6. If peer responds → restore LOCKED (no full re-handshake)
7. If max_reconnect_attempts exceeded → DISCONNECTED

---

## 5. LAN Discovery Protocol

### 5.1 Wire Format

UDP broadcast on configurable `discovery_port` (default: 42069).

Beacon payload (plain UDP, no encryption, no transport header):

```
Offset  Size  Field
0       32    identity_hash       SHA-256(identity_master_key)
32      1     protocol_version    Must equal 1
33      2     listening_port      Primary port for connections (network byte order)
35      4     flags               Bit 0: accepting_connections
```

Total beacon size: 39 bytes.

### 5.2 Beacon Timing

| Phase | Interval | Duration |
|---|---|---|
| Start / scan trigger | 1 second | Until first peer discovered, or 10 seconds max |
| Steady state | 30 seconds | While engine is running |
| On missed beacon | Immediate probe | Send single beacon to specific peer address |

### 5.3 Peer Timeout

- A peer is considered online if a beacon was received within `BEACON_TIMEOUT_MS` (3 × current interval, max 90s).
- If no beacon within timeout, peer is marked offline.
- Offline peers remain in the peer table (for reconnect attempts) but are greyed out in TUI.
- Peers are only removed from the table on explicit disconnect or after `PEER_EVICTION_MS` (5 minutes offline).

### 5.4 Security

- Discovery beacons are **unencrypted** — they only carry identity_hash and listening port.
- The identity_hash is the same one used in the handshake IDENTITY_PROOF phase.
- Any discovered peer must go through the full PQ handshake and HMAC identity verification before being trusted.
- Spoofed beacons have no effect on security — they just add noise to the peer table.
- Discovery runs on a **separate UDP socket** from data paths.

---

## 6. TUI Design

### 6.1 Technology

Raw ANSI escape codes (no ncurses dependency).
Single header: `app/tui_render.h`.

Rationale: zero external dependencies, full control over rendering,
portable across any terminal.

### 6.2 Screen Layout

```
┌──────────────────────────────────────────────────────────┐
│  STATUS BAR (1 line)                                      │
│  Session: LOCKED  Peer: ::1:9002  FEC:ON  Path:P0  Loss:0%│
├────────────────────────┬─────────────────────────────────┤
│  CONNECTION PANEL      │  CHAT PANEL                     │
│  (left 30 cols)        │  (remaining space)              │
│                        │                                  │
│  > ::1:9002 ● LOCKED   │  [12:34:01] you: hello there    │
│    ::1:9004 ○ IDLE     │  [12:34:02] peer: hi!           │
│    ::1:9006 ○ OFFLINE  │  [12:34:05] you: how's it going?│
│                        │  [12:34:07] peer: all good!     │
│                        │                                  │
│                        │  ┌──────────────────────────┐   │
│                        │  │ > _                       │   │
│                        │  └──────────────────────────┘   │
├────────────────────────┴─────────────────────────────────┤
│  STATUS PANEL (bottom 5 lines)                            │
│  Path 0: rtt=1.2ms loss=0% sent=12 recv=10               │
│  Path 1: rtt=2.1ms loss=0% sent=12 recv=12               │
│  FEC: groups=3 recovered=1 parity_tx=3 parity_rx=3       │
│  Pool: free=4080 used=16                                  │
└──────────────────────────────────────────────────────────┘
```

### 6.3 Panel Details

**Connection Panel (left)**
- Lists all known peers (manual + discovered)
- Each line: address + port, online indicator (●/○), connection state
- Highlighted row = selected peer
- Press Enter to connect to selected peer
- Press `c` to open manual connect dialog (enter address:port)

**Chat Panel (right, main area)**
- Scrollable message history
- Each message: timestamp, sender label, text
- Text input bar at bottom
- Page up/down to scroll history
- Terminal bell on incoming message (if configured)

**Status Panel (bottom)**
- Always visible, auto-refreshes on each event
- Path stats per path
- FEC counters
- Session uptime, pool usage, packet rates

### 6.4 Controls

| Key | Action |
|---|---|
| `c` | Open connect dialog |
| `d` | Disconnect selected peer |
| `q` / `Ctrl+C` | Quit |
| `Tab` | Switch between panels (connections ↔ chat) |
| `↑`/`↓` | Navigate peer list / scroll chat |
| `PgUp`/`PgDn` | Scroll chat faster |
| `Enter` | Select peer or send message |

### 6.5 TUI Thread Interaction

```
TUI main loop:
  1. Check stdin for keypress (non-blocking via select/poll)
  2. If keypress: process input → maybe call API function
  3. Poll transport_event() in a loop until no more events
  4. For each event: update TUI state (peer table, chat buffer, stats)
  5. Re-render screen
  6. Sleep ~16ms (~60 FPS)
```

TUI never blocks on API calls. All API calls are non-blocking
(push command into ring, return immediately).

---

## 7. Test Runner

### 7.1 Architecture

```
test_runner executable:
  - Parses command-line: test_runner [--list] [test_name...]
  - With no args, runs all tests
  - Each test is a function: int test_xyz(void)
  - Returns 0 = pass, nonzero = fail
  - Links libtransport.a
  - Uses API functions to drive scenarios
  - Spawns child process for peer when needed (fork+exec or
    separate thread running responder mode)
```

### 7.2 Test Scenarios

| Test | What it verifies | Status |
|---|---|---|---|
| `test_connect_basic` | Manual connect → handshake → LOCKED | Skel |
| `test_fec_recovery` | XOR parity encode → lose 1 → rebuild original | ✅ |
| `test_fec_no_recovery_all_present` | All packets received → no false rebuild | ✅ |
| `test_route_table_add_find` | Add entries, find by node_id | ✅ |
| `test_route_table_remove` | Remove entry, verify count and not found | ✅ |
| `test_route_table_update_metrics` | Update loss_rate and rtt on entry | ✅ |
| `test_abr_off` | 0% loss → FEC disabled | ✅ |
| `test_abr_low_loss` | ~6% loss → group size 8 | ✅ |
| `test_abr_high_loss` | ~25% loss → group size 2 | ✅ |
| `test_path_loss_window` | 50% loss rate, then flood with receives → 0% | ✅ |
| `test_path_state_transition` | ACTIVE → DEGRADED → DOWN → RX restores | ✅ |
| `test_path_select` | Lowest-loss path selected, fallback on DOWN | ✅ |
| `test_fec_loss_10pct` | Drop 10% packets, verify FEC recovers | Skel |
| `test_fec_loss_30pct` | Drop 30% packets, verify FEC recovers | Skel |
| `test_reconnect` | Kill transport → restore → session survives | Skel |
| `test_port_hop` | Hop port mid-session, verify chat continues | Skel |
| `test_multipath_failover` | Kill path 0, verify path 1 takes over | Skel |

### 7.3 Peer Simulation

For tests requiring two peers, test_runner uses two approaches:
1. **In-process**: Create two transport engines in the same process,
   each bound to different ports, pipe packets between them via
   loopback. Good for basic protocol tests.
2. **Subprocess**: Fork a child that runs transport in responder mode.
   Good for timing-sensitive tests (reconnect, multipath failover).

---

## 8. Build System

### 8.1 CMake Targets

```cmake
# libtransport.a
add_library(transport STATIC
    lib/api/transport_api.c
    lib/core/session.c
    lib/core/pool.c
    lib/core/udp_posix.c           # or _win.c
    lib/core/rx_thread.c
    lib/core/tx_thread.c
    lib/core/scheduler.c
    lib/core/ring.c
    lib/core/resilience_ctx.c
    lib/core/rx_worker.c
    lib/crypto/kem.c
    lib/crypto/hkdf.c
    lib/crypto/aead.c
    lib/handshake/handshake.c
    lib/pipeline/pipeline_inbound.c
    # lib/pipeline/pipeline_outbound.c  # ❌ Not yet implemented
    lib/pipeline/pipeline_selftest.c
    lib/layers/packet_parse.c
    lib/layers/offensive.c
    lib/layers/anti_analysis.c
    lib/layers/static_shell.c
    lib/layers/kernel_filter.c
    lib/layers/session_gate.c
    lib/layers/session_enc.c
    lib/layers/seq_check.c
    lib/layers/rx_demux.c
    lib/layers/resilience.c
    lib/layers/port_hop.c
    lib/connection/connection_manager.c
    lib/discovery/lan_discovery.c
    lib/engine/transport_engine.c
    lib/engine/heartbeat.c
    lib/engine/reconnect.c
    lib/engine/adaptive_bitrate.c
    lib/engine/timer_wheel.c
    lib/relay/relay.c
    lib/relay/route_table.c
)

target_include_directories(transport PUBLIC lib/api)
target_link_libraries(transport PUBLIC
    MbedTLS::mbedtls
    MbedTLS::mbedcrypto
    MbedTLS::mbedx509
    OQS::oqs
    Threads::Threads
)

# transport (TUI executable)
add_executable(transport app/main.c app/tui_screen.c app/tui_input.c app/tui_panels.c)
target_link_libraries(transport PRIVATE transport)

# test_runner
add_executable(test_runner
    tests/test_runner_main.c
    tests/test_connect.c
    tests/test_fec_loss.c
    tests/test_reconnect.c
    tests/test_port_hop.c
    tests/test_multipath_failover.c
    tests/test_helpers.c
    tests/test_route_table.c
    tests/test_abr.c
    tests/test_path_metrics.c
)
target_link_libraries(test_runner PRIVATE transport)
```

### 8.2 Build Steps

```bash
cmake -S . -B build_linux -G Ninja
cmake --build build_linux
# Outputs: build_linux/libtransport.a, build_linux/transport, build_linux/test_runner

# Run demo (TUI)
./build_linux/transport

# Run tests
./build_linux/test_runner
./build_linux/test_runner test_fec_loss_30pct test_reconnect
./build_linux/test_runner --list
```

---

## 9. Migration Path (Current → Target)

### Phase 4.5 substeps

| Step | Description |
|---|---|
| 4.5.1 | Create directory structure (lib/, app/, tests/) |
| 4.5.2 | Move source files into lib/ directories, update #include paths |
| 4.5.3 | Create `api/transport_api.h` with the public API |
| 4.5.4 | Create `engine/transport_engine.c` — orchestrator thread + event dispatch |
| 4.5.5 | Create `connection/connection_manager.c` — peer table + state machine |
| 4.5.6 | Create `discovery/lan_discovery.c` — beacon send/recv + timeout |
| 4.5.7 | Restructure CMakeLists.txt into library + executables |
| 4.5.8 | Build and verify existing FEC/multipath/port-hop demo still works |
| 4.5.9 | Update AGENTS.md, IMPLEMENTATION_PHASE_STATUS.md |

### Then Phase 4 continues

| Substep | Description | Status |
|---|---|---|---|
| 4.5 | Reconnect policy (heartbeat + reconnect protocol) | ✅ Complete |
| 4.6 | Relay / mesh routing (ROUTE channel, route table, forwarding) | ✅ Complete |
| 4.7 | Adaptive bitrate (FEC group size from loss rate feedback) | ✅ Complete |
| 4.8 | Test scenarios (11 unit tests in test_runner) | ✅ Complete |

---

## 10. File Migration Map

| Current file | Target file | Changes |
|---|---|---|
| `core/session.h` | `lib/core/session.h` | Add `peer_t` ref, no structural change |
| `core/session.c` | `lib/core/session.c` | No change |
| `core/pool.c` | `lib/core/pool.c` | No change |
| `core/udp_posix.c` | `lib/core/udp_posix.c` | No change |
| `core/rx_thread.c` | `lib/core/rx_thread.c` | No change |
| `core/tx_thread.c` | `lib/core/tx_thread.c` | No change |
| `core/scheduler.c` | `lib/core/scheduler.c` | No change |
| `core/resilience_ctx.c` | `lib/core/resilience_ctx.c` | No change |
| `core/rx_worker.c` | `lib/core/rx_worker.c` | No change |
| `crypto/kem.c` | `lib/crypto/kem.c` | No change |
| `crypto/hkdf.c` | `lib/crypto/hkdf.c` | No change |
| `crypto/aead.c` | `lib/crypto/aead.c` | No change |
| `handshake/handshake.c` | `lib/handshake/handshake.c` | No change |
| `layers/*.c` | `lib/layers/*.c` | No change |
| `pipeline/*.c` | `lib/pipeline/*.c` | No change |
| `main.c` | `app/main.c` | Rewrite: minimal TUI bootstrap |
| *(new)* | `api/transport_api.h` | Public API header |
| *(new)* | `api/transport_api.c` | API implementation (dispatches to engine) |
| *(new)* | `engine/transport_engine.c` | Thread orchestration |
| *(new)* | `engine/heartbeat.c` | Heartbeat send/handle/tick |
| *(new)* | `engine/reconnect.c` | Reconnect request/ack protocol |
| *(new)* | `engine/adaptive_bitrate.c` | ABR controller |
| *(new)* | `relay/relay.c` | CH_ROUTE forwarding |
| *(new)* | `relay/route_table.c` | Route table |
| *(new)* | `connection/connection_manager.c` | Peer table + connect/disconnect |
| *(new)* | `discovery/lan_discovery.c` | Beacon + timeout |
| *(new)* | `app/tui_*.c` | TUI rendering/input |
| *(new)* | `tests/*.c` | Test scenarios |
| `CMakeLists.txt` | `CMakeLists.txt` | Restructure for library + executables |

---

## 8. User-Facing Flow

The end-to-end user flow (login → discover → connect → chat) is fully documented
in **`SSM_USER_FLOW.md`**. That doc defines the target UX for all UI work.
