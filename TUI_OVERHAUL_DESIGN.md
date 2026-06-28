# TUI Overhaul Design - User Space + Advanced Space

Status: proposed implementation design  
Scope: terminal UI/UX, observability surface, operator workflows  
Architecture constraint: no transport, wire-format, crypto, or pipeline reordering changes

This document defines a production-grade TUI direction for pqCOMMbulds Secure
Communication Transport. The goal is to make the application feel like a
professional secure communication client for normal users while also exposing a
full advanced operator space for diagnostics, security posture, layer activity,
watchers, and system health.

The TUI must remain an API consumer. It must not access UDP sockets, packet
buffers, crypto internals, or pipeline state directly. All advanced visibility
must come from stable read-only snapshots/events exposed by the transport layer.

---

## 1. Current TUI Audit

### 1.1 What Exists Today

The current TUI already provides:

- First-launch identity setup and identity auto-load.
- Peer list with LAN discovery, online/offline marking, and unread indicator.
- One-to-one chat with timestamps, delivery/read states, typing indicator, RTT,
  secure-session banner, audio/video toggles, and file send.
- Incoming connection and call popups.
- Group screen with rooms, group chat area, and member sidebar.
- Mouse support for peer selection, panel focus, and scroll.
- Runtime event loop based on `transport_poll_event()`.
- Connection stats via `transport_get_connection_info()`.
- Coarse architecture/rule status via `transport_get_status()`.

### 1.2 Main Gaps

The current UI is functionally useful but not yet production-grade:

- User communication and technical status are mixed into the same small footer.
- There is no dedicated settings or advanced space.
- There is no persistent navigation model for chat, calls, files, groups,
  settings, and diagnostics.
- Advanced observability exists in code, but is mostly printed to stdout or kept
  inside monitor/layer globals instead of being presented in the TUI.
- The current `transport_get_status()` result is static PASS/N/A text; it is not
  enough for live operations.
- The monitor snapshot exists, but is not public through `transport_api.h`.
- Layer drops, handshake failure categories, pool pressure, thread liveness,
  key epoch, rekey state, FEC, reconnect, port-hop, relay, ABR, and path metrics
  need dedicated views.
- The UI does not separate safe user actions from advanced controls that could
  affect a live session.
- Error and security events need severity, timestamps, and retention instead of
  transient chat-line injection.

### 1.3 Contract Issues To Resolve Before Implementation

These are documentation/API alignment issues found during the audit:

- `PHASE1_WIRE_CONTRACT.md` says valid channel IDs are `[1..5]`, while the
  current user flow and implementation describe video as channel `6`.
- `PHASE1_WIRE_CONTRACT.md` lists `CTRL_RECONNECT` as opcode + session_id, while
  AGENTS.md lists opcode + session_id + seq.
- `SSM_Secure_Communication_Spec_v1.0.md` says RULE-13 kernel filter must be
  first, while AGENTS.md and the current pipeline describe kernel filter before
  session gate but not first.
- `transport_get_status()` reports RULE-13 as "kernel filter must be first PASS",
  which should be reworded if the accepted rule is the current pipeline order.

The overhaul can proceed without changing wire behavior, but these should be
cleaned up in docs/status text to avoid misleading operator views.

---

## 2. Product Model

The TUI has two top-level spaces:

1. User Space
2. Advanced Space

User Space is the default. It is where people communicate, discover peers, chat,
make audio/video calls, send files, work in groups, and manage identity.

Advanced Space is reached from Settings. It is read-only by default and shows
debugging, security, performance, transport, layer, and watcher views. Any
control that changes runtime behavior must be explicit, confirmed, and clearly
marked as an operator action.

### 2.1 Design Principles

- Default to calm communication, not engineering noise.
- Always show whether the active conversation is secure, connecting, degraded,
  or disconnected.
- Never expose cryptographic secrets, raw keys, plaintext packet dumps, or
  decrypted payloads in Advanced Space.
- Show evidence, not marketing labels: session state, handshake counters, RTT,
  loss, key epoch, replay drops, FEC recovery, and watcher health.
- Advanced views must sample snapshots. They must not add hot-path logging or
  allocations to packet processing.
- Keep keyboard control complete. Mouse is optional convenience, not required.
- Keep screen layouts useful on 80x24 and richer on wide terminals.

---

## 3. Top-Level Navigation

### 3.1 Global Shell

Every screen uses the same shell:

```text
pqCOMMbulds | daksh | SECURE | 12:41 | loss 0.0% | 18ms
----------------------------------------------------------------
 left navigation / current workspace / detail panel
----------------------------------------------------------------
 command/status line
```

Topbar fields:

- Product: `pqCOMMbulds`
- Identity: username/display name
- Session state: `IDLE`, `CONNECTING`, `HANDSHAKE`, `SECURE`, `DEGRADED`,
  `RECONNECTING`, `FAILED`
- Active peer or group name when relevant
- Health summary: RTT, loss, FEC, audio/video, unread

The topbar never shows secret material. Fingerprints may be shown only on
identity/security screens.

### 3.2 User Space Navigation

Default tabs:

```text
[Peers] [Chats] [Groups] [Calls] [Files] [Settings]
```

Keyboard:

- `Tab` / `Shift+Tab`: move between panels or tabs.
- `Enter`: open/confirm selected item.
- `Esc`: back one level.
- `Ctrl+P`: command palette.
- `Ctrl+S`: open Settings.
- `Ctrl+D`: open Advanced Space only from Settings.
- `q`: quit only from safe root screens or empty input.

### 3.3 Advanced Space Navigation

Advanced tabs:

```text
[Overview] [Security] [Pipeline] [Watchers] [Network] [Crypto] [Events] [Controls]
```

Keyboard:

- `F2`: return to User Space.
- `[` / `]`: previous/next advanced tab.
- `r`: refresh snapshot immediately.
- `p`: pause/resume live updates.
- `/`: filter current table.
- `Enter`: drill into selected row.
- `Esc`: back to previous advanced view.

Advanced Space must start read-only. Runtime controls live only in the
`Controls` tab and require confirmation.

---

## 4. User Space Design

### 4.1 First Launch / Identity

Purpose: create or load local identity before networking starts.

Screen:

```text
pqCOMMbulds | SETUP
----------------------------------------------------------------
Username      [daksh________________________]
Display name  [Daksh Patel__________________]

Identity      new local identity will be created
Storage       ~/.config/ssm

[Enter] Continue    [Tab] Next field
```

Behavior:

- Existing identity skips setup.
- New identity creation must save username, display name, and local identity key.
- Show identity fingerprint after creation with a "save this in your records"
  style operator message, but do not force the user to handle raw key material.
- If secure storage/env-key loading fails, show a blocking error with retry/quit.

### 4.2 Peers

Purpose: discover and start communication with users.

Layout:

```text
Peers                                      Details
-------------------------------------     --------------------------
> alice        ONLINE      18ms           Display: Alice
  bob          SECURE      audio           Address: 192.168.1.14:9001
  charlie      OFFLINE     8m ago          Trust: known fingerprint
                                           Last seen: now
                                           Session: none

Actions: Enter open/connect | a audio | v video | f file | /connect manual
```

Behavior:

- Online peers come from LAN discovery.
- Manual `/connect <ip> <port>` remains available.
- Selecting an offline peer opens the detail panel but does not attempt connect
  without explicit confirmation.
- A secure connected peer gets a stronger badge than an online discovered peer.
- Incoming requests open a centered modal and do not destroy current context.

### 4.3 One-To-One Chat

Purpose: primary communication surface.

Layout:

```text
alice | SECURE | key epoch 2 | 18ms | fec on
----------------------------------------------------------------
[12:40] me       hello
[12:40] alice    hey
[12:41] me       sending file now                         delivered

alice is typing...
----------------------------------------------------------------
> message text
```

Side panel on wide terminals:

```text
Session
 state       LOCKED
 uptime      00:12:41
 rtt         18ms
 loss        0.0%
 fec         on group 4
 rekey       epoch 2
 path        primary active
```

Behavior:

- Chat remains clean and conversation-first.
- System notices are compact, timestamped, and collapsible.
- Connection changes use a small inline separator, not noisy chat spam.
- File transfer progress appears as a single updating row, not repeated lines.
- Message status uses text-safe symbols or words depending on terminal support.
- User cannot send chat until `CONN_LOCKED`; input shows "waiting for secure
  session" during handshake.

### 4.4 Calls

Purpose: manage active and incoming audio/video calls.

Call states:

- `idle`
- `ringing`
- `connecting`
- `active`
- `degraded`
- `ending`

Audio call view:

```text
Call with alice | AUDIO | SECURE | 18ms
----------------------------------------------------------------
Mic        active
Speaker    active
Codec      Opus
Jitter     42ms
Loss       0.0%
FEC        on

[m] mute  [Ctrl+A] end  [Esc] back to chat
```

Video call view:

- Shows video status, frame rate, last frame timestamp, capture backend, and
  receive path.
- In a terminal, video preview should remain optional. The production TUI should
  show state and controls, while external display behavior remains platform
  dependent.

### 4.5 Files

Purpose: send and receive files with progress, integrity, and history.

Layout:

```text
Files
----------------------------------------------------------------
> report.pdf       sending     64%   640/1000 chunks
  build.zip        received    OK    checksum verified
  image.jpg        failed      peer disconnected
```

Behavior:

- `Ctrl+F` from chat opens file picker/input mode.
- File path typing in the chat input remains supported for compatibility.
- Transfers show metadata, progress, checksum state, and final save path.
- Failed transfers expose retry where safe.

### 4.6 Groups

Purpose: multi-peer rooms without hiding transport state.

Layout:

```text
Rooms              #ops-secure                         Members
--------------     --------------------------------     --------------
> ops-secure       [12:41] daksh  status?               alice online
  lab              [12:42] bob    all locked            bob secure
                                                        charlie stale
```

Behavior:

- Group UI uses three panels: rooms, messages, members.
- Member rows show online/secure/stale status.
- Group messages should surface whether they were delivered directly or via
  relay when that information is available.

### 4.7 Settings

Settings is the bridge into Advanced Space.

Sections:

- Identity
- Network
- Discovery
- Notifications
- Runtime options
- Advanced

Advanced entry:

```text
Advanced Space
View diagnostics, security posture, pipeline activity, watcher health,
transport metrics, and controlled runtime operations.

[Enter] Open Advanced Space
```

---

## 5. Advanced Space Design

Advanced Space is an operator cockpit. It must be useful for debugging a live
secure session without exposing secrets or changing architecture rules.

### 5.1 Advanced Overview

Purpose: one-screen health summary.

```text
Advanced / Overview                         live 2s
----------------------------------------------------------------
System       OK        uptime 00:12:41   pool 3984/4096 free
Session      LOCKED    peer alice        session 0x7b...e2
Security     OK        ML-KEM 768        ChaCha20-Poly1305
Transport    OK        rtt 18ms          loss 0.0%
Resilience   OK        fec on group 4    recovered 2
Watchers     OK        rx tx crypto monitor alive

Recent events
12:40:02 handshake success
12:40:04 session locked
12:41:11 rekey epoch 2 confirmed
```

Data sources:

- `transport_get_connection_info()`
- `transport_get_status()`
- future `transport_get_monitor_snapshot()`
- future event journal snapshot

### 5.2 Security

Purpose: show security posture and trust state.

Panels:

- Identity
- Session
- Handshake
- Replay
- Key rotation
- Secure storage

Fields:

- Local username/display name
- Local identity fingerprint
- Peer identity hash/fingerprint when available
- Session state
- Session ID shortened by default, full copy/view via explicit action
- KEM type: ML-KEM 768
- AEAD: ChaCha20-Poly1305
- HKDF: SHA-256
- Key epoch
- Last rekey time/result
- Handshake attempts/successes/failure categories
- Replay window status and replay drops
- Secure memory mode: mlock/MADV_DONTDUMP/env-key status

Forbidden:

- Raw session key
- Raw channel keys
- Raw KEM secret key/shared secret
- Decrypted payloads

### 5.3 Pipeline

Purpose: show inbound/outbound layer status and drops.

Inbound layer order shown:

1. packet_parse
2. offensive
3. anti_analysis
4. static_shell
5. kernel_filter
6. session_gate
7. resilience
8. session_enc
9. seq_check
10. rx_demux

Outbound path shown:

1. channel enqueue
2. scheduler
3. header build
4. session_enc
5. resilience/multipath
6. tx send

Table:

```text
Layer              State   Pass      Drop      Last reason
packet_parse       OK      12420     2         length mismatch
offensive          OK      12418     0         trusted bypass
anti_analysis      OK      12418     4         source high score
static_shell       OK      12414     1         bad magic
kernel_filter      OK      12413     0         -
session_gate       OK      12413     3         peer mismatch
resilience         OK      12410     0         fec recovered seq=5
session_enc        OK      12410     1         auth failed
seq_check          OK      12409     2         replay
rx_demux           OK      12407     0         chat/audio/file
```

Implementation rule:

- Counters are updated by existing layer code or low-cost atomic counters.
- No printf/logging inside fast-path layers.
- TUI reads snapshots periodically.

### 5.4 Watchers

Purpose: expose watchdog/liveness state.

Watchers:

- RX thread
- TX thread
- RX worker
- Crypto worker
- Audio worker
- Video worker
- Discovery
- Heartbeat
- Monitor
- Pool pressure
- Event queue pressure
- Scheduler queues

Table:

```text
Watcher       State       Last tick    Detail
rx-worker     alive       122ms        polling
tx-worker     alive       118ms        queue empty
crypto        alive       1.2s         0 pending
pool          OK          now          min free 3902
heartbeat     OK          900ms        last ack 18ms
discovery     OK          2.1s         4 peers
```

Severity levels:

- `OK`: normal
- `WARN`: degraded but session can continue
- `FAULT`: user-facing impact likely
- `SECURITY`: suspicious or trust-impacting event

### 5.5 Network

Purpose: show transport and resilience state.

Panels:

- Bind ports and discovery port
- Peer address/port
- Path table
- Multipath state
- Port hop state
- Reconnect state
- Relay routes
- ABR/FEC state

Path table:

```text
Path  State     RTT     Loss    Sent    Recv    Role
0     active    18ms    0.0%    1200    1199    primary
1     idle      -       -       0       0       standby
```

Resilience:

- FEC enabled/group size
- FEC recovered count
- Loss window
- ABR decision
- Reconnect attempts
- Last port-hop request/ack
- Relay forwarded count and route table health

### 5.6 Crypto

Purpose: show crypto system state without exposing secrets.

Fields:

- KEM implementation: liboqs ML-KEM 768
- AEAD implementation: mbedtls ChaCha20-Poly1305
- Identity proof: HMAC-SHA256
- HKDF: SHA-256
- Nonce mode: deterministic session_id + channel_id + seq
- AAD mode: header with encrypted flag cleared + channel key XOR-fold
- Key epoch
- Rekey status
- Crypto worker liveness
- Auth failure count
- Post-lock PQ rejection count

### 5.7 Events

Purpose: event journal for debugging and security review.

Event categories:

- connection
- security
- pipeline
- resilience
- media
- file
- discovery
- watcher
- operator

Event row:

```text
time        level     category     event
12:40:02    INFO      security     handshake success
12:41:11    INFO      security     rekey epoch 2 confirmed
12:42:00    WARN      network      path 1 degraded
12:42:10    SECURITY  pipeline     replay drop from peer
```

Retention:

- In-memory ring buffer.
- No plaintext message payloads.
- Export is optional and must redact peer-sensitive fields by default.

### 5.8 Controls

Purpose: safe operator actions.

Controls:

- Trigger discovery scan
- Toggle FEC
- Request port hop
- Trigger rekey
- Disconnect session
- Clear event journal
- Export redacted diagnostics

Rules:

- Controls require confirmation if they affect an active session.
- Dangerous controls are unavailable while calls/file transfers are active unless
  the user explicitly confirms.
- Controls call public transport APIs only.

---

## 6. Data And API Requirements

The current API is enough for a first visual pass but not for the full advanced
space. Add read-only snapshot APIs in later implementation phases.

### 6.1 Existing APIs To Use Immediately

- `transport_get_connection_info(conn_info_t*)`
- `transport_get_peer_list(peer_entry_t*, int)`
- `transport_poll_event(transport_event_t*)`
- `transport_get_status(transport_status_t*)`
- `transport_set_fec_enabled(int)`
- `transport_discovery_scan(void)`
- `transport_port_hop(uint16_t)`

### 6.2 Proposed Read-Only APIs

Keep signatures stable and snapshot-based:

```c
typedef struct {
    uint32_t pool_free_min;
    uint32_t pool_free_current;
    uint32_t rx_thread_stalled;
    uint32_t tx_thread_stalled;
    uint32_t crypto_thread_stalled;
    uint32_t handshake_attempts;
    uint32_t handshake_successes;
    uint32_t handshake_failures_timeout;
    uint32_t handshake_failures_identity;
    uint32_t handshake_failures_replay;
    uint32_t handshake_failures_state;
    uint32_t total_drops;
    uint64_t uptime_ms;
    uint64_t sample_count;
} transport_monitor_snapshot_t;

int transport_get_monitor_snapshot(transport_monitor_snapshot_t* out);
```

```c
typedef struct {
    char name[32];
    uint64_t pass_count;
    uint64_t drop_count;
    uint32_t last_reason;
    uint8_t state;
} transport_layer_snapshot_t;

int transport_get_layer_snapshots(transport_layer_snapshot_t* out, int max);
```

```c
typedef struct {
    uint64_t timestamp_ms;
    uint8_t level;
    char category[16];
    char message[160];
} transport_journal_event_t;

int transport_get_event_journal(transport_journal_event_t* out, int max);
```

These APIs must never expose secret key material or decrypted payloads.

---

## 7. TUI State Model

Add screens:

```c
SCREEN_SETTINGS
SCREEN_ADVANCED
```

Add sub-tabs:

```c
USER_TAB_PEERS
USER_TAB_CHATS
USER_TAB_GROUPS
USER_TAB_CALLS
USER_TAB_FILES
USER_TAB_SETTINGS

ADV_TAB_OVERVIEW
ADV_TAB_SECURITY
ADV_TAB_PIPELINE
ADV_TAB_WATCHERS
ADV_TAB_NETWORK
ADV_TAB_CRYPTO
ADV_TAB_EVENTS
ADV_TAB_CONTROLS
```

State additions:

- Current top-level space: user or advanced.
- Current user tab.
- Current advanced tab.
- Advanced selected row.
- Advanced live-update paused flag.
- Advanced filter string.
- Cached monitor snapshot.
- Cached layer snapshots.
- Cached event journal.
- Current modal type.

The TUI should keep rendering pure: panels read from `tui_t`, while the event
loop updates `tui_t` from public APIs.

---

## 8. Visual Rules

- Use restrained colors: green for secure/OK, yellow for degraded/warn, red for
  failed/security, blue/cyan for active communication, gray for metadata.
- Do not rely only on color. Every status must have text.
- Avoid decorative boxes inside boxes. Use full-width bands, tables, separators,
  and fixed-width columns.
- Fit 80x24:
  - User Space shows one primary list/detail view.
  - Advanced Space shows one tab at a time.
- Wide terminals add side panels instead of increasing text size.
- Text truncation must be explicit with ellipsis-like `...` in ASCII.
- No long instructions inside the main UI. Put compact command hints in footer.

---

## 9. Implementation Plan

### Phase TUI-1: Navigation And Settings

- Add User Space tab bar.
- Add Settings screen.
- Add Advanced Space entry from Settings.
- Keep existing peer/chat/group behavior working.
- Move current key hints into a consistent footer.

### Phase TUI-2: Advanced Read-Only MVP

- Add Advanced Overview, Security, Pipeline, and Network tabs.
- Use existing `transport_get_connection_info()` and `transport_get_status()`.
- Add local event journal in the TUI from events already received by
  `transport_poll_event()`.
- No transport API changes required.

### Phase TUI-3: Monitor Snapshot API

- Expose monitor snapshot through `transport_api.h`.
- Render Watchers tab.
- Show pool pressure, thread stalls, handshake counters, and uptime.
- Replace stdout-only monitor warnings with event journal entries where
  appropriate, without adding fast-path logs.

### Phase TUI-4: Layer Snapshot API

- Add low-cost per-layer counters and last-drop reason snapshots.
- Render full Pipeline tab.
- Add replay, auth failure, kernel filter, anti-analysis, offensive, FEC, and
  demux metrics.
- Ensure counters use atomics or existing globals and do not allocate/log in the
  fast path.

### Phase TUI-5: Controls And Export

- Add Advanced Controls tab.
- Add confirmations for FEC toggle, port hop, rekey, disconnect, and journal
  clear.
- Add redacted diagnostics export if needed.

### Phase TUI-6: Polish And Verification

- Test 80x24, 100x30, and wide terminal layouts.
- Verify keyboard-only operation.
- Verify mouse remains optional.
- Run Linux build, Windows cross-build, demo, and test runner.
- Update `SSM_USER_FLOW.md`, `ARCHITECTURE.md`, and implementation status if
  screens/APIs are implemented.

---

## 10. Definition Of Done

The overhaul is complete when:

- Normal users can communicate without seeing advanced noise.
- Advanced Space can show session, security, pipeline, watcher, network, crypto,
  and event state from read-only snapshots.
- All runtime-changing advanced actions require explicit confirmation.
- No secret key material or decrypted payloads can be displayed.
- No fast-path logging or allocation is introduced.
- TUI remains a public API consumer and never touches UDP directly.
- Existing demo and test expectations still pass.
- Documentation matches actual channel IDs, opcodes, and pipeline rule wording.
