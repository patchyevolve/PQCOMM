# SSM Transport — User Flow & Architecture Design

## 1. Overview

SSM is a peer-to-peer, end-to-end encrypted communication system.
There is **no central server**. Two instances connect directly over
UDP after discovering each other via LAN broadcast beacons.

All packets are encrypted with post-quantum ML-KEM 768 key exchange
and ChaCha20-Poly1305 session AEAD. No one — including the app itself —
can read a conversation after session keys are wiped.

**Supported features:**
- Encrypted chat (CH_CHAT, channel 3)
- Audio calls (CH_AUDIO, channel 2) — Opus codec over arecord/aplay (Linux) or ffmpeg DirectShow (Windows)
- Video calls (CH_VIDEO, channel 6) — V4L2+ffmpeg (Linux) or ffmpeg DirectShow (Windows) JPEG capture
- File transfer (CH_FILE, channel 4) — chunked with checksum
- PQ handshake, key rotation, LAN discovery, reconnect, FEC, multipath,
  port hopping, relay forwarding
- Cross-platform: Linux (primary), Windows (MinGW cross-compile or native)

## 2. First Launch (Setup)

### 2.1 Login Screen

```
+------------------------------------------------+
|       SSM Secure Messenger                       |
|                                                  |
|  Username: [daksh___________]                    |
|  Display:  [Daksh Patel_______]                  |
|                                                  |
|  [Enter] Start        [TAB] next field           |
+------------------------------------------------+
```

### 2.2 Persistent Identity

- Identity is saved to `~/.config/ssm/` (Linux) or `%APPDATA%/ssm/` (Windows) (auto-loaded on restart)
- Fields: username, display name, 256-bit HMAC identity key
- On subsequent launches the login screen is **skipped** entirely

## 3. Main Screen — Peer List

```
pqCOMMbulds  |  daksh  |  PEERS
────────────────────────────────────
 Peers (3)
 ● alice              [ONLINE]
 ● bob                [ONLINE]
 ○ charlie
 >
────────────────────────────────────
 [j/k:nav] [Enter:select] [q:quit]
```

- Green `●` = online (beacon received within 30s)
- Red `○` = offline (no beacon for 30s+)
- `[SECURE]` badge = connected with active PQ-encrypted session
- `[ONLINE]` badge = discovered but not connected
- Username shown (not raw IP address)

## 4. Connection Flow

### 4.1 LAN Discovery

Every 3s a UDP beacon is broadcast:
```
magic(4) + version(1) + transport_port(2) + username_len(1) + username(N)
```

Receiving peers auto-add the sender to their peer list. Peers are marked
offline after 30s of no beacon.

### 4.2 Connect / Accept / Decline

User presses Enter on a peer:

- **Not connected**: sends `CONNECT_REQUEST` → switches to chat screen
- **Already connected**: opens chat screen directly

When a `CONNECT_REQUEST` arrives, a popup appears:

```
+------------------------------------------------+
|          Incoming Connection                     |
|  alice (192.168.1.10:9001)                      |
|  wants to start a secure chat                   |
|                                                  |
|      [ Accept ]    [ Decline ]                   |
+------------------------------------------------+
```

- Press `Tab` to toggle, `Enter` to confirm
- Accept → PQ handshake → `[PQ encrypted]` status
- Decline → sender sees "Connection declined"

### 4.3 PQ Handshake (Automatic)

Six-message handshake (ML-KEM 768):

```
[initiator] ── HELLO ──────────────────► [responder]
            ◄── ACCEPT ──────────────────
            ── KEM_INIT ───────────────►
            ◄── KEM_RESPONSE ────────────
            ── IDENTITY_PROOF ─────────►
            ◄── SESSION_LOCKED ──────────
```

Both sides derive session + per-channel keys via HKDF.

## 5. Chat Screen

```
pqCOMMbulds  |  daksh  |  SECURE
────────────────────────────────────
 Chat with alice

 [me] hello from daksh!
 [alice] hey there — secure?
 [me] yes PQ encrypted!
 [alice] want to try audio?
────────────────────────────────────
> _                  [Esc:back] [Ctrl+A:audio] [Ctrl+V:video] [Ctrl+F:file]
```

- Top bar shows connection state: `SECURE` when locked, `CONN` during handshake
- Messages prefixed `[me]` (blue) or `[partner]` (green)
- `[PQ encrypted]` indicator at bottom of chat
- Chat supports 200 lines scrollback

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Esc` | Back to peer list |
| `q` | Quit (only when input empty) |
| `Enter` | Send message |
| `Backspace` / `DEL` | Delete char before cursor |
| `Ctrl+A` | Toggle audio call |
| `Ctrl+V` | Toggle video call |
| `Ctrl+F` | Send file (path from input buffer) |

### Status Bar Hints

Context-sensitive keybinding hints appear on the last line:
- Peer list: `[j/k:nav] [Enter:select] [q:quit]`
- Chat: `[Esc:back] [Ctrl+A:audio/end] [Ctrl+V:video/end] [Ctrl+F:file]`

## 6. Audio Calls (Ctrl+A)

- Press `Ctrl+A` to start an audio call with a locked connection
- Mic captured via `arecord |` pipe (Linux, 48kHz mono S16_LE) or ffmpeg DirectShow (Windows `dshow`)
- Encoded with Opus (20ms frames, 960 samples)
- Encrypted on CH_AUDIO (channel 2)
- Peer decodes and plays via `| aplay` (Linux) or ffmpeg DirectShow (Windows)
- Press `Ctrl+A` again to end the call
- Incoming call shows popup: `[ Accept ] / [ Decline ]`

Status indicators: `[AUDIO]` in status bar when active.

## 7. Video Calls (Ctrl+V)

- Press `Ctrl+V` to start a video call
- Camera captured via V4L2 + ffmpeg (Linux) or ffmpeg DirectShow (Windows) → JPEG frames
- Sent on CH_VIDEO (channel 6) at ~5fps
- Received frames saved to `/tmp/ssm_video/frame_NNNNN.jpg`
- Press `Ctrl+V` again to end
- Incoming call shows popup: `[ Accept ] / [ Decline ]`

Status indicators: `[VIDEO]` in status bar when active.

## 8. File Transfer (Ctrl+F)

- Type the file path in the input buffer, then press Ctrl+F
- Sends metadata (filename, size, SHA-256 checksum) on CH_CONTROL
- Splits file into 1024-byte chunks on CH_FILE
- Receiver reassembles, verifies checksum, saves to `~/Downloads/`
- Status shown in chat: `[File: report.pdf 25600/102400]`

## 9. Online/Offline Tracking

- Peers are **online** while their LAN beacon is received every 3s
- Peers are **auto-marked offline** after 30s of no beacon
- `connection_manager_mark_stale()` runs every poll cycle (10 frames)
- Peer list updates immediately with `●`/`○` indicators
- Connected peers are never marked offline by timeout

## 10. Keyboard Reference (Complete)

| Key | Screen | Action |
|-----|--------|--------|
| `Tab` | Login | Switch Username / Display fields |
| `Enter` | Login | Submit login |
| `Backspace` | Login | Delete character |
| Printable | Login | Type in active field (max 30) |
| `j` / `Ctrl+N` | Peer List | Move selection down |
| `k` / `Ctrl+P` | Peer List | Move selection up |
| `Enter` | Peer List | Connect to / open chat with selected peer |
| `q` | Peer List | Quit |
| `Esc` | Peer List or Chat | Back to previous screen |
| `Esc` | Popup | Dismiss popup |
| `Tab` | Popup | Toggle Accept / Decline |
| `Enter` | Popup | Confirm |
| `q` | Chat | Quit (only when input empty) |
| `Enter` | Chat | Send message |
| `Backspace` | Chat | Delete char before cursor |
| `Ctrl+A` | Chat | Toggle audio call |
| `Ctrl+V` | Chat | Toggle video call |
| `Ctrl+F` | Chat | Send file at path in input buffer |

## 11. Feature Matrix

| Feature | Channel | Encrypted | Status |
|---|---|---|---|---|
| Chat text | CH_CHAT (3) | ✅ AEAD | ✅ Done |
| Audio call | CH_AUDIO (2) | ✅ AEAD | ✅ Done (Opus, arecord/dshow) |
| Video call | CH_VIDEO (6) | ✅ AEAD | ✅ Done (V4L2/dshow+ffmpeg) |
| File transfer | CH_FILE (4) | ✅ AEAD | ✅ Done (chunked) |
| Relay / mesh | CH_ROUTE (5) | ✅ AEAD | ✅ Done |
| Key rotation | CH_CONTROL | bypass | ✅ Done |
| LAN discovery | — | — | ✅ Done (beacon broadcast) |
| Online/offline | — | — | ✅ Done (30s timeout) |
| Connection request | CH_CONTROL | bypass | ✅ Done (popup accept/decline) |
| Cross-platform | — | — | ✅ Done (Linux + Windows MinGW) |

## 12. Flow Diagram

```
┌─────────────┐    ┌─────────────┐
│   User A    │    │   User B    │
├─────────────┤    ├─────────────┤
│ 1. Login    │    │ 1. Login    │
│ 2. Discover ├────┤ 2. Discover │
│    (beacon) │◄───┤    (beacon) │
│ 3. Select A │    │             │
│    ──req──► │    │ 4. Popup!   │
│             │    │    Accept   │
│ 5. Handshake│◄───┤             │
│    ────────►│    │             │
│             │◄───┤             │
│ 6. Chat!    ├────┤ 6. Chat!    │
│ 7. Ctrl+A   ├────┤ 7. Audio!   │
│ 8. Ctrl+V   ├────┤ 8. Video!   │
│ 9. Ctrl+F   ├────┤ 9. File RX! │
└─────────────┘    └─────────────┘
```
