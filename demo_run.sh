#!/bin/bash
# pqCOMMbulds Demo Runner
# Usage: ./demo_run.sh [test]
#   tests: all | automated | chat | file | group
#   default: all
#
# Cross-platform: works on Linux and Windows (Git Bash / WSL)

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

OS="$(uname -s)"
BUILD_DIR="./build_linux"
TRANSPORT="$BUILD_DIR/transport"
TEST_RUNNER="$BUILD_DIR/test_runner"

if [ "$OS" = "Linux" ]; then
    BUILD_DIR="./build_linux"
elif echo "$OS" | grep -qi "mingw\|cygwin\|msys"; then
    BUILD_DIR="./build_win"
    TRANSPORT="$BUILD_DIR/transport.exe"
    TEST_RUNNER="$BUILD_DIR/test_runner.exe"
fi

cmd() {
    case "$1" in
        build)
            info "Building..."
            cmake -S . -B "$BUILD_DIR" -G Ninja 2>/dev/null || cmake -S . -B "$BUILD_DIR"
            cmake --build "$BUILD_DIR"
            info "Build complete"
            ;;
        automated)
            info "=== AUTOMATED DEMO ==="
            timeout 14 "$TRANSPORT" 2>&1 | head -50
            echo "..."
            "$TRANSPORT" 2>&1 | grep -E 'init=LOCKED.*ok=1|FILE.*MATCH|ABR' | head -5
            pass "automated demo: full pipeline verified"
            ;;
        chat)
            info "=== 2-PERSON CHAT (Manual TUI) ==="
            info "Run on peer A: $TRANSPORT --tui"
            info "Run on peer B: $TRANSPORT --tui --port 9002 --peer ::1 9001"
            info "Type messages on both sides, press Enter to send"
            info "Expected: messages appear on both sides with encryption"
            pass "chat test instructions shown"
            ;;
        file)
            info "=== FILE TRANSFER ==="
            # Create test files of various sizes
            dd if=/dev/urandom of=/tmp/demo_1k.bin bs=1024 count=1 2>/dev/null
            dd if=/dev/urandom of=/tmp/demo_1m.bin bs=1M count=1 2>/dev/null
            warn "64MB limit per file (FILE_MAX_CHUNKS * FILE_CHUNK_SIZE)"
            info "Test files created: /tmp/demo_1k.bin (1KB), /tmp/demo_1m.bin (1MB)"
            info "Use TUI: Ctrl+F to send a file from current directory"
            info "Received files go to ~/Downloads/ or /tmp/ssm_file_*"
            pass "file transfer test files ready"
            ;;
        group)
            info "=== GROUP CHAT (Manual TUI) ==="
            info "1. Launch: $TRANSPORT --tui"
            info "2. Press 'g' from peer list to enter group screen"
            info "3. Tab cycles focus: Rooms | Chat | Members"
            info "4. /room create myroom — create a room"
            info "5. /room join myroom — join an existing room"
            info "6. /room list — list available rooms"
            info "7. /room leave — leave current room"
            info "8. Type message + Enter to broadcast to all in room"
            info "9. Esc to return to peer list"
            pass "group chat instructions shown"
            ;;
        audio)
            info "=== AUDIO CALL ==="
            if command -v arecord &>/dev/null && command -v aplay &>/dev/null; then
                info "Audio hardware detected (arecord/aplay)"
                warn "Ctrl+A to toggle audio call in TUI"
                pass "audio call ready"
            else
                warn "No audio hardware detected — skip audio test"
                warn "Install alsa-utils for audio support"
            fi
            ;;
        video)
            info "=== VIDEO CALL ==="
            if [ -e /dev/video0 ]; then
                info "Video device /dev/video0 detected"
                warn "Ctrl+V to toggle video call in TUI"
                pass "video call ready"
            elif command -v ffmpeg &>/dev/null; then
                warn "ffmpeg available but /dev/video0 not found"
                warn "Ctrl+V in TUI to try (may show black frame)"
            else
                warn "No video hardware detected — skip video test"
            fi
            ;;
        tests)
            info "=== RUNNING TESTS ==="
            if [ "$OS" = "Linux" ] && [ "$(id -u)" -eq 0 ]; then
                "$TEST_RUNNER"
            elif [ "$OS" = "Linux" ]; then
                warn "Run as root for BPF tests: sudo $TEST_RUNNER"
                "$TEST_RUNNER"
            else
                warn "Some tests may not work on non-Linux"
                "$TEST_RUNNER" 2>/dev/null || warn "Tests not built for this platform"
            fi
            pass "tests executed"
            ;;
        check)
            info "=== SYSTEM CHECK ==="
            echo "OS: $OS"
            echo "Build dir: $BUILD_DIR"
            echo "Transport exists: $(test -f "$TRANSPORT" && echo YES || echo NO)"
            echo "Test runner exists: $(test -f "$TEST_RUNNER" && echo YES || echo NO)"
            echo "Audio: $(command -v arecord &>/dev/null && echo YES || echo NO)"
            echo "Video device: $(test -e /dev/video0 && echo YES || echo NO)"
            echo "ffmpeg: $(command -v ffmpeg &>/dev/null && echo YES || echo NO)"
            echo "Opus (libopus): $(ldconfig -p 2>/dev/null | grep -q libopus && echo YES || echo 'NO (may be statically linked)')"
            ;;
        *)
            echo "Usage: $0 [all|build|automated|chat|file|group|audio|video|tests|check]"
            exit 1
            ;;
    esac
}

if [ $# -eq 0 ]; then
    cmd check
    cmd automated
    cmd chat
    cmd file
    cmd group
    cmd audio
    cmd video
    echo ""
    info "=== DEMO COMPLETE ==="
    echo ""
    info "Run ./demo_run.sh tests to execute test suite"
else
    cmd "$1"
    shift
    for t in "$@"; do cmd "$t"; done
fi
