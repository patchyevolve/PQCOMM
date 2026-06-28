#include "tui_input.h"
#include <unistd.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>

#define TUI_KEY_LOGIN_SUBMIT  -10
#define TUI_KEY_CONN_ACCEPT   -4
#define TUI_KEY_CONN_DECLINE  -5
#define TUI_KEY_AUDIO_TOGGLE  -20
#define TUI_KEY_VIDEO_TOGGLE  -21
#define TUI_KEY_FILE_SEND     -22
#define TUI_KEY_CALL_ACCEPT   -30
#define TUI_KEY_CALL_DECLINE  -31
#define TUI_KEY_VID_CALL_ACCEPT  -32
#define TUI_KEY_VID_CALL_DECLINE -33
#define TUI_KEY_PEER_BASE     10

void tui_input_init(void) { }

/* read an escape sequence (arrow keys: \033[A/B/C/D) */
static int read_escape_seq(void)
{
    char seq[2];
    if (read(STDIN_FILENO, &seq[0], 1) != 1) return 0;
    if (seq[0] != '[') return 0;
    if (read(STDIN_FILENO, &seq[1], 1) != 1) return 0;
    switch (seq[1]) {
        case 'A': return -1; /* up */
        case 'B': return -2; /* down */
        case 'C': return -3; /* right */
        case 'D': return -4; /* left */
        default:  return 0;
    }
}

static int handle_login_input(tui_t* t, char c)
{
    if (c == '\t') {
        t->login_field = 1 - t->login_field;
        t->dirty = 1;
        return 0;
    }
    if (c == '\n' || c == '\r') {
        if (t->login_username[0] == '\0') {
            t->login_error = 1;
            t->dirty = 1;
            return 0;
        }
        t->login_error = 0;
        if (t->login_display[0] == '\0')
            snprintf(t->login_display, sizeof(t->login_display), "%s", t->login_username);
        t->input_buf[0] = '\0';
        t->input_len = 0;
        t->input_pos = 0;
        t->dirty = 1;
        return TUI_KEY_LOGIN_SUBMIT;
    }
    if (c == 27) return 0;

    char* field = t->login_field == 0 ? t->login_username : t->login_display;
    int max = t->login_field == 0 ? 30 : 30;
    int flen = (int)strlen(field);

    if (c == 127 || c == '\b') {
        if (flen > 0) field[flen - 1] = '\0';
        t->dirty = 1;
        return 0;
    }
    if (c >= 32 && c < 127 && flen < max) {
        field[flen] = c;
        field[flen + 1] = '\0';
        t->dirty = 1;
    }
    return 0;
}

static int handle_peer_list_input(tui_t* t, int c, int* selected_peer)
{
    if (c == 'q' || c == 'Q') {
        t->running = 0;
        return 0;
    }
    if (c == 27 || c == -4) {
        /* ESC or left arrow — back to login screen for re-setup */
        t->screen = SCREEN_LOGIN;
        t->input_buf[0] = '\0';
        t->input_len = 0;
        t->input_pos = 0;
        t->dirty = 1;
        return 0;
    }
    if (c == 'r' || c == 'R') {
        t->dirty = 1;
        return 0;
    }

    /* Enter or right arrow — select peer */
    if (c == '\n' || c == -3) {
        if (t->peer_selected >= 0 && t->peer_selected < t->peer_count) {
            *selected_peer = t->peer_selected;
            return 1;
        }
        return 0;
    }

    /* down: j, ctrl-n, or down arrow */
    if (c == 'j' || c == 14 || c == -2) {
        if (t->peer_selected < t->peer_count - 1) {
            t->peer_selected++;
            if (t->peer_selected - t->peer_scroll >= t->height - 5)
                t->peer_scroll++;
            t->dirty = 1;
        }
        return 0;
    }

    /* up: k, ctrl-p, or up arrow */
    if (c == 'k' || c == 16 || c == -1) {
        if (t->peer_selected > 0) {
            t->peer_selected--;
            if (t->peer_selected < t->peer_scroll)
                t->peer_scroll--;
            t->dirty = 1;
        }
        return 0;
    }
    return 0;
}

static int handle_popup_input(tui_t* t, char c, int* popup_accept)
{
    if (c == '\t') {
        t->conn_popup_selection = 1 - t->conn_popup_selection;
        t->dirty = 1;
        return 0;
    }
    if (c == '\n' || c == -3) {
        *popup_accept = (t->conn_popup_selection == 0) ? 1 : 0;
        t->show_conn_popup = 0;
        t->dirty = 1;
        return 1;
    }
    if (c == 27 || c == -4) {
        t->show_conn_popup = 0;
        t->dirty = 1;
        return 0;
    }
    return 0;
}

static int handle_call_popup_input(tui_t* t, char c)
{
    if (c == '\t') {
        t->call_popup_selection = 1 - t->call_popup_selection;
        t->dirty = 1;
        return 0;
    }
    if (c == '\n' || c == -3) {
        int accept = (t->call_popup_selection == 0) ? 1 : 0;
        t->show_call_popup = 0;
        t->dirty = 1;
        if (t->call_popup_type == 0)
            return accept ? TUI_KEY_CALL_ACCEPT : TUI_KEY_CALL_DECLINE;
        else
            return accept ? TUI_KEY_VID_CALL_ACCEPT : TUI_KEY_VID_CALL_DECLINE;
    }
    if (c == 27 || c == -4) {
        t->show_call_popup = 0;
        t->dirty = 1;
        return 0;
    }
    return 0;
}

static int handle_chat_input(tui_t* t, int c)
{
    if (c == 27 || c == -4) {
        /* ESC or left arrow — back to peer list */
        t->screen = SCREEN_PEER_LIST;
        t->input_buf[0] = '\0';
        t->input_len = 0;
        t->input_pos = 0;
        t->dirty = 1;
        return 0;
    }
    if (c == 'q' && t->input_len == 0) {
        t->running = 0;
        return 0;
    }
    if (c == 1) return TUI_KEY_AUDIO_TOGGLE;
    if (c == 22) return TUI_KEY_VIDEO_TOGGLE;
    if (c == 6) return TUI_KEY_FILE_SEND;

    if (c == '\n' || c == '\r') {
        if (t->input_len > 0) {
            int len = t->input_len;
            t->input_buf[len] = '\0';
            t->input_len = 0;
            t->input_pos = 0;
            t->dirty = 1;
            return len;
        }
        return 0;
    }
    if (c == 127 || c == '\b') {
        if (t->input_pos > 0) {
            t->input_pos--;
            memmove(t->input_buf + t->input_pos, t->input_buf + t->input_pos + 1,
                    (size_t)(t->input_len - t->input_pos - 1));
            t->input_len--;
            t->dirty = 1;
        }
        return 0;
    }
    if (c >= 32 && c < 127 && t->input_len < TUI_INPUT_BUF - 1) {
        memmove(t->input_buf + t->input_pos + 1, t->input_buf + t->input_pos,
                (size_t)(t->input_len - t->input_pos));
        t->input_buf[t->input_pos] = (char)c;
        t->input_pos++;
        t->input_len++;
        t->dirty = 1;
        t->typing_flag = 1;
    }
    return 0;
}

int tui_input_poll(tui_t* t, int timeout_ms)
{
    struct pollfd pfd;
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret <= 0) return 0;

    char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return 0;

    /* escape sequence handling (arrow keys) */
    int key = (unsigned char)c;
    if (key == 27) {
        struct pollfd peek;
        peek.fd = STDIN_FILENO;
        peek.events = POLLIN;
        if (poll(&peek, 1, 0) > 0) {
            int esc = read_escape_seq();
            if (esc) key = esc;
            /* else bare ESC, handled as 27 in screen handlers */
        }
    }

    /* Ctrl+C (0x03) — quit from anywhere */
    if (key == 0x03) {
        t->running = 0;
        return 0;
    }
    /* Ctrl+Z (0x1A) — suspend (SIGTSTP) */
    if (key == 0x1A) {
        tui_suspend(t);
        return 0;
    }

    /* connection request popup (peer list overlay) */
    if (t->show_conn_popup) {
        int popup_accept = 0;
        int r = handle_popup_input(t, (char)key, &popup_accept);
        if (r > 0) return popup_accept ? TUI_KEY_CONN_ACCEPT : TUI_KEY_CONN_DECLINE;
        return 0;
    }

    /* incoming call popup (chat overlay) */
    if (t->show_call_popup) {
        return handle_call_popup_input(t, (char)key);
    }

    switch (t->screen) {
        case SCREEN_LOGIN:
            return handle_login_input(t, (char)key);
        case SCREEN_PEER_LIST: {
            int selected_peer = -1;
            int r = handle_peer_list_input(t, key, &selected_peer);
            if (r > 0 && selected_peer >= 0)
                return selected_peer + TUI_KEY_PEER_BASE;
            return 0;
        }
        case SCREEN_CHAT:
            return handle_chat_input(t, key);
        default:
            return 0;
    }
}
