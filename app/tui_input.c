#include "tui_input.h"
#include <unistd.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>

void tui_input_init(void) { }

static int handle_login_input(tui_t* t, char c)
{
    if (c == '\t') {
        t->login_field = 1 - t->login_field;
        t->dirty = 1;
        return 0;
    }
    if (c == '\n') {
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
        return -10; /* special code: login submitted */
    }
    if (c == 27) return 0;

    char* field = t->login_field == 0 ? t->login_username : t->login_display;
    int* len = t->login_field == 0 ? &t->login_cursor : &t->login_cursor;
    (void)len;
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

static int handle_peer_list_input(tui_t* t, char c, int* selected_peer)
{
    if (c == 'q' || c == 'Q') {
        t->running = 0;
        return 0;
    }
    if (c == 27) { /* ESC — could go back to login, but not needed */
        return 0;
    }
    if (c == '\n') {
        if (t->peer_selected >= 0 && t->peer_selected < t->peer_count) {
            *selected_peer = t->peer_selected;
            return 1;
        }
        return 0;
    }
    if (c == 'j' || c == 14) { /* down or ctrl-n */
        if (t->peer_selected < t->peer_count - 1) {
            t->peer_selected++;
            if (t->peer_selected - t->peer_scroll >= t->height - 5)
                t->peer_scroll++;
            t->dirty = 1;
        }
        return 0;
    }
    if (c == 'k' || c == 16) { /* up or ctrl-p */
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
    if (c == '\n') {
        *popup_accept = (t->conn_popup_selection == 0) ? 1 : 0;
        t->show_conn_popup = 0;
        t->dirty = 1;
        return 1;
    }
    if (c == 27) {
        t->show_conn_popup = 0;
        t->dirty = 1;
        return 0;
    }
    return 0;
}

static int handle_chat_input(tui_t* t, char c)
{
    if (c == 27) {
        /* ESC — back to peer list */
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
    if (c == 1) { /* Ctrl+A — audio call toggle */
        return -20;
    }
    if (c == 22) { /* Ctrl+V — video call toggle */
        return -21;
    }
    if (c == 6) { /* Ctrl+F — send file */
        return -22;
    }
    if (c == '\n') {
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
        t->input_buf[t->input_pos] = c;
        t->input_pos++;
        t->input_len++;
        t->dirty = 1;
        t->typing_flag = 1; /* signal main loop to send typing notification */
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

    /* handle connection request popup (peer list overlay) */
    if (t->show_conn_popup) {
        int popup_accept = 0;
        int r = handle_popup_input(t, c, &popup_accept);
        if (r > 0) return popup_accept ? -4 : -5; /* -4 = accept, -5 = decline */
        return 0;
    }

    /* handle incoming call popup (chat overlay) */
    if (t->show_call_popup) {
        if (c == '\t') {
            t->call_popup_selection = 1 - t->call_popup_selection;
            t->dirty = 1;
            return 0;
        }
        if (c == '\n') {
            int accept = (t->call_popup_selection == 0) ? 1 : 0;
            t->show_call_popup = 0;
            t->dirty = 1;
            if (t->call_popup_type == 0)
                return accept ? -30 : -31; /* -30 = audio accept, -31 = audio decline */
            else
                return accept ? -32 : -33; /* -32 = video accept, -33 = video decline */
        }
        if (c == 27) {
            t->show_call_popup = 0;
            t->dirty = 1;
            return 0;
        }
        return 0;
    }

    switch (t->screen) {
        case SCREEN_LOGIN:
            return handle_login_input(t, c);
        case SCREEN_PEER_LIST: {
            int selected_peer = -1;
            int r = handle_peer_list_input(t, c, &selected_peer);
            if (r > 0 && selected_peer >= 0)
                return selected_peer + 10; /* return peer index + 10 to distinguish from chat submit */
            return 0;
        }
        case SCREEN_CHAT:
            return handle_chat_input(t, c);
        default:
            return 0;
    }
}
