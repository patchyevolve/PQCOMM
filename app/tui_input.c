#include "tui_input.h"
#include "group.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static HANDLE g_hStdin = NULL;
static int g_win_console_mode_initialized = 0;
#else
#include <unistd.h>
#include <poll.h>
#endif

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

void tui_input_init(void)
{
#ifdef _WIN32
    g_hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (g_hStdin && g_hStdin != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        GetConsoleMode(g_hStdin, &mode);
        mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
        SetConsoleMode(g_hStdin, mode);
        g_win_console_mode_initialized = 1;
    }
#endif
}

static int g_mouse_enabled = 0;

void tui_input_enable_mouse(void)
{
#ifdef _WIN32
    if (g_hStdin && g_hStdin != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        GetConsoleMode(g_hStdin, &mode);
        mode |= ENABLE_MOUSE_INPUT;
        SetConsoleMode(g_hStdin, mode);
    }
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) {
        const char* seq = "\033[?1000h\033[?1006h";
        DWORD written = 0;
        WriteConsole(h, seq, 16, &written, NULL);
    }
#else
    write(STDOUT_FILENO, "\033[?1000h\033[?1006h", 16);
#endif
    g_mouse_enabled = 1;
}

void tui_input_disable_mouse(void)
{
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) {
        const char* seq = "\033[?1006l\033[?1000l";
        DWORD written = 0;
        WriteConsole(h, seq, 16, &written, NULL);
    }
    if (g_hStdin && g_hStdin != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        GetConsoleMode(g_hStdin, &mode);
        mode &= ~ENABLE_MOUSE_INPUT;
        SetConsoleMode(g_hStdin, mode);
    }
#else
    write(STDOUT_FILENO, "\033[?1006l\033[?1000l", 16);
#endif
    g_mouse_enabled = 0;
}

static int read_mouse_sgr(int* button, int* mx, int* my)
{
    char buf[32];
    int n = 0;
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE) return 0;
    while (n < (int)sizeof(buf) - 1) {
        DWORD read_count = 0;
        if (!ReadFile(h, &buf[n], 1, &read_count, NULL) || read_count != 1) return 0;
        if (buf[n] == 'M' || buf[n] == 'm') { buf[n] = '\0'; break; }
        n++;
    }
#else
    while (n < (int)sizeof(buf) - 1) {
        if (read(STDIN_FILENO, &buf[n], 1) != 1) return 0;
        if (buf[n] == 'M' || buf[n] == 'm') { buf[n] = '\0'; break; }
        n++;
    }
#endif
    if (n == 0) return 0;
    int b = 0, x = 0, y = 0;
    if (sscanf(buf, "%d;%d;%d", &b, &x, &y) >= 3) {
        *button = b; *mx = x; *my = y; return 1;
    }
    return 0;
}

static int read_escape_seq(int* is_mouse, int* mouse_btn, int* mouse_x, int* mouse_y)
{
    char seq[2];
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE) return 0;
    DWORD read_count = 0;
    if (!ReadFile(h, &seq[0], 1, &read_count, NULL) || read_count != 1) return 0;
    if (ReadFile(h, &seq[1], 1, &read_count, NULL) || read_count != 1) return 0;
    if (seq[1] != '[') { if (ReadFile(h, &seq[1], 1, &read_count, NULL), 0) {} }
#else
    if (read(STDIN_FILENO, &seq[0], 1) != 1) return 0;
    if (seq[0] != '[') return 0;
    if (read(STDIN_FILENO, &seq[1], 1) != 1) return 0;
#endif
    if (seq[1] == '<' && g_mouse_enabled) {
        if (read_mouse_sgr(mouse_btn, mouse_x, mouse_y)) { *is_mouse = 1; return 0; }
        *is_mouse = 0; return 0;
    }
    switch (seq[1]) {
        case 'A': return -1;
        case 'B': return -2;
        case 'C': return -3;
        case 'D': return -4;
        default:  return 0;
    }
}

static int handle_login_input(tui_t* t, char c)
{
    if (c == '\t') { t->login_field = 1 - t->login_field; t->dirty = 1; return 0; }
    if (c == '\n' || c == '\r') {
        if (t->login_username[0] == '\0') { t->login_error = 1; t->dirty = 1; return 0; }
        t->login_error = 0;
        if (t->login_display[0] == '\0')
            snprintf(t->login_display, sizeof(t->login_display), "%s", t->login_username);
        t->input_buf[0] = '\0'; t->input_len = 0; t->input_pos = 0; t->dirty = 1;
        return TUI_KEY_LOGIN_SUBMIT;
    }
    if (c == 27) return 0;
    char* field = t->login_field == 0 ? t->login_username : t->login_display;
    int max = 30;
    int flen = (int)strlen(field);
    if (c == 127 || c == '\b') { if (flen > 0) field[flen - 1] = '\0'; t->dirty = 1; return 0; }
    if (c >= 32 && c < 127 && flen < max) { field[flen] = c; field[flen + 1] = '\0'; t->dirty = 1; }
    return 0;
}

static int handle_peer_list_input(tui_t* t, int c, int* selected_peer)
{
    if (c == 'q' || c == 'Q') { t->running = 0; return 0; }
    if (c == 27 || c == -4) {
        t->screen = SCREEN_LOGIN; t->input_buf[0] = '\0'; t->input_len = 0; t->input_pos = 0; t->dirty = 1;
        return 0;
    }
    if (c == 'r' || c == 'R') { t->dirty = 1; return 0; }
    if (c == 'g' || c == 'G') {
        t->screen = SCREEN_GROUP; t->group_focus = GROUP_FOCUS_ROOMS;
        t->input_buf[0] = '\0'; t->input_len = 0; t->input_pos = 0; t->dirty = 1;
        return 0;
    }
    if (c == '\n' || c == -3) {
        if (t->peer_selected >= 0 && t->peer_selected < t->peer_count) { *selected_peer = t->peer_selected; return 1; }
        return 0;
    }
    if (c == 'j' || c == 14 || c == -2) {
        if (t->peer_selected < t->peer_count - 1) { t->peer_selected++; if (t->peer_selected - t->peer_scroll >= t->height - 5) t->peer_scroll++; t->dirty = 1; }
        return 0;
    }
    if (c == 'k' || c == 16 || c == -1) {
        if (t->peer_selected > 0) { t->peer_selected--; if (t->peer_selected < t->peer_scroll) t->peer_scroll--; t->dirty = 1; }
        return 0;
    }
    return 0;
}

static int handle_popup_input(tui_t* t, char c, int* popup_accept)
{
    if (c == '\t') { t->conn_popup_selection = 1 - t->conn_popup_selection; t->dirty = 1; return 0; }
    if (c == '\n' || c == -3) { *popup_accept = (t->conn_popup_selection == 0) ? 1 : 0; t->show_conn_popup = 0; t->dirty = 1; return 1; }
    if (c == 27 || c == -4) { t->show_conn_popup = 0; t->dirty = 1; return 0; }
    return 0;
}

static int handle_call_popup_input(tui_t* t, char c)
{
    if (c == '\t') { t->call_popup_selection = 1 - t->call_popup_selection; t->dirty = 1; return 0; }
    if (c == '\n' || c == -3) {
        int accept = (t->call_popup_selection == 0) ? 1 : 0; t->show_call_popup = 0; t->dirty = 1;
        return accept ? (t->call_popup_type == 0 ? TUI_KEY_CALL_ACCEPT : TUI_KEY_VID_CALL_ACCEPT)
                      : (t->call_popup_type == 0 ? TUI_KEY_CALL_DECLINE : TUI_KEY_VID_CALL_DECLINE);
    }
    if (c == 27 || c == -4) { t->show_call_popup = 0; t->dirty = 1; return 0; }
    return 0;
}

static int handle_chat_input(tui_t* t, int c)
{
    if (c == 27 || c == -4) {
        t->screen = SCREEN_PEER_LIST; t->input_buf[0] = '\0'; t->input_len = 0; t->input_pos = 0; t->dirty = 1;
        return 0;
    }
    if (c == 'q' && t->input_len == 0) { t->running = 0; return 0; }
    if (c == 1) return TUI_KEY_AUDIO_TOGGLE;
    if (c == 22) return TUI_KEY_VIDEO_TOGGLE;
    if (c == 6) return TUI_KEY_FILE_SEND;
    if (c == '\n' || c == '\r') {
        if (t->input_len > 0) { int len = t->input_len; t->input_buf[len] = '\0'; t->input_len = 0; t->input_pos = 0; t->dirty = 1; return len; }
        return 0;
    }
    if (c == 127 || c == '\b') {
        if (t->input_pos > 0) { t->input_pos--; memmove(t->input_buf + t->input_pos, t->input_buf + t->input_pos + 1, (size_t)(t->input_len - t->input_pos - 1)); t->input_len--; t->dirty = 1; }
        return 0;
    }
    if (c >= 32 && c < 127 && t->input_len < TUI_INPUT_BUF - 1) {
        memmove(t->input_buf + t->input_pos + 1, t->input_buf + t->input_pos, (size_t)(t->input_len - t->input_pos));
        t->input_buf[t->input_pos] = (char)c; t->input_pos++; t->input_len++; t->dirty = 1; t->typing_flag = 1;
    }
    return 0;
}

static int handle_group_input(tui_t* t, int c)
{
    if (c == '\t') { t->group_focus = (t->group_focus + 1) % 3; t->dirty = 1; return 0; }
    if (c == 27 || c == -4) {
        t->screen = SCREEN_PEER_LIST; t->input_buf[0] = '\0'; t->input_len = 0; t->input_pos = 0; t->dirty = 1;
        return 0;
    }
    if (c == 'q' && t->input_len == 0) { t->running = 0; return 0; }
    int count;
    group_room_t* rooms = group_get_rooms(&count);
    if (t->group_focus == GROUP_FOCUS_ROOMS) {
        if ((c == 'j' || c == -2) && t->group_room_scroll + 1 < count) { t->group_room_scroll++; t->dirty = 1; }
        if ((c == 'k' || c == -1) && t->group_room_scroll > 0) { t->group_room_scroll--; t->dirty = 1; }
        if (c == '\n' || c == -3) {
            int idx = t->group_room_scroll;
            if (idx < count) { snprintf(t->current_room, sizeof(t->current_room), "%s", rooms[idx].name); t->input_buf[0] = '\0'; t->input_len = 0; t->input_pos = 0; t->dirty = 1; }
            return 0;
        }
    } else if (t->group_focus == GROUP_FOCUS_MEMBERS) {
        group_room_t* room = t->current_room[0] ? group_find(t->current_room) : NULL;
        if (!room) return 0;
        if ((c == 'j' || c == -2) && t->group_member_scroll + 1 < room->member_count) { t->group_member_scroll++; t->dirty = 1; }
        if ((c == 'k' || c == -1) && t->group_member_scroll > 0) { t->group_member_scroll--; t->dirty = 1; }
    } else if (t->group_focus == GROUP_FOCUS_CHAT) {
        return handle_chat_input(t, c);
    }
    return 0;
}

#ifdef _WIN32
static int read_win32_console_input(tui_t* t)
{
    if (!g_hStdin || g_hStdin == INVALID_HANDLE_VALUE) return 0;
    INPUT_RECORD ir[8];
    DWORD count = 0;
    if (!PeekConsoleInput(g_hStdin, ir, 8, &count) || count == 0) return 0;
    if (!ReadConsoleInput(g_hStdin, ir, count, &count) || count == 0) return 0;
    int key = 0;
    for (DWORD i = 0; i < count; i++) {
        if (ir[i].EventType == KEY_EVENT && ir[i].Event.KeyEvent.bKeyDown) {
            KEY_EVENT_RECORD* k = &ir[i].Event.KeyEvent;
            if (k->uChar.AsciiChar != 0) {
                key = (unsigned char)k->uChar.AsciiChar;
            } else {
                switch (k->wVirtualKeyCode) {
                    case VK_UP:    key = -1; break;
                    case VK_DOWN:  key = -2; break;
                    case VK_RIGHT: key = -3; break;
                    case VK_LEFT:  key = -4; break;
                    case VK_RETURN: key = '\n'; break;
                    case VK_ESCAPE: key = 27; break;
                    case VK_BACK:  key = 127; break;
                    case VK_TAB:   key = '\t'; break;
#ifdef VK_OEM_PLUS
                    case VK_OEM_PLUS: key = '+'; break;
#endif
                    default: key = 0; break;
                }
            }
            break;
        } else if (ir[i].EventType == MOUSE_EVENT) {
            MOUSE_EVENT_RECORD* m = &ir[i].Event.MouseEvent;
            t->mouse_last_x = m->dwMousePosition.X + 1;
            t->mouse_last_y = m->dwMousePosition.Y + 1;
            t->mouse_event = 1;
            t->dirty = 1;
            if (m->dwEventFlags & MOUSE_WHEELED) {
                int dir = (int)(short)HIWORD(m->dwButtonState) > 0 ? -1 : 1;
                key = -200 + dir;
                t->mouse_scroll = dir;
            } else if (m->dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED) {
                key = -99;
                t->mouse_btn = 1;
            } else if (m->dwButtonState & RIGHTMOST_BUTTON_PRESSED) {
                key = -101;
                t->mouse_btn = 2;
            } else {
                t->mouse_btn = 0;
            }
            break;
        }
    }
    return key;
}
#endif

int tui_input_poll(tui_t* t, int timeout_ms)
{
#ifdef _WIN32
    if (!g_hStdin || g_hStdin == INVALID_HANDLE_VALUE) return 0;
    DWORD wait = WaitForSingleObject(g_hStdin, timeout_ms);
    if (wait != WAIT_OBJECT_0) return 0;
    int key = read_win32_console_input(t);
    if (key == 0) return 0;
#else
    struct pollfd pfd;
    pfd.fd = STDIN_FILENO; pfd.events = POLLIN;
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret <= 0) return 0;
    char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return 0;
    int key = (unsigned char)c;
    if (key == 27) {
        struct pollfd peek; peek.fd = STDIN_FILENO; peek.events = POLLIN;
        if (poll(&peek, 1, 0) > 0) {
            int is_mouse = 0, mouse_btn = 0, mouse_x = 0, mouse_y = 0;
            int esc = read_escape_seq(&is_mouse, &mouse_btn, &mouse_x, &mouse_y);
            if (is_mouse) {
                int is_release = (mouse_btn & 32) ? 1 : 0, btn = mouse_btn & ~32;
                int is_scroll = (btn >= 64 && btn <= 65), scroll_dir = (btn == 64) ? -1 : (btn == 65) ? 1 : 0;
                t->mouse_last_x = mouse_x; t->mouse_last_y = mouse_y;
                t->mouse_btn = is_release ? 0 : (btn <= 2 ? btn : 0);
                t->mouse_scroll = scroll_dir; t->mouse_event = 1; t->dirty = 1;
                key = is_scroll ? -200 + scroll_dir : (!is_release && btn <= 2 ? -100 + btn : 0);
            } else if (esc) { key = esc; }
        }
    }
#endif

    if (key == 0x03) { t->running = 0; return 0; }
#ifndef _WIN32
    if (key == 0x1A) { tui_suspend(t); return 0; }
#endif

    if (t->show_conn_popup) { int popup_accept = 0; int r = handle_popup_input(t, (char)key, &popup_accept); if (r > 0) return popup_accept ? TUI_KEY_CONN_ACCEPT : TUI_KEY_CONN_DECLINE; return 0; }
    if (t->show_call_popup) { return handle_call_popup_input(t, (char)key); }
    switch (t->screen) {
        case SCREEN_LOGIN:     return handle_login_input(t, (char)key);
        case SCREEN_PEER_LIST: { int sel = -1; int r = handle_peer_list_input(t, key, &sel); if (r > 0 && sel >= 0) return sel + TUI_KEY_PEER_BASE; return 0; }
        case SCREEN_CHAT:      return handle_chat_input(t, key);
        case SCREEN_GROUP:     return handle_group_input(t, key);
        default: return 0;
    }
}
