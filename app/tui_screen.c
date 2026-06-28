#include "tui.h"
#include "tui_input.h"
#include "tui_panels.h"
#include "group.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <signal.h>
#endif

static int g_raw_mode = 0;
#ifdef _WIN32
static HANDLE g_hStdout = NULL;
static HANDLE g_hStdin = NULL;
static DWORD g_orig_out = 0, g_orig_in = 0;
#else
static struct termios g_orig_term;
static struct winsize g_ws;
#endif

void tui_raw_mode_enter(void)
{
    if (g_raw_mode) return;
#ifdef _WIN32
    g_hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    g_hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (g_hStdout && g_hStdout != INVALID_HANDLE_VALUE) {
        GetConsoleMode(g_hStdout, &g_orig_out);
        DWORD mode = g_orig_out;
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(g_hStdout, mode);
    }
    if (g_hStdin && g_hStdin != INVALID_HANDLE_VALUE) {
        GetConsoleMode(g_hStdin, &g_orig_in);
        DWORD mode = g_orig_in;
        mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
        SetConsoleMode(g_hStdin, mode);
    }
#else
    struct termios raw;
    tcgetattr(STDIN_FILENO, &g_orig_term);
    raw = g_orig_term;
    raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
    raw.c_iflag &= ~(IXON | ICRNL | ISTRIP | BRKINT);
    raw.c_oflag &= ~(OPOST);
    raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
#endif
    g_raw_mode = 1;
}

void tui_raw_mode_exit(void)
{
    if (!g_raw_mode) return;
#ifdef _WIN32
    if (g_hStdout && g_hStdout != INVALID_HANDLE_VALUE)
        SetConsoleMode(g_hStdout, g_orig_out);
    if (g_hStdin && g_hStdin != INVALID_HANDLE_VALUE)
        SetConsoleMode(g_hStdin, g_orig_in);
#else
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_term);
#endif
    g_raw_mode = 0;
}

int tui_terminal_width(void)
{
#ifdef _WIN32
    if (!g_hStdout || g_hStdout == INVALID_HANDLE_VALUE) return 80;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_hStdout, &csbi))
        return csbi.srWindow.Right - csbi.srWindow.Left + 1;
    return 80;
#else
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &g_ws) == 0 && g_ws.ws_col > 0)
        return g_ws.ws_col;
    return 80;
#endif
}

int tui_terminal_height(void)
{
#ifdef _WIN32
    if (!g_hStdout || g_hStdout == INVALID_HANDLE_VALUE) return 24;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_hStdout, &csbi))
        return csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    return 24;
#else
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &g_ws) == 0 && g_ws.ws_row > 0)
        return g_ws.ws_row;
    return 24;
#endif
}

void tui_write(const char* s)
{
#ifdef _WIN32
    if (g_hStdout && g_hStdout != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteConsole(g_hStdout, s, (DWORD)strlen(s), &written, NULL);
    }
#else
    write(STDOUT_FILENO, s, strlen(s));
#endif
}

void tui_printf(const char* fmt, ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    tui_write(buf);
}

void tui_clear(void)
{
    tui_write("\033[2J\033[3J\033[H");
}

void tui_move_cursor(int x, int y)
{
    tui_printf("\033[%d;%dH", y, x);
}

void tui_cursor_save(void)
{
    tui_write("\0337");
}

void tui_cursor_restore(void)
{
    tui_write("\0338");
}

void tui_cursor_hide(void)
{
    tui_write("\033[?25l");
}

void tui_cursor_show(void)
{
    tui_write("\033[?25h");
}

void tui_set_bg(int color)
{
    tui_printf("\033[48;5;%dm", color);
}

void tui_set_fg(int color)
{
    tui_printf("\033[38;5;%dm", color);
}

void tui_reset_attr(void)
{
    tui_write("\033[0m");
}

void tui_set_bold(void)
{
    tui_write("\033[1m");
}

void tui_set_dim(void)
{
    tui_write("\033[2m");
}

void tui_erase_line(void)
{
    tui_write("\033[2K\r");
}



#ifndef _WIN32
static void tui_sigwinch_handler(int sig)
{
    (void)sig;
}
#endif

void tui_screen_setup(void)
{
#ifdef _WIN32
    g_hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    g_hStdin = GetStdHandle(STD_INPUT_HANDLE);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = tui_sigwinch_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGWINCH, &sa, NULL);
    sigaction(SIGCONT, &sa, NULL);
#endif
    tui_raw_mode_enter();
    tui_clear();
    tui_cursor_hide();
}

void tui_screen_restore(void)
{
    tui_cursor_show();
    tui_clear();
    tui_raw_mode_exit();
}

void tui_suspend(tui_t* t)
{
    (void)t;
#ifndef _WIN32
    tui_cursor_show();
    tui_raw_mode_exit();
    raise(SIGTSTP);
    tui_raw_mode_enter();
    tui_cursor_hide();
    tui_clear();
    t->dirty = 1;
#endif
}

/* ================================================================
 * Legacy API wrappers (used by main.c)
 * ================================================================ */

void tui_init(tui_t* t)
{
    memset(t, 0, sizeof(*t));
    t->running = 1;
    t->dirty = 1;
    t->screen = SCREEN_LOGIN;
    t->login_field = 0;
    t->input_active = 1;
    t->peer_scroll = 0;
    t->peer_selected = 0;
}

void tui_term_init(tui_t* t)
{
    (void)t;
    tui_screen_setup();
    tui_input_init();
}

void tui_term_restore(void)
{
    tui_screen_restore();
}

void tui_shutdown(tui_t* t)
{
    (void)t;
    tui_input_disable_mouse();
    tui_term_restore();
}

void tui_render(tui_t* t)
{
    t->width = tui_terminal_width();
    t->height = tui_terminal_height();
    char buf[65536];
    int pos = 0;
    int max = (int)sizeof(buf);
    pos += tui_panel_topbar(t, buf + pos, max - pos);
    switch (t->screen) {
        case SCREEN_LOGIN:
            pos += tui_panel_login(t, buf + pos, max - pos);
            break;
        case SCREEN_PEER_LIST:
            pos += tui_panel_peer_list(t, buf + pos, max - pos);
            break;
        case SCREEN_CHAT:
            pos += tui_panel_chat(t, buf + pos, max - pos);
            break;
        case SCREEN_GROUP:
            pos += tui_panel_room_sidebar(t, buf + pos, max - pos);
            pos += tui_panel_group_chat(t, buf + pos, max - pos);
            pos += tui_panel_member_sidebar(t, buf + pos, max - pos);
            break;
    }
    pos += tui_panel_request_popup(t, buf + pos, max - pos);
    pos += tui_panel_call_popup(t, buf + pos, max - pos);
    pos += tui_panel_statusbar(t, buf + pos, max - pos);
    if (pos > 0) tui_write(buf);
    if (pos > max) tui_write("[render truncated]");
    t->dirty = 0;
}

void tui_add_chat(tui_t* t, const char* text, uint16_t port, int is_self)
{
    if (t->chat_count >= TUI_MAX_CHAT_LINES) {
        memmove(t->chat_lines, t->chat_lines + 1,
                (size_t)(TUI_MAX_CHAT_LINES - 1) * sizeof(chat_line_t));
        t->chat_count = TUI_MAX_CHAT_LINES - 1;
    }
    chat_line_t* cl = &t->chat_lines[t->chat_count++];
    snprintf(cl->text, sizeof(cl->text), "%s", text);
    cl->sender_port = port;
    cl->is_self = is_self;
    cl->line = t->chat_count;
    cl->timestamp = time(NULL);
    cl->status = is_self ? 0 : 1;
    cl->seq = 0;
    t->dirty = 1;
}

void tui_add_chat_with_seq(tui_t* t, const char* text, uint16_t port, int is_self, uint32_t seq)
{
    tui_add_chat(t, text, port, is_self);
    if (t->chat_count > 0)
        t->chat_lines[t->chat_count - 1].seq = seq;
}

void tui_update_info(tui_t* t, conn_info_t* info)
{
    memcpy(&t->conn_info, info, sizeof(conn_info_t));
}

void tui_add_log(tui_t* t, const char* msg)
{
    if (t->log_line < 32)
        snprintf(t->log[t->log_line++], 256, "%s", msg);
}
