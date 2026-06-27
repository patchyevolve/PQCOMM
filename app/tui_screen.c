#include "tui_screen.h"
#include "tui_panels.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <time.h>

void tui_init(tui_t* t)
{
    memset(t, 0, sizeof(*t));
    t->width = 80;
    t->height = 24;
    t->dirty = 1;
    t->screen = SCREEN_LOGIN;
    t->running = 1;
    t->login_field = 0;
    t->input_active = 1;
    t->typing_tick = 0;
}

void tui_term_init(void)
{
    write(STDOUT_FILENO, "\033[?25l\033[2J\033[H", 12);
}

void tui_term_restore(void)
{
    write(STDOUT_FILENO, "\033[?25h\033[2J\033[H", 12);
}

void tui_add_chat(tui_t* t, const char* text, uint16_t port, int is_self)
{
    if (t->chat_count < TUI_MAX_CHAT_LINES) {
        chat_line_t* cl = &t->chat_lines[t->chat_count++];
        size_t len = strlen(text);
        if (len > sizeof(cl->text) - 1) len = sizeof(cl->text) - 1;
        memcpy(cl->text, text, len);
        cl->text[len] = '\0';
        cl->sender_port = port;
        cl->is_self = is_self;
        cl->timestamp = time(NULL);
        cl->seq = 0;
        cl->status = 0;
    }
    t->dirty = 1;
}

void tui_add_chat_with_seq(tui_t* t, const char* text, uint16_t port, int is_self, uint32_t seq)
{
    if (t->chat_count < TUI_MAX_CHAT_LINES) {
        chat_line_t* cl = &t->chat_lines[t->chat_count++];
        size_t len = strlen(text);
        if (len > sizeof(cl->text) - 1) len = sizeof(cl->text) - 1;
        memcpy(cl->text, text, len);
        cl->text[len] = '\0';
        cl->sender_port = port;
        cl->is_self = is_self;
        cl->timestamp = time(NULL);
        cl->seq = seq;
        cl->status = 0; /* sent */
    }
    t->dirty = 1;
}

void tui_update_info(tui_t* t, conn_info_t* info)
{
    if (memcmp(&t->conn_info, info, sizeof(*info)) != 0) {
        memcpy(&t->conn_info, info, sizeof(*info));
        t->dirty = 1;
    }
}

void tui_add_log(tui_t* t, const char* msg)
{
    if (t->log_line < 32)
        snprintf(t->log[t->log_line++], 256, "%s", msg);
}

void tui_shutdown(tui_t* t)
{
    (void)t;
    tui_term_restore();
}

static void get_term_size(int* w, int* h)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        *w = ws.ws_col;
        *h = ws.ws_row;
    }
}

void tui_render(tui_t* t)
{
    if (!t->dirty) return;
    t->dirty = 0;
    get_term_size(&t->width, &t->height);
    if (t->width < 60) t->width = 60;
    if (t->height < 16) t->height = 16;

    char buf[8192];
    int n = 0;
    n += snprintf(buf + n, sizeof(buf) - (size_t)n, "\033[H\033[J");

    n += tui_panel_topbar(t, buf + n, (int)(sizeof(buf) - (size_t)n));

    if (t->screen == SCREEN_LOGIN) {
        n += tui_panel_login(t, buf + n, (int)(sizeof(buf) - (size_t)n));
    } else if (t->screen == SCREEN_PEER_LIST) {
        n += tui_panel_peer_list(t, buf + n, (int)(sizeof(buf) - (size_t)n));
        if (t->show_conn_popup)
            n += tui_panel_request_popup(t, buf + n, (int)(sizeof(buf) - (size_t)n));
    } else if (t->screen == SCREEN_CHAT) {
        n += tui_panel_chat(t, buf + n, (int)(sizeof(buf) - (size_t)n));
        if (t->show_call_popup)
            n += tui_panel_call_popup(t, buf + n, (int)(sizeof(buf) - (size_t)n));
    }

    n += tui_panel_statusbar(t, buf + n, (int)(sizeof(buf) - (size_t)n));
    write(STDOUT_FILENO, buf, (size_t)n);
}
