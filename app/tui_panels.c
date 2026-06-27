#include "tui_panels.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>

int tui_panel_topbar(tui_t* t, char* buf, int max)
{
    int n = 0;
    char title[128];
    const char* state = "?";
    if (t->screen == SCREEN_LOGIN) state = "SETUP";
    else if (t->screen == SCREEN_PEER_LIST) state = "PEERS";
    else if (t->screen == SCREEN_CHAT) state = t->conn_info.state == CONN_LOCKED ? "SECURE" : "CONN";
    snprintf(title, sizeof(title), " pqCOMMbulds  |  %s  |  %s",
             t->username[0] ? t->username : "(setup)", state);
    int pad = t->width - (int)strlen(title);
    if (pad < 1) pad = 1;
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37;44m%s%*s\033[0m\n", title, pad, "");
    return n;
}

int tui_panel_login(tui_t* t, char* buf, int max)
{
    int n = 0;
    int cx = t->width / 2;
    int cy = t->height / 2 - 4;
    if (cy < 0) cy = 0;

    /* clear area */
    for (int i = 0; i < 10; i++)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;1H\033[K", cy + 1 + i);

    int box_x = cx - 24;
    if (box_x < 0) box_x = 0;

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m+------------------------------------------------+\033[0m",
                  cy + 1, box_x + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m       \033[1;37mSSM Secure Messenger\033[0m       \033[1;33m|\033[0m",
                  cy + 2, box_x + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m                                          \033[1;33m|\033[0m",
                  cy + 3, box_x + 1);

    int ulen = (int)strlen(t->login_username);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m  Username: [", cy + 4, box_x + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH", cy + 4, box_x + 15);
    for (int i = 0; i < 20; i++) {
        if (i < ulen)
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "%c", t->login_username[i]);
        else
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), " ");
    }
    if (t->login_field == 0 && ulen < 20)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "\033[5m_\033[0m");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "]     \033[1;33m|\033[0m");

    int dlen = (int)strlen(t->login_display);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m  Display:  [", cy + 5, box_x + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH", cy + 5, box_x + 15);
    for (int i = 0; i < 20; i++) {
        if (i < dlen)
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "%c", t->login_display[i]);
        else
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), " ");
    }
    if (t->login_field == 1 && dlen < 20)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "\033[5m_\033[0m");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "]     \033[1;33m|\033[0m");

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m                                          \033[1;33m|\033[0m",
                  cy + 6, box_x + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m  \033[1;32m[Enter]\033[0m Start        \033[1;33m[TAB]\033[0m next field  \033[1;33m|\033[0m",
                  cy + 7, box_x + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m+------------------------------------------------+\033[0m",
                  cy + 8, box_x + 1);

    if (t->login_error)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[1;31mUsername required\033[0m", cy + 10, box_x + 8);
    return n;
}

int tui_panel_peer_list(tui_t* t, char* buf, int max)
{
    int n = 0;
    int col_w = 28;
    if (col_w > t->width / 3) col_w = t->width / 3;
    if (col_w < 20) col_w = 20;

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37m Peers (%d)%s\033[0m\n", t->peer_count,
                  t->unread_count > 0 ? " \033[1;31m(!)\033[0m" : "");

    int rows = t->height - 4;
    for (int i = 0; i < rows && i < t->peer_count; i++) {
        int idx = i + t->peer_scroll;
        if (idx >= t->peer_count) break;
        peer_entry_t* p = &t->peers[idx];
        char sel = (idx == t->peer_selected) ? '>' : ' ';
        const char* dot = p->is_online ? "\033[1;32m●\033[0m" : "\033[1;31m○\033[0m";
        const char* badge = "";
        if (p->is_connected) badge = " \033[1;34m[SECURE]\033[0m";
        else if (p->is_online) badge = " \033[1;33m[ONLINE]\033[0m";

        /* last seen */
        char last_seen[32] = "";
        if (!p->is_online && p->last_seen_ms > 0) {
            uint64_t ago = ((uint64_t)time(NULL) * 1000 - p->last_seen_ms) / 60000;
            if (ago < 1) snprintf(last_seen, sizeof(last_seen), "just now");
            else if (ago < 60) snprintf(last_seen, sizeof(last_seen), "%llum ago", (unsigned long long)ago);
            else snprintf(last_seen, sizeof(last_seen), ">1h ago");
        }

        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "%c %s \033[1;37m%-12s\033[0m %s%s\n",
                      sel, dot,
                      p->username[0] ? p->username : p->addr,
                      badge,
                      p->is_online ? "" : "\033[1;30m");

        /* show last_seen on a second line only for selected offline peer */
        if (idx == t->peer_selected && !p->is_online && last_seen[0]) {
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                          "   \033[1;30mlast seen %s\033[0m\n", last_seen);
        }
    }
    return n;
}

int tui_panel_chat(tui_t* t, char* buf, int max)
{
    int n = 0;
    if (t->chat_partner[0]) {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[1;37m Chat with %s\033[0m", t->chat_partner);
        /* show latency in header */
        if (t->conn_info.path_count > 0) {
            uint64_t rtt = t->conn_info.paths[0].rtt_ns;
            if (rtt > 0)
                n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                              "  \033[1;30m%llums\033[0m", (unsigned long long)(rtt / 1000000));
        }
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "\n");
    } else {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[1;30m Select a peer to chat\033[0m\n");
    }

    conn_info_t* info = &t->conn_info;
    int chat_h = t->height - 6;
    int start = t->chat_count > chat_h ? t->chat_count - chat_h : 0;
    for (int i = start; i < t->chat_count; i++) {
        chat_line_t* cl = &t->chat_lines[i];
        struct tm* tm_info = localtime(&cl->timestamp);
        char ts[16];
        strftime(ts, sizeof(ts), "%H:%M", tm_info);

        const char* status_str = "";
        if (cl->is_self) {
            if (cl->status == 2) status_str = " \033[1;32m✓✓\033[0m";
            else if (cl->status == 1) status_str = " \033[1;33m✓✓\033[0m";
            else if (cl->status == 0) status_str = " \033[1;30m✓\033[0m";
        }

        if (cl->is_self)
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                          "\033[1;30m[%s]\033[0m \033[1;34m[me]\033[0m %s%s\n",
                          ts, cl->text, status_str);
        else
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                          "\033[1;30m[%s]\033[0m \033[1;32m[%s]\033[0m %s\n",
                          ts,
                          t->chat_partner[0] ? t->chat_partner : "them", cl->text);
    }

    /* typing indicator */
    if (t->typing_tick > 0 && t->typing_peer[0]) {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[1;33m%s is typing...\033[0m\n", t->typing_peer);
    }

    if (info->state == CONN_LOCKED)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[1;32m[PQ encrypted]\033[0m\n");
    else if (info->state == CONN_HANDSHAKE)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[1;33m[PQ handshake...]\033[0m\n");
    return n;
}

int tui_panel_request_popup(tui_t* t, char* buf, int max)
{
    if (!t->show_conn_popup) return 0;
    int n = 0;
    int pw = 46, ph = 7;
    int px = (t->width - pw) / 2;
    int py = (t->height - ph) / 2;
    if (px < 0) px = 0;
    if (py < 0) py = 0;

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m+------------------------------------------------+\033[0m",
                  py, px + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m          \033[1;37mIncoming Connection\033[0m          \033[1;33m|\033[0m",
                  py + 1, px + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m  %s (%s:%u)                   \033[1;33m|\033[0m",
                  py + 2, px + 1,
                  t->conn_req_display[0] ? t->conn_req_display : t->conn_req_username,
                  t->conn_req_addr, t->conn_req_port);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m  wants to start a secure chat         \033[1;33m|\033[0m",
                  py + 3, px + 1);
    if (t->conn_popup_selection == 0)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[1;33m|\033[0m      \033[1;32m[ Accept ]\033[0m    [ Decline ]      \033[1;33m|\033[0m",
                      py + 4, px + 1);
    else
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[1;33m|\033[0m        [ Accept ]    \033[1;31m[ Decline ]\033[0m    \033[1;33m|\033[0m",
                      py + 4, px + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m+------------------------------------------------+\033[0m",
                  py + 5, px + 1);
    return n;
}

int tui_panel_call_popup(tui_t* t, char* buf, int max)
{
    if (!t->show_call_popup) return 0;
    int n = 0;
    int pw = 46, ph = 7;
    int px = (t->width - pw) / 2;
    int py = (t->height - ph) / 2;
    if (px < 0) px = 0;
    if (py < 0) py = 0;

    const char* call_type = t->call_popup_type == 0 ? "Audio" : "Video";
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m+------------------------------------------------+\033[0m",
                  py, px + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m       \033[1;37mIncoming %s Call\033[0m         \033[1;33m|\033[0m",
                  py + 1, px + 1, call_type);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m  %s wants to start a %s call        \033[1;33m|\033[0m",
                  py + 2, px + 1, t->call_req_peer, call_type);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m|\033[0m                                          \033[1;33m|\033[0m",
                  py + 3, px + 1);
    if (t->call_popup_selection == 0)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[1;33m|\033[0m      \033[1;32m[ Accept ]\033[0m    [ Decline ]      \033[1;33m|\033[0m",
                      py + 4, px + 1);
    else
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[1;33m|\033[0m        [ Accept ]    \033[1;31m[ Decline ]\033[0m    \033[1;33m|\033[0m",
                      py + 4, px + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m+------------------------------------------------+\033[0m",
                  py + 5, px + 1);
    return n;
}

int tui_panel_statusbar(tui_t* t, char* buf, int max)
{
    int n = 0;
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;1H\033[2K\033[0m", t->height);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;1H", t->height - 1);
    /* status indicators */
    char status[192] = "";
    if (t->conn_info.state == CONN_LOCKED) {
        const char* audio_s = t->audio_active ? "\033[1;35m[AUDIO]\033[0m" : "";
        const char* video_s = t->video_active ? "\033[1;36m[VIDEO]\033[0m" : "";

        /* latency indicator */
        uint64_t rtt = t->conn_info.paths[0].rtt_ns / 1000000;
        const char* rtt_color = "\033[1;32m";
        if (rtt > 200) rtt_color = "\033[1;33m";
        if (rtt > 500) rtt_color = "\033[1;31m";

        snprintf(status, sizeof(status), " %s%s %s%llums\033[0m",
                 audio_s, video_s, rtt_color, (unsigned long long)rtt);
    }
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[2K> %s%s\033[0m", t->input_buf, status);

    /* keybinding hints at status line */
    if (t->screen == SCREEN_CHAT && t->conn_info.state == CONN_LOCKED) {
        char hints[192] = "";
        snprintf(hints, sizeof(hints),
                 "\033[1;30m [Esc:back] %s %s [Ctrl+F:file]\033[0m",
                 t->audio_active ? "[Ctrl+A:end]" : "[Ctrl+A:audio]",
                 t->video_active ? "[Ctrl+V:end]" : "[Ctrl+V:video]");
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH%s", t->height, 1, hints);
    } else if (t->screen == SCREEN_PEER_LIST) {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[1;30m [j/k:nav] [Enter:select] [q:quit]\033[0m",
                      t->height, 1);
    }

    if (t->input_active) {
        int col = 3 + t->input_pos;
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[5m_\033[0m", t->height - 1, col);
    }
    return n;
}
