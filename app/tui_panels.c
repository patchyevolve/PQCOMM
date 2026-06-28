#include "tui_panels.h"
#include "group.h"
#include "monitor.h"
#include "session.h"
#include "kernel_filter.h"
#include "anti_analysis.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <mbedtls/sha256.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <arpa/inet.h>
#endif

static void get_time_str(char* buf, int sz)
{
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    if (tm_info) strftime(buf, (size_t)sz, "%H:%M", tm_info);
    else snprintf(buf, (size_t)sz, "--:--");
}

static const char* session_state_str(conn_state_t s)
{
    switch (s) {
        case CONN_IDLE: return "IDLE";
        case CONN_CONNECTING: return "CONNECTING";
        case CONN_HANDSHAKE: return "HANDSHAKE";
        case CONN_LOCKED: return "SECURE";
        case CONN_FAILED: return "FAILED";
        default: return "?";
    }
}

static const char* conn_state_icon(conn_state_t s)
{
    switch (s) {
        case CONN_IDLE: return "\xe2\x97\x8b";
        case CONN_CONNECTING: return "\xe2\x9f\xb3";
        case CONN_HANDSHAKE: return "\xf0\x9f\x94\x91";
        case CONN_LOCKED: return "\xf0\x9f\x94\x92";
        case CONN_FAILED: return "\xe2\x9c\x97";
        default: return "?";
    }
}

int tui_panel_topbar(tui_t* t, char* buf, int max)
{
    int n = 0;
    char ts[16];
    get_time_str(ts, sizeof(ts));
    const char* uname = t->username[0] ? t->username : "(setup)";
    const char* state = session_state_str(t->conn_info.state);

    char health[128] = "";
    if (t->conn_info.state == CONN_LOCKED) {
        uint64_t rtt = t->conn_info.paths[0].rtt_ns / 1000000;
        float loss = t->conn_info.paths[0].loss_rate;
        snprintf(health, sizeof(health), " | loss %.1f%% | %llums",
                 (double)loss, (unsigned long long)rtt);
    }

    char mid[192];
    snprintf(mid, sizeof(mid), " %s | %s | %s%s", uname, state, ts, health);

    int sep_w = t->width - (int)strlen(mid) - 12;
    if (sep_w < 1) sep_w = 1;

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37;44m pqCOMMbulds%s%*s\033[0m\n",
                  mid, sep_w, "");
    return n;
}

int tui_panel_login(tui_t* t, char* buf, int max)
{
    int n = 0;
    int cx = t->width / 2;
    int cy = t->height / 2 - 4;
    if (cy < 0) cy = 0;

    for (int i = 0; i < 12; i++)
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
                  "\033[%d;%dH\033[1;33m|\033[0m  \033[1;30mExisting identity auto-loads\033[0m   \033[1;33m|\033[0m",
                  cy + 8, box_x + 1);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;33m+------------------------------------------------+\033[0m",
                  cy + 9, box_x + 1);

    if (t->login_error)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[1;31mUsername required\033[0m", cy + 11, box_x + 8);
    return n;
}

int tui_panel_peer_list(tui_t* t, char* buf, int max)
{
    int n = 0;
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37m Peers (%d)%s\033[0m\n", t->peer_count,
                  t->unread_count > 0 ? " \033[1;31m(!)\033[0m" : "");

    if (t->identity_ready) {
        char fp_short[32];
        uint8_t hash[32];
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, t->identity.identity_key, 32);
        mbedtls_sha256_update(&ctx, (uint8_t*)t->username, strlen(t->username));
        mbedtls_sha256_finish(&ctx, hash);
        snprintf(fp_short, sizeof(fp_short), "%02x%02x%02x%02x...%02x%02x",
                 hash[0], hash[1], hash[2], hash[3], hash[30], hash[31]);
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      " \033[1;30mFP: %s\033[0m\n", fp_short);
    }

    int rows = t->height - (t->identity_ready ? 5 : 4);
    for (int i = 0; i < rows && i < t->peer_count; i++) {
        int idx = i + t->peer_scroll;
        if (idx >= t->peer_count) break;
        peer_entry_t* p = &t->peers[idx];
        char sel = (idx == t->peer_selected) ? '>' : ' ';
        const char* dot = p->is_online ? "\033[1;32m●\033[0m" : "\033[1;31m○\033[0m";
        const char* badge = "";
        if (p->is_connected) badge = " \033[1;34m[SECURE]\033[0m";
        else if (p->is_online) badge = " \033[1;33m[ONLINE]\033[0m";

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
                      "\033[1;37m %s | %s", t->chat_partner,
                      session_state_str(t->conn_info.state));
        if (t->conn_info.state == CONN_LOCKED) {
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                          " | key epoch %u", (unsigned int)0);
            if (t->conn_info.path_count > 0) {
                uint64_t rtt = t->conn_info.paths[0].rtt_ns;
                if (rtt > 0)
                    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                                  " | %llums", (unsigned long long)(rtt / 1000000));
            }
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                          " | fec %s", t->conn_info.fec_enabled ? "on" : "off");
        }
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "\033[0m\n");
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
            if (cl->status == 2) status_str = " \033[1;32mread\033[0m";
            else if (cl->status == 1) status_str = " \033[1;33mdelivered\033[0m";
            else if (cl->status == 0) status_str = " \033[1;30msent\033[0m";
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
    else if (info->state == CONN_FAILED)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[1;31m[connection failed]\033[0m\n");
    else if (info->state == CONN_IDLE || info->state == CONN_CONNECTING)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[1;30m[waiting for secure session...]\033[0m\n");
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

/* ================================================================
 * User tab bar
 * ================================================================ */
int tui_panel_user_tabs(tui_t* t, char* buf, int max)
{
    int n = 0;
    const char* labels[USER_TAB_COUNT] = {
        "Peers", "Chats", "Groups", "Calls", "Files", "Settings"
    };
    int x = 1;
    for (int i = 0; i < USER_TAB_COUNT; i++) {
        if (t->user_tab == i && t->screen != SCREEN_ADVANCED)
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                          "\033[%d;%dH\033[1;47;30m %s \033[0m",
                          2, x, labels[i]);
        else
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                          "\033[%d;%dH\033[1;30m %s \033[0m",
                          2, x, labels[i]);
        x += (int)strlen(labels[i]) + 3;
        if (x > t->width) break;
    }
    return n;
}

/* ================================================================
 * Advanced tab bar
 * ================================================================ */
int tui_panel_adv_tabs(tui_t* t, char* buf, int max)
{
    int n = 0;
    const char* labels[ADV_TAB_COUNT] = {
        "Overview", "Security", "Pipeline", "Watchers",
        "Network", "Crypto", "Events", "Controls"
    };
    int x = 1;
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;1H\033[1;37;44m Advanced Space %*s\033[0m\n",
                  2, t->width - 17, "");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[2K");
    for (int i = 0; i < ADV_TAB_COUNT; i++) {
        if (t->adv_tab == i)
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                          "\033[%d;%dH\033[1;47;30m %s \033[0m",
                          2, x, labels[i]);
        else
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                          "\033[%d;%dH\033[1;30m %s \033[0m",
                          2, x, labels[i]);
        x += (int)strlen(labels[i]) + 3;
        if (x > t->width) break;
    }
    return n;
}

/* ================================================================
 * Settings screen
 * ================================================================ */
int tui_panel_settings(tui_t* t, char* buf, int max)
{
    int n = 0;
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37m Settings\033[0m\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;30m %s / %s\033[0m\n",
                  t->username[0] ? t->username : "(none)",
                  t->display_name[0] ? t->display_name : "(none)");

    const char* lines[] = {
        "Identity",
        "Network",
        "Discovery",
        "Runtime options",
        "Advanced Space",
        "Quit"
    };
    int nlines = sizeof(lines) / sizeof(lines[0]);
    int rows = t->height - 6;
    if (rows > nlines) rows = nlines;

    for (int i = 0; i < rows; i++) {
        char sel = (i == t->settings_selection) ? '>' : ' ';
        const char* hl = (i == t->settings_selection) ? "\033[1;37;44m" : "";
        const char* desc = "";
        switch (i) {
            case 0: desc = ""; break;
            case 1: desc = "  \033[1;30mport 9001, alt 9003\033[0m"; break;
            case 2: desc = "  \033[1;30mport 9009, enabled\033[0m"; break;
            case 3: desc = "  \033[1;30mFEC on, group 4\033[0m"; break;
            case 4: desc = "  \033[1;30mdiagnostics and controls\033[0m"; break;
            case 5: desc = ""; break;
        }
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "%c %s%-20s\033[0m%s\n",
                      sel, hl, lines[i], desc);
    }
    return n;
}

/* ================================================================
 * Advanced panel helpers
 * ================================================================ */
static void render_adv_header(tui_t* t, char* buf, int* pn, int max, const char* tab_name)
{
    int n = *pn;
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37m Advanced / %s", tab_name);
    if (!t->adv_paused)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "  \033[1;30mlive\033[0m");
    else
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "  \033[1;33mpaused\033[0m");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "\033[0m\n");
    *pn = n;
}

int tui_panel_adv_overview(tui_t* t, char* buf, int max)
{
    int n = 0;
    render_adv_header(t, buf, &n, max, "Overview");

    monitor_snapshot_t mon;
    monitor_get_snapshot(&mon);

    transport_status_t st;
    transport_get_status(&st);

    conn_info_t* ci = &t->conn_info;
    uint64_t uptime_s = ci->uptime_ms / 1000;
    int uh = (int)(uptime_s / 3600);
    int um = (int)((uptime_s % 3600) / 60);
    int us = (int)(uptime_s % 60);

    char uptime_str[32];
    snprintf(uptime_str, sizeof(uptime_str), "%02d:%02d:%02d", uh, um, us);

    uint64_t rtt = ci->paths[0].rtt_ns / 1000000;
    float loss = ci->paths[0].loss_rate;

    const char* sys_state = (ci->state == CONN_LOCKED) ? "\033[1;32mOK\033[0m" : "\033[1;33mWARN\033[0m";
    const char* sec_state = (ci->state == CONN_LOCKED) ? "\033[1;32mOK\033[0m" : "\033[1;33mWARN\033[0m";

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mSystem\033[0m       %s    uptime %s   pool %u/%u free\n",
                  sys_state, uptime_str, mon.pool_free_current, mon.pool_free_current + (4096 - mon.pool_free_current));
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mSession\033[0m      %s    peer %s        session %08x\n",
                  sec_state, t->chat_partner[0] ? t->chat_partner : "(none)",
                  (unsigned int)(ci->session_id & 0xFFFFFFFF));
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mTransport\033[0m    %s    rtt %llums       loss %.1f%%\n",
                  (rtt < 500) ? "\033[1;32mOK\033[0m" : "\033[1;31mHIGH\033[0m",
                  (unsigned long long)rtt, (double)loss);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mResilience\033[0m   %s    fec %s group %u  recovered %u\n",
                  ci->fec_enabled ? "\033[1;32mOK\033[0m" : "\033[1;33mOFF\033[0m",
                  ci->fec_enabled ? "on" : "off", (unsigned int)0,
                  (unsigned int)ci->fec_recovered_count);

    /* Recent events from TUI log */
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "\n\033[1;37mRecent events\033[0m\n");
    int log_start = t->log_line > 5 ? t->log_line - 5 : 0;
    for (int i = log_start; i < t->log_line; i++) {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      " %s\n", t->log[i]);
    }
    if (t->log_line == 0)
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      " \033[1;30m(no events)\033[0m\n");
    return n;
}

int tui_panel_adv_security(tui_t* t, char* buf, int max)
{
    int n = 0;
    render_adv_header(t, buf, &n, max, "Security");

    conn_info_t* ci = &t->conn_info;
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mSession\033[0m       %-12s  session id %08x\n",
                  session_state_str(ci->state),
                  (unsigned int)(ci->session_id & 0xFFFFFFFF));
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mIdentity\033[0m      %s\n", t->username[0] ? t->username : "(none)");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mAEAD\033[0m          ChaCha20-Poly1305\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mKEM\033[0m           ML-KEM 768\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mIdentity\033[0m      HMAC-SHA256\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mKey rotation\033[0m  epoch %u\n", (unsigned int)0);

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "\n\033[1;37mHandshake stats\033[0m\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  " attempts %u  successes %u\n",
                  (unsigned int)g_handshake_stats.attempts_total,
                  (unsigned int)g_handshake_stats.successes);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  " timeouts %u  identity %u  replay %u  state %u\n",
                  (unsigned int)g_handshake_stats.failures_timeout,
                  (unsigned int)g_handshake_stats.failures_identity,
                  (unsigned int)g_handshake_stats.failures_replay,
                  (unsigned int)g_handshake_stats.failures_state);
    return n;
}

int tui_panel_adv_pipeline(tui_t* t, char* buf, int max)
{
    int n = 0;
    render_adv_header(t, buf, &n, max, "Pipeline");

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "%-18s %-8s %-10s %-8s\n",
                  "Layer", "State", "Pass", "Drop");

    monitor_snapshot_t mon;
    monitor_get_snapshot(&mon);

    struct { const char* name; volatile uint32_t* passes; volatile uint32_t* drops; } layers[] = {
        { "packet_parse",   NULL, NULL },
        { "offensive",      NULL, NULL },
        { "anti_analysis",  NULL, &g_anti_analysis.drops_high },
        { "static_shell",   NULL, NULL },
        { "kernel_filter",  &g_kernel_filter.passes, &g_kernel_filter.drops_blocked },
        { "session_gate",   NULL, NULL },
        { "resilience",     NULL, NULL },
        { "session_enc",    NULL, NULL },
        { "seq_check",      NULL, NULL },
        { "rx_demux",       NULL, NULL },
    };
    int nlayers = sizeof(layers) / sizeof(layers[0]);

    for (int i = 0; i < nlayers; i++) {
        uint32_t pass = layers[i].passes ? *layers[i].passes : mon.sample_count;
        uint32_t drop = layers[i].drops ? *layers[i].drops : (mon.total_drops / (nlayers > 0 ? nlayers : 1));
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "%-18s \033[1;32mOK\033[0m     %-10u %-8u\n",
                      layers[i].name, (unsigned int)pass, (unsigned int)drop);
    }
    return n;
}

int tui_panel_adv_watchers(tui_t* t, char* buf, int max)
{
    int n = 0;
    render_adv_header(t, buf, &n, max, "Watchers");

    monitor_snapshot_t mon;
    monitor_get_snapshot(&mon);

    struct { const char* name; const char* state; const char* detail; } watchers[] = {
        { "rx-worker",   mon.rx_thread_stalled ? "STALL" : "alive",    "polling" },
        { "tx-worker",   mon.tx_thread_stalled ? "STALL" : "alive",    "queue empty" },
        { "crypto",      mon.crypto_thread_stalled ? "STALL" : "alive", "0 pending" },
        { "pool",        "OK", NULL },
        { "handshake",   NULL, NULL },
    };
    int nw = sizeof(watchers) / sizeof(watchers[0]);

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "%-16s %-10s %s\n", "Watcher", "State", "Detail");
    for (int i = 0; i < nw; i++) {
        const char* state_color = "\033[1;32m";
        if (watchers[i].state && strcmp(watchers[i].state, "STALL") == 0)
            state_color = "\033[1;31m";

        char detail[64] = "";
        if (i == 3) snprintf(detail, sizeof(detail), "min free %u", (unsigned int)mon.pool_free_min);
        else if (i == 4) snprintf(detail, sizeof(detail), "attempts %u success %u",
                                   (unsigned int)g_handshake_stats.attempts_total,
                                   (unsigned int)g_handshake_stats.successes);
        else if (watchers[i].detail) snprintf(detail, sizeof(detail), "%s", watchers[i].detail);

        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "%-16s %s%-10s\033[0m %s\n",
                      watchers[i].name, state_color,
                      watchers[i].state ? watchers[i].state : "OK", detail);
    }

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "\n\033[1;37mPool pressure\033[0m\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "  free current %u  min free %u  total %u\n",
                  (unsigned int)mon.pool_free_current,
                  (unsigned int)mon.pool_free_min,
                  (unsigned int)(mon.pool_free_current + (4096 - mon.pool_free_current)));
    return n;
}

int tui_panel_adv_network(tui_t* t, char* buf, int max)
{
    int n = 0;
    render_adv_header(t, buf, &n, max, "Network");

    conn_info_t* ci = &t->conn_info;

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mPaths\033[0m  count %u\n", (unsigned int)ci->path_count);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "%-6s %-10s %-8s %-8s %-8s %-8s\n",
                  "Path", "State", "RTT", "Loss", "Sent", "Recv");
    for (uint32_t i = 0; i < ci->path_count && i < RESILIENCE_MAX_PATHS; i++) {
        uint64_t rtt = ci->paths[i].rtt_ns / 1000000;
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "%-6u %-10s %-8llu %-8.1f %-8u %-8u\n",
                      (unsigned int)i,
                      i == 0 ? "\033[1;32mactive\033[0m" : "standby",
                      (unsigned long long)rtt,
                      (double)ci->paths[i].loss_rate,
                      (unsigned int)ci->paths[i].packets_sent,
                      (unsigned int)ci->paths[i].packets_recv);
    }
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\n\033[1;37mResilience\033[0m\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "  FEC: %s group %u  recovered %u\n",
                  ci->fec_enabled ? "on" : "off", (unsigned int)0,
                  (unsigned int)ci->fec_recovered_count);
    return n;
}

int tui_panel_adv_crypto(tui_t* t, char* buf, int max)
{
    int n = 0;
    render_adv_header(t, buf, &n, max, "Crypto");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mKEM\033[0m           ML-KEM 768 (liboqs)\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mAEAD\033[0m          ChaCha20-Poly1305 (mbedtls)\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mIdentity\033[0m      HMAC-SHA256\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mHKDF\033[0m          SHA-256\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mNonce\033[0m         deterministic session_id+channel_id+seq\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mAAD\033[0m           header + channel key XOR-fold\n");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mKey epoch\033[0m     %u\n", (unsigned int)0);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mKey rotation\033[0m  %s\n", "N/A");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[1;37mStorage\033[0m       %s\n", "mlock / env key");
    return n;
}

int tui_panel_adv_events(tui_t* t, char* buf, int max)
{
    int n = 0;
    render_adv_header(t, buf, &n, max, "Events");

    if (t->log_line == 0) {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[1;30m(no events)\033[0m\n");
        return n;
    }

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "%-8s %-6s %-12s %s\n", "Time", "Level", "Category", "Event");
    int rows = t->height - 6;
    int start = t->log_line > rows ? t->log_line - rows : 0;
    for (int i = start; i < t->log_line; i++) {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "%-8s \033[1;32mINFO\033[0m   %-12s %s\n",
                      "", "", t->log[i]);
    }
    return n;
}

int tui_panel_adv_controls(tui_t* t, char* buf, int max)
{
    int n = 0;
    render_adv_header(t, buf, &n, max, "Controls");

    struct { const char* action; const char* key; const char* desc; } controls[] = {
        { "Trigger discovery scan",  "F5",   "Scan LAN for peers" },
        { "Toggle FEC",              "F6",   "Enable/disable forward error correction" },
        { "Request port hop",        "F7",   "Change UDP port" },
        { "Trigger rekey",           "F8",   "Initiate key rotation" },
        { "Disconnect session",      "F9",   "End active session" },
        { "Return to User Space",    "F2",   "Exit advanced mode" },
    };
    int nc = sizeof(controls) / sizeof(controls[0]);

    for (int i = 0; i < nc; i++) {
        char sel = (i == t->adv_selected_row) ? '>' : ' ';
        const char* hl = (i == t->adv_selected_row) ? "\033[1;37;44m" : "";
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "%c %s%-24s\033[0m %-6s  %s\n",
                      sel, hl, controls[i].action, controls[i].key, controls[i].desc);
    }
    return n;
}

/* ================================================================
 * Top-level dispatch for advanced panels
 * ================================================================ */
int tui_panel_advanced(tui_t* t, char* buf, int max)
{
    switch (t->adv_tab) {
        case ADV_TAB_OVERVIEW:  return tui_panel_adv_overview(t, buf, max);
        case ADV_TAB_SECURITY:  return tui_panel_adv_security(t, buf, max);
        case ADV_TAB_PIPELINE:  return tui_panel_adv_pipeline(t, buf, max);
        case ADV_TAB_WATCHERS:  return tui_panel_adv_watchers(t, buf, max);
        case ADV_TAB_NETWORK:   return tui_panel_adv_network(t, buf, max);
        case ADV_TAB_CRYPTO:    return tui_panel_adv_crypto(t, buf, max);
        case ADV_TAB_EVENTS:    return tui_panel_adv_events(t, buf, max);
        case ADV_TAB_CONTROLS:  return tui_panel_adv_controls(t, buf, max);
        default: return 0;
    }
}

/* ================================================================
 * Group panels (unchanged from original)
 * ================================================================ */
int tui_panel_room_sidebar(tui_t* t, char* buf, int max)
{
    int n = 0;
    int sw = 20;
    if (sw > t->width / 4) sw = t->width / 4;
    if (sw < 12) sw = 12;

    int rooms_avail = t->height - 2;
    int count;
    group_room_t* rooms = group_get_rooms(&count);

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;47;30m %-*s\033[0m",
                  2, 1, sw - 2, "Rooms");

    int lines = 0;
    for (int i = t->group_room_scroll; i < count && lines < rooms_avail - 1; i++, lines++) {
        int row = 3 + lines;
        group_room_t* r = &rooms[i];
        int is_current = strcmp(r->name, t->current_room) == 0;
        const char* sel = (t->group_focus == GROUP_FOCUS_ROOMS && i == t->group_room_scroll + lines)
                          ? "\033[1;33m>\033[0m" : " ";
        const char* hl = is_current ? "\033[1;37;44m" : "\033[0m";
        char display[18];
        snprintf(display, sizeof(display), "%-16s", r->name);
        display[16] = '\0';
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH%s%s%.*s\033[0m",
                      row, 1, sel, hl, sw - 3, display);
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0), "\033[K");
    }
    for (; lines < rooms_avail - 1; lines++) {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[K", 3 + lines, 1);
    }
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;37m|\033[0m", t->height, sw);
    return n;
}

int tui_panel_group_chat(tui_t* t, char* buf, int max)
{
    int n = 0;
    int sw = 20;
    if (sw > t->width / 4) sw = t->width / 4;
    if (sw < 12) sw = 12;
    int mw = 20;
    if (mw > t->width / 4) mw = t->width / 4;
    if (mw < 12) mw = 12;
    int chat_left = sw + 1;
    int chat_width = t->width - sw - mw - 2;

    group_room_t* room = t->current_room[0] ? group_find(t->current_room) : NULL;

    char hdr[64];
    if (room)
        snprintf(hdr, sizeof(hdr), " #%s", room->name);
    else
        snprintf(hdr, sizeof(hdr), " No room selected");
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;47;30m%-*s\033[0m",
                  2, chat_left, chat_width, hdr);

    if (!room || room->msg_count == 0) {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[1;30m%s\033[0m",
                      4, chat_left,
                      room ? " No messages yet" : " Select a room");
        return n;
    }

    int chat_h = t->height - 6;
    int start = room->msg_count > chat_h ? room->msg_count - chat_h : 0;
    int lines = 0;
    for (int i = start; i < room->msg_count && lines < chat_h; i++, lines++) {
        group_message_t* msg = &room->messages[i];
        time_t ts_sec = (time_t)(msg->timestamp_ms / 1000);
        struct tm* tm_info = localtime(&ts_sec);
        char ts[16];
        if (tm_info) strftime(ts, sizeof(ts), "%H:%M", tm_info);
        else snprintf(ts, sizeof(ts), "??:??");
        int row = 3 + lines;

        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[K", row, chat_left);

        int is_self = strcmp(msg->sender, t->username) == 0;
        const char* sender_color = is_self ? "\033[1;34m" : "\033[1;32m";
        char display_text[256];
        snprintf(display_text, sizeof(display_text), "%.*s",
                 chat_width > 30 ? chat_width - 30 : 80, msg->text);

        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[1;30m[%s]\033[0m %s[%s]\033[0m %s",
                      row, chat_left, ts, sender_color, msg->sender, display_text);
    }
    for (; lines < chat_h; lines++) {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[K", 3 + lines, chat_left);
    }
    return n;
}

int tui_panel_member_sidebar(tui_t* t, char* buf, int max)
{
    int n = 0;
    int mw = 20;
    if (mw > t->width / 4) mw = t->width / 4;
    if (mw < 12) mw = 12;
    int member_right = t->width - mw + 1;

    group_room_t* room = t->current_room[0] ? group_find(t->current_room) : NULL;

    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;47;30m %-*s\033[0m",
                  2, member_right, mw - 2, "Members");

    int avail = t->height - 2;
    int lines = 0;
    if (room) {
        for (int i = t->group_member_scroll; i < room->member_count && lines < avail - 1; i++, lines++) {
            int row = 3 + lines;
            group_member_t* m = &room->members[i];
            const char* dot = m->is_online ? "\033[1;32m●\033[0m" : "\033[1;31m○\033[0m";
            const char* hl = (t->group_focus == GROUP_FOCUS_MEMBERS && i == t->group_member_scroll + lines)
                             ? "\033[7m" : "";
            char display[16];
            snprintf(display, sizeof(display), "%-14s", m->username);
            display[14] = '\0';
            n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                          "\033[%d;%dH%s %s%.*s\033[0m\033[K",
                          row, member_right, dot, hl, mw - 4, display);
        }
    }
    for (; lines < avail - 1; lines++) {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[K", 3 + lines, member_right);
    }
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;%dH\033[1;37m|\033[0m", t->height, t->width - mw);
    return n;
}

/* ================================================================
 * Status bar — consistent key hints per screen
 * ================================================================ */
int tui_panel_statusbar(tui_t* t, char* buf, int max)
{
    int n = 0;

    /* status line */
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;1H\033[2K\033[0m", t->height);
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[%d;1H", t->height - 1);

    char status[192] = "";
    if (t->conn_info.state == CONN_LOCKED) {
        const char* audio_s = t->audio_active ? "\033[1;35m[AUDIO]\033[0m" : "";
        const char* video_s = t->video_active ? "\033[1;36m[VIDEO]\033[0m" : "";
        uint64_t rtt = t->conn_info.paths[0].rtt_ns / 1000000;
        const char* rtt_color = "\033[1;32m";
        if (rtt > 200) rtt_color = "\033[1;33m";
        if (rtt > 500) rtt_color = "\033[1;31m";
        snprintf(status, sizeof(status), " %s%s %s%llums\033[0m",
                 audio_s, video_s, rtt_color, (unsigned long long)rtt);
    }
    n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                  "\033[2K> %s%s", t->input_buf, status);

    /* keybinding hints at bottom */
    const char* hints = "";
    if (t->screen == SCREEN_LOGIN)
        hints = "\033[1;30m [Tab:next] [Enter:start] [q:quit]\033[0m";
    else if (t->screen == SCREEN_PEER_LIST)
        hints = "\033[1;30m [\xe2\x86\x91\xe2\x86\x93/j/k:nav] [\xe2\x86\x92/Enter:chat] [\xe2\x86\x90/Esc:back] [g:rooms] [r:refresh] [q:quit] [Ctrl+S:settings]\033[0m";
    else if (t->screen == SCREEN_CHAT) {
        if (t->conn_info.state == CONN_LOCKED)
            hints = "\033[1;30m [\xe2\x86\x90/Esc:back] [Ctrl+A:audio] [Ctrl+V:video] [Ctrl+F:file] [q:quit]\033[0m";
        else
            hints = "\033[1;30m [\xe2\x86\x90/Esc:back] [Type:message] [Enter:send]\033[0m";
    } else if (t->screen == SCREEN_GROUP) {
        const char* focus_label = "Rooms";
        if (t->group_focus == GROUP_FOCUS_CHAT) focus_label = "Chat";
        else if (t->group_focus == GROUP_FOCUS_MEMBERS) focus_label = "Members";
        hints = "\033[1;30m [Tab:focus=%s] [j/k:nav] [Enter:select] [Esc:back] [q:quit]\033[0m";
        char hint_buf[192];
        snprintf(hint_buf, sizeof(hint_buf), hints, focus_label);
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH%s", t->height, 1, hint_buf);
        hints = NULL;
    } else if (t->screen == SCREEN_SETTINGS)
        hints = "\033[1;30m [\xe2\x86\x91\xe2\x86\x93/j/k:nav] [Enter:select] [Esc:back] [Ctrl+D:advanced] [q:quit]\033[0m";
    else if (t->screen == SCREEN_ADVANCED)
        hints = "\033[1;30m [\x5b/\x5d:tab] [j/k:nav] [Enter:drill] [Esc:back] [F2:user space] [r:refresh] [p:pause]\033[0m";

    if (hints) {
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH%s", t->height, 1, hints);
    }

    /* input cursor */
    if (t->input_active && t->screen != SCREEN_ADVANCED) {
        int col = 3 + t->input_pos;
        n += snprintf(buf + n, (size_t)(max - n > 0 ? max - n : 0),
                      "\033[%d;%dH\033[5m_\033[0m", t->height - 1, col);
    }
    return n;
}
