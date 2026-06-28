#pragma once
#include <time.h>
#include "transport_api.h"
#include "identity.h"

typedef enum { SCREEN_LOGIN, SCREEN_PEER_LIST, SCREEN_CHAT, SCREEN_GROUP } screen_t;

typedef enum { GROUP_FOCUS_ROOMS = 0, GROUP_FOCUS_CHAT = 1, GROUP_FOCUS_MEMBERS = 2 } group_focus_t;

typedef struct {
    char text[1024];
    uint16_t sender_port;
    int is_self;
    uint32_t line;
    time_t timestamp;
    uint8_t status;
    uint32_t seq;
} chat_line_t;

#define TUI_MAX_CHAT_LINES 200
#define TUI_INPUT_BUF 256
#define TUI_MAX_PEERS 32

typedef enum {
    TUI_ACTION_NONE = 0,
    TUI_ACTION_QUIT,
    TUI_ACTION_LOGIN_SUBMIT,
    TUI_ACTION_PEER_SELECT,
    TUI_ACTION_CHAT_SEND,
    TUI_ACTION_CONN_ACCEPT,
    TUI_ACTION_CONN_DECLINE,
    TUI_ACTION_CALL_ACCEPT,
    TUI_ACTION_CALL_DECLINE,
    TUI_ACTION_AUDIO_TOGGLE,
    TUI_ACTION_VIDEO_TOGGLE,
    TUI_ACTION_FILE_SEND,
    TUI_ACTION_GO_BACK,
} tui_action_t;

typedef struct {
    int width, height;
    int dirty;
    int resize_dirty;

    screen_t screen;
    int running;

    /* identity */
    char username[32];
    char display_name[64];
    identity_t identity;
    int identity_ready;

    /* login screen */
    char login_username[32];
    char login_display[64];
    int login_field;
    int login_cursor;
    int login_error;

    /* peer list */
    int peer_scroll;
    int peer_selected;
    peer_entry_t peers[TUI_MAX_PEERS];
    int peer_count;

    /* connection request popup */
    int show_conn_popup;
    char conn_req_addr[64];
    uint16_t conn_req_port;
    char conn_req_username[32];
    char conn_req_display[64];
    int conn_popup_selection;

    /* incoming call popup */
    int show_call_popup;
    char call_req_peer[32];
    int call_popup_type;
    int call_popup_selection;

    /* chat */
    int chat_scroll;
    int chat_count;
    chat_line_t chat_lines[TUI_MAX_CHAT_LINES];
    char chat_partner[32];
    conn_info_t conn_info;

    /* group chat */
    char current_room[32];
    int group_focus;
    int group_room_scroll;
    int group_member_scroll;
    int group_chat_scroll;
    int group_dirty;

    /* input */
    char input_buf[TUI_INPUT_BUF];
    int input_len;
    int input_pos;
    int input_active;

    /* typing indicator */
    char typing_peer[32];
    int typing_tick;
    int typing_flag;

    /* unread count */
    int unread_count;

    /* mouse state */
    int mouse_event;
    int mouse_last_x;
    int mouse_last_y;
    int mouse_btn;
    int mouse_scroll;

    /* status */
    int log_line;
    char log[32][256];
    int audio_active;
    int video_active;
} tui_t;

void tui_init(tui_t* t);
void tui_term_init(tui_t* t);
void tui_term_restore(void);
void tui_render(tui_t* t);
int tui_poll_input(tui_t* t, int timeout_ms);
void tui_add_chat(tui_t* t, const char* text, uint16_t port, int is_self);
void tui_add_chat_with_seq(tui_t* t, const char* text, uint16_t port, int is_self, uint32_t seq);
void tui_update_info(tui_t* t, conn_info_t* info);
void tui_suspend(tui_t* t);
void tui_add_log(tui_t* t, const char* msg);
void tui_shutdown(tui_t* t);
