#pragma once
#include "tui.h"

int tui_panel_topbar(tui_t* t, char* buf, int max);
int tui_panel_login(tui_t* t, char* buf, int max);
int tui_panel_peer_list(tui_t* t, char* buf, int max);
int tui_panel_chat(tui_t* t, char* buf, int max);
int tui_panel_request_popup(tui_t* t, char* buf, int max);
int tui_panel_call_popup(tui_t* t, char* buf, int max);
int tui_panel_statusbar(tui_t* t, char* buf, int max);
int tui_panel_room_sidebar(tui_t* t, char* buf, int max);
int tui_panel_group_chat(tui_t* t, char* buf, int max);
int tui_panel_member_sidebar(tui_t* t, char* buf, int max);

/* new panels for overhaul */
int tui_panel_user_tabs(tui_t* t, char* buf, int max);
int tui_panel_adv_tabs(tui_t* t, char* buf, int max);
int tui_panel_settings(tui_t* t, char* buf, int max);
int tui_panel_advanced(tui_t* t, char* buf, int max);
int tui_panel_adv_overview(tui_t* t, char* buf, int max);
int tui_panel_adv_security(tui_t* t, char* buf, int max);
int tui_panel_adv_pipeline(tui_t* t, char* buf, int max);
int tui_panel_adv_watchers(tui_t* t, char* buf, int max);
int tui_panel_adv_network(tui_t* t, char* buf, int max);
int tui_panel_adv_crypto(tui_t* t, char* buf, int max);
int tui_panel_adv_events(tui_t* t, char* buf, int max);
int tui_panel_adv_controls(tui_t* t, char* buf, int max);
