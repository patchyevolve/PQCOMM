#pragma once
#include "tui.h"

int tui_panel_topbar(tui_t* t, char* buf, int max);
int tui_panel_login(tui_t* t, char* buf, int max);
int tui_panel_peer_list(tui_t* t, char* buf, int max);
int tui_panel_chat(tui_t* t, char* buf, int max);
int tui_panel_request_popup(tui_t* t, char* buf, int max);
int tui_panel_call_popup(tui_t* t, char* buf, int max);
int tui_panel_statusbar(tui_t* t, char* buf, int max);
