#pragma once
#include "tui.h"

void tui_input_init(void);
int tui_input_poll(tui_t* t, int timeout_ms);
void tui_input_enable_mouse(void);
void tui_input_disable_mouse(void);
