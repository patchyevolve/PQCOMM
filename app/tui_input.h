#pragma once
#include "tui.h"

void tui_input_init(void);
int tui_input_poll(tui_t* t, int timeout_ms);
