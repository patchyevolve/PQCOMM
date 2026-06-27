#pragma once
#include "session.h"
#include "packet_view.h"

int seq_check(session_t* s, packet_view_t* p);