#pragma once

#include "packet_view.h"
#include "session.h"

int resilience_check(packet_view_t* p, session_t* sess);
