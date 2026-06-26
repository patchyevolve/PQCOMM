#pragma once
#include "packet_view.h"
#include "session.h"

int channel_enc_check(packet_view_t* p, session_t* sess);
int channel_enc_apply(packet_buf_t* p, packet_view_t* view, session_t* sess);
