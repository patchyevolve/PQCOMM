#pragma once
#include "packet_view.h"
#include "session.h"

/* called from pipeline on rx side: decrypt session layer */
int session_enc_check(packet_view_t* p, session_t* sess);

/* called from tx side before sending: encrypt session layer */
int session_enc_apply(packet_buf_t* p, packet_view_t* view, session_t* sess);
