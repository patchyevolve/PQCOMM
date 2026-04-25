#include "pipeline_inbound.h"

#include "packet_parse.h"
#include "offensive.h"
#include "anti_analysis.h"
#include "static_shell.h"
#include "kernel_filter_stub.h"
#include "session_gate.h"
#include "resilience.h"
#include "session_enc.h"
#include "channel_enc.h"
#include "seq_check.h"
#include "channel.h"

pipeline_result_t pipeline_inbound_process(packet_buf_t* p, pipeline_ctx_t* ctx) {
    packet_view_t view = { 0 };

    // Layer 1: Parse
    if (packet_parse(p, &view) != 0) return PIPELINE_DROP_PARSE;

    // Layer 2-5: Security checks (no session needed)
    if (offensive_check(&view) != 0) return PIPELINE_DROP_OFFENSIVE;
    if (anti_analysis_check(&view) != 0) return PIPELINE_DROP_ANTI;
    if (static_check(&view) != 0) return PIPELINE_DROP_STATIC;
    if (kernel_filter_check(&view) != 0) return PIPELINE_DROP_KERNEL;

    // Layer 6: Session check (uses ctx->sess)
    if (session_check(ctx->sess, &view) != 0) return PIPELINE_DROP_SESSION;

    // Layer 7-9: Crypto checks (uses ctx->sess)
    if (resilience_check(&view) != 0) return PIPELINE_DROP_RESILIENCE;
    if (session_enc_check(&view) != 0) return PIPELINE_DROP_SESSION_ENC;
    if (channel_enc_check(&view) != 0) return PIPELINE_DROP_CHANNEL_ENC;

    // Layer 10: Anti-replay (uses ctx->sess)
    if (seq_check(ctx->sess, &view) != 0) return PIPELINE_DROP_SEQ;

    // Layer 11: Route to channel (uses ctx->rxq)
    if (rx_demux_push(ctx->rxq, p, view.channel_id) != 0) return PIPELINE_DROP_DEMUX;

    return PIPELINE_OK;
}
