#include "pipeline_inbound.h"

#include "packet_parse.h"
#include "offensive.h"
#include "anti_analysis.h"
#include "static_shell.h"
#include "kernel_filter_stub.h"
#include "session_gate.h"
#include "resilience.h"
#include "pool.h"
#include "session_enc.h"
#include "channel_enc.h"
#include "seq_check.h"
#include "channel.h"

pipeline_result_t pipeline_inbound_process(packet_buf_t* p, pipeline_ctx_t* ctx) {
    packet_view_t view = { 0 };

    if (packet_parse(p, &view) != 0) return PIPELINE_DROP_PARSE;

    if (offensive_check(&view) != 0) return PIPELINE_DROP_OFFENSIVE;
    if (anti_analysis_check(&view) != 0) return PIPELINE_DROP_ANTI;
    if (static_check(&view) != 0) return PIPELINE_DROP_STATIC;
    if (kernel_filter_check(&view) != 0) return PIPELINE_DROP_KERNEL;

    if (session_check(ctx->sess, &view) != 0) return PIPELINE_DROP_SESSION;

    if (resilience_check(&view, ctx->sess) != 0) return PIPELINE_DROP_RESILIENCE;

    /* process any FEC-recovered packet before continuing with the normal pipeline */
    if (ctx->sess->fec_recovered) {
        packet_buf_t* rec = ctx->sess->fec_recovered;
        ctx->sess->fec_recovered = NULL;
        packet_view_t rec_view = { 0 };
        if (packet_parse(rec, &rec_view) == 0 && rec_view.encrypted) {
            if (session_enc_check(&rec_view, ctx->sess) == 0) {
                if (channel_enc_check(&rec_view, ctx->sess) == 0) {
                    if (seq_check(ctx->sess, &rec_view) == 0) {
                        ctx->recovered = rec;
                        rec = NULL;
                    }
                }
            }
        }
        if (rec) pool_return(rec);
    }

    /* phase 3: decrypt session layer, then channel layer */
    if (view.encrypted) {
        if (session_enc_check(&view, ctx->sess) != 0) return PIPELINE_DROP_SESSION_ENC;
        if (channel_enc_check(&view, ctx->sess) != 0) return PIPELINE_DROP_CHANNEL_ENC;
    }

    if (seq_check(ctx->sess, &view) != 0) return PIPELINE_DROP_SEQ;

    if (rx_demux_push(ctx->rxq, p, view.channel_id) != 0) return PIPELINE_DROP_DEMUX;

    return PIPELINE_OK;
}
