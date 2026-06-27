#include "pipeline_inbound.h"

#include "packet_parse.h"
#include "offensive.h"
#include "anti_analysis.h"
#include "static_shell.h"
#include "kernel_filter.h"
#include "session_gate.h"
#include "resilience.h"
#include "pool.h"
#include "session_enc.h"
#include "seq_check.h"
#include "channel.h"

pipeline_result_t pipeline_inbound_pre_crypto(packet_buf_t* p, pipeline_ctx_t* ctx)
{
    packet_view_t view = { 0 };

    if (packet_parse(p, &view) != 0) return PIPELINE_DROP_PARSE;

    if (offensive_check(&view) != 0) return PIPELINE_DROP_OFFENSIVE;
    if (anti_analysis_check(&view) != 0) return PIPELINE_DROP_ANTI;
    if (static_check(&view) != 0) return PIPELINE_DROP_STATIC;
    if (kernel_filter_check(&view) != 0) return PIPELINE_DROP_KERNEL;

    if (session_check(ctx->sess, &view) != 0) return PIPELINE_DROP_SESSION;

    if (resilience_check(&view, ctx->sess) != 0) return PIPELINE_DROP_RESILIENCE;

    ctx->view = view;
    return PIPELINE_OK;
}

static int process_fec_recovered(session_t* sess, packet_buf_t* rec, packet_buf_t** recovered_out)
{
    packet_view_t rec_view = { 0 };
    if (packet_parse(rec, &rec_view) != 0) return -1;
    if (!rec_view.encrypted) return -1;
    if (session_enc_check(&rec_view, sess) != 0) return -1;
    if (seq_check(sess, &rec_view) == 0) {
        *recovered_out = rec;
        return 0;
    }
    return -1;
}

pipeline_result_t pipeline_inbound_post_crypto(packet_buf_t* p, pipeline_ctx_t* ctx)
{
    packet_view_t* view = &ctx->view;

    if (ctx->sess->fec_recovered) {
        packet_buf_t* rec = ctx->sess->fec_recovered;
        ctx->sess->fec_recovered = NULL;
        packet_buf_t* recovered = NULL;
        if (process_fec_recovered(ctx->sess, rec, &recovered) == 0) {
            ctx->recovered = recovered;
        } else {
            pool_return(rec);
        }
    }

    if (view->encrypted) {
        if (session_enc_check(view, ctx->sess) != 0) return PIPELINE_DROP_SESSION_ENC;
    }

    if (seq_check(ctx->sess, view) != 0) return PIPELINE_DROP_SEQ;

    if (rx_demux_push(ctx->rxq, p, view->channel_id) != 0) return PIPELINE_DROP_DEMUX;

    return PIPELINE_OK;
}

pipeline_result_t pipeline_inbound_process(packet_buf_t* p, pipeline_ctx_t* ctx)
{
    pipeline_result_t res = pipeline_inbound_pre_crypto(p, ctx);
    if (res != PIPELINE_OK) return res;
    return pipeline_inbound_post_crypto(p, ctx);
}
