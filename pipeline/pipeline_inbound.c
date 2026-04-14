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

pipeline_result_t pipeline_inbound_process(packet_buf_t* rp,
                                           packet_view_t* view,
                                           session_t* sess,
                                           rx_queues_t* rxq)
{
    if (packet_parse(rp, view) != 0)
        return PIPELINE_DROP_PARSE;

    if (offensive_check(view) != 0)
        return PIPELINE_DROP_OFFENSIVE;

    if (anti_analysis_check(view) != 0)
        return PIPELINE_DROP_ANTI;

    if (static_check(view) != 0)
        return PIPELINE_DROP_STATIC;

    if (kernel_filter_check(view) != 0)
        return PIPELINE_DROP_KERNEL;

    if (session_check(sess, view) != 0)
        return PIPELINE_DROP_SESSION;

    if (resilience_check(view) != 0)
        return PIPELINE_DROP_RESILIENCE;

    /*
     * Phase 2 insertion point:
     * 1) session-level auth/decrypt
     * 2) channel-level auth/decrypt
     * 3) nonce/tag verification
     * Keep ordering: gate -> (security) -> replay -> demux
     */
    if (session_enc_check(view) != 0)
        return PIPELINE_DROP_SESSION_ENC;

    if (channel_enc_check(view) != 0)
        return PIPELINE_DROP_CHANNEL_ENC;

    if (sess->state == SESSION_LOCKED &&
        view->channel_id != CH_CONTROL &&
        seq_check(sess, view) != 0)
    {
        return PIPELINE_DROP_SEQ;
    }

    if (view->channel_id < CH_CONTROL || view->channel_id > CH_ROUTE)
        return PIPELINE_DROP_CHANNEL;

    if (rx_demux_push(rxq, rp, view->channel_id) != 0)
        return PIPELINE_DROP_DEMUX;

    return PIPELINE_OK;
}
