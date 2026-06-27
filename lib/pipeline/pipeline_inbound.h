#pragma once

#include "packet.h"
#include "packet_view.h"
#include "session.h"
#include "rx_demux.h"

typedef enum
{
    PIPELINE_OK = 0,
    PIPELINE_DROP_PARSE,
    PIPELINE_DROP_OFFENSIVE,
    PIPELINE_DROP_ANTI,
    PIPELINE_DROP_STATIC,
    PIPELINE_DROP_KERNEL,
    PIPELINE_DROP_SESSION,
    PIPELINE_DROP_RESILIENCE,
    PIPELINE_DROP_SESSION_ENC,
    PIPELINE_DROP_SEQ,
    PIPELINE_DROP_CHANNEL,
    PIPELINE_DROP_DEMUX
} pipeline_result_t;

// Pipeline context - holds session-specific state
typedef struct {
    session_t* sess;
    rx_queues_t* rxq;
    packet_buf_t* recovered;
    packet_view_t view;
} pipeline_ctx_t;

pipeline_result_t pipeline_inbound_process(
    packet_buf_t* p,
    pipeline_ctx_t* ctx
);

pipeline_result_t pipeline_inbound_pre_crypto(
    packet_buf_t* p,
    pipeline_ctx_t* ctx
);

pipeline_result_t pipeline_inbound_post_crypto(
    packet_buf_t* p,
    pipeline_ctx_t* ctx
);
