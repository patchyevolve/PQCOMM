#include "audio_pipeline.h"
#include <string.h>
#include <stdlib.h>
#include <opus/opus.h>

#define OPUS_APPLICATION OPUS_APPLICATION_VOIP
#define OPUS_BITRATE     32000

int audio_init(audio_ctx_t* ctx)
{
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));

    int err = 0;
    ctx->encoder = opus_encoder_create(AUDIO_SAMPLE_RATE, AUDIO_CHANNELS,
                                        OPUS_APPLICATION, &err);
    if (err != OPUS_OK || !ctx->encoder) return -1;

    ctx->decoder = opus_decoder_create(AUDIO_SAMPLE_RATE, AUDIO_CHANNELS, &err);
    if (err != OPUS_OK || !ctx->decoder) {
        opus_encoder_destroy(ctx->encoder);
        ctx->encoder = NULL;
        return -1;
    }

    opus_encoder_ctl(ctx->encoder, OPUS_SET_BITRATE(OPUS_BITRATE));
    opus_encoder_ctl(ctx->encoder, OPUS_SET_COMPLEXITY(5));
    opus_encoder_ctl(ctx->encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));

    jitter_init(&ctx->jitter, 40);
    return 0;
}

int audio_encode(audio_ctx_t* ctx, const int16_t* pcm, uint32_t pcm_len,
                 uint8_t* out, uint32_t* out_len)
{
    if (!ctx || !ctx->encoder || !pcm || !out || !out_len) return -1;
    if (pcm_len < AUDIO_FRAME_SAMPLES) return -1;

    opus_int32 ret = opus_encode(ctx->encoder, pcm, AUDIO_FRAME_SAMPLES,
                                  out, *out_len);
    if (ret < 0) return -1;

    *out_len = (uint32_t)ret;
    ctx->packets_encoded++;
    return 0;
}

int audio_decode(audio_ctx_t* ctx, const uint8_t* data, uint32_t data_len,
                 int16_t* pcm, uint32_t* pcm_len)
{
    if (!ctx || !ctx->decoder || !pcm || !pcm_len) return -1;
    if (*pcm_len < AUDIO_FRAME_SAMPLES) return -1;

    opus_int32 ret;
    if (data && data_len > 0) {
        ret = opus_decode(ctx->decoder, data, (opus_int32)data_len,
                          pcm, AUDIO_FRAME_SAMPLES, 0);
    } else {
        ret = opus_decode(ctx->decoder, NULL, 0, pcm, AUDIO_FRAME_SAMPLES, 0);
        ctx->packets_lost++;
    }
    if (ret < 0) return -1;

    *pcm_len = (uint32_t)ret;
    ctx->packets_decoded++;
    return 0;
}

void audio_destroy(audio_ctx_t* ctx)
{
    if (!ctx) return;
    if (ctx->encoder) opus_encoder_destroy(ctx->encoder);
    if (ctx->decoder) opus_decoder_destroy(ctx->decoder);
    memset(ctx, 0, sizeof(*ctx));
}

void jitter_init(jitter_buffer_t* jb, uint32_t target_ms)
{
    memset(jb, 0, sizeof(*jb));
    jb->target_frames = target_ms / AUDIO_FRAME_MS;
    if (jb->target_frames < 1) jb->target_frames = 1;
    if (jb->target_frames > JITTER_MAX_FRAMES) jb->target_frames = JITTER_MAX_FRAMES;
}

int jitter_push(jitter_buffer_t* jb, audio_frame_t* frame)
{
    if (!jb || !frame) return -1;
    if (jb->count >= JITTER_MAX_FRAMES) return -1;

    uint32_t pos = (jb->write_cursor + jb->count) % JITTER_MAX_FRAMES;
    jb->buffer[pos] = *frame;
    jb->count++;
    return 0;
}

int jitter_pop(jitter_buffer_t* jb, audio_frame_t* frame)
{
    if (!jb || !frame) return -1;
    if (jb->count == 0) return -1;

    if (jb->count < jb->target_frames) return -1;

    *frame = jb->buffer[jb->read_cursor];
    jb->read_cursor = (jb->read_cursor + 1) % JITTER_MAX_FRAMES;
    jb->count--;
    return 0;
}

void jitter_reset(jitter_buffer_t* jb)
{
    jb->count = 0;
    jb->read_cursor = 0;
    jb->write_cursor = 0;
}
